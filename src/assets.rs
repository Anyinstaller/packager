use anyhow::{bail, Context, Result};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::archive::{MAX_ENTRIES, MAX_ENTRY_SIZE};
use crate::fsutil;
use crate::path;

#[derive(Clone, Debug)]
pub struct Asset {
    pub package_path: String,
    pub source_path: PathBuf,
}

/// Collect every regular file under `build/assets` recursively. Reparse points
/// and symlinks are rejected instead of followed, and every package path is
/// validated before it can enter the archive.
pub fn scan(build_dir: &Path) -> Result<Vec<Asset>> {
    let root = build_dir.join("assets");
    let root_metadata = match std::fs::symlink_metadata(&root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", root.display()))
        }
    };
    if fsutil::is_reparse_point(&root_metadata) {
        bail!(
            "assets directory must not be a reparse point: {}",
            root.display()
        );
    }
    if !root_metadata.is_dir() {
        bail!("assets path must be a directory: {}", root.display());
    }

    let mut assets = Vec::new();
    let mut names = HashSet::new();
    for entry in WalkDir::new(&root).follow_links(false) {
        let entry = entry.with_context(|| format!("failed to walk {}", root.display()))?;
        let metadata = std::fs::symlink_metadata(entry.path())
            .with_context(|| format!("failed to inspect {}", entry.path().display()))?;
        if fsutil::is_reparse_point(&metadata) {
            bail!(
                "assets must not contain reparse points: {}",
                entry.path().display()
            );
        }
        if metadata.is_dir() {
            continue;
        }
        if !metadata.is_file() {
            bail!(
                "assets must contain only regular files: {}",
                entry.path().display()
            );
        }
        if metadata.len() > MAX_ENTRY_SIZE {
            bail!(
                "asset is larger than the allowed {MAX_ENTRY_SIZE} bytes: {}",
                entry.path().display()
            );
        }
        let relative = entry
            .path()
            .strip_prefix(&root)
            .with_context(|| format!("asset path escaped {}", root.display()))?;
        let relative = path::asset_relative_path(relative)?;
        let package_path = format!("assets/{relative}");
        let package_path = path::validate_entry_name(&package_path)?;
        if !names.insert(package_path.to_lowercase()) {
            bail!("duplicate asset path: {package_path}");
        }
        assets.push(Asset {
            package_path,
            source_path: entry.path().to_path_buf(),
        });
    }

    if assets.len() > MAX_ENTRIES.saturating_sub(8) {
        bail!("assets contain too many files");
    }
    assets.sort_by(|left, right| left.package_path.cmp(&right.package_path));
    Ok(assets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scans_and_sorts_assets() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("assets/icons")).unwrap();
        std::fs::write(dir.path().join("assets/z.txt"), b"z").unwrap();
        std::fs::write(dir.path().join("assets/icons/a.txt"), b"a").unwrap();
        let assets = scan(dir.path()).unwrap();
        assert_eq!(assets.len(), 2);
        assert_eq!(assets[0].package_path, "assets/icons/a.txt");
        assert_eq!(assets[1].package_path, "assets/z.txt");
    }

    #[test]
    fn missing_assets_directory_is_allowed() {
        let dir = tempfile::tempdir().unwrap();
        assert!(scan(dir.path()).unwrap().is_empty());
    }
}
