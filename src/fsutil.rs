use anyhow::{bail, Context, Result};
use std::fs::Metadata;
use std::path::Path;

/// True when the metadata describes a Windows reparse point (symlink, junction,
/// mount point, or any other reparse tag). Reparse points are never followed
/// while packaging input.
pub fn is_reparse_point(metadata: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }

    #[cfg(not(windows))]
    {
        let _ = metadata;
        false
    }
}

pub fn ensure_regular_file(path: &Path, description: &str) -> Result<Metadata> {
    let metadata = std::fs::symlink_metadata(path).with_context(|| {
        format!(
            "failed to read metadata for {description}: {}",
            path.display()
        )
    })?;
    if is_reparse_point(&metadata) {
        bail!(
            "{description} must not be a reparse point: {}",
            path.display()
        );
    }
    if !metadata.is_file() {
        bail!("{description} must be a regular file: {}", path.display());
    }
    Ok(metadata)
}

pub fn read_limited(path: &Path, limit: u64, description: &str) -> Result<Vec<u8>> {
    let metadata = ensure_regular_file(path, description)?;
    if metadata.len() > limit {
        bail!(
            "{description} is larger than the allowed {limit} bytes: {}",
            path.display()
        );
    }
    std::fs::read(path).with_context(|| format!("failed to read {description}: {}", path.display()))
}
