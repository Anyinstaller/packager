use anyhow::{bail, Context, Result};
use crc32fast::Hasher;
use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use zip::CompressionMethod;

use crate::fsutil;
use crate::path;

pub const MAX_ZIP_ENTRIES: usize = 100_000;
pub const MAX_TOTAL_UNCOMPRESSED: u64 = 8 * 1024 * 1024 * 1024;
pub const MAX_FILE_UNCOMPRESSED: u64 = 4 * 1024 * 1024 * 1024;
pub const MAX_COMPRESSION_RATIO: u64 = 100;
pub const MAX_PAYLOAD_BYTES: u64 = 8 * 1024 * 1024 * 1024;

const READ_BUFFER: usize = 1024 * 1024;
const EOCD_SIGNATURE: &[u8; 4] = b"PK\x05\x06";
const ZIP64_EOCD_SIGNATURE: &[u8; 4] = b"PK\x06\x06";
const ZIP64_LOCATOR_SIGNATURE: &[u8; 4] = b"PK\x06\x07";
const EOCD_LEN: usize = 22;
const MAX_COMMENT: usize = u16::MAX as usize;
const MAX_EOCD_SEARCH: usize = EOCD_LEN + MAX_COMMENT + 20;
const DOS_DIRECTORY: u32 = 0x10;
const DOS_REPARSE_POINT: u32 = 0x400;
const DOS_ATTRIBUTES_MASK: u32 = 0xFFFF;
const UNIX_FILE_TYPE_MASK: u32 = 0o170000;
const UNIX_DIRECTORY: u32 = 0o040000;
const UNIX_REGULAR: u32 = 0o100000;

#[derive(Clone, Debug)]
pub struct ZipStats {
    pub entries: usize,
    pub files: usize,
    pub total_size: u64,
    pub total_compressed: u64,
}

/// Read the central-directory end record before the ZIP library allocates a
/// map for every entry. This keeps a malicious central directory from forcing
/// an unbounded allocation before the entry-count limit is checked.
fn check_entry_count(file: &mut File, file_len: u64) -> Result<()> {
    if file_len < EOCD_LEN as u64 {
        bail!("payload.zip is not a valid ZIP archive");
    }
    let window_len = file_len.min(MAX_EOCD_SEARCH as u64) as usize;
    let window_start = file_len - window_len as u64;
    file.seek(SeekFrom::Start(window_start))?;
    let mut window = vec![0u8; window_len];
    file.read_exact(&mut window)
        .context("failed to read payload.zip end record")?;

    let mut eocd = None;
    for position in (0..=window.len() - EOCD_LEN).rev() {
        if &window[position..position + 4] != EOCD_SIGNATURE {
            continue;
        }
        let comment_len =
            u16::from_le_bytes(window[position + 20..position + 22].try_into().unwrap()) as usize;
        if position + EOCD_LEN + comment_len <= window.len() {
            eocd = Some(position);
            break;
        }
    }
    let Some(eocd) = eocd else {
        bail!("payload.zip has no end-of-central-directory record");
    };
    let total = u16::from_le_bytes(window[eocd + 10..eocd + 12].try_into().unwrap());
    let directory_size = u32::from_le_bytes(window[eocd + 12..eocd + 16].try_into().unwrap());
    let directory_offset = u32::from_le_bytes(window[eocd + 16..eocd + 20].try_into().unwrap());
    if total != u16::MAX && directory_size != u32::MAX && directory_offset != u32::MAX {
        if total as usize > MAX_ZIP_ENTRIES {
            bail!("payload.zip contains more than {MAX_ZIP_ENTRIES} entries");
        }
        return Ok(());
    }

    if eocd < 20 || &window[eocd - 20..eocd - 16] != ZIP64_LOCATOR_SIGNATURE {
        bail!("payload.zip has an invalid ZIP64 locator");
    }
    let locator = eocd - 20;
    let zip64_offset = u64::from_le_bytes(window[locator + 8..locator + 16].try_into().unwrap());
    let Some(zip64_end) = zip64_offset.checked_add(56) else {
        bail!("payload.zip ZIP64 end record overflows");
    };
    if zip64_end > file_len {
        bail!("payload.zip ZIP64 end record is outside the file");
    }
    file.seek(SeekFrom::Start(zip64_offset))?;
    let mut header = [0u8; 56];
    file.read_exact(&mut header)
        .context("failed to read ZIP64 end record")?;
    if &header[0..4] != ZIP64_EOCD_SIGNATURE {
        bail!("payload.zip has an invalid ZIP64 end record");
    }
    let total = u64::from_le_bytes(header[32..40].try_into().unwrap());
    if total > MAX_ZIP_ENTRIES as u64 {
        bail!("payload.zip contains more than {MAX_ZIP_ENTRIES} entries");
    }
    Ok(())
}

/// Validate `payload.zip` with the same limits the runtime applies. Every file
/// entry is decompressed and its CRC checked, so a zip bomb or a lying central
/// directory is rejected before the payload is embedded.
pub fn validate(path: &Path) -> Result<ZipStats> {
    let metadata = fsutil::ensure_regular_file(path, "payload.zip")?;
    if metadata.len() == 0 {
        bail!("payload.zip is empty");
    }
    if metadata.len() > MAX_PAYLOAD_BYTES {
        bail!("payload.zip is larger than {MAX_PAYLOAD_BYTES} bytes");
    }
    let mut file = File::open(path).context("failed to open payload.zip")?;
    check_entry_count(&mut file, metadata.len())?;
    file.seek(SeekFrom::Start(0))?;
    let mut archive =
        zip::ZipArchive::new(file).context("payload.zip is not a valid ZIP archive")?;
    if archive.is_empty() {
        bail!("payload.zip must not be empty");
    }
    if archive.len() > MAX_ZIP_ENTRIES {
        bail!("payload.zip contains more than {MAX_ZIP_ENTRIES} entries");
    }

    let mut files = HashSet::new();
    let mut file_ancestors = HashSet::new();
    let mut directories = HashSet::new();
    let mut total_size = 0u64;
    let mut total_compressed = 0u64;
    let mut file_count = 0usize;
    let mut buffer = vec![0u8; READ_BUFFER];

    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .with_context(|| format!("failed to read ZIP entry {index}"))?;
        let raw_name = entry.name().context("ZIP entry name is not valid UTF-8")?;
        if entry.encrypted() {
            bail!("payload.zip contains an encrypted entry: {raw_name}");
        }
        if raw_name.contains('\\') {
            bail!("payload.zip entry uses a backslash: {raw_name:?}");
        }
        let unix_mode = entry.unix_mode();
        if entry.is_symlink() {
            bail!("payload.zip contains a symbolic link: {raw_name:?}");
        }
        if entry.external_attributes() & DOS_ATTRIBUTES_MASK & DOS_REPARSE_POINT != 0 {
            bail!("payload.zip contains a reparse point: {raw_name:?}");
        }
        let is_directory = entry.is_dir()
            || unix_mode.is_some_and(|mode| mode & UNIX_FILE_TYPE_MASK == UNIX_DIRECTORY)
            || entry.external_attributes() & DOS_DIRECTORY != 0;
        if is_directory {
            let trimmed = raw_name.trim_end_matches('/');
            if trimmed.is_empty() {
                bail!("payload.zip contains an empty directory name");
            }
            if entry.size() != 0 || entry.compressed_size() != 0 {
                bail!("payload.zip directory entry has data: {raw_name:?}");
            }
            let normalized =
                path::validate_relative_path(trimmed).context("invalid ZIP directory path")?;
            if normalized != trimmed {
                bail!("ZIP paths must use '/' separators: {raw_name:?}");
            }
            let key = normalized.to_lowercase();
            if files.contains(&key) {
                bail!("payload.zip has both a file and a directory named {normalized:?}");
            }
            directories.insert(key);
            continue;
        }

        if let Some(mode) = unix_mode {
            let file_type = mode & UNIX_FILE_TYPE_MASK;
            if file_type != 0 && file_type != UNIX_REGULAR {
                bail!(
                    "payload.zip contains an unsupported file type ({file_type:#o}): {raw_name:?}"
                );
            }
        }
        let normalized =
            path::validate_relative_path(raw_name.as_ref()).context("invalid ZIP entry path")?;
        if normalized != raw_name.as_ref() {
            bail!("ZIP paths must use '/' separators: {raw_name:?}");
        }
        let size = entry.size();
        let compressed = entry.compressed_size();
        if size > MAX_FILE_UNCOMPRESSED {
            bail!("payload.zip entry {normalized} is larger than {MAX_FILE_UNCOMPRESSED} bytes");
        }
        if compressed == 0 && size > 0 {
            bail!("payload.zip entry {normalized} has no compressed data");
        }
        if size > compressed.saturating_mul(MAX_COMPRESSION_RATIO) {
            bail!("payload.zip entry {normalized} exceeds the {MAX_COMPRESSION_RATIO}:1 compression ratio");
        }
        total_size = total_size
            .checked_add(size)
            .context("payload.zip total size overflows")?;
        if total_size > MAX_TOTAL_UNCOMPRESSED {
            bail!("payload.zip expands to more than {MAX_TOTAL_UNCOMPRESSED} bytes");
        }
        total_compressed = total_compressed
            .checked_add(compressed)
            .context("payload.zip compressed size overflows")?;

        match entry.compression() {
            CompressionMethod::Stored => {
                if compressed != size {
                    bail!("payload.zip stored entry {normalized} has inconsistent sizes");
                }
            }
            CompressionMethod::Deflated => {}
            other => bail!(
                "payload.zip entry {normalized} uses an unsupported compression method: {other:?}"
            ),
        }

        let key = normalized.to_lowercase();
        if !files.insert(key.clone()) {
            bail!("payload.zip contains duplicate entry: {normalized}");
        }
        if directories.contains(&key) {
            bail!("payload.zip has both a directory and a file named {normalized:?}");
        }
        if !file_ancestors.insert(key) {
            bail!("payload.zip entry {normalized} is both a file and a parent directory");
        }
        let mut ancestor = String::new();
        for component in normalized.split('/') {
            if !ancestor.is_empty() {
                ancestor.push('/');
            }
            ancestor.push_str(component);
            if ancestor == normalized {
                break;
            }
            let ancestor = ancestor.to_lowercase();
            if files.contains(&ancestor) {
                bail!("payload.zip entry {normalized} is nested under a file");
            }
            file_ancestors.insert(ancestor);
        }

        let mut hasher = Hasher::new();
        let mut actual = 0u64;
        loop {
            let count = entry
                .read(&mut buffer)
                .with_context(|| format!("failed to decompress {normalized}"))?;
            if count == 0 {
                break;
            }
            actual = actual
                .checked_add(count as u64)
                .context("payload.zip entry size overflows")?;
            if actual > size {
                bail!("payload.zip entry {normalized} expands beyond its declared size");
            }
            hasher.update(&buffer[..count]);
        }
        if actual != size {
            bail!("payload.zip entry {normalized} is shorter than its declared size");
        }
        if hasher.finalize() != entry.crc32() {
            bail!("payload.zip entry {normalized} failed its CRC check");
        }
        file_count += 1;
    }

    for directory in &directories {
        let mut ancestor = String::new();
        for component in directory.split('/') {
            if !ancestor.is_empty() {
                ancestor.push('/');
            }
            ancestor.push_str(component);
            if files.contains(&ancestor) {
                bail!("payload.zip directory {directory:?} is nested under a file");
            }
        }
    }

    if file_count == 0 {
        bail!("payload.zip contains no files");
    }

    Ok(ZipStats {
        entries: archive.len(),
        files: file_count,
        total_size,
        total_compressed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    fn write_zip(
        dir: &tempfile::TempDir,
        files: &[(&str, &[u8], CompressionMethod)],
    ) -> std::path::PathBuf {
        write_zip_with_options(dir, files, SimpleFileOptions::default())
    }

    fn write_zip_with_options(
        dir: &tempfile::TempDir,
        files: &[(&str, &[u8], CompressionMethod)],
        base: SimpleFileOptions,
    ) -> std::path::PathBuf {
        let path = dir.path().join("payload.zip");
        let file = File::create(&path).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        for (name, bytes, method) in files {
            writer
                .start_file(*name, base.compression_method(*method))
                .unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap();
        path
    }

    #[test]
    fn accepts_valid_zip() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_zip(
            &dir,
            &[
                ("app.exe", b"contents", CompressionMethod::Deflated),
                ("data/file.txt", b"hello", CompressionMethod::Stored),
            ],
        );
        let stats = validate(&path).unwrap();
        assert_eq!(stats.files, 2);
        assert_eq!(stats.total_size, 13);
    }

    #[test]
    fn rejects_empty_zip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.zip");
        let file = File::create(&path).unwrap();
        zip::ZipWriter::new(file).finish().unwrap();
        assert!(validate(&path).is_err());
    }

    #[test]
    fn rejects_traversal_and_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_zip(
            &dir,
            &[
                ("../escape.txt", b"x", CompressionMethod::Stored),
                ("A.txt", b"x", CompressionMethod::Stored),
                ("a.txt", b"y", CompressionMethod::Stored),
            ],
        );
        assert!(validate(&path).is_err());
    }

    #[test]
    fn rejects_compression_bomb() {
        let dir = tempfile::tempdir().unwrap();
        let zeros = vec![0u8; 200_000];
        let path = write_zip(
            &dir,
            &[("bomb.bin", zeros.as_slice(), CompressionMethod::Deflated)],
        );
        assert!(validate(&path).is_err());
    }

    #[test]
    fn rejects_file_directory_conflict() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_zip(
            &dir,
            &[
                ("a", b"x", CompressionMethod::Stored),
                ("a/b", b"y", CompressionMethod::Stored),
            ],
        );
        assert!(validate(&path).is_err());
    }

    #[test]
    fn rejects_case_insensitive_file_ancestor_conflict() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_zip(
            &dir,
            &[
                ("a", b"x", CompressionMethod::Stored),
                ("A/b", b"y", CompressionMethod::Stored),
            ],
        );
        assert!(validate(&path).is_err());
    }

    #[test]
    fn rejects_symlink_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_zip_with_options(
            &dir,
            &[("link", b"target", CompressionMethod::Stored)],
            SimpleFileOptions::default()
                .system(zip::System::Unix)
                .external_attributes(0o120777 << 16),
        );
        assert!(validate(&path).is_err());
    }

    #[test]
    fn rejects_reparse_point_attributes() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_zip_with_options(
            &dir,
            &[("link", b"target", CompressionMethod::Stored)],
            SimpleFileOptions::default().external_attributes(0x400),
        );
        assert!(validate(&path).is_err());
    }

    #[test]
    fn preflight_rejects_zip64_entry_count() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.zip");
        let mut data = vec![0u8; 0x400];
        let zip64 = 0x100usize;
        let locator = 0x2ecusize;
        let eocd = 0x300usize;
        data[zip64..zip64 + 4].copy_from_slice(ZIP64_EOCD_SIGNATURE);
        data[zip64 + 32..zip64 + 40].copy_from_slice(&200_000u64.to_le_bytes());
        data[locator..locator + 4].copy_from_slice(ZIP64_LOCATOR_SIGNATURE);
        data[locator + 8..locator + 16].copy_from_slice(&(zip64 as u64).to_le_bytes());
        data[eocd..eocd + 4].copy_from_slice(EOCD_SIGNATURE);
        data[eocd + 10..eocd + 12].copy_from_slice(&u16::MAX.to_le_bytes());
        data[eocd + 12..eocd + 16].copy_from_slice(&u32::MAX.to_le_bytes());
        data[eocd + 16..eocd + 20].copy_from_slice(&u32::MAX.to_le_bytes());
        std::fs::write(&path, &data).unwrap();

        let mut file = File::open(&path).unwrap();
        let error = check_entry_count(&mut file, data.len() as u64).unwrap_err();
        assert!(error.to_string().contains("more than"));
    }
}
