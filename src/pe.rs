use anyhow::{bail, Context, Result};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::fsutil;

const MAX_PE_HEADER_OFFSET: u64 = 16 * 1024 * 1024;

/// Check that an input file is a regular PE image and is not larger than the
/// limit the runtime applies to embedded executables.
pub fn validate_executable(path: &Path, max_size: u64, description: &str) -> Result<()> {
    let metadata = fsutil::ensure_regular_file(path, description)?;
    if metadata.len() == 0 {
        bail!("{description} is empty: {}", path.display());
    }
    if metadata.len() > max_size {
        bail!(
            "{description} is larger than the allowed {max_size} bytes: {}",
            path.display()
        );
    }
    let mut file = File::open(path)
        .with_context(|| format!("failed to open {description}: {}", path.display()))?;
    if !looks_like_pe(&mut file)? {
        bail!(
            "{description} is not a valid PE executable: {}",
            path.display()
        );
    }
    Ok(())
}

pub fn looks_like_pe(file: &mut File) -> Result<bool> {
    let mut dos = [0u8; 64];
    match file.read_exact(&mut dos) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(false),
        Err(error) => return Err(error).context("failed to read PE header"),
    }
    if &dos[0..2] != b"MZ" {
        return Ok(false);
    }
    let pe_offset = u32::from_le_bytes(dos[0x3c..0x40].try_into().unwrap()) as u64;
    if pe_offset > MAX_PE_HEADER_OFFSET {
        return Ok(false);
    }
    file.seek(SeekFrom::Start(pe_offset))?;
    let mut signature = [0u8; 4];
    match file.read_exact(&mut signature) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(false),
        Err(error) => return Err(error).context("failed to read PE signature"),
    }
    Ok(&signature == b"PE\0\0")
}

/// Detect an existing Authenticode certificate table. The packager must not
/// append its archive after a pre-existing signature: signing the final file
/// removes the old certificate table and could truncate the appended data.
pub fn has_certificate_table(path: &Path) -> Result<bool> {
    let mut file =
        File::open(path).with_context(|| format!("failed to open PE image {}", path.display()))?;
    if !looks_like_pe(&mut file)? {
        return Ok(false);
    }
    let mut coff = [0u8; 20];
    if file.read_exact(&mut coff).is_err() {
        return Ok(false);
    }
    let optional_size = u16::from_le_bytes(coff[16..18].try_into().unwrap()) as usize;
    if optional_size == 0 {
        return Ok(false);
    }
    let mut optional = vec![0u8; optional_size];
    if file.read_exact(&mut optional).is_err() {
        return Ok(false);
    }
    let magic = u16::from_le_bytes(optional[0..2].try_into().unwrap());
    let (count_offset, directory_offset) = match magic {
        0x10b => (92usize, 96usize),
        0x20b => (108usize, 112usize),
        _ => return Ok(false),
    };
    if optional.len() < count_offset + 4 {
        return Ok(false);
    }
    let count = u32::from_le_bytes(optional[count_offset..count_offset + 4].try_into().unwrap());
    if count <= 4 {
        return Ok(false);
    }
    let certificate_offset = directory_offset + 4 * 8;
    if optional.len() < certificate_offset + 8 {
        return Ok(false);
    }
    let address = u32::from_le_bytes(
        optional[certificate_offset..certificate_offset + 4]
            .try_into()
            .unwrap(),
    );
    let size = u32::from_le_bytes(
        optional[certificate_offset + 4..certificate_offset + 8]
            .try_into()
            .unwrap(),
    );
    Ok(address != 0 || size != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn fake_pe() -> Vec<u8> {
        let mut data = vec![0u8; 256];
        data[0..2].copy_from_slice(b"MZ");
        data[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        data[0x80..0x84].copy_from_slice(b"PE\0\0");
        data
    }

    fn fake_pe_with_certificate(certificate: bool) -> Vec<u8> {
        let mut data = vec![0u8; 512];
        data[0..2].copy_from_slice(b"MZ");
        data[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        data[0x80..0x84].copy_from_slice(b"PE\0\0");
        data[0x94..0x96].copy_from_slice(&224u16.to_le_bytes());
        let optional = 0x98;
        data[optional..optional + 2].copy_from_slice(&0x10bu16.to_le_bytes());
        data[optional + 92..optional + 96].copy_from_slice(&16u32.to_le_bytes());
        if certificate {
            let directory = optional + 96 + 4 * 8;
            data[directory..directory + 4].copy_from_slice(&0x180u32.to_le_bytes());
            data[directory + 4..directory + 8].copy_from_slice(&16u32.to_le_bytes());
        }
        data
    }

    #[test]
    fn accepts_fake_pe() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fake.exe");
        std::fs::write(&path, fake_pe()).unwrap();
        validate_executable(&path, 1024 * 1024, "test executable").unwrap();
        assert!(!has_certificate_table(&path).unwrap());
    }

    #[test]
    fn detects_existing_certificate_table() {
        let dir = tempfile::tempdir().unwrap();
        let unsigned = dir.path().join("unsigned.exe");
        std::fs::write(&unsigned, fake_pe_with_certificate(false)).unwrap();
        assert!(!has_certificate_table(&unsigned).unwrap());

        let signed = dir.path().join("signed.exe");
        std::fs::write(&signed, fake_pe_with_certificate(true)).unwrap();
        assert!(has_certificate_table(&signed).unwrap());
    }

    #[test]
    fn rejects_non_pe() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fake.exe");
        std::fs::write(&path, b"MZ").unwrap();
        assert!(validate_executable(&path, 1024, "test executable").is_err());
    }
}
