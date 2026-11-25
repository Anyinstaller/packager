use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::fsutil;
use crate::path;

pub const ARCHIVE_MAGIC: &[u8; 4] = b"AIPK";
pub const DIRECTORY_MAGIC: &[u8; 4] = b"AIPD";
pub const FOOTER_MAGIC: &[u8; 4] = b"AIPF";
pub const FOOTER_END_MAGIC: &[u8; 8] = b"AIP1END\0";
pub const FORMAT_VERSION: u32 = 1;

pub const ARCHIVE_HEADER_LEN: u64 = 16;
pub const DIRECTORY_HEADER_LEN: u64 = 12;
pub const FOOTER_LEN: usize = 48;
pub const MAX_ENTRIES: usize = 100_000;
pub const MAX_DIRECTORY_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_ENTRY_SIZE: u64 = 8 * 1024 * 1024 * 1024;
pub const MAX_TOTAL_SIZE: u64 = 16 * 1024 * 1024 * 1024;
pub const MAX_FOOTER_SCAN: u64 = 32 * 1024 * 1024;

const COPY_BUFFER: usize = 1024 * 1024;

#[derive(Clone, Debug)]
pub struct Entry {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    pub sha256: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct Layout {
    pub archive_offset: u64,
    pub entries: Vec<Entry>,
}

impl Layout {
    pub fn entry(&self, name: &str) -> Option<&Entry> {
        self.entries.iter().find(|entry| entry.name == name)
    }
}

/// Streaming writer for the appended AIP archive. The stub is copied first and
/// hashed; every added entry is hashed while it is written, so no component is
/// ever held in memory as a whole.
pub struct Writer {
    output: BufWriter<File>,
    archive_offset: u64,
    position: u64,
    total_size: u64,
    directory_size: u64,
    entries: Vec<Entry>,
    names: HashSet<String>,
    stub_size: u64,
    stub_sha256: [u8; 32],
    buffer: Vec<u8>,
}

impl Writer {
    pub fn create(file: File, stub: &Path) -> Result<Self> {
        let mut stub_file =
            File::open(stub).with_context(|| format!("failed to open stub: {}", stub.display()))?;
        let metadata = fsutil::ensure_regular_file(stub, "stub.exe")?;
        if metadata.len() == 0 {
            bail!("stub.exe is empty: {}", stub.display());
        }

        let mut output = BufWriter::with_capacity(COPY_BUFFER, file);
        output.seek(SeekFrom::Start(0))?;
        output.get_mut().set_len(0)?;

        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; COPY_BUFFER];
        let mut remaining = metadata.len();
        while remaining > 0 {
            let chunk = remaining.min(buffer.len() as u64) as usize;
            stub_file
                .read_exact(&mut buffer[..chunk])
                .context("failed to read stub.exe")?;
            hasher.update(&buffer[..chunk]);
            output
                .write_all(&buffer[..chunk])
                .context("failed to write stub.exe")?;
            remaining -= chunk as u64;
        }
        let mut extra = [0u8; 1];
        if stub_file
            .read(&mut extra)
            .context("failed to read stub.exe")?
            != 0
        {
            bail!("stub.exe changed while it was being copied");
        }
        let stub_sha256: [u8; 32] = hasher.finalize().into();
        let stub_size = metadata.len();
        let archive_offset = stub_size;

        output.write_all(ARCHIVE_MAGIC)?;
        output.write_all(&FORMAT_VERSION.to_le_bytes())?;
        output.write_all(&0u32.to_le_bytes())?;
        output.write_all(&0u32.to_le_bytes())?;

        Ok(Self {
            output,
            archive_offset,
            position: archive_offset + ARCHIVE_HEADER_LEN,
            total_size: 0,
            directory_size: DIRECTORY_HEADER_LEN,
            entries: Vec::new(),
            names: HashSet::new(),
            stub_size,
            stub_sha256,
            buffer: vec![0u8; COPY_BUFFER],
        })
    }

    pub fn stub_size(&self) -> u64 {
        self.stub_size
    }

    pub fn stub_sha256(&self) -> [u8; 32] {
        self.stub_sha256
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn add_file(&mut self, name: &str, path: &Path, limit: u64) -> Result<Entry> {
        let name = self.prepare_name(name)?;
        let metadata = fsutil::ensure_regular_file(path, &format!("package entry {name}"))?;
        if metadata.len() > limit {
            bail!(
                "{name} is larger than the allowed {limit} bytes: {}",
                path.display()
            );
        }
        self.check_size(name.as_str(), metadata.len())?;

        let mut input = File::open(path)
            .with_context(|| format!("failed to open {name}: {}", path.display()))?;
        let offset = self.position;
        let mut hasher = Sha256::new();
        let mut remaining = metadata.len();
        while remaining > 0 {
            let chunk = remaining.min(self.buffer.len() as u64) as usize;
            input
                .read_exact(&mut self.buffer[..chunk])
                .with_context(|| format!("failed to read {name}"))?;
            hasher.update(&self.buffer[..chunk]);
            self.output
                .write_all(&self.buffer[..chunk])
                .with_context(|| format!("failed to write {name}"))?;
            remaining -= chunk as u64;
        }
        let mut extra = [0u8; 1];
        if input
            .read(&mut extra)
            .with_context(|| format!("failed to read {name}"))?
            != 0
        {
            bail!(
                "{name} changed while it was being packaged: {}",
                path.display()
            );
        }

        self.commit_entry(name, offset, metadata.len(), hasher.finalize().into())
    }

    pub fn add_bytes(&mut self, name: &str, bytes: &[u8]) -> Result<Entry> {
        let name = self.prepare_name(name)?;
        let size = bytes.len() as u64;
        self.check_size(name.as_str(), size)?;
        let offset = self.position;
        self.output
            .write_all(bytes)
            .with_context(|| format!("failed to write {name}"))?;
        let sha256: [u8; 32] = Sha256::digest(bytes).into();
        self.commit_entry(name, offset, size, sha256)
    }

    pub fn finish(mut self) -> Result<Layout> {
        let count = self.entries.len() as u32;
        self.output
            .seek(SeekFrom::Start(self.archive_offset + 12))?;
        self.output.write_all(&count.to_le_bytes())?;
        self.output.seek(SeekFrom::Start(self.position))?;

        let directory_offset = self.position;
        self.output.write_all(DIRECTORY_MAGIC)?;
        self.output.write_all(&FORMAT_VERSION.to_le_bytes())?;
        self.output.write_all(&count.to_le_bytes())?;
        for entry in &self.entries {
            let name_len = entry.name.len() as u16;
            self.output.write_all(&name_len.to_le_bytes())?;
            self.output.write_all(entry.name.as_bytes())?;
            self.output.write_all(&entry.offset.to_le_bytes())?;
            self.output.write_all(&entry.size.to_le_bytes())?;
            self.output.write_all(&entry.sha256)?;
        }
        let directory_size = self.directory_size;
        self.output.flush().context("failed to flush package")?;

        let footer = self.position + directory_size;
        self.output.write_all(FOOTER_MAGIC)?;
        self.output.write_all(&FORMAT_VERSION.to_le_bytes())?;
        self.output.write_all(&self.archive_offset.to_le_bytes())?;
        self.output
            .write_all(&(footer - self.archive_offset).to_le_bytes())?;
        self.output.write_all(&directory_offset.to_le_bytes())?;
        self.output.write_all(&directory_size.to_le_bytes())?;
        self.output.write_all(FOOTER_END_MAGIC)?;
        self.output.flush().context("failed to flush package")?;

        Ok(Layout {
            archive_offset: self.archive_offset,
            entries: self.entries,
        })
    }

    fn prepare_name(&mut self, name: &str) -> Result<String> {
        let name = path::validate_entry_name(name)?;
        let key = name.to_lowercase();
        if !self.names.insert(key) {
            bail!("duplicate package entry: {name}");
        }
        if self.entries.len() >= MAX_ENTRIES {
            bail!("package has more than {MAX_ENTRIES} entries");
        }
        let directory_size = self
            .directory_size
            .checked_add(2 + name.len() as u64 + 48)
            .context("package directory size overflows")?;
        if directory_size > MAX_DIRECTORY_BYTES {
            bail!("package directory would exceed {MAX_DIRECTORY_BYTES} bytes");
        }
        self.directory_size = directory_size;
        Ok(name)
    }

    fn check_size(&mut self, name: &str, size: u64) -> Result<()> {
        if size > MAX_ENTRY_SIZE {
            bail!("{name} is larger than the allowed {MAX_ENTRY_SIZE} bytes");
        }
        let total = self
            .total_size
            .checked_add(size)
            .context("package total size overflows")?;
        if total > MAX_TOTAL_SIZE {
            bail!("package contents would exceed {MAX_TOTAL_SIZE} bytes");
        }
        self.total_size = total;
        Ok(())
    }

    fn commit_entry(
        &mut self,
        name: String,
        offset: u64,
        size: u64,
        sha256: [u8; 32],
    ) -> Result<Entry> {
        let end = offset
            .checked_add(size)
            .context("package entry range overflows")?;
        if offset != self.position {
            bail!("internal package position mismatch for {name}");
        }
        self.position = end;
        let entry = Entry {
            name,
            offset,
            size,
            sha256,
        };
        self.entries.push(entry.clone());
        Ok(entry)
    }
}

/// An opened package. Parsing mirrors the stub's checks so a package that the
/// packager accepts is one the stub will accept too.
pub struct Package {
    file: File,
    layout: Layout,
}

impl Package {
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("failed to open package {}", path.display()))?;
        Self::from_file(file)
    }

    pub fn from_file(mut file: File) -> Result<Self> {
        let file_len = file
            .metadata()
            .context("failed to read package metadata")?
            .len();
        if file_len < ARCHIVE_HEADER_LEN + FOOTER_LEN as u64 {
            bail!("file is too small to contain an AIP package");
        }
        let scan_len = file_len.min(MAX_FOOTER_SCAN);
        let scan_start = file_len - scan_len;
        file.seek(SeekFrom::Start(scan_start))?;
        let mut window = vec![0u8; scan_len as usize];
        file.read_exact(&mut window)
            .context("failed to read package footer window")?;

        let mut last_error = None;
        for position in (0..=window.len().saturating_sub(FOOTER_END_MAGIC.len())).rev() {
            if &window[position..position + FOOTER_END_MAGIC.len()] != FOOTER_END_MAGIC {
                continue;
            }
            let Some(footer_start) = position.checked_sub(FOOTER_LEN - FOOTER_END_MAGIC.len())
            else {
                continue;
            };
            let absolute_footer = scan_start + footer_start as u64;
            match parse_footer(
                &window[footer_start..footer_start + FOOTER_LEN],
                absolute_footer,
                file_len,
            )
            .and_then(|footer| parse_archive(&file, &footer))
            {
                Ok(layout) => return Ok(Self { file, layout }),
                Err(error) => last_error = Some(error),
            }
        }

        match last_error {
            Some(error) => Err(error).context("AIP package footer is invalid"),
            None => bail!("no AIP package footer found"),
        }
    }

    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    pub fn read_entry_bytes(&self, name: &str, max_size: u64) -> Result<Vec<u8>> {
        let entry = self
            .layout
            .entry(name)
            .with_context(|| format!("package is missing {name}"))?;
        if entry.size > max_size {
            bail!("{name} is larger than the allowed {max_size} bytes");
        }
        let mut file = self
            .file
            .try_clone()
            .context("failed to clone package handle")?;
        file.seek(SeekFrom::Start(entry.offset))?;
        let mut data = vec![0u8; entry.size as usize];
        file.read_exact(&mut data)
            .with_context(|| format!("failed to read {name} from package"))?;
        let actual: [u8; 32] = Sha256::digest(&data).into();
        if actual != entry.sha256 {
            bail!("SHA-256 mismatch for {name}");
        }
        Ok(data)
    }

    pub fn verify_entries(&self) -> Result<()> {
        let mut buffer = vec![0u8; COPY_BUFFER];
        let mut file = self
            .file
            .try_clone()
            .context("failed to clone package handle")?;
        for entry in &self.layout.entries {
            file.seek(SeekFrom::Start(entry.offset))?;
            let mut hasher = Sha256::new();
            let mut remaining = entry.size;
            while remaining > 0 {
                let chunk = remaining.min(buffer.len() as u64) as usize;
                file.read_exact(&mut buffer[..chunk])
                    .with_context(|| format!("failed to read {}", entry.name))?;
                hasher.update(&buffer[..chunk]);
                remaining -= chunk as u64;
            }
            let actual: [u8; 32] = hasher.finalize().into();
            if actual != entry.sha256 {
                bail!("SHA-256 mismatch for {}", entry.name);
            }
        }
        Ok(())
    }

    pub fn extract_all(&self, root: &Path) -> Result<()> {
        let root_metadata = std::fs::symlink_metadata(root)
            .with_context(|| format!("failed to read extraction root {}", root.display()))?;
        if fsutil::is_reparse_point(&root_metadata) || !root_metadata.is_dir() {
            bail!(
                "extraction root must be a real directory: {}",
                root.display()
            );
        }
        let mut buffer = vec![0u8; COPY_BUFFER];
        let mut source = self
            .file
            .try_clone()
            .context("failed to clone package handle")?;
        for entry in &self.layout.entries {
            let destination = root.join(entry.name.replace('/', std::path::MAIN_SEPARATOR_STR));
            if let Some(parent) = destination.parent() {
                create_private_subdirectories(root, parent)?;
            }
            extract_entry(entry, &destination, &mut source, &mut buffer)?;
        }
        for entry in &self.layout.entries {
            verify_extracted_entry(entry, root, &mut buffer)?;
        }
        Ok(())
    }
}

fn extract_entry(
    entry: &Entry,
    destination: &Path,
    source: &mut File,
    buffer: &mut [u8],
) -> Result<()> {
    source.seek(SeekFrom::Start(entry.offset))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .with_context(|| format!("failed to create {}", destination.display()))?;

    let mut hasher = Sha256::new();
    let mut remaining = entry.size;
    let result = (|| -> Result<()> {
        while remaining > 0 {
            let chunk = remaining.min(buffer.len() as u64) as usize;
            source
                .read_exact(&mut buffer[..chunk])
                .with_context(|| format!("failed to read {}", entry.name))?;
            hasher.update(&buffer[..chunk]);
            output
                .write_all(&buffer[..chunk])
                .with_context(|| format!("failed to write {}", destination.display()))?;
            remaining -= chunk as u64;
        }
        output.flush().context("failed to flush extracted file")?;
        let actual: [u8; 32] = hasher.finalize().into();
        if actual != entry.sha256 {
            bail!("SHA-256 mismatch for {}", entry.name);
        }
        Ok(())
    })();

    drop(output);
    if result.is_err() {
        let _ = std::fs::remove_file(destination);
    }
    result
}

pub fn hash_prefix(path: &Path, size: u64) -> Result<[u8; 32]> {
    let mut file =
        File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut remaining = size;
    let mut buffer = vec![0u8; COPY_BUFFER];
    while remaining > 0 {
        let chunk = remaining.min(buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..chunk])
            .context("failed to read package prefix")?;
        hasher.update(&buffer[..chunk]);
        remaining -= chunk as u64;
    }
    Ok(hasher.finalize().into())
}

fn verify_extracted_entry(entry: &Entry, root: &Path, buffer: &mut [u8]) -> Result<()> {
    let path = root.join(entry.name.replace('/', std::path::MAIN_SEPARATOR_STR));
    let mut file =
        File::open(&path).with_context(|| format!("failed to reopen extracted {}", entry.name))?;
    let mut hasher = Sha256::new();
    let mut remaining = entry.size;
    while remaining > 0 {
        let chunk = remaining.min(buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..chunk])
            .with_context(|| format!("failed to re-read extracted {}", entry.name))?;
        hasher.update(&buffer[..chunk]);
        remaining -= chunk as u64;
    }
    let actual: [u8; 32] = hasher.finalize().into();
    if actual != entry.sha256 {
        bail!("SHA-256 mismatch for extracted {}", entry.name);
    }
    Ok(())
}

struct Footer {
    archive_offset: u64,
    directory_offset: u64,
    directory_size: u64,
}

fn parse_footer(bytes: &[u8], footer_start: u64, file_len: u64) -> Result<Footer> {
    if bytes.len() != FOOTER_LEN {
        bail!("truncated package footer");
    }
    if &bytes[0..4] != FOOTER_MAGIC {
        bail!("bad package footer magic");
    }
    let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    if version != FORMAT_VERSION {
        bail!("unsupported package format version {version}");
    }
    let archive_offset = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let archive_size = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
    let directory_offset = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
    let directory_size = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
    if &bytes[40..48] != FOOTER_END_MAGIC {
        bail!("bad package footer terminator");
    }
    if archive_size < ARCHIVE_HEADER_LEN {
        bail!("package archive is too small");
    }
    let archive_end = archive_offset
        .checked_add(archive_size)
        .context("package archive range overflows")?;
    if archive_end != footer_start {
        bail!("package footer is not adjacent to the archive");
    }
    if archive_end > file_len {
        bail!("package archive extends past the end of the file");
    }
    let directory_end = directory_offset
        .checked_add(directory_size)
        .context("package directory range overflows")?;
    if directory_offset < archive_offset + ARCHIVE_HEADER_LEN || directory_end != archive_end {
        bail!("package directory range is invalid");
    }
    if !(DIRECTORY_HEADER_LEN..=MAX_DIRECTORY_BYTES).contains(&directory_size) {
        bail!("package directory size is invalid");
    }
    Ok(Footer {
        archive_offset,
        directory_offset,
        directory_size,
    })
}

fn parse_archive(file: &File, footer: &Footer) -> Result<Layout> {
    let mut reader = file.try_clone().context("failed to clone package handle")?;
    let mut header = [0u8; ARCHIVE_HEADER_LEN as usize];
    reader.seek(SeekFrom::Start(footer.archive_offset))?;
    reader
        .read_exact(&mut header)
        .context("truncated archive header")?;
    if &header[0..4] != ARCHIVE_MAGIC {
        bail!("bad archive magic");
    }
    let version = u32::from_le_bytes(header[4..8].try_into().unwrap());
    if version != FORMAT_VERSION {
        bail!("unsupported archive version {version}");
    }
    let flags = u32::from_le_bytes(header[8..12].try_into().unwrap());
    if flags != 0 {
        bail!("unsupported archive flags: {flags:#x}");
    }
    let count = u32::from_le_bytes(header[12..16].try_into().unwrap()) as usize;
    if count == 0 || count > MAX_ENTRIES {
        bail!("invalid archive entry count: {count}");
    }

    let mut directory = vec![0u8; footer.directory_size as usize];
    reader.seek(SeekFrom::Start(footer.directory_offset))?;
    reader
        .read_exact(&mut directory)
        .context("truncated archive directory")?;

    let mut cursor = Cursor::new(&directory);
    if cursor.take(4)? != DIRECTORY_MAGIC {
        bail!("bad archive directory magic");
    }
    let directory_version = cursor.u32()?;
    if directory_version != FORMAT_VERSION {
        bail!("unsupported archive directory version {directory_version}");
    }
    let directory_count = cursor.u32()? as usize;
    if directory_count != count {
        bail!("archive and directory entry counts differ");
    }

    let mut entries = Vec::with_capacity(count);
    let mut names = HashSet::new();
    let mut total_size = 0u64;
    for _ in 0..count {
        let name_len = cursor.u16()? as usize;
        if name_len == 0 || name_len > 1024 {
            bail!("invalid archive entry name length");
        }
        let raw_name = cursor.take(name_len)?;
        let raw_name = std::str::from_utf8(raw_name).context("entry name is not UTF-8")?;
        let name = path::validate_entry_name(raw_name)?;
        if name != raw_name {
            bail!("archive entry names must use '/' separators: {raw_name:?}");
        }
        if !names.insert(name.to_lowercase()) {
            bail!("duplicate archive entry: {name}");
        }
        let offset = cursor.u64()?;
        let size = cursor.u64()?;
        let sha256: [u8; 32] = cursor.take(32)?.try_into().unwrap();
        if size > MAX_ENTRY_SIZE {
            bail!("archive entry {name} is too large");
        }
        let end = offset
            .checked_add(size)
            .context("archive entry range overflows")?;
        if offset < footer.archive_offset + ARCHIVE_HEADER_LEN || end > footer.directory_offset {
            bail!("archive entry {name} has an invalid range");
        }
        total_size = total_size
            .checked_add(size)
            .context("archive total size overflows")?;
        if total_size > MAX_TOTAL_SIZE {
            bail!("archive contents are too large");
        }
        entries.push(Entry {
            name,
            offset,
            size,
            sha256,
        });
    }
    if cursor.remaining() != 0 {
        bail!("archive directory has trailing data");
    }

    for required in ["client.exe", "backend.exe", "config.toml", "payload.zip"] {
        if !entries.iter().any(|entry| entry.name == required) {
            bail!("package is missing required entry {required}");
        }
    }

    Ok(Layout {
        archive_offset: footer.archive_offset,
        entries,
    })
}

fn create_private_subdirectories(root: &Path, parent: &Path) -> Result<()> {
    let relative = parent.strip_prefix(root).with_context(|| {
        format!(
            "destination {} escapes the extraction root",
            parent.display()
        )
    })?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        match std::fs::create_dir(&current) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to create {}", current.display()))
            }
        }
        let metadata = std::fs::symlink_metadata(&current)
            .with_context(|| format!("failed to inspect {}", current.display()))?;
        if fsutil::is_reparse_point(&metadata) || !metadata.is_dir() {
            bail!("refusing to extract through {}", current.display());
        }
    }
    Ok(())
}

struct Cursor<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .context("directory cursor overflow")?;
        if end > self.data.len() {
            bail!("truncated archive directory");
        }
        let slice = &self.data[self.position..end];
        self.position = end;
        Ok(slice)
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.position
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_pe() -> Vec<u8> {
        let mut data = vec![0u8; 256];
        data[0..2].copy_from_slice(b"MZ");
        data[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        data[0x80..0x84].copy_from_slice(b"PE\0\0");
        data
    }

    fn write_test_package(dir: &tempfile::TempDir) -> (std::path::PathBuf, Layout) {
        let stub = dir.path().join("stub.exe");
        std::fs::write(&stub, fake_pe()).unwrap();
        let output = dir.path().join("foo.exe");
        let file = File::create(&output).unwrap();
        let mut writer = Writer::create(file, &stub).unwrap();
        writer.add_bytes("client.exe", b"MZclient").unwrap();
        writer.add_bytes("backend.exe", b"MZbackend").unwrap();
        writer.add_bytes("config.toml", b"protocol = 1\n").unwrap();
        writer.add_bytes("payload.zip", b"PK\x03\x04").unwrap();
        writer.add_bytes("assets/a.txt", b"asset").unwrap();
        let layout = writer.finish().unwrap();
        (output, layout)
    }

    #[test]
    fn writes_and_reads_package() {
        let dir = tempfile::tempdir().unwrap();
        let stub = dir.path().join("stub.exe");
        std::fs::write(&stub, fake_pe()).unwrap();
        let output = dir.path().join("foo.exe");
        let file = File::create(&output).unwrap();
        let mut writer = Writer::create(file, &stub).unwrap();
        writer.add_bytes("client.exe", b"MZclient").unwrap();
        writer.add_bytes("backend.exe", b"MZbackend").unwrap();
        writer.add_bytes("config.toml", b"protocol = 1\n").unwrap();
        writer.add_bytes("payload.zip", b"PK\x03\x04").unwrap();
        let layout = writer.finish().unwrap();

        let package = Package::open(&output).unwrap();
        assert_eq!(package.layout().entries.len(), 4);
        assert_eq!(package.layout().archive_offset, layout.archive_offset);
        assert_eq!(
            package.read_entry_bytes("config.toml", 1024).unwrap(),
            b"protocol = 1\n"
        );
        package.verify_entries().unwrap();
    }

    #[test]
    fn rejects_duplicate_and_traversal_names() {
        let dir = tempfile::tempdir().unwrap();
        let stub = dir.path().join("stub.exe");
        std::fs::write(&stub, fake_pe()).unwrap();
        let file = File::create(dir.path().join("foo.exe")).unwrap();
        let mut writer = Writer::create(file, &stub).unwrap();
        writer.add_bytes("assets/a.txt", b"a").unwrap();
        assert!(writer.add_bytes("assets/A.txt", b"b").is_err());
        assert!(writer.add_bytes("../escape", b"c").is_err());
    }

    #[test]
    fn tolerates_trailing_certificate_table() {
        let dir = tempfile::tempdir().unwrap();
        let stub = dir.path().join("stub.exe");
        std::fs::write(&stub, fake_pe()).unwrap();
        let output = dir.path().join("foo.exe");
        let file = File::create(&output).unwrap();
        let mut writer = Writer::create(file, &stub).unwrap();
        writer.add_bytes("client.exe", b"MZclient").unwrap();
        writer.add_bytes("backend.exe", b"MZbackend").unwrap();
        writer.add_bytes("config.toml", b"x").unwrap();
        writer.add_bytes("payload.zip", b"PK\x03\x04").unwrap();
        writer.finish().unwrap();
        {
            let mut file = OpenOptions::new().append(true).open(&output).unwrap();
            file.write_all(b"certificate-table").unwrap();
        }
        let package = Package::open(&output).unwrap();
        assert_eq!(package.layout().entries.len(), 4);
    }

    #[test]
    fn detects_tampered_entry() {
        let dir = tempfile::tempdir().unwrap();
        let (output, layout) = write_test_package(&dir);
        let entry = layout.entry("config.toml").unwrap();
        let mut file = OpenOptions::new().write(true).open(&output).unwrap();
        file.seek(SeekFrom::Start(entry.offset)).unwrap();
        file.write_all(b"X").unwrap();

        let package = Package::open(&output).unwrap();
        assert!(package.verify_entries().is_err());
        assert!(package.read_entry_bytes("config.toml", 1024).is_err());
    }

    #[test]
    fn rejects_bad_footer_and_missing_entries() {
        let dir = tempfile::tempdir().unwrap();
        let (output, _) = write_test_package(&dir);
        let bytes = std::fs::read(&output).unwrap();
        let mut file = OpenOptions::new().write(true).open(&output).unwrap();
        file.seek(SeekFrom::Start(bytes.len() as u64 - 1)).unwrap();
        file.write_all(b"X").unwrap();
        assert!(Package::open(&output).is_err());

        let stub = dir.path().join("stub.exe");
        std::fs::write(&stub, fake_pe()).unwrap();
        let incomplete = dir.path().join("incomplete.exe");
        let file = File::create(&incomplete).unwrap();
        let mut writer = Writer::create(file, &stub).unwrap();
        writer.add_bytes("client.exe", b"MZclient").unwrap();
        writer.add_bytes("backend.exe", b"MZbackend").unwrap();
        writer.add_bytes("config.toml", b"x").unwrap();
        writer.finish().unwrap();
        assert!(Package::open(&incomplete).is_err());
    }

    #[test]
    fn extracts_verified_files() {
        let dir = tempfile::tempdir().unwrap();
        let (output, _) = write_test_package(&dir);
        let package = Package::open(&output).unwrap();
        let target = dir.path().join("extract");
        std::fs::create_dir(&target).unwrap();
        package.extract_all(&target).unwrap();

        assert_eq!(
            std::fs::read(target.join("client.exe")).unwrap(),
            b"MZclient"
        );
        assert_eq!(
            std::fs::read(target.join("assets/a.txt")).unwrap(),
            b"asset"
        );
    }
}
