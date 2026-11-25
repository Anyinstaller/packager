use anyhow::{bail, Context, Result};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use toml::Value;
use toml_edit::{value, ArrayOfTables, DocumentMut, Item, Table};

use crate::archive::{self, Entry};
use crate::path;

pub const MANIFEST_NAME: &str = "manifest.toml";
pub const MANIFEST_VERSION: i64 = 1;
pub const MAX_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentKind {
    Executable,
    Config,
    Archive,
    Resource,
}

impl ComponentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Executable => "executable",
            Self::Config => "config",
            Self::Archive => "archive",
            Self::Resource => "resource",
        }
    }

    fn parse(text: &str) -> Result<Self> {
        match text {
            "executable" => Ok(Self::Executable),
            "config" => Ok(Self::Config),
            "archive" => Ok(Self::Archive),
            "resource" => Ok(Self::Resource),
            other => bail!("manifest contains an unknown component type: {other:?}"),
        }
    }
}

pub fn kind_for_path(path: &str) -> ComponentKind {
    match path {
        "client.exe" | "backend.exe" => ComponentKind::Executable,
        "config.toml" => ComponentKind::Config,
        "payload.zip" => ComponentKind::Archive,
        _ => ComponentKind::Resource,
    }
}

#[derive(Clone, Debug)]
pub struct StubRecord {
    pub size: u64,
    pub sha256: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct Component {
    pub name: String,
    pub path: String,
    pub kind: ComponentKind,
    pub size: u64,
    pub sha256: [u8; 32],
}

impl Component {
    pub fn from_entry(entry: &Entry) -> Self {
        Self {
            name: entry.name.clone(),
            path: entry.name.clone(),
            kind: kind_for_path(&entry.name),
            size: entry.size,
            sha256: entry.sha256,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Manifest {
    pub generator: String,
    pub stub: StubRecord,
    pub components: Vec<Component>,
}

impl Manifest {
    pub fn create(generator: impl Into<String>, stub: StubRecord, entries: &[Entry]) -> Self {
        Self {
            generator: generator.into(),
            stub,
            components: entries.iter().map(Component::from_entry).collect(),
        }
    }

    pub fn render(&self) -> Result<Vec<u8>> {
        let mut document = DocumentMut::new();
        document["format"] = value(MANIFEST_VERSION);
        document["generator"] = value(self.generator.clone());

        let mut stub = Table::new();
        stub["name"] = value("stub.exe");
        stub["path"] = value("stub.exe");
        stub["type"] = value(ComponentKind::Executable.as_str());
        stub["size"] = value(self.stub.size as i64);
        stub["sha256"] = value(hex(&self.stub.sha256));
        stub["embedded"] = value(false);
        document["stub"] = Item::Table(stub);

        let mut components = ArrayOfTables::new();
        for component in &self.components {
            let mut table = Table::new();
            table["name"] = value(component.name.clone());
            table["path"] = value(component.path.clone());
            table["type"] = value(component.kind.as_str());
            table["size"] = value(component.size as i64);
            table["sha256"] = value(hex(&component.sha256));
            components.push(table);
        }
        document["component"] = Item::ArrayOfTables(components);

        let bytes = document.to_string().into_bytes();
        if bytes.len() as u64 > MAX_MANIFEST_BYTES {
            bail!("manifest.toml is larger than {MAX_MANIFEST_BYTES} bytes");
        }
        Ok(bytes)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() as u64 > MAX_MANIFEST_BYTES {
            bail!("manifest.toml is larger than {MAX_MANIFEST_BYTES} bytes");
        }
        let text = std::str::from_utf8(bytes).context("manifest.toml is not valid UTF-8")?;
        let value: Value = toml::from_str(text).context("manifest.toml is not valid TOML")?;
        let table = value
            .as_table()
            .context("manifest.toml root must be a TOML table")?;

        let format = match table.get("format") {
            Some(Value::Integer(value)) => *value,
            Some(_) => bail!("manifest format must be an integer"),
            None => bail!("manifest format is required"),
        };
        if format != MANIFEST_VERSION {
            bail!("unsupported manifest format: {format}");
        }
        let generator = match table.get("generator") {
            Some(Value::String(value)) => value.clone(),
            Some(_) => bail!("manifest generator must be a string"),
            None => bail!("manifest generator is required"),
        };
        if generator.is_empty() {
            bail!("manifest generator must not be empty");
        }

        let stub_table = match table.get("stub") {
            Some(Value::Table(value)) => value,
            Some(_) => bail!("manifest stub must be a table"),
            None => bail!("manifest stub is required"),
        };
        let stub_name = required_string(stub_table, "name")?;
        let stub_path = required_string(stub_table, "path")?;
        let stub_type = ComponentKind::parse(&required_string(stub_table, "type")?)?;
        if stub_name != "stub.exe" || stub_path != "stub.exe" {
            bail!("manifest stub must be named stub.exe");
        }
        if stub_type != ComponentKind::Executable {
            bail!("manifest stub must have type executable");
        }
        let embedded = match stub_table.get("embedded") {
            Some(Value::Boolean(value)) => *value,
            Some(_) => bail!("manifest stub embedded flag must be a boolean"),
            None => bail!("manifest stub embedded flag is required"),
        };
        if embedded {
            bail!("manifest stub must be marked as not embedded");
        }
        let stub = StubRecord {
            size: required_size(stub_table, "size")?,
            sha256: required_sha256(stub_table, "sha256")?,
        };

        let component_values = match table.get("component") {
            Some(Value::Array(values)) => values,
            Some(_) => bail!("manifest component must be an array of tables"),
            None => bail!("manifest component is required"),
        };
        let mut components = Vec::with_capacity(component_values.len());
        let mut names = HashSet::new();
        let mut paths = HashSet::new();
        for value in component_values {
            let component_table = value
                .as_table()
                .context("manifest component entries must be tables")?;
            let name = required_string(component_table, "name")?;
            let entry_path = required_string(component_table, "path")?;
            let kind = ComponentKind::parse(&required_string(component_table, "type")?)?;
            if name.is_empty() {
                bail!("manifest component name must not be empty");
            }
            if name != entry_path {
                bail!(
                    "manifest component names must match their package paths: {name:?} vs {entry_path:?}"
                );
            }
            let normalized = path::validate_relative_path(&entry_path)
                .context("manifest component path is invalid")?;
            if normalized != entry_path {
                bail!("manifest component paths must use '/' separators: {entry_path:?}");
            }
            if entry_path == MANIFEST_NAME {
                bail!("manifest must not list itself as a component");
            }
            if !names.insert(name.to_lowercase()) {
                bail!("duplicate manifest component name: {name}");
            }
            if !paths.insert(entry_path.to_lowercase()) {
                bail!("duplicate manifest component path: {entry_path}");
            }
            components.push(Component {
                name,
                path: entry_path,
                kind,
                size: required_size(component_table, "size")?,
                sha256: required_sha256(component_table, "sha256")?,
            });
        }

        Ok(Self {
            generator,
            stub,
            components,
        })
    }

    /// Check the manifest against the archive directory and, before signing,
    /// against the actual stub bytes. Signing changes the PE headers, so the
    /// stub hash is only authoritative for the pre-signature file.
    pub fn verify(&self, package: &archive::Package, stub_path: Option<&Path>) -> Result<()> {
        let layout = package.layout();
        if self.stub.size != layout.archive_offset {
            bail!(
                "manifest stub size {} does not match the archive offset {}",
                self.stub.size,
                layout.archive_offset
            );
        }
        if let Some(path) = stub_path {
            let actual = archive::hash_prefix(path, self.stub.size)?;
            if actual != self.stub.sha256 {
                bail!("SHA-256 mismatch for the package stub");
            }
        }

        if !layout
            .entries
            .iter()
            .any(|entry| entry.name == MANIFEST_NAME)
        {
            bail!("package is missing {MANIFEST_NAME}");
        }
        let embedded: Vec<&Entry> = layout
            .entries
            .iter()
            .filter(|entry| entry.name != MANIFEST_NAME)
            .collect();
        if embedded.len() != self.components.len() {
            bail!(
                "manifest lists {} components but the package has {}",
                self.components.len(),
                embedded.len()
            );
        }

        let mut seen = HashSet::new();
        let entries: HashMap<&str, &Entry> = layout
            .entries
            .iter()
            .map(|entry| (entry.name.as_str(), entry))
            .collect();
        for component in &self.components {
            if !seen.insert(component.path.to_lowercase()) {
                bail!("duplicate manifest component: {}", component.path);
            }
            let entry = entries
                .get(component.path.as_str())
                .with_context(|| format!("manifest component is missing: {}", component.path))?;
            if component.name != component.path {
                bail!(
                    "manifest component names must match their package paths: {}",
                    component.name
                );
            }
            if component.size != entry.size {
                bail!("manifest size mismatch for {}", component.path);
            }
            if component.sha256 != entry.sha256 {
                bail!("manifest SHA-256 mismatch for {}", component.path);
            }
            let expected = kind_for_path(&component.path);
            if component.kind != expected {
                bail!(
                    "manifest type for {} is {}, expected {}",
                    component.path,
                    component.kind.as_str(),
                    expected.as_str()
                );
            }
        }
        Ok(())
    }
}

fn required_string(table: &toml::value::Table, key: &str) -> Result<String> {
    match table.get(key) {
        Some(Value::String(value)) => Ok(value.clone()),
        Some(_) => bail!("manifest field {key} must be a string"),
        None => bail!("manifest field {key} is required"),
    }
}

fn required_size(table: &toml::value::Table, key: &str) -> Result<u64> {
    match table.get(key) {
        Some(Value::Integer(value)) if *value >= 0 => Ok(*value as u64),
        Some(Value::Integer(_)) => bail!("manifest field {key} must not be negative"),
        Some(_) => bail!("manifest field {key} must be an integer"),
        None => bail!("manifest field {key} is required"),
    }
}

fn required_sha256(table: &toml::value::Table, key: &str) -> Result<[u8; 32]> {
    let text = required_string(table, key)?;
    parse_sha256(&text)
}

pub fn parse_sha256(text: &str) -> Result<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("SHA-256 must be 64 hexadecimal characters");
    }
    let mut output = [0u8; 32];
    for (index, chunk) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let high = hex_digit(chunk[0]);
        let low = hex_digit(chunk[1]);
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

fn hex_digit(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => unreachable!(),
    }
}

pub fn hex(bytes: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, size: u64, byte: u8) -> Entry {
        Entry {
            name: name.into(),
            offset: 0,
            size,
            sha256: [byte; 32],
        }
    }

    #[test]
    fn renders_and_parses_manifest() {
        let entries = vec![
            entry("client.exe", 10, 1),
            entry("backend.exe", 20, 2),
            entry("config.toml", 30, 3),
            entry("payload.zip", 40, 4),
            entry("assets/icon.ico", 50, 5),
        ];
        let manifest = Manifest::create(
            "test",
            StubRecord {
                size: 4096,
                sha256: [9; 32],
            },
            &entries,
        );
        let bytes = manifest.render().unwrap();
        let parsed = Manifest::parse(&bytes).unwrap();
        assert_eq!(parsed.generator, "test");
        assert_eq!(parsed.stub.size, 4096);
        assert_eq!(parsed.components.len(), 5);
        assert_eq!(parsed.components[4].kind, ComponentKind::Resource);
        assert!(bytes.starts_with(b"format = 1"));
    }

    #[test]
    fn rejects_tampered_manifest() {
        let entries = vec![entry("client.exe", 10, 1)];
        let manifest = Manifest::create(
            "test",
            StubRecord {
                size: 1,
                sha256: [9; 32],
            },
            &entries,
        );
        let text = String::from_utf8(manifest.render().unwrap()).unwrap();
        let text = text.replace("sha256 = \"01", "sha256 = \"02");
        let parsed = Manifest::parse(text.as_bytes()).unwrap();
        assert_ne!(parsed.components[0].sha256, [1; 32]);
    }
}
