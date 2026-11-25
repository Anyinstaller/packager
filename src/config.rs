use anyhow::{bail, Context, Result};
use std::path::Path;
use toml::Value;
use toml_edit::DocumentMut;

use crate::fsutil;
use crate::path;

pub const MAX_CONFIG_BYTES: u64 = 64 * 1024;
pub const MAX_NAME_CHARS: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedConfig {
    pub protocol: i64,
    pub name: String,
    pub icon: Option<String>,
    pub background: Option<String>,
    pub install_location: String,
    pub create_start_menu_folder: bool,
    pub create_desktop_shortcut: bool,
}

pub struct SourceConfig {
    pub document: DocumentMut,
    pub parsed: ParsedConfig,
}

impl ParsedConfig {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() as u64 > MAX_CONFIG_BYTES {
            bail!("config.toml is larger than 64 KiB");
        }
        if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
            bail!("config.toml must be UTF-8 without a BOM");
        }
        let text = std::str::from_utf8(bytes).context("config.toml is not valid UTF-8")?;
        let value: Value = toml::from_str(text).context("config.toml is not valid TOML")?;
        let table = value
            .as_table()
            .context("config.toml root must be a TOML table")?;

        let protocol = match table.get("protocol") {
            Some(Value::Integer(value)) => *value,
            Some(_) => bail!("protocol must be an integer"),
            None => bail!("protocol is required"),
        };
        if protocol != 1 {
            bail!("unsupported AIP protocol number: {protocol}");
        }

        let name = match table.get("name") {
            Some(Value::String(value)) => value.clone(),
            Some(_) => bail!("name must be a string"),
            None => bail!("name is required"),
        };
        validate_name(&name)?;

        let icon = optional_string(table.get("icon"), "icon")?;
        let background = optional_string(table.get("background"), "background")?;

        let defaults = match table.get("defaults") {
            Some(Value::Table(value)) => value,
            Some(_) => bail!("defaults must be a table"),
            None => bail!("[defaults] is required"),
        };
        let install_location = match defaults.get("installLocation") {
            Some(Value::String(value)) => value.clone(),
            Some(_) => bail!("defaults.installLocation must be a string"),
            None => bail!("defaults.installLocation is required"),
        };
        path::validate_install_location(&install_location)
            .context("defaults.installLocation is invalid")?;

        let create_start_menu_folder = match defaults.get("createStartMenuFolder") {
            Some(Value::Boolean(value)) => *value,
            Some(_) => bail!("defaults.createStartMenuFolder must be a boolean"),
            None => bail!("defaults.createStartMenuFolder is required"),
        };
        let create_desktop_shortcut = match defaults.get("createDesktopShortcut") {
            Some(Value::Boolean(value)) => *value,
            Some(_) => bail!("defaults.createDesktopShortcut must be a boolean"),
            None => bail!("defaults.createDesktopShortcut is required"),
        };

        Ok(Self {
            protocol,
            name,
            icon,
            background,
            install_location,
            create_start_menu_folder,
            create_desktop_shortcut,
        })
    }

    /// True when `background` is a visual effect or a `#RRGGBB` color rather
    /// than an image path.
    #[cfg(test)]
    pub fn background_is_visual(&self) -> Option<bool> {
        self.background
            .as_deref()
            .map(|value| path::is_special_background(value) || path::is_hex_color(value))
    }
}

impl SourceConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = fsutil::read_limited(path, MAX_CONFIG_BYTES, "config.toml")?;
        Self::from_bytes(&bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let parsed = ParsedConfig::parse(bytes)?;
        let text = std::str::from_utf8(bytes).context("config.toml is not valid UTF-8")?;
        let document = text
            .parse::<DocumentMut>()
            .context("config.toml is not valid TOML")?;
        Ok(Self { document, parsed })
    }
}

/// Write the packaged config. `icon` and `background` are package-relative
/// paths; `None` leaves the original value untouched (for empty values,
/// effects, and colors). Unknown keys and comments are preserved.
pub fn render(
    document: &mut DocumentMut,
    icon: Option<&str>,
    background: Option<&str>,
) -> Result<Vec<u8>> {
    if let Some(icon) = icon {
        document["icon"] = toml_edit::value(icon);
    }
    if let Some(background) = background {
        document["background"] = toml_edit::value(background);
    }

    let text = document.to_string();
    let bytes = text.into_bytes();
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        bail!("packaged config.toml is larger than 64 KiB");
    }
    ParsedConfig::parse(&bytes).context("packaged config.toml is invalid")?;
    Ok(bytes)
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("name must not be empty");
    }
    if name.chars().count() > MAX_NAME_CHARS {
        bail!("name must be at most {MAX_NAME_CHARS} characters");
    }
    if name.chars().any(|ch| ch == '\0' || (ch as u32) < 0x20) {
        bail!("name must not contain control characters");
    }
    Ok(())
}

fn optional_string(value: Option<&Value>, field: &str) -> Result<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let text = match value {
        Value::String(value) => value,
        _ => bail!("{field} must be a string"),
    };
    if text.is_empty() {
        return Ok(None);
    }
    if text.contains('\0') {
        bail!("{field} must not contain NUL");
    }
    Ok(Some(text.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
protocol = 1
name = "Example App"
icon = 'C:\Users\Ali\Pictures\app.ico'
background = 'C:\Users\Ali\Pictures\bg.avif'
unknownKey = "kept"

[defaults]
installLocation = '%LocalAppData%\Programs\Example App'
createStartMenuFolder = true
createDesktopShortcut = false
"#;

    #[test]
    fn parses_source_config() {
        let config = ParsedConfig::parse(VALID.as_bytes()).unwrap();
        assert_eq!(config.protocol, 1);
        assert_eq!(config.name, "Example App");
        assert_eq!(
            config.icon.as_deref(),
            Some(r"C:\Users\Ali\Pictures\app.ico")
        );
        assert_eq!(config.background_is_visual(), Some(false));
    }

    #[test]
    fn accepts_effects_and_empty_optional_fields() {
        let config = ParsedConfig::parse(
            br#"
protocol = 1
name = "X"
icon = ""
background = "Acrylic"

[defaults]
installLocation = "C:\\Apps\\X"
createStartMenuFolder = true
createDesktopShortcut = true
"#,
        )
        .unwrap();
        assert_eq!(config.icon, None);
        assert_eq!(config.background_is_visual(), Some(true));
    }

    #[test]
    fn rejects_bad_configs() {
        let cases = [
            ("protocol = 2\nname = \"X\"\n[defaults]\ninstallLocation = 'C:\\X'\ncreateStartMenuFolder = true\ncreateDesktopShortcut = true", "protocol"),
            ("protocol = 1\n[defaults]\ninstallLocation = 'C:\\X'\ncreateStartMenuFolder = true\ncreateDesktopShortcut = true", "name"),
            ("protocol = 1\nname = \"\"\n[defaults]\ninstallLocation = 'C:\\X'\ncreateStartMenuFolder = true\ncreateDesktopShortcut = true", "name"),
            ("protocol = 1\nname = \"X\"\nicon = 1\n[defaults]\ninstallLocation = 'C:\\X'\ncreateStartMenuFolder = true\ncreateDesktopShortcut = true", "icon"),
            ("protocol = 1\nname = \"X\"\n[defaults]\ninstallLocation = '\\\\server\\share\\X'\ncreateStartMenuFolder = true\ncreateDesktopShortcut = true", "install"),
            ("protocol = 1\nname = \"X\"\n[defaults]\ninstallLocation = 'C:\\X'\ncreateStartMenuFolder = \"yes\"\ncreateDesktopShortcut = true", "StartMenu"),
        ];
        for (text, label) in cases {
            assert!(
                ParsedConfig::parse(text.as_bytes()).is_err(),
                "expected rejection for {label}"
            );
        }
    }

    #[test]
    fn rewrites_paths_and_preserves_unknown_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, VALID).unwrap();
        let mut source = SourceConfig::load(&path).unwrap();
        let bytes = render(
            &mut source.document,
            Some("assets/icon.ico"),
            Some("assets/background.webp"),
        )
        .unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.contains(r#"icon = "assets/icon.ico""#));
        assert!(text.contains(r#"background = "assets/background.webp""#));
        assert!(text.contains("unknownKey = \"kept\""));
        assert!(!text.contains(r"C:\Users"));
    }

    #[test]
    fn rejects_bom_and_oversize() {
        let mut bom = vec![0xEF, 0xBB, 0xBF];
        bom.extend_from_slice(VALID.as_bytes());
        assert!(ParsedConfig::parse(&bom).is_err());
        assert!(ParsedConfig::parse(&vec![b' '; MAX_CONFIG_BYTES as usize + 1]).is_err());
    }
}
