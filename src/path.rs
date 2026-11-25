use anyhow::{bail, Context, Result};
use std::path::{Component, Path, PathBuf};

use crate::fsutil;

pub const MAX_ENTRY_NAME_BYTES: usize = 1024;
pub const MAX_PATH_UTF16: usize = 32_767;
const MAX_INSTALL_PATH_UTF16: usize = 32_767;

/// Validate a path that will be stored inside the AIP archive or a ZIP
/// payload. `input` may use either slash direction; the result always uses
/// `/`. Absolute paths, traversal, ADS, device names, and control characters
/// are rejected.
pub fn validate_relative_path(input: &str) -> Result<String> {
    if input.is_empty() {
        bail!("path is empty");
    }
    if input.encode_utf16().count() > MAX_PATH_UTF16 {
        bail!("path is too long");
    }
    if input.starts_with('/') || input.starts_with('\\') {
        bail!("path must be relative: {input:?}");
    }

    let mut normalized = String::with_capacity(input.len());
    for (index, component) in input.split(['/', '\\']).enumerate() {
        if index > 0 {
            normalized.push('/');
        }
        if component.is_empty() {
            bail!("path contains an empty component: {input:?}");
        }
        if component == "." || component == ".." {
            bail!("path contains a relative component: {input:?}");
        }
        if component.ends_with('.') || component.ends_with(' ') {
            bail!("path component ends with a dot or space: {component:?}");
        }
        if component.contains(':') {
            bail!("path must not contain a drive or alternate data stream: {input:?}");
        }
        if component.chars().any(|ch| {
            ch == '\0' || (ch as u32) < 0x20 || matches!(ch, '<' | '>' | '"' | '|' | '?' | '*')
        }) {
            bail!("path contains an invalid character: {input:?}");
        }
        if is_device_name(component) {
            bail!("path contains a reserved device name: {component:?}");
        }
        normalized.push_str(component);
    }
    Ok(normalized)
}

/// Archive directory names use a 16-bit length field and the stub only accepts
/// names up to 1024 UTF-8 bytes.
pub fn validate_entry_name(input: &str) -> Result<String> {
    let normalized = validate_relative_path(input)?;
    if normalized.len() > MAX_ENTRY_NAME_BYTES {
        bail!("package entry name is longer than {MAX_ENTRY_NAME_BYTES} bytes: {normalized:?}");
    }
    Ok(normalized)
}

/// Convert a path relative to an asset directory to a package-relative path.
pub fn asset_relative_path(relative: &Path) -> Result<String> {
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => {
                let part = part.to_str().with_context(|| {
                    format!("asset path is not valid UTF-8: {}", relative.display())
                })?;
                parts.push(part);
            }
            _ => bail!(
                "asset path contains an unexpected component: {}",
                relative.display()
            ),
        }
    }
    if parts.is_empty() {
        bail!("asset path is empty");
    }
    validate_relative_path(&parts.join("/"))
}

pub fn is_device_name(component: &str) -> bool {
    let stem = component
        .split_once('.')
        .map(|(stem, _)| stem)
        .unwrap_or(component);
    let upper = stem.to_ascii_uppercase();
    matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (upper.len() == 4
            && (upper.starts_with("COM") || upper.starts_with("LPT"))
            && upper.as_bytes()[3].is_ascii_digit()
            && upper.as_bytes()[3] != b'0')
}

/// Compare two canonical Windows paths case-insensitively. Windows paths are
/// compared component by component so `C:\foo` does not match `C:\foobar`.
pub fn same_path(left: &Path, right: &Path) -> bool {
    let left = simplified(left);
    let right = simplified(right);
    let mut left = left.components();
    let mut right = right.components();
    loop {
        match (left.next(), right.next()) {
            (None, None) => return true,
            (Some(left), Some(right)) if components_equal(left, right) => {}
            _ => return false,
        }
    }
}

/// True when `path` is `root` or lies below it, using the same
/// case-insensitive component comparison as [`same_path`].
pub fn is_path_under(path: &Path, root: &Path) -> bool {
    let path = simplified(path);
    let root = simplified(root);
    let mut path = path.components();
    for component in root.components() {
        match path.next() {
            Some(candidate) if components_equal(candidate, component) => {}
            _ => return false,
        }
    }
    true
}

fn components_equal(left: Component<'_>, right: Component<'_>) -> bool {
    left.as_os_str().to_string_lossy().to_lowercase()
        == right.as_os_str().to_string_lossy().to_lowercase()
}

/// Strip the Win32 verbatim prefix so canonicalized paths can be compared with
/// the plain absolute paths stored in configuration files.
fn simplified(path: &Path) -> std::borrow::Cow<'_, Path> {
    let text = path.as_os_str().to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        std::borrow::Cow::Owned(PathBuf::from(format!(r"\\{rest}")))
    } else if let Some(rest) = text.strip_prefix(r"\\?\") {
        std::borrow::Cow::Owned(PathBuf::from(rest))
    } else {
        std::borrow::Cow::Borrowed(path)
    }
}

pub fn is_special_background(value: &str) -> bool {
    [
        "acrylic",
        "acrylicblur",
        "mica",
        "windowsmanaged",
        "transparent",
    ]
    .iter()
    .any(|candidate| value.eq_ignore_ascii_case(candidate))
}

pub fn is_hex_color(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 7 && bytes[0] == b'#' && bytes[1..].iter().all(|byte| byte.is_ascii_hexdigit())
}

/// Expand `%VAR%` references once. Unresolvable or malformed references are
/// fatal so a packaged config cannot silently keep a literal `%VAR%`.
pub fn expand_environment(input: &str) -> Result<String> {
    let chars: Vec<char> = input.chars().collect();
    let mut output = String::with_capacity(input.len());
    let mut index = 0;
    while index < chars.len() {
        let ch = chars[index];
        if ch == '%' {
            let start = index;
            index += 1;
            while index < chars.len() && chars[index] != '%' {
                index += 1;
            }
            if index == chars.len() {
                bail!("unterminated environment variable reference in {input:?}");
            }
            let name: String = chars[start + 1..index].iter().collect();
            if name.is_empty() {
                bail!("empty environment variable reference in {input:?}");
            }
            let value = std::env::var_os(&name)
                .with_context(|| format!("environment variable %{name}% is not defined"))?;
            output.push_str(&value.to_string_lossy());
            index += 1;
        } else {
            output.push(ch);
            index += 1;
        }
    }
    Ok(output)
}

/// Validate the install-location template from `[defaults]`. This mirrors the
/// stub's checks closely enough to catch mistakes at build time; the stub
/// performs the authoritative check on the target machine.
pub fn validate_install_location(input: &str) -> Result<String> {
    if input.is_empty() {
        bail!("install location is empty");
    }
    if input.encode_utf16().count() > MAX_INSTALL_PATH_UTF16 {
        bail!("install location is too long");
    }
    let expanded = expand_environment(input)?;
    let normalized = normalize_absolute(&expanded)?;
    reject_protected_locations(&normalized)?;
    Ok(normalized)
}

fn normalize_absolute(path: &str) -> Result<String> {
    if path.encode_utf16().count() > MAX_INSTALL_PATH_UTF16 {
        bail!("path is too long");
    }
    for ch in path.chars() {
        if ch == '\0' || (ch as u32) < 0x20 {
            bail!("path contains a control character");
        }
    }
    let bytes = path.as_bytes();
    if bytes.len() < 3
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || (bytes[2] != b'\\' && bytes[2] != b'/')
    {
        bail!("path must be an absolute local drive path: {path:?}");
    }
    let rest = &path[2..];
    if rest.contains(':') {
        bail!("path must not contain an alternate data stream: {path:?}");
    }
    let mut components = Vec::new();
    for component in rest.split(['\\', '/']) {
        if component.is_empty() {
            continue;
        }
        if component == "." || component == ".." {
            bail!("path must not contain relative components: {path:?}");
        }
        if component.ends_with('.') || component.ends_with(' ') {
            bail!("path component ends with a dot or space: {component:?}");
        }
        if is_device_name(component) {
            bail!("path contains a reserved device name: {component:?}");
        }
        components.push(component);
    }
    let drive = bytes[0].to_ascii_uppercase() as char;
    if components.is_empty() {
        return Ok(format!("{drive}:\\"));
    }
    Ok(format!("{drive}:\\{}", components.join("\\")))
}

fn reject_protected_locations(path: &str) -> Result<()> {
    let bytes = path.as_bytes();
    if bytes.len() == 3 && bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/') {
        bail!("install location must not be a drive root: {path:?}");
    }

    let mut roots: Vec<(String, bool, &'static str)> = Vec::new();
    if let Some(windows) = env_path("SystemRoot").or_else(|| env_path("WINDIR")) {
        roots.push((windows, true, "the Windows directory"));
    }
    if let Some(program_files) = env_path("ProgramFiles") {
        roots.push((program_files, false, "the Program Files root"));
    }
    if let Some(program_files_x86) = env_path("ProgramFiles(x86)") {
        roots.push((program_files_x86, false, "the Program Files (x86) root"));
    }
    if let Some(program_data) = env_path("ProgramData") {
        roots.push((program_data, false, "the ProgramData root"));
    }
    if let Some(profile) = env_path("USERPROFILE") {
        roots.push((format!("{profile}\\Desktop"), false, "the Desktop root"));
        roots.push((profile, false, "the user profile root"));
    }
    if let Some(app_data) = env_path("APPDATA") {
        roots.push((
            format!("{app_data}\\Microsoft\\Windows\\Start Menu"),
            false,
            "the Start Menu root",
        ));
    }

    for (root, include_children, description) in roots {
        if same_or_under(path, &root, include_children) {
            bail!("install location must not be {description}: {path:?}");
        }
    }
    Ok(())
}

fn env_path(name: &str) -> Option<String> {
    std::env::var_os(name).map(|value| value.to_string_lossy().into_owned())
}

fn same_or_under(path: &str, root: &str, include_children: bool) -> bool {
    let path = normalize_for_compare(path);
    let root = normalize_for_compare(root);
    if path == root {
        return true;
    }
    include_children
        && path
            .strip_prefix(&root)
            .is_some_and(|rest| rest.starts_with('\\'))
}

fn normalize_for_compare(path: &str) -> String {
    path.trim_end_matches(['\\', '/']).to_lowercase()
}

/// Resolve an `icon` or `background` source path from a source config. Relative
/// paths are relative to the config file. URLs, UNC/device paths, reparse
/// points, and non-files are rejected.
pub fn resolve_source_image(config_dir: &Path, input: &str) -> Result<PathBuf> {
    if input.is_empty() {
        bail!("image path is empty");
    }
    if input.chars().any(|ch| ch == '\0' || (ch as u32) < 0x20) {
        bail!("image path contains a control character");
    }
    let lower = input.to_ascii_lowercase();
    if ["http://", "https://", "ftp://", "file://"]
        .iter()
        .any(|prefix| lower.starts_with(prefix))
    {
        bail!("image path must be a local file, not a URL: {input:?}");
    }
    if input.starts_with(r"\\") {
        bail!("image path must not be a UNC or device path: {input:?}");
    }

    let path = PathBuf::from(input);
    let path = if path.is_absolute() {
        path
    } else {
        config_dir.join(path)
    };

    if let Ok(metadata) = std::fs::symlink_metadata(&path) {
        if fsutil::is_reparse_point(&metadata) {
            bail!("image path must not be a reparse point: {}", path.display());
        }
    }
    let canonical = std::fs::canonicalize(&path)
        .with_context(|| format!("failed to resolve image path: {}", path.display()))?;
    fsutil::ensure_regular_file(&canonical, "image")?;
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_relative_paths() {
        assert_eq!(
            validate_relative_path(r"assets\background.avif").unwrap(),
            "assets/background.avif"
        );
        assert_eq!(
            validate_relative_path("assets/icon.ico").unwrap(),
            "assets/icon.ico"
        );
    }

    #[test]
    fn rejects_unsafe_relative_paths() {
        for path in [
            "",
            "/absolute",
            r"C:\absolute",
            r"..\escape",
            "a/../b",
            "a//b",
            "a/b.",
            "a/NUL",
            "a/file:stream",
            "a/<bad>",
            "./file",
            "a/b\0",
        ] {
            assert!(
                validate_relative_path(path).is_err(),
                "expected rejection: {path:?}"
            );
        }
    }

    #[test]
    fn validates_install_locations() {
        assert!(validate_install_location(r"D:\Apps\Example").is_ok());
        assert!(validate_install_location(r"C:\Program Files\Example").is_ok());
        assert!(validate_install_location(r"%LOCALAPPDATA%\Programs\Example").is_ok());

        for path in [
            r"\\server\share\app",
            r"\\.\C:\app",
            r"\\?\C:\app",
            r"C:app",
            r"app\sub",
            r"C:\Apps\..\Windows",
            r"C:\Apps\file:stream",
            r"C:\Apps\CON",
            r"C:\Apps\trailing.",
            r"C:\Apps\%NOPE%",
            "",
            r"C:\",
        ] {
            assert!(
                validate_install_location(path).is_err(),
                "expected rejection: {path:?}"
            );
        }
    }

    #[test]
    fn background_values() {
        assert!(is_special_background("AcrylicBlur"));
        assert!(is_hex_color("#1e90ff"));
        assert!(!is_hex_color("#fff"));
        assert!(!is_hex_color("#GGGGGG"));
    }

    #[test]
    fn compares_windows_paths_case_insensitively() {
        assert!(same_path(
            Path::new(r"C:\Apps\Example\foo.exe"),
            Path::new(r"c:\apps\example\FOO.EXE")
        ));
        assert!(!same_path(
            Path::new(r"C:\Apps\Example"),
            Path::new(r"C:\Apps\Example2")
        ));
        assert!(is_path_under(
            Path::new(r"C:\Apps\Example\foo.exe"),
            Path::new(r"c:\apps\example")
        ));
        assert!(is_path_under(
            Path::new(r"C:\Apps\Example"),
            Path::new(r"C:\Apps\Example")
        ));
        assert!(!is_path_under(
            Path::new(r"C:\Apps\Example2"),
            Path::new(r"C:\Apps\Example")
        ));
        assert!(same_path(
            Path::new(r"\\?\C:\Apps\Example"),
            Path::new(r"C:\Apps\Example")
        ));
        assert!(is_path_under(
            Path::new(r"\\?\C:\Apps\Example\foo.exe"),
            Path::new(r"C:\Apps\Example")
        ));
    }

    #[test]
    fn asset_paths_use_forward_slashes() {
        assert_eq!(
            asset_relative_path(Path::new(r"icons\app.ico")).unwrap(),
            "icons/app.ico"
        );
        assert!(asset_relative_path(Path::new("../escape")).is_err());
    }

    #[test]
    fn rejects_absolute_image_urls() {
        let root = std::env::temp_dir();
        assert!(resolve_source_image(&root, "https://example.com/a.png").is_err());
        assert!(resolve_source_image(&root, r"\\server\share\a.png").is_err());
    }
}
