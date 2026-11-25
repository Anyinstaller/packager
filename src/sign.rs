use anyhow::{bail, Context, Result};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
#[cfg(windows)]
use windows::Win32::Foundation::{HANDLE, HWND};
#[cfg(windows)]
use windows::Win32::Security::WinTrust::{
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO,
    WTD_CHOICE_FILE, WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
    WTD_UI_NONE,
};

#[derive(Clone, Debug)]
pub enum Certificate {
    Pfx { path: PathBuf, password: OsString },
    Thumbprint(String),
}

#[derive(Clone, Debug)]
pub struct SignOptions {
    pub signtool: PathBuf,
    pub certificate: Certificate,
    pub timestamp_url: String,
    pub description: Option<String>,
}

impl SignOptions {
    pub fn sign_args(&self, file: &Path) -> Vec<OsString> {
        let mut args = vec![
            OsString::from("sign"),
            OsString::from("/fd"),
            OsString::from("SHA256"),
            OsString::from("/td"),
            OsString::from("SHA256"),
            OsString::from("/tr"),
            OsString::from(&self.timestamp_url),
        ];
        if let Some(description) = &self.description {
            args.push(OsString::from("/d"));
            args.push(OsString::from(description));
        }
        match &self.certificate {
            Certificate::Pfx { path, password } => {
                args.push(OsString::from("/f"));
                args.push(path.as_os_str().to_os_string());
                args.push(OsString::from("/p"));
                args.push(password.clone());
            }
            Certificate::Thumbprint(thumbprint) => {
                args.push(OsString::from("/sha1"));
                args.push(OsString::from(thumbprint));
            }
        }
        args.push(file.as_os_str().to_os_string());
        args
    }
}

pub fn sign(file: &Path, options: &SignOptions) -> Result<()> {
    let args = options.sign_args(file);
    run_tool(&options.signtool, &args, "signtool sign")
}

pub fn signtool_verify(signtool: &Path, file: &Path) -> Result<()> {
    let args = vec![
        OsString::from("verify"),
        OsString::from("/pa"),
        OsString::from("/all"),
        file.as_os_str().to_os_string(),
    ];
    run_tool(signtool, &args, "signtool verify")
}

fn run_tool(tool: &Path, args: &[OsString], operation: &str) -> Result<()> {
    let output = Command::new(tool)
        .args(args)
        .output()
        .with_context(|| format!("failed to run {} at {}", operation, tool.display()))?;
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "{operation} failed with {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            stdout.trim_end(),
            stderr.trim_end()
        );
    }
    Ok(())
}

/// Verify the Authenticode signature with the same API and policy the stub
/// uses: whole-chain revocation checking, no UI, and the open file handle so
/// the signature is checked against the bytes on disk.
pub fn verify_authenticode(path: &Path) -> Result<()> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("failed to open signed file {}", path.display()))?;
    #[cfg(windows)]
    {
        verify_with_handle(path, HANDLE(file.as_raw_handle()))
    }
    #[cfg(not(windows))]
    {
        let _ = file;
        bail!("Authenticode verification is only available on Windows")
    }
}

#[cfg(windows)]
fn verify_with_handle(path: &Path, handle: HANDLE) -> Result<()> {
    use std::mem::size_of;
    use windows::core::PCWSTR;

    let wide_path = crate::winutil::wide(path.as_os_str());
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wide_path.as_ptr()),
        hFile: handle,
        pgKnownSubject: std::ptr::null_mut(),
    };
    let mut data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice: WTD_CHOICE_FILE,
        dwStateAction: WTD_STATEACTION_VERIFY,
        ..Default::default()
    };
    data.Anonymous.pFile = &mut file_info;
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    let status = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action,
            &mut data as *mut _ as *mut std::ffi::c_void,
        )
    };

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        let _ = WinVerifyTrust(
            HWND::default(),
            &mut action,
            &mut data as *mut _ as *mut std::ffi::c_void,
        );
    }

    if status != 0 {
        let code = status as u32;
        let reason = match code {
            0x800B_0100 => "the file is not signed",
            0x800B_0109 => "the certificate chain is not trusted",
            0x800B_0101 => "the certificate has expired",
            0x800B_010C => "the certificate has been revoked",
            0x8009_6010 => "the file digest does not match the signature",
            0x800B_0003 => "the signature subject is not a file",
            _ => "signature validation failed",
        };
        bail!("Authenticode verification failed: {reason} (0x{code:08X})");
    }
    Ok(())
}

pub fn find_signtool() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("SIGNTOOL_PATH") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
    }
    if let Some(path) = search_path() {
        return Ok(path);
    }
    for root in windows_kit_roots() {
        if let Some(path) = search_kits(&root) {
            return Ok(path);
        }
    }
    bail!("signtool.exe was not found; install the Windows SDK or pass --signtool <path>")
}

fn search_path() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join("signtool.exe");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn windows_kit_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for variable in ["ProgramFiles(x86)", "ProgramFiles"] {
        if let Some(base) = std::env::var_os(variable) {
            let root = PathBuf::from(base)
                .join("Windows Kits")
                .join("10")
                .join("bin");
            if root.is_dir() {
                roots.push(root);
            }
        }
    }
    roots
}

fn search_kits(root: &Path) -> Option<PathBuf> {
    let mut versions: Vec<PathBuf> = std::fs::read_dir(root)
        .ok()?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    versions.sort_by(|left, right| right.file_name().cmp(&left.file_name()));
    for version in versions {
        for architecture in ["x64", "x86"] {
            let candidate = version.join(architecture).join("signtool.exe");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        let candidate = version.join("signtool.exe");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

pub fn normalize_thumbprint(input: &str) -> Result<String> {
    let thumbprint: String = input
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect();
    if thumbprint.len() != 40 || !thumbprint.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("certificate thumbprint must be 40 hexadecimal characters");
    }
    Ok(thumbprint.to_ascii_uppercase())
}

pub fn validate_timestamp_url(url: &str) -> Result<()> {
    if url.is_empty() {
        bail!("timestamp URL must not be empty");
    }
    if url
        .chars()
        .any(|ch| ch == '\0' || (ch as u32) < 0x20 || ch.is_whitespace())
    {
        bail!("timestamp URL contains an invalid character");
    }
    let lower = url.to_ascii_lowercase();
    if !lower.starts_with("http://") && !lower.starts_with("https://") {
        bail!("timestamp URL must use http or https: {url:?}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_pfx_sign_arguments() {
        let options = SignOptions {
            signtool: PathBuf::from("signtool.exe"),
            certificate: Certificate::Pfx {
                path: PathBuf::from(r"C:\keys\release.pfx"),
                password: OsString::from("secret"),
            },
            timestamp_url: "http://timestamp.example".into(),
            description: Some("Example".into()),
        };
        let args = options.sign_args(Path::new("foo.exe"));
        let args: Vec<String> = args
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args[0], "sign");
        assert!(args.contains(&"/tr".to_string()));
        assert!(args.contains(&"/f".to_string()));
        assert!(args.contains(&"/p".to_string()));
        assert_eq!(args.last().unwrap(), "foo.exe");
    }

    #[test]
    fn builds_thumbprint_sign_arguments() {
        let options = SignOptions {
            signtool: PathBuf::from("signtool.exe"),
            certificate: Certificate::Thumbprint("A".repeat(40)),
            timestamp_url: "https://timestamp.example".into(),
            description: None,
        };
        let args = options.sign_args(Path::new("foo.exe"));
        let args: Vec<String> = args
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect();
        assert!(args.contains(&"/sha1".to_string()));
        assert!(!args.contains(&"/f".to_string()));
    }

    #[test]
    fn validates_thumbprints_and_urls() {
        assert!(normalize_thumbprint(&"a".repeat(40)).is_ok());
        assert!(normalize_thumbprint("abc").is_err());
        assert!(validate_timestamp_url("http://timestamp.digicert.com").is_ok());
        assert!(validate_timestamp_url("https://tsa.example/path").is_ok());
        assert!(validate_timestamp_url("file:///tmp").is_err());
        assert!(validate_timestamp_url("http://a b").is_err());
    }

    #[test]
    fn rejects_unsigned_executable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unsigned.exe");
        std::fs::write(&path, b"MZ").unwrap();
        assert!(verify_authenticode(&path).is_err());
    }
}
