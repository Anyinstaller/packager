use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use tempfile::Builder;

use crate::archive; // archive::Entry is referenced through layout entries only.
use crate::assets;
use crate::config::{self, ParsedConfig, SourceConfig, MAX_CONFIG_BYTES};
use crate::fsutil;
use crate::imageasset::{self, ProcessedImage};
use crate::manifest::{self, Manifest, StubRecord, MANIFEST_NAME, MAX_MANIFEST_BYTES};
use crate::path;
use crate::payload;
use crate::pe;
use crate::sign::{self, Certificate, SignOptions};

pub const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_STUB_BYTES: u64 = 512 * 1024 * 1024;
pub const DEFAULT_TIMESTAMP_URL: &str = "http://timestamp.digicert.com";

pub struct BuildRequest {
    pub build_dir: PathBuf,
    pub output: PathBuf,
    pub force: bool,
    pub unsigned: bool,
    pub pfx: Option<PathBuf>,
    pub pfx_password_env: Option<String>,
    pub thumbprint: Option<String>,
    pub timestamp_url: String,
    pub signtool: Option<PathBuf>,
    pub description: Option<String>,
}

struct Inputs {
    build_dir: PathBuf,
    stub: PathBuf,
    client: PathBuf,
    backend: PathBuf,
    config: PathBuf,
    payload: PathBuf,
}

struct GeneratedImage {
    image: ProcessedImage,
}

impl GeneratedImage {
    fn package_name(&self) -> &str {
        &self.image.package_name
    }
}

pub fn run(request: BuildRequest) -> Result<()> {
    let inputs = validate_inputs(&request.build_dir)?;
    let output = prepare_output(&request, &inputs)?;

    println!("Validating inputs in {}", inputs.build_dir.display());
    pe::validate_executable(&inputs.stub, MAX_STUB_BYTES, "stub.exe")?;
    if pe::has_certificate_table(&inputs.stub)? {
        bail!(
            "stub.exe already has an Authenticode certificate table; use the unsigned stub build"
        );
    }
    pe::validate_executable(&inputs.client, MAX_EXECUTABLE_BYTES, "client.exe")?;
    pe::validate_executable(&inputs.backend, MAX_EXECUTABLE_BYTES, "backend.exe")?;

    let mut source_config = SourceConfig::load(&inputs.config)?;
    let zip_stats = payload::validate(&inputs.payload)?;
    println!(
        "  payload.zip: {} entries ({} files), {:.1} MiB uncompressed, {:.1} MiB compressed",
        zip_stats.entries,
        zip_stats.files,
        zip_stats.total_size as f64 / (1024.0 * 1024.0),
        zip_stats.total_compressed as f64 / (1024.0 * 1024.0)
    );

    let assets = assets::scan(&inputs.build_dir)?;
    let mut generated = Vec::new();
    let mut icon_rewrite = None;
    let mut background_rewrite = None;

    if let Some(icon) = &source_config.parsed.icon {
        let source = path::resolve_source_image(&inputs.build_dir, icon)
            .context("failed to resolve the icon path")?;
        let processed = imageasset::process_icon(&source).context("failed to process the icon")?;
        icon_rewrite = Some(processed.package_name.clone());
        generated.push(GeneratedImage { image: processed });
    }
    if let Some(background) = &source_config.parsed.background {
        if !path::is_special_background(background) && !path::is_hex_color(background) {
            let source = path::resolve_source_image(&inputs.build_dir, background)
                .context("failed to resolve the background path")?;
            let processed = imageasset::process_background(&source)
                .context("failed to process the background")?;
            background_rewrite = Some(processed.package_name.clone());
            generated.push(GeneratedImage { image: processed });
        }
    }

    let packaged_config = config::render(
        &mut source_config.document,
        icon_rewrite.as_deref(),
        background_rewrite.as_deref(),
    )
    .context("failed to render the packaged config.toml")?;
    let packaged =
        ParsedConfig::parse(&packaged_config).context("packaged config.toml is invalid")?;

    let mut generated_sources: HashMap<String, PathBuf> = HashMap::new();
    for image in &generated {
        generated_sources.insert(
            image.package_name().to_lowercase(),
            canonical_source(&image.image.source)?,
        );
    }

    let mut asset_entries = Vec::new();
    for asset in assets {
        if let Some(source) = generated_sources.get(&asset.package_path.to_lowercase()) {
            let asset_source = canonical_source(&asset.source_path)?;
            if !path::same_path(&asset_source, source) {
                bail!(
                    "asset {} collides with a generated resource from {}",
                    asset.package_path,
                    source.display()
                );
            }
            continue;
        }
        asset_entries.push(asset);
    }

    let mut entry_names: HashSet<String> = HashSet::new();
    for name in ["client.exe", "backend.exe", "config.toml", "payload.zip"] {
        entry_names.insert(name.to_string());
    }
    for image in &generated {
        entry_names.insert(image.package_name().to_string());
    }
    for asset in &asset_entries {
        entry_names.insert(asset.package_path.clone());
    }
    validate_resource_references(&packaged, &entry_names)?;

    let sign_options = prepare_signing(&request, &inputs, &packaged)?;

    let parent = output
        .parent()
        .context("output path has no parent directory")?;
    let temporary = Builder::new()
        .prefix(".anyinstaller-")
        .suffix(".exe")
        .tempfile_in(parent)
        .with_context(|| format!("failed to create a temporary file in {}", parent.display()))?;
    let temporary_path = temporary.into_temp_path();
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .truncate(true)
        .open(&temporary_path)
        .with_context(|| format!("failed to open {}", temporary_path.display()))?;

    println!("Writing package");
    let mut writer = archive::Writer::create(file, &inputs.stub)?;
    writer.add_file("client.exe", &inputs.client, MAX_EXECUTABLE_BYTES)?;
    writer.add_file("backend.exe", &inputs.backend, MAX_EXECUTABLE_BYTES)?;
    writer.add_bytes("config.toml", &packaged_config)?;
    writer.add_file("payload.zip", &inputs.payload, payload::MAX_PAYLOAD_BYTES)?;
    for image in &generated {
        writer.add_bytes(image.package_name(), &image.image.bytes)?;
    }
    drop(generated);
    for asset in &asset_entries {
        writer.add_file(
            &asset.package_path,
            &asset.source_path,
            archive::MAX_ENTRY_SIZE,
        )?;
    }

    let manifest = Manifest::create(
        format!("anyinstaller-packager {}", env!("CARGO_PKG_VERSION")),
        StubRecord {
            size: writer.stub_size(),
            sha256: writer.stub_sha256(),
        },
        writer.entries(),
    );
    let manifest_bytes = manifest.render()?;
    writer.add_bytes(MANIFEST_NAME, &manifest_bytes)?;
    drop(manifest_bytes);
    drop(manifest);
    let layout = writer.finish()?;

    println!(
        "Verifying package: {} components, {:.1} MiB",
        layout.entries.len(),
        layout.entries.iter().map(|entry| entry.size).sum::<u64>() as f64 / (1024.0 * 1024.0)
    );
    verify_package(&temporary_path, true, true)?;

    if let Some(options) = &sign_options {
        println!("Signing with signtool");
        sign::sign(&temporary_path, options)?;
        println!("Verifying Authenticode signature");
        sign::verify_authenticode(&temporary_path)?;
        sign::signtool_verify(&options.signtool, &temporary_path)?;
        verify_package(&temporary_path, false, false)?;
    } else {
        println!(
            "WARNING: --unsigned produced a development package with no Authenticode signature"
        );
    }

    let size = std::fs::metadata(&temporary_path)?.len();
    let digest = hash_file(&temporary_path)?;

    if request.force {
        temporary_path
            .persist(&output)
            .with_context(|| format!("failed to replace {}", output.display()))?;
    } else {
        temporary_path
            .persist_noclobber(&output)
            .with_context(|| format!("failed to create {}", output.display()))?;
    }

    println!(
        "Wrote {} ({:.1} MiB, sha256 {})",
        output.display(),
        size as f64 / (1024.0 * 1024.0),
        manifest::hex(&digest)
    );
    if sign_options.is_none() {
        println!("This file is not signed and must not be published.");
    }
    Ok(())
}

fn validate_inputs(build_dir: &Path) -> Result<Inputs> {
    let metadata = std::fs::symlink_metadata(build_dir)
        .with_context(|| format!("failed to read build directory {}", build_dir.display()))?;
    if fsutil::is_reparse_point(&metadata) {
        bail!(
            "build directory must not be a reparse point: {}",
            build_dir.display()
        );
    }
    if !metadata.is_dir() {
        bail!("build path must be a directory: {}", build_dir.display());
    }
    let build_dir = std::fs::canonicalize(build_dir)
        .with_context(|| format!("failed to resolve {}", build_dir.display()))?;

    let inputs = Inputs {
        stub: build_dir.join("stub.exe"),
        client: build_dir.join("client.exe"),
        backend: build_dir.join("backend.exe"),
        config: build_dir.join("config.toml"),
        payload: build_dir.join("payload.zip"),
        build_dir,
    };
    for (path, description) in [
        (&inputs.stub, "stub.exe"),
        (&inputs.client, "client.exe"),
        (&inputs.backend, "backend.exe"),
        (&inputs.config, "config.toml"),
        (&inputs.payload, "payload.zip"),
    ] {
        fsutil::ensure_regular_file(path, description)?;
    }
    Ok(inputs)
}

fn prepare_output(request: &BuildRequest, inputs: &Inputs) -> Result<PathBuf> {
    let output = std::path::absolute(&request.output)
        .with_context(|| format!("failed to resolve output path {}", request.output.display()))?;
    if !output
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
    {
        bail!(
            "output file must use the .exe extension: {}",
            output.display()
        );
    }
    if output.is_dir() {
        bail!("output path is a directory: {}", output.display());
    }
    match std::fs::symlink_metadata(&output) {
        Ok(metadata) => {
            if fsutil::is_reparse_point(&metadata) {
                bail!("refusing to replace a reparse point: {}", output.display());
            }
            if !request.force {
                bail!(
                    "output file already exists; pass --force to replace it: {}",
                    output.display()
                );
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", output.display()))
        }
    }

    let parent = output
        .parent()
        .context("output path has no parent directory")?;
    if !parent.is_dir() {
        bail!("output directory does not exist: {}", parent.display());
    }
    let parent = std::fs::canonicalize(parent)
        .with_context(|| format!("failed to resolve {}", parent.display()))?;
    let file_name = output.file_name().context("output path has no file name")?;
    let output = parent.join(file_name);

    let build_dir = std::fs::canonicalize(&inputs.build_dir)?;
    if path::is_path_under(&output, &build_dir) {
        bail!(
            "output must be outside the build directory: {}",
            output.display()
        );
    }
    for input in [
        &inputs.stub,
        &inputs.client,
        &inputs.backend,
        &inputs.config,
        &inputs.payload,
    ] {
        let canonical = std::fs::canonicalize(input)?;
        if path::same_path(&output, &canonical) {
            bail!("output would overwrite an input file: {}", output.display());
        }
    }
    Ok(output)
}

fn prepare_signing(
    request: &BuildRequest,
    inputs: &Inputs,
    packaged: &ParsedConfig,
) -> Result<Option<SignOptions>> {
    if request.unsigned {
        if request.pfx.is_some() || request.thumbprint.is_some() {
            bail!("--unsigned cannot be combined with a signing certificate");
        }
        return Ok(None);
    }
    if request.pfx.is_some() && request.thumbprint.is_some() {
        bail!("pass either --pfx or --thumbprint, not both");
    }
    let certificate = if let Some(pfx) = &request.pfx {
        let pfx = std::fs::canonicalize(pfx)
            .with_context(|| format!("failed to resolve PFX file {}", pfx.display()))?;
        let metadata = fsutil::ensure_regular_file(&pfx, "PFX file")?;
        if metadata.len() == 0 {
            bail!("PFX file is empty: {}", pfx.display());
        }
        if path::is_path_under(&pfx, &inputs.build_dir) {
            bail!("PFX file must not be stored inside the build directory");
        }
        let install_location = path::validate_install_location(&packaged.install_location)?;
        if path::is_path_under(&pfx, Path::new(&install_location)) {
            bail!("PFX file must not be stored inside the configured install location");
        }
        let variable = request
            .pfx_password_env
            .as_deref()
            .context("--pfx requires --pfx-password-env")?;
        let password = std::env::var_os(variable)
            .with_context(|| format!("environment variable {variable} is not defined"))?;
        Certificate::Pfx {
            path: pfx,
            password,
        }
    } else if let Some(thumbprint) = &request.thumbprint {
        Certificate::Thumbprint(sign::normalize_thumbprint(thumbprint)?)
    } else {
        bail!("a signing certificate is required; pass --pfx or --thumbprint, or use --unsigned for a development build");
    };

    sign::validate_timestamp_url(&request.timestamp_url)?;
    let signtool = match &request.signtool {
        Some(path) => {
            let path = std::fs::canonicalize(path)
                .with_context(|| format!("failed to resolve signtool {}", path.display()))?;
            fsutil::ensure_regular_file(&path, "signtool.exe")?;
            path
        }
        None => sign::find_signtool()?,
    };
    let description = request
        .description
        .clone()
        .or_else(|| Some(packaged.name.clone()));

    Ok(Some(SignOptions {
        signtool,
        certificate,
        timestamp_url: request.timestamp_url.clone(),
        description,
    }))
}

fn validate_resource_references(config: &ParsedConfig, entries: &HashSet<String>) -> Result<()> {
    if let Some(icon) = &config.icon {
        if !entries.contains(icon) {
            bail!("config.toml references an icon missing from the package: {icon:?}");
        }
    }
    if let Some(background) = &config.background {
        if !path::is_special_background(background)
            && !path::is_hex_color(background)
            && !entries.contains(background)
        {
            bail!("config.toml references a background missing from the package: {background:?}");
        }
    }
    Ok(())
}

fn canonical_source(path: &Path) -> Result<PathBuf> {
    std::fs::canonicalize(path).with_context(|| format!("failed to resolve {}", path.display()))
}

fn verify_package(path: &Path, check_stub_hash: bool, extract: bool) -> Result<()> {
    let package = archive::Package::open(path)
        .with_context(|| format!("failed to reopen {}", path.display()))?;

    let extracted = if extract {
        let directory = tempfile::tempdir().context("failed to create a verification directory")?;
        package.extract_all(directory.path())?;
        Some(directory)
    } else {
        package.verify_entries()?;
        None
    };

    let manifest_bytes = package.read_entry_bytes(MANIFEST_NAME, MAX_MANIFEST_BYTES)?;
    let manifest = Manifest::parse(&manifest_bytes)?;
    manifest.verify(&package, check_stub_hash.then_some(path))?;

    let config_bytes = package.read_entry_bytes("config.toml", MAX_CONFIG_BYTES)?;
    let config = ParsedConfig::parse(&config_bytes)?;
    validate_resource_references(
        &config,
        &package
            .layout()
            .entries
            .iter()
            .map(|entry| entry.name.clone())
            .collect(),
    )?;

    if let Some(directory) = extracted {
        validate_extracted(&package, directory.path(), &config)?;
    }
    Ok(())
}

fn validate_extracted(
    package: &archive::Package,
    root: &Path,
    config: &ParsedConfig,
) -> Result<()> {
    pe::validate_executable(
        &root.join("client.exe"),
        MAX_EXECUTABLE_BYTES,
        "extracted client.exe",
    )?;
    pe::validate_executable(
        &root.join("backend.exe"),
        MAX_EXECUTABLE_BYTES,
        "extracted backend.exe",
    )?;

    let mut payload =
        File::open(root.join("payload.zip")).context("failed to open extracted payload.zip")?;
    let mut signature = [0u8; 4];
    payload
        .read_exact(&mut signature)
        .context("extracted payload.zip is truncated")?;
    if &signature[..2] != b"PK" {
        bail!("extracted payload.zip is not a ZIP archive");
    }

    let extracted_config =
        std::fs::read(root.join("config.toml")).context("failed to read extracted config.toml")?;
    let extracted = ParsedConfig::parse(&extracted_config)?;
    if &extracted != config {
        bail!("extracted config.toml does not match the packaged configuration");
    }
    for (field, value) in [
        ("icon", &extracted.icon),
        ("background", &extracted.background),
    ] {
        let Some(value) = value else {
            continue;
        };
        if field == "background"
            && (path::is_special_background(value) || path::is_hex_color(value))
        {
            continue;
        }
        if !root
            .join(value.replace('/', std::path::MAIN_SEPARATOR_STR))
            .is_file()
        {
            bail!("extracted config.toml references a missing {field}: {value:?}");
        }
    }

    let extracted_manifest = std::fs::read(root.join(MANIFEST_NAME))
        .context("failed to read extracted manifest.toml")?;
    let manifest = Manifest::parse(&extracted_manifest)?;
    manifest.verify(package, None)?;
    Ok(())
}

fn hash_file(path: &Path) -> Result<[u8; 32]> {
    let mut file =
        File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .with_context(|| format!("failed to read {}", path.display()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;
    use zip::CompressionMethod;

    const CONFIG: &str = r#"protocol = 1
name = "Test App"

[defaults]
installLocation = 'D:\Anyinstaller\TestApp'
createStartMenuFolder = true
createDesktopShortcut = false
"#;

    fn fake_pe() -> Vec<u8> {
        let mut data = vec![0u8; 256];
        data[0..2].copy_from_slice(b"MZ");
        data[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        data[0x80..0x84].copy_from_slice(b"PE\0\0");
        data
    }

    fn write_payload(path: &Path) {
        let file = File::create(path).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        writer
            .start_file("app.exe", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"MZpayload").unwrap();
        writer
            .start_file(
                "data/readme.txt",
                SimpleFileOptions::default().compression_method(CompressionMethod::Deflated),
            )
            .unwrap();
        writer.write_all(b"payload data").unwrap();
        writer.finish().unwrap();
    }

    fn write_png(path: &Path) {
        use image::codecs::png::PngEncoder;
        use image::{ExtendedColorType, ImageEncoder};
        let mut bytes = Vec::new();
        PngEncoder::new(&mut bytes)
            .write_image(&[30, 60, 90, 255], 1, 1, ExtendedColorType::Rgba8)
            .unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    struct Fixture {
        _root: tempfile::TempDir,
        build: PathBuf,
        out: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let build = root.path().join("build");
            let out = root.path().join("out");
            std::fs::create_dir_all(&build).unwrap();
            std::fs::create_dir_all(&out).unwrap();
            let stub = fake_pe();
            std::fs::write(build.join("stub.exe"), &stub).unwrap();
            std::fs::write(build.join("client.exe"), fake_pe()).unwrap();
            std::fs::write(build.join("backend.exe"), fake_pe()).unwrap();
            std::fs::write(build.join("config.toml"), CONFIG).unwrap();
            write_payload(&build.join("payload.zip"));
            std::fs::create_dir_all(build.join("assets")).unwrap();
            std::fs::write(build.join("assets/data.txt"), b"asset").unwrap();
            Self {
                _root: root,
                build,
                out,
            }
        }

        fn request(&self, force: bool) -> BuildRequest {
            BuildRequest {
                build_dir: self.build.clone(),
                output: self.out.join("foo.exe"),
                force,
                unsigned: true,
                pfx: None,
                pfx_password_env: None,
                thumbprint: None,
                timestamp_url: DEFAULT_TIMESTAMP_URL.into(),
                signtool: None,
                description: None,
            }
        }
    }

    fn entries(package: &archive::Package) -> Vec<&str> {
        package
            .layout()
            .entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect()
    }

    #[test]
    fn builds_and_verifies_unsigned_package() {
        let fixture = Fixture::new();
        let output = fixture.out.join("foo.exe");
        let stub = std::fs::read(fixture.build.join("stub.exe")).unwrap();

        run(fixture.request(false)).unwrap();

        let bytes = std::fs::read(&output).unwrap();
        assert_eq!(&bytes[..stub.len()], stub.as_slice());
        let package = archive::Package::open(&output).unwrap();
        package.verify_entries().unwrap();
        assert_eq!(
            entries(&package),
            vec![
                "client.exe",
                "backend.exe",
                "config.toml",
                "payload.zip",
                "assets/data.txt",
                "manifest.toml",
            ]
        );

        let manifest_bytes = package
            .read_entry_bytes(MANIFEST_NAME, MAX_MANIFEST_BYTES)
            .unwrap();
        let manifest = Manifest::parse(&manifest_bytes).unwrap();
        manifest.verify(&package, Some(&output)).unwrap();
        assert_eq!(manifest.stub.size, stub.len() as u64);
        assert_eq!(manifest.components.len(), 5);
        assert_eq!(
            manifest.components[4].kind,
            manifest::ComponentKind::Resource
        );
        assert!(manifest
            .components
            .iter()
            .any(|component| component.path == "payload.zip"
                && component.kind == manifest::ComponentKind::Archive));
        drop(package);

        let before = std::fs::read(&output).unwrap();
        assert!(run(fixture.request(false)).is_err());
        assert_eq!(std::fs::read(&output).unwrap(), before);
        run(fixture.request(true)).unwrap();
    }

    #[test]
    fn invalid_payload_leaves_no_output() {
        let fixture = Fixture::new();
        std::fs::write(fixture.build.join("payload.zip"), b"not a zip").unwrap();
        let output = fixture.out.join("foo.exe");
        assert!(run(fixture.request(false)).is_err());
        assert!(!output.exists());
        assert_eq!(std::fs::read_dir(&fixture.out).unwrap().count(), 0);
    }

    #[test]
    fn rejects_output_inside_build_directory() {
        let fixture = Fixture::new();
        let mut request = fixture.request(false);
        request.output = fixture.build.join("foo.exe");
        let error = run(request).unwrap_err();
        assert!(format!("{error:#}").contains("outside the build directory"));
        assert!(!fixture.build.join("foo.exe").exists());
    }

    #[test]
    fn requires_a_certificate_unless_unsigned() {
        let fixture = Fixture::new();
        let mut request = fixture.request(false);
        request.unsigned = false;
        let error = run(request).unwrap_err();
        assert!(format!("{error:#}").contains("signing certificate is required"));
        assert!(!fixture.out.join("foo.exe").exists());
    }

    #[test]
    fn rejects_invalid_icon_and_cleans_up() {
        let fixture = Fixture::new();
        std::fs::write(fixture.build.join("assets/icon.png"), b"<html>").unwrap();
        let config = CONFIG.replace(
            "name = \"Test App\"",
            "name = \"Test App\"\nicon = 'assets/icon.png'",
        );
        std::fs::write(fixture.build.join("config.toml"), config).unwrap();
        assert!(run(fixture.request(false)).is_err());
        assert!(!fixture.out.join("foo.exe").exists());
        assert_eq!(std::fs::read_dir(&fixture.out).unwrap().count(), 0);
    }

    #[test]
    fn rewrites_image_paths_and_packages_generated_assets() {
        let fixture = Fixture::new();
        write_png(&fixture.build.join("assets/icon.png"));
        write_png(&fixture.build.join("assets/background.png"));
        let config = CONFIG.replace(
            "name = \"Test App\"",
            "name = \"Test App\"\nicon = 'assets/icon.png'\nbackground = 'assets/background.png'",
        );
        std::fs::write(fixture.build.join("config.toml"), config).unwrap();

        let output = fixture.out.join("foo.exe");
        run(fixture.request(false)).unwrap();
        let package = archive::Package::open(&output).unwrap();
        let names = entries(&package);
        assert!(names.contains(&"assets/icon.ico"));
        assert!(names.contains(&"assets/background.png"));
        assert!(names.contains(&"assets/icon.png"));
        assert_eq!(
            names
                .iter()
                .filter(|name| **name == "assets/background.png")
                .count(),
            1
        );

        let config = String::from_utf8(
            package
                .read_entry_bytes("config.toml", MAX_CONFIG_BYTES)
                .unwrap(),
        )
        .unwrap();
        assert!(config.contains(r#"icon = "assets/icon.ico""#));
        assert!(config.contains(r#"background = "assets/background.png""#));

        let manifest = Manifest::parse(
            &package
                .read_entry_bytes(MANIFEST_NAME, MAX_MANIFEST_BYTES)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(manifest.components.len(), 8);
        assert!(manifest
            .components
            .iter()
            .all(|component| component.path != "assets/background.png"
                || component.kind == manifest::ComponentKind::Resource));
    }

    #[test]
    fn rejects_pfx_inside_install_location() {
        let fixture = Fixture::new();
        let install = fixture._root.path().join("install");
        std::fs::create_dir_all(&install).unwrap();
        let pfx = install.join("release.pfx");
        std::fs::write(&pfx, b"not really a pfx").unwrap();
        let config = format!(
            r#"protocol = 1
name = "Test App"

[defaults]
installLocation = '{}'
createStartMenuFolder = true
createDesktopShortcut = false
"#,
            install.display()
        );
        std::fs::write(fixture.build.join("config.toml"), config).unwrap();

        let mut request = fixture.request(false);
        request.unsigned = false;
        request.pfx = Some(pfx);
        request.pfx_password_env = Some("AIP_TEST_UNUSED_PASSWORD".into());
        let error = run(request).unwrap_err();
        assert!(format!("{error:#}").contains("install location"));
        assert!(!fixture.out.join("foo.exe").exists());
    }

    #[test]
    fn rejects_generated_asset_collision() {
        let fixture = Fixture::new();
        write_png(&fixture.build.join("assets/icon.png"));
        std::fs::write(fixture.build.join("assets/icon.ico"), b"other").unwrap();
        let config = CONFIG.replace(
            "name = \"Test App\"",
            "name = \"Test App\"\nicon = 'assets/icon.png'",
        );
        std::fs::write(fixture.build.join("config.toml"), config).unwrap();
        assert!(run(fixture.request(false)).is_err());
        assert!(!fixture.out.join("foo.exe").exists());
    }
}
