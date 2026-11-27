# packager

Builds signed AIP v1 single-file installers for Anyinstaller. The packager
copies `stub.exe`, appends the `AIPK` archive, `AIPD` directory and `AIPF`
footer used by the stub, verifies the result by reopening and extracting it,
signs it with Authenticode and an RFC 3161 timestamp, then verifies the signed
file again.

The stub package format is unchanged. The packager adds one archive entry,
`manifest.toml`, which records every other embedded component with its logical
name, package-relative path, type, size and SHA-256. `manifest.toml` is itself
covered by the `AIPD` hash directory and by the Authenticode signature.

## Requirements

- Windows 10 or Windows 11
- Rust 1.95 or newer with the MSVC toolchain
- `signtool.exe` from the Windows SDK for signed builds
- A trusted public code-signing certificate (`.pfx` or certificate store
  thumbprint) for release builds

`--unsigned` is intended for local development. Public release builds are
not recommended without Authenticode signing; the release stub still verifies
Authenticode before reading the package.

## Build

```powershell
cargo build --release
```

The executable is `target\release\packager.exe`.

## Input layout

```text
build\
├─ stub.exe           # unsigned PE body
├─ client.exe
├─ backend.exe
├─ config.toml
├─ payload.zip
└─ assets\            # optional, embedded recursively as assets\...
```

`config.toml` is the source configuration. Its `icon` and `background` values
may be absolute local paths or paths relative to the build directory. When
`icon` is omitted, the packager embeds the built-in Anyinstaller icon and
rewrites the packaged config to `assets/icon.ico`. URLs,
UNC/device paths, reparse points and non-files are rejected. Source images are
decoded and re-encoded before being written to `assets\`; the packaged
configuration is rewritten to the package-relative path.

`stub.exe` must be an unsigned PE image. The packager rejects a stub with an
existing Authenticode certificate table: signing the final `foo.exe` replaces
that table and could truncate the appended archive. The final package is signed
after the archive is written.

The optional `assets\` directory is embedded recursively. Asset paths are
validated and converted to forward-slash package paths. If a source image
produces the same package path as an asset:

- the asset is skipped when it is the same source file;
- the build fails when it is a different file.

## Usage

Signed build with a PFX file:

```powershell
$env:AIP_PFX_PASSWORD = "correct horse battery staple"
packager build `
  --build-dir build `
  --output dist\foo.exe `
  --pfx C:\keys\release.pfx `
  --pfx-password-env AIP_PFX_PASSWORD
```

Signed build with a certificate in the current user's certificate store:

```powershell
packager build `
  --build-dir build `
  --output dist\foo.exe `
  --thumbprint 0123456789ABCDEF0123456789ABCDEF01234567
```

Development build without a signature:

```powershell
packager build --build-dir build --output dist\foo.exe --unsigned
```

Options:

| Option | Description |
| --- | --- |
| `--build-dir <DIR>` | Input directory, default `build` |
| `--output <FILE>` / `-o` | Output installer, default `foo.exe` |
| `--force` | Replace an existing output file |
| `--unsigned` | Local development; public release is not recommended |
| `--pfx <PFX>` | Code-signing certificate file |
| `--pfx-password-env <VAR>` | Environment variable holding the PFX password |
| `--thumbprint <HEX>` | 40-character SHA-1 thumbprint in the current user's store |
| `--timestamp-url <URL>` | RFC 3161 timestamp service, default `http://timestamp.digicert.com` |
| `--signtool <PATH>` | Explicit `signtool.exe`; otherwise found in `SIGNTOOL_PATH`, `PATH` or the Windows SDK |
| `--description <TEXT>` | Signature description, default is the configured application name |

`--pfx` requires `--pfx-password-env`. `--unsigned` conflicts with `--pfx`
and `--thumbprint`; it is intended for local development and is not recommended
for public release.

The output is first written to a temporary file in the output directory. It is
moved into place only after every validation and signature check passes. A
failed build leaves no output and removes its temporary file. Without
`--force`, an existing output file is never replaced.

## Validation

Before writing the archive, the packager validates:

1. `config.toml`: UTF-8 without BOM, valid TOML, protocol 1, required fields,
   name length/characters, install-location shape and protected roots.
2. `payload.zip`: valid ZIP, at least one file, at most 100,000 entries, only
   store/deflate, no encryption, symlinks or reparse points, safe relative
   paths, no file/directory conflicts, per-file and total size limits,
   compression-ratio limit, and CRC/actual-size checks for every entry.
3. Source images: local regular files, supported format, size and pixel limits,
   decoded and re-encoded without metadata.
4. `stub.exe`, `client.exe` and `backend.exe`: regular PE files within size
   limits; `stub.exe` must not have an existing certificate table.
5. Asset tree: regular files only, no reparse points, safe package paths.
6. Package totals: entry count, single-entry size, total content size and
   directory size.

After writing, it reopens the package and:

- verifies every `AIPD` SHA-256;
- parses `manifest.toml` and checks every component type, path, size and hash;
- verifies the stub hash before signing;
- parses the packaged `config.toml` and checks its resource references;
- extracts the whole package to a temporary directory and re-hashes the
  extracted files;
- checks the extracted executables, payload ZIP header and configuration.

After signing, it verifies the Authenticode chain with `WinVerifyTrust`
(whole-chain revocation, no UI), runs `signtool verify /pa /all`, and reopens
the package to check the archive directory and manifest again. Stub hashing is
skipped after signing because Authenticode modifies the PE header; the
manifest still records the original stub hash and the stub size must equal the
archive offset.

## Package resources

- PNG, JPEG, WebP and ICO sources are decoded with the `image` crate.
- AVIF sources are decoded with `oxideav-avif`.
- Icons are re-encoded as a multi-size ICO (`assets/icon.ico`) with frames from
  16 to 256 pixels.
- PNG backgrounds stay PNG; JPEG backgrounds are re-encoded as JPEG; WebP and
  AVIF backgrounds are re-encoded as lossless WebP.
- Metadata and auxiliary chunks are discarded by re-encoding.
- `acrylic`, `acrylicBlur`, `mica`, `windowsManaged`, `transparent` and
  `#RRGGBB` background values are passed through unchanged.

## Limits

| Item | Limit |
| --- | --- |
| `config.toml` | 64 KiB |
| `client.exe`, `backend.exe` | 512 MiB each |
| `payload.zip` (compressed file) | 8 GiB |
| ZIP entries | 100,000 |
| ZIP total uncompressed | 8 GiB |
| ZIP single file uncompressed | 4 GiB |
| ZIP compression ratio | 100:1 |
| Archive entries | 100,000 |
| Archive single entry | 8 GiB |
| Archive total content | 16 GiB |
| Archive directory | 16 MiB |
| Image file | 64 MiB |
| Image pixels | 256,000,000 |
| Image side | 16,384 |
| Package path | 32,767 UTF-16 units |
| Archive entry name | 1,024 UTF-8 bytes |

## Development

```powershell
cargo test
cargo clippy --all-targets -- -D warnings
```

Unit tests cover archive writing/parsing, hash verification, extraction,
manifest rendering/parsing, ZIP validation (including traversal, bombs,
symlinks and reparse attributes), image re-encoding, path validation, config
rewriting and CLI behavior. The build tests exercise the full unsigned pipeline
with a fake PE stub and verify the resulting package by reopening it.

The packager was also exercised end-to-end against a development build of the
stub: a package produced with `--unsigned`, a dev stub and the dev child helper
completed the pipe relay, installation handshake and session cleanup. Real
Authenticode signing requires a code-signing certificate and `signtool.exe`;
both are environment-specific and are not part of the unit test suite.

## Security notes

- Public release of a package built with `--unsigned` is not recommended.
- Keep the signing key outside the build directory and outside any directory
  the installer can write. The packager rejects a PFX located inside the build
  directory or the configured install location.
- Use a trusted public code-signing certificate and a trusted RFC 3161
  timestamp service.
- Do not disable revocation checking or add "ignore certificate errors"
  options to release builds.
- `foo.exe` must be the only file in its release directory; everything the
  runtime needs is embedded.
