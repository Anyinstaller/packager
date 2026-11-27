#![cfg_attr(not(windows), allow(dead_code))]

#[cfg(not(windows))]
compile_error!("anyinstaller-packager only builds Windows installers and only runs on Windows");

mod archive;
mod assets;
mod build;
mod config;
mod fsutil;
mod imageasset;
mod manifest;
mod path;
mod payload;
mod pe;
mod sign;
mod winutil;

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

use crate::build::{BuildRequest, DEFAULT_TIMESTAMP_URL};

#[derive(Parser)]
#[command(
    name = "packager",
    version,
    about = "Builds signed AIP v1 single-file installers",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Build foo.exe from a build directory
    Build(BuildArgs),
}

#[derive(Args)]
struct BuildArgs {
    /// Directory containing stub.exe, client.exe, backend.exe, config.toml,
    /// payload.zip and an optional assets directory
    #[arg(long, value_name = "DIR", default_value = "build")]
    build_dir: PathBuf,

    /// Output installer path
    #[arg(long, short = 'o', value_name = "FILE", default_value = "foo.exe")]
    output: PathBuf,

    /// Replace an existing output file
    #[arg(long)]
    force: bool,

    /// Local development: produce an unsigned package (public release is not recommended).
    #[arg(long)]
    unsigned: bool,

    /// Code-signing certificate file (.pfx)
    #[arg(
        long,
        value_name = "PFX",
        conflicts_with_all = ["unsigned", "thumbprint"],
        requires = "pfx_password_env"
    )]
    pfx: Option<PathBuf>,

    /// Environment variable holding the PFX password
    #[arg(long, value_name = "VAR", requires = "pfx")]
    pfx_password_env: Option<String>,

    /// Certificate SHA-1 thumbprint in the current user's certificate store
    #[arg(long, value_name = "HEX", conflicts_with_all = ["unsigned", "pfx"])]
    thumbprint: Option<String>,

    /// RFC 3161 timestamp service URL
    #[arg(long, value_name = "URL", default_value = DEFAULT_TIMESTAMP_URL)]
    timestamp_url: String,

    /// Path to signtool.exe (otherwise found in PATH or the Windows SDK)
    #[arg(long, value_name = "PATH")]
    signtool: Option<PathBuf>,

    /// Signing description shown in the signature
    #[arg(long, value_name = "TEXT")]
    description: Option<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Build(args) => {
            let request = BuildRequest {
                build_dir: args.build_dir,
                output: args.output,
                force: args.force,
                unsigned: args.unsigned,
                pfx: args.pfx,
                pfx_password_env: args.pfx_password_env,
                thumbprint: args.thumbprint,
                timestamp_url: args.timestamp_url,
                signtool: args.signtool,
                description: args.description,
            };
            match build::run(request) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("error: {error:#}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}
