//! Command-line shell for relay administration and startup.

use std::{fs, sync::Arc};

use anyhow::{Context, Result, bail};
use camino::{Utf8Path, Utf8PathBuf};
use clap::{Args, Parser, Subcommand};
use serde::Serialize;

use crate::output;

#[derive(Debug, Parser)]
#[command(name = "wormholed", version, about = "Wormhole relay server")]
pub struct Cli {
    #[arg(long, global = true, default_value = "/etc/wormhole/wormholed.toml")]
    config: Utf8PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the relay or validate startup configuration.
    Serve(ServeArgs),
    /// Write a development-safe default configuration.
    Init,
    /// Manage authorized client keys.
    Key(KeyArgs),
    /// Show relay health and counters.
    Status(JsonArgs),
    /// List public binds without reservation secrets.
    Binds(JsonArgs),
}

#[derive(Debug, Args)]
struct ServeArgs {
    /// Validate configuration and exit without binding sockets.
    #[arg(long)]
    check: bool,
}

#[derive(Debug, Args)]
struct JsonArgs {
    /// Emit stable machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct KeyArgs {
    #[command(subcommand)]
    command: KeyCommand,
}

#[derive(Debug, Subcommand)]
enum KeyCommand {
    /// Add an authorized public key or public-key file.
    Authorize {
        /// Padded public key or path to a public-key file.
        pubkey_or_file: String,
        /// Human-readable key name.
        #[arg(long)]
        name: String,
    },
    /// List imported and managed keys.
    Ls(JsonArgs),
    /// Revoke a key by fingerprint.
    Revoke {
        /// Stable WH256 fingerprint.
        fingerprint: String,
    },
}

#[derive(Debug, Serialize)]
struct StatusStub {
    status: &'static str,
    sessions: u64,
    binds: u64,
}

#[derive(Debug, Serialize)]
struct EmptyList<T> {
    items: Vec<T>,
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve(args) => serve(&cli.config, args),
        Command::Init => initialize(&cli.config),
        Command::Key(args) => key(&cli.config, args),
        Command::Status(args) => status(args),
        Command::Binds(args) => empty_list("No binds", args),
    }
}

fn serve(path: &Utf8PathBuf, args: ServeArgs) -> Result<()> {
    let config = wormholed::config::WormholedConfig::load(path)
        .with_context(|| format!("loading relay config {path}"))?;
    config.validate().context("validating relay config")?;
    if args.check {
        output::human("configuration valid");
        return Ok(());
    }
    bail!("relay serving is implemented in Stage 03 S4")
}

fn initialize(path: &Utf8PathBuf) -> Result<()> {
    wormholed::config::WormholedConfig::initialize(path)
        .with_context(|| format!("initializing relay config {path}"))?;
    output::human(&format!("created {path}"));
    Ok(())
}

fn key(path: &Utf8Path, args: KeyArgs) -> Result<()> {
    let config = wormholed::config::WormholedConfig::load(path)
        .with_context(|| format!("loading relay config {path}"))?;
    config.validate().context("validating relay config")?;
    let database = Arc::new(wormholed::db::RelayDb::open(&config.server.data_dir)?);
    let store = wormholed::authz::AuthStore::new(
        database,
        wormholed::authz::KeyLimits::from(&config.limits),
    );
    store.import_directory(&config.auth.authorized_keys)?;
    match args.command {
        KeyCommand::Authorize { pubkey_or_file, name } => {
            let public_key = read_public_input(&pubkey_or_file)?;
            let fingerprint = store.authorize(&public_key, &name)?;
            output::human(&format!("authorized {fingerprint}"));
            Ok(())
        }
        KeyCommand::Ls(args) => {
            let keys = store.list()?;
            if args.json {
                output::json(&keys)
            } else {
                let rendered = keys
                    .iter()
                    .map(|(fingerprint, key)| {
                        let status = if key.revoked { "revoked" } else { "allowed" };
                        format!("{fingerprint}\t{}\t{status}", key.name)
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                output::human(if rendered.is_empty() { "No authorized keys" } else { &rendered });
                Ok(())
            }
        }
        KeyCommand::Revoke { fingerprint } => {
            store.revoke(&fingerprint)?;
            output::human(&format!("revoked {fingerprint}"));
            Ok(())
        }
    }
}

fn read_public_input(input: &str) -> Result<String> {
    let path = Utf8Path::new(input);
    if !path.is_file() {
        return Ok(input.to_owned());
    }
    let contents =
        fs::read_to_string(path).with_context(|| format!("reading public key {path}"))?;
    contents
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("public key file contains no key: {path}"))
}

fn status(args: JsonArgs) -> Result<()> {
    let status = StatusStub { status: "offline", sessions: 0, binds: 0 };
    if args.json {
        output::json(&status)
    } else {
        output::human("Relay offline — 0 sessions, 0 binds");
        Ok(())
    }
}

fn empty_list(message: &str, args: JsonArgs) -> Result<()> {
    if args.json {
        output::json(&EmptyList::<String> { items: Vec::new() })
    } else {
        output::human(message);
        Ok(())
    }
}
