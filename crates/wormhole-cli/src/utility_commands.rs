//! Remotes, keys, diagnostics, interfaces, and shell completions.

use std::{
    fs,
    io::Write as _,
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::PathBuf,
};

use camino::Utf8PathBuf;
use clap::CommandFactory as _;
use serde::Serialize;
use wormhole_core::{
    ClientConfig, Remote,
    config::{ConfigLayer, global_config_path},
    keys_store::IdentityStore,
    wormhole_driver::test_remote,
};

use crate::{
    cli::{Cli, CompletionShell, KeyCommand, RemoteCommand},
    client::DaemonClient,
    error::CliError,
    output,
};

#[derive(Debug, Serialize)]
pub struct RemoteView {
    pub name: String,
    pub addr: String,
    pub server_name: String,
    pub identity: Option<Utf8PathBuf>,
}

#[derive(Debug, Serialize)]
pub struct KeyView {
    pub fingerprint: String,
    pub public_key: String,
}

#[derive(Debug, Serialize)]
pub struct RotationView {
    pub old_fingerprint: String,
    pub new_fingerprint: String,
    pub reminder: &'static str,
}

#[derive(Debug, Serialize)]
pub struct RemoteTestView {
    pub name: String,
    pub latency_ms: u128,
}

pub async fn remote(cli: &Cli, command: &RemoteCommand) -> Result<(), CliError> {
    match command {
        RemoteCommand::Add { name, addr, identity } => {
            let server_name = authority_host(addr)?;
            let identity = identity
                .as_ref()
                .map(|path| Utf8PathBuf::from_path_buf(path.clone()))
                .transpose()
                .map_err(|_| CliError::Invalid("identity path is not UTF-8".to_owned()))?;
            let mut config = load(cli.config.as_ref())?;
            config.remotes.insert(name.clone(), Remote::new(addr.clone(), server_name, identity));
            save(cli.config.as_ref(), &config)?;
            output::emit(super::format(cli.json), &remote_views(&config));
        }
        RemoteCommand::Ls => {
            output::emit(super::format(cli.json), &remote_views(&load(cli.config.as_ref())?));
        }
        RemoteCommand::Rm { name } => {
            let mut config = load(cli.config.as_ref())?;
            if config.remotes.remove(name).is_none() {
                return Err(CliError::Invalid(format!("unknown remote: {name}")));
            }
            if config.default_remote.as_deref() == Some(name) {
                config.default_remote = None;
            }
            save(cli.config.as_ref(), &config)?;
            output::emit(super::format(cli.json), &remote_views(&config));
        }
        RemoteCommand::Test { name } => {
            let config = load(cli.config.as_ref())?;
            let remote = config
                .remotes
                .get(name)
                .ok_or_else(|| CliError::Invalid(format!("unknown remote: {name}")))?;
            let identities = IdentityStore::from_environment()?;
            let identity = identities.resolve_identity(remote)?;
            let latency = test_remote(remote, identity).await.map_err(|error| {
                if error.to_string().to_ascii_lowercase().contains("denied") {
                    CliError::Denied(error.to_string())
                } else {
                    CliError::Driver(error)
                }
            })?;
            let view = RemoteTestView { name: name.clone(), latency_ms: latency.as_millis() };
            output::emit(super::format(cli.json), &view);
        }
    }
    Ok(())
}

pub fn key(cli: &Cli, command: &KeyCommand) -> Result<(), CliError> {
    let identities = IdentityStore::from_environment()?;
    match command {
        KeyCommand::Show => {
            let identity = identities.default_identity()?;
            output::emit(
                super::format(cli.json),
                &KeyView {
                    fingerprint: identity.fingerprint(),
                    public_key: identity.public_base64(),
                },
            );
        }
        KeyCommand::Rotate => {
            let (old_fingerprint, new_fingerprint) = identities.rotate_default()?;
            output::emit(
                super::format(cli.json),
                &RotationView {
                    old_fingerprint,
                    new_fingerprint,
                    reminder: "re-authorize the new key on every Wormhole server",
                },
            );
        }
    }
    Ok(())
}

pub async fn interfaces(cli: &Cli) -> Result<(), CliError> {
    let client = DaemonClient::ensure(cli.config.as_ref()).await?;
    output::emit(super::format(cli.json), &client.interfaces().await?);
    Ok(())
}

pub async fn doctor(cli: &Cli) -> Result<(), CliError> {
    let client = DaemonClient::ensure(cli.config.as_ref()).await?;
    output::emit(super::format(cli.json), &client.doctor().await?);
    Ok(())
}

pub fn completions(shell: CompletionShell) -> Result<(), CliError> {
    let shell = match shell {
        CompletionShell::Bash => clap_complete::Shell::Bash,
        CompletionShell::Fish => clap_complete::Shell::Fish,
        CompletionShell::Zsh => clap_complete::Shell::Zsh,
    };
    let mut command = Cli::command();
    let mut buffer = Vec::new();
    clap_complete::generate(shell, &mut command, "wormhole", &mut buffer);
    output::emit_raw(&buffer)?;
    Ok(())
}

fn load(path: Option<&PathBuf>) -> Result<ClientConfig, CliError> {
    let path = config_path(path)?;
    Ok(ClientConfig::load_from_paths(Some(&path), None, ConfigLayer::default())?)
}

fn save(path: Option<&PathBuf>, config: &ClientConfig) -> Result<(), CliError> {
    config.validate()?;
    let path = config_path(path)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("toml.tmp");
    let encoded =
        toml::to_string_pretty(config).map_err(|error| CliError::Invalid(error.to_string()))?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&temporary)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(encoded.as_bytes())?;
    file.sync_all()?;
    fs::rename(&temporary, &path)?;
    if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn config_path(path: Option<&PathBuf>) -> Result<Utf8PathBuf, CliError> {
    path.map_or_else(
        || global_config_path().map_err(Into::into),
        |path| {
            Utf8PathBuf::from_path_buf(path.clone())
                .map_err(|_| CliError::Invalid("config path is not UTF-8".to_owned()))
        },
    )
}

fn authority_host(addr: &str) -> Result<String, CliError> {
    let (host, port) = addr
        .rsplit_once(':')
        .ok_or_else(|| CliError::Invalid("remote address must be HOST:PORT".to_owned()))?;
    port.parse::<u16>().map_err(|error| CliError::Invalid(error.to_string()))?;
    Ok(host.trim_matches(['[', ']']).to_owned())
}

fn remote_views(config: &ClientConfig) -> Vec<RemoteView> {
    config
        .remotes
        .iter()
        .map(|(name, remote)| RemoteView {
            name: name.clone(),
            addr: remote.addr.clone(),
            server_name: remote.server_name.clone(),
            identity: remote.identity.clone(),
        })
        .collect()
}
