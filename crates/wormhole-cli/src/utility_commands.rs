//! Remotes, keys, diagnostics, interfaces, and shell completions.

use std::{
    fs,
    io::{IsTerminal as _, Write as _},
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::PathBuf,
};

use camino::Utf8PathBuf;
use clap::CommandFactory as _;
use serde::Serialize;
use wormhole_core::{
    ClientConfig,
    config::{ConfigLayer, global_config_path},
    enroll_remote,
    keys_store::IdentityStore,
    wormhole_driver::{inspect_remote, test_remote},
};

use crate::{
    api_types::RemoteAddRequest,
    cli::{Cli, CompletionShell, KeyCommand, RemoteCommand},
    client::DaemonClient,
    error::CliError,
    output,
    remote_onboarding::{apply_add, apply_remove, prepare, views},
};

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

#[derive(Debug, Serialize)]
pub struct RemoteDomainsView {
    pub remote: String,
    pub domains: Vec<String>,
    pub latency_ms: Option<u128>,
    pub error: Option<String>,
}

pub async fn remote(cli: &Cli, command: &RemoteCommand) -> Result<(), CliError> {
    match command {
        RemoteCommand::Add { name, addr, identity, invite } => {
            let inputs = remote_add_inputs(
                name.clone(),
                addr.clone(),
                identity.clone(),
                invite.clone(),
                !cli.json && std::io::stdin().is_terminal() && std::io::stderr().is_terminal(),
            )?;
            let prepared = prepare(RemoteAddRequest {
                name: inputs.name,
                addr: inputs.addr,
                server_name: None,
                identity: inputs.identity,
                invite: inputs.invite,
            })
            .map_err(CliError::Invalid)?;
            if let Some(invite) = prepared.invite.as_deref() {
                let identities = IdentityStore::from_environment()?;
                let identity = identities.resolve_identity(&prepared.remote)?;
                enroll_remote(&prepared.remote, &identity, invite).await?;
            }
            let mut config = load(cli.config.as_ref())?;
            apply_add(&mut config, prepared.name, prepared.remote);
            save(cli.config.as_ref(), &config)?;
            output::emit(super::format(cli.json), &views(&config));
        }
        RemoteCommand::Ls => {
            output::emit(super::format(cli.json), &views(&load(cli.config.as_ref())?));
        }
        RemoteCommand::Rm { name } => {
            let mut config = load(cli.config.as_ref())?;
            apply_remove(&mut config, name).map_err(CliError::Invalid)?;
            save(cli.config.as_ref(), &config)?;
            output::emit(super::format(cli.json), &views(&config));
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

pub async fn domains(cli: &Cli) -> Result<(), CliError> {
    let config = load(cli.config.as_ref())?;
    let identities = IdentityStore::from_environment()?;
    let mut views = Vec::with_capacity(config.remotes.len());
    for (name, remote) in &config.remotes {
        let identity = identities.resolve_identity(remote)?;
        let view = match inspect_remote(remote, identity).await {
            Ok(inspected) => RemoteDomainsView {
                remote: name.clone(),
                domains: inspected.domains,
                latency_ms: Some(inspected.latency.as_millis()),
                error: None,
            },
            Err(error) => RemoteDomainsView {
                remote: name.clone(),
                domains: Vec::new(),
                latency_ms: None,
                error: Some(error.to_string()),
            },
        };
        views.push(view);
    }
    output::emit(super::format(cli.json), &views);
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
    let mut checks = client.doctor().await?;
    let config = load(cli.config.as_ref())?;
    checks.extend(crate::local_commands::doctor_checks(&config, super::config_path(cli)).await);
    output::emit(super::format(cli.json), &checks);
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

pub fn load(path: Option<&PathBuf>) -> Result<ClientConfig, CliError> {
    let path = config_path(path)?;
    Ok(ClientConfig::load_from_paths(Some(&path), None, ConfigLayer::default())?)
}

pub fn save(path: Option<&PathBuf>, config: &ClientConfig) -> Result<(), CliError> {
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

#[derive(Debug)]
struct RemoteAddInputs {
    name: String,
    addr: String,
    identity: Option<String>,
    invite: Option<String>,
}

fn remote_add_inputs(
    name: Option<String>,
    addr: Option<String>,
    identity: Option<PathBuf>,
    invite: Option<String>,
    interactive: bool,
) -> Result<RemoteAddInputs, CliError> {
    let wizard = name.is_none() || addr.is_none();
    if wizard && !interactive {
        return Err(CliError::Invalid(
            "remote add requires NAME and ADDR in JSON or non-interactive mode".to_owned(),
        ));
    }
    let name = name.map_or_else(|| prompt_line("Remote name"), Ok)?;
    let addr = addr.map_or_else(|| prompt_line("Relay address (HOST:PORT)"), Ok)?;
    let identity = match identity {
        Some(path) => Some(
            Utf8PathBuf::from_path_buf(path)
                .map(Utf8PathBuf::into_string)
                .map_err(|_| CliError::Invalid("identity path is not UTF-8".to_owned()))?,
        ),
        None if wizard => Some(prompt_line("Identity path (optional)")?),
        None => None,
    }
    .filter(|value| !value.is_empty());
    let invite = if invite.is_some() || !wizard {
        invite
    } else {
        output::prompt("Enrollment invite (optional)")?;
        Some(rpassword::read_password()?).filter(|value| !value.trim().is_empty())
    };
    if name.trim().is_empty() || addr.trim().is_empty() {
        return Err(CliError::Invalid("remote name and address cannot be empty".to_owned()));
    }
    Ok(RemoteAddInputs { name, addr, identity, invite })
}

fn prompt_line(message: &str) -> Result<String, CliError> {
    output::prompt(message)?;
    let mut value = String::new();
    std::io::stdin().read_line(&mut value)?;
    Ok(value.trim().to_owned())
}

#[cfg(test)]
#[path = "utility_commands_tests.rs"]
mod tests;
