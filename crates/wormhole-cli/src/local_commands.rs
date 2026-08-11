//! Explicit local trust, hosts, and privileged-port commands.

use std::io::{BufRead as _, IsTerminal as _, Write as _};

use camino::{Utf8Path, Utf8PathBuf};
use serde::Serialize;
use tokio::net::{TcpListener, TcpStream};
use wormhole_core::{
    config::global_config_path,
    local_ca::LocalCertificateAuthority,
    local_system::{
        CommandRunner, CommandSpec, LinuxTrust, LocalPlatform, SystemCommandRunner,
        elevation_activate_commands, elevation_enabled, elevation_install_commands,
        forwarder_definition, hosts_block_state, hosts_install_command, prepare_hosts_file,
        remove_elevation_marker, resolve_executable_source, root_forwarder_path, trust_commands,
        trust_state, unelevation_commands, untrust_commands, verify_forwarder_destination,
        write_elevation_marker,
    },
};

use crate::{
    cli::{Cli, LocalCommand, LocalHostsCommand},
    error::CliError,
    output::{self, HumanRender},
    utility_commands,
};

#[derive(Debug, Serialize)]
pub struct LocalActionResult {
    action: String,
    changed: bool,
    pub commands: Vec<String>,
}

impl HumanRender for LocalActionResult {
    fn render(&self) -> String {
        format!("{}: {}", self.action, if self.changed { "updated" } else { "unchanged" })
    }
}

pub async fn execute(cli: &Cli, command: &LocalCommand) -> Result<(), CliError> {
    match command {
        LocalCommand::Trust { yes } => trust(cli, true, *yes),
        LocalCommand::Untrust { yes } => trust(cli, false, *yes),
        LocalCommand::Hosts { command } => hosts(cli, command),
        LocalCommand::Elevate { yes } => elevate(cli, *yes),
        LocalCommand::Unelevate { yes } => unelevate(cli, *yes),
        LocalCommand::PrivilegedForward { clear_target, tls_target, user_id, group_id } => {
            privileged_forward(*clear_target, *tls_target, *user_id, *group_id).await
        }
    }
}

pub async fn doctor_checks(
    config: &wormhole_core::ClientConfig,
    config_path: Option<&Utf8Path>,
) -> Vec<wormhole_core::model::DoctorCheck> {
    let directory = match config_directory(config_path) {
        Ok(directory) => directory,
        Err(error) => {
            return vec![doctor_check("local:ca-trust", false, error.to_string())];
        }
    };
    let (trusted, trust_detail) = trust_state(
        LocalPlatform::current(),
        linux_trust(),
        directory.join("local-ca.pem").is_file(),
        std::path::Path::new(linux_anchor()).is_file(),
        &SystemCommandRunner,
    );
    let hosts = hosts_check(config);
    let portless = elevation_enabled(&directory);
    let clear_port = if portless { 80 } else { config.defaults.local_http_port };
    let tls_port = if portless { 443 } else { config.defaults.local_https_port };
    vec![
        doctor_check("local:ca-trust", trusted, trust_detail),
        hosts,
        listener_check("local:http-listener", clear_port).await,
        listener_check("local:https-listener", tls_port).await,
    ]
}

fn trust(cli: &Cli, install: bool, yes: bool) -> Result<(), CliError> {
    let directory = config_directory(super::config_path(cli))?;
    let ca_path = if install {
        LocalCertificateAuthority::load_or_create(&directory)
            .map_err(|error| CliError::Invalid(error.to_string()))?
            .certificate_path()
            .to_owned()
    } else {
        directory.join("local-ca.pem")
    };
    let commands = if install {
        trust_commands(LocalPlatform::current(), &ca_path, linux_trust())
    } else {
        untrust_commands(LocalPlatform::current(), &ca_path, linux_trust())
    };
    let action = if install { "local CA trust" } else { "local CA untrust" };
    let result = apply_commands(action, commands, yes, &SystemCommandRunner)?;
    if install {
        verify_trusted()?;
    }
    output::emit(super::format(cli.json), &result);
    Ok(())
}

/// Confirms the authority is genuinely trusted after installing it.
///
/// `security add-trusted-cert` exits zero even when it could not record the trust setting, so its
/// exit status alone does not mean local HTTPS will be accepted.
fn verify_trusted() -> Result<(), CliError> {
    let (trusted, detail) = trust_state(
        LocalPlatform::current(),
        linux_trust(),
        true,
        std::path::Path::new(linux_anchor()).is_file(),
        &SystemCommandRunner,
    );
    if trusted {
        return Ok(());
    }
    Err(CliError::Invalid(format!(
        "the certificate was installed but is not trusted ({detail}); local HTTPS will still be rejected"
    )))
}

fn hosts(cli: &Cli, command: &LocalHostsCommand) -> Result<(), CliError> {
    let config = utility_commands::load(cli.config.as_ref())?;
    let (hostnames, yes, action) = match command {
        LocalHostsCommand::Sync { hostnames, yes } => {
            validate_hosts(hostnames, &config.defaults.local_tld)?;
            (hostnames.clone(), *yes, "local hosts sync")
        }
        LocalHostsCommand::Clear { yes } => (Vec::new(), *yes, "local hosts clear"),
    };
    let hosts_path = Utf8Path::new("/etc/hosts");
    let existing = std::fs::read_to_string(hosts_path)?;
    let rendered = prepare_hosts_file(hosts_path, &hostnames)?;
    if rendered == existing {
        output::emit(
            super::format(cli.json),
            &LocalActionResult { action: action.to_owned(), changed: false, commands: Vec::new() },
        );
        return Ok(());
    }
    let directory = config_directory(super::config_path(cli))?;
    let temporary = temporary_file(&directory, &rendered)?;
    let path = utf8_path(temporary.path())?;
    let result = apply_commands(
        action,
        vec![hosts_install_command(&path, hosts_path)],
        yes,
        &SystemCommandRunner,
    )?;
    output::emit(super::format(cli.json), &result);
    Ok(())
}

fn elevate(cli: &Cli, yes: bool) -> Result<(), CliError> {
    let config = utility_commands::load(cli.config.as_ref())?;
    let directory = config_directory(super::config_path(cli))?;
    let executable = std::env::current_exe()?;
    let (executable, source_warning) =
        resolve_executable_source(&utf8_path(&executable)?).map_err(CliError::Invalid)?;
    if let Some(warning) = source_warning {
        output::preview_warning(&warning);
    }
    let definition = forwarder_definition(
        LocalPlatform::current(),
        config.defaults.local_http_port,
        config.defaults.local_https_port,
        nix::unistd::getuid().as_raw(),
        nix::unistd::getgid().as_raw(),
    );
    let temporary = temporary_file(&directory, &definition)?;
    let path = utf8_path(temporary.path())?;
    let mut result = apply_commands(
        "local privileged ports",
        elevation_install_commands(LocalPlatform::current(), &executable),
        yes,
        &SystemCommandRunner,
    )?;
    verify_forwarder_destination(&root_forwarder_path(LocalPlatform::current()))
        .map_err(CliError::Invalid)?;
    let activation = apply_commands(
        "local privileged ports",
        elevation_activate_commands(LocalPlatform::current(), &path),
        true,
        &SystemCommandRunner,
    )?;
    result.commands.extend(activation.commands);
    write_elevation_marker(&directory)?;
    output::emit(super::format(cli.json), &result);
    Ok(())
}

fn unelevate(cli: &Cli, yes: bool) -> Result<(), CliError> {
    let directory = config_directory(super::config_path(cli))?;
    let result = apply_commands(
        "local privileged ports removal",
        unelevation_commands(LocalPlatform::current()),
        yes,
        &SystemCommandRunner,
    )?;
    remove_elevation_marker(&directory)?;
    output::emit(super::format(cli.json), &result);
    Ok(())
}

fn apply_commands<R: CommandRunner>(
    action: &str,
    commands: Vec<CommandSpec>,
    yes: bool,
    runner: &R,
) -> Result<LocalActionResult, CliError> {
    let displays = commands.iter().map(CommandSpec::display).collect::<Vec<_>>();
    for command in &displays {
        output::preview_command(command);
    }
    confirm(action, yes)?;
    for command in &commands {
        let result = runner.run(command)?;
        if !result.success {
            return Err(CliError::Invalid(format!(
                "command failed: {}: {}",
                command.display(),
                result.stderr.trim()
            )));
        }
    }
    Ok(LocalActionResult { action: action.to_owned(), changed: true, commands: displays })
}

fn confirm(action: &str, yes: bool) -> Result<(), CliError> {
    if yes {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return Err(CliError::Invalid(format!("{action} requires `--yes` outside a terminal")));
    }
    output::prompt(&format!("Apply {action}? [y/N]"))?;
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    if matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(())
    } else {
        Err(CliError::Invalid(format!("{action} cancelled")))
    }
}

/// Validates each hostname on its own suffix rather than the configured one.
///
/// Judging by configuration rejected `hosts sync app.test` with ".localhost needs no hosts entry"
/// whenever `local_tld` was still the default, which describes a hostname the user never typed.
fn validate_hosts(hostnames: &[String], _tld: &str) -> Result<(), CliError> {
    for hostname in hostnames {
        let suffix = hostname.rsplit('.').next().unwrap_or_default();
        if suffix == "localhost" {
            return Err(CliError::Invalid(format!(
                "{hostname} resolves without a hosts entry; .localhost needs no sync"
            )));
        }
        if !hostname.contains('.') {
            return Err(CliError::Invalid(format!(
                "{hostname} must be a dotted name such as app.test"
            )));
        }
        if hostname.chars().any(|character| {
            !(character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '-' | '.'))
        }) {
            return Err(CliError::Invalid(format!("{hostname} must be a lowercase DNS name")));
        }
    }
    Ok(())
}

fn hosts_check(config: &wormhole_core::ClientConfig) -> wormhole_core::model::DoctorCheck {
    if config.defaults.local_tld == "localhost" {
        return doctor_check("local:hosts", true, ".localhost needs no hosts block".to_owned());
    }
    match hosts_block_state(Utf8Path::new("/etc/hosts"), &config.defaults.local_tld) {
        Ok(hosts) => doctor_check(
            "local:hosts",
            !hosts.is_empty(),
            if hosts.is_empty() { "managed block missing".to_owned() } else { hosts.join(",") },
        ),
        Err(error) => doctor_check("local:hosts", false, error.to_string()),
    }
}

async fn listener_check(name: &str, port: u16) -> wormhole_core::model::DoctorCheck {
    let address = (std::net::Ipv4Addr::LOCALHOST, port);
    let result =
        tokio::time::timeout(std::time::Duration::from_millis(250), TcpStream::connect(address))
            .await;
    doctor_check(
        name,
        matches!(result, Ok(Ok(_))),
        match result {
            Ok(Ok(_)) => format!("127.0.0.1:{port} reachable"),
            Ok(Err(error)) => error.to_string(),
            Err(_) => "connection timed out".to_owned(),
        },
    )
}

fn doctor_check(name: &str, healthy: bool, detail: String) -> wormhole_core::model::DoctorCheck {
    wormhole_core::model::DoctorCheck { name: name.to_owned(), healthy, detail }
}

/// Detects how this machine stores additional certificate authorities.
///
/// p11-kit is preferred when present because it serves either family. Otherwise the Debian layout
/// is chosen only when its directory exists, so a Red Hat host is never handed Debian commands.
fn linux_trust() -> LinuxTrust {
    if std::path::Path::new("/usr/bin/trust").is_file()
        || std::path::Path::new("/bin/trust").is_file()
    {
        return LinuxTrust::P11Kit;
    }
    if std::path::Path::new("/usr/local/share/ca-certificates").is_dir() {
        return LinuxTrust::Debian;
    }
    LinuxTrust::RedHat
}

/// Anchor path for the detected layout, used as the fallback trust signal.
fn linux_anchor() -> &'static str {
    match linux_trust() {
        LinuxTrust::Debian => wormhole_core::local_system::DEBIAN_ANCHOR,
        LinuxTrust::P11Kit | LinuxTrust::RedHat => wormhole_core::local_system::REDHAT_ANCHOR,
    }
}

fn config_directory(config_path: Option<&Utf8Path>) -> Result<Utf8PathBuf, CliError> {
    config_path
        .map_or_else(global_config_path, |path| Ok(path.to_owned()))?
        .parent()
        .map(Utf8Path::to_owned)
        .ok_or_else(|| CliError::Invalid("configuration path has no parent".to_owned()))
}

fn temporary_file(
    directory: &Utf8Path,
    contents: &str,
) -> Result<tempfile::NamedTempFile, CliError> {
    std::fs::create_dir_all(directory)?;
    let mut file = tempfile::NamedTempFile::new_in(directory)?;
    file.write_all(contents.as_bytes())?;
    file.as_file().sync_all()?;
    Ok(file)
}

fn utf8_path(path: &std::path::Path) -> Result<Utf8PathBuf, CliError> {
    Utf8PathBuf::from_path_buf(path.to_owned())
        .map_err(|path| CliError::Invalid(format!("path is not UTF-8: {}", path.display())))
}

async fn privileged_forward(
    clear_target: u16,
    tls_target: u16,
    user_id: u32,
    group_id: u32,
) -> Result<(), CliError> {
    // Both loopbacks, because `*.localhost` resolves to ::1 first and a TLS client that reaches an
    // unserved address fails outright rather than falling back. IPv6 is best effort so a host with
    // it disabled still forwards. Every bind happens before privileges are dropped.
    let mut listeners = Vec::new();
    for (port, target) in [(80, clear_target), (443, tls_target)] {
        listeners.push((TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await?, target));
        if let Ok(listener) = TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, port)).await {
            listeners.push((listener, target));
        }
    }
    drop_forwarder_privileges(user_id, group_id)?;
    // Collected eagerly: a lazy iterator would spawn each listener only as it is awaited, leaving
    // every listener after the first bound but never accepted.
    let served = listeners
        .into_iter()
        .map(|(listener, target)| tokio::spawn(serve_listener(listener, target)))
        .collect::<Vec<_>>();
    for task in served {
        task.await.map_err(|error| CliError::Invalid(error.to_string()))??;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn drop_forwarder_privileges(user_id: u32, group_id: u32) -> Result<(), CliError> {
    nix::unistd::setgroups(&[])
        .map_err(|error| CliError::Invalid(format!("cannot clear forwarder groups: {error}")))?;
    nix::unistd::setgid(nix::unistd::Gid::from_raw(group_id))
        .and_then(|()| nix::unistd::setuid(nix::unistd::Uid::from_raw(user_id)))
        .map_err(|error| CliError::Invalid(format!("cannot drop forwarder privileges: {error}")))
}

#[cfg(target_os = "macos")]
fn drop_forwarder_privileges(user_id: u32, group_id: u32) -> Result<(), CliError> {
    privdrop::PrivDrop::default()
        .user(user_id.to_string())
        .group(group_id.to_string())
        .group_list::<&str>(&[])
        .fallback_to_ids_if_names_are_numeric()
        .apply()
        .map_err(|error| CliError::Invalid(format!("cannot drop forwarder privileges: {error}")))
}

async fn serve_listener(listener: TcpListener, target_port: u16) -> Result<(), std::io::Error> {
    loop {
        let (incoming, _) = listener.accept().await?;
        tokio::spawn(forward(incoming, target_port));
    }
}

async fn forward(mut incoming: TcpStream, target_port: u16) {
    let Ok(mut outgoing) = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, target_port)).await
    else {
        return;
    };
    let _copied = tokio::io::copy_bidirectional(&mut incoming, &mut outgoing).await;
}

#[cfg(test)]
#[path = "local_commands_tests.rs"]
mod tests;
