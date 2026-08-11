//! Testable plans for local trust, managed hosts, and privileged port forwarding.

use std::{fs, process::Command};

use camino::Utf8Path;

pub use crate::local_elevation::{
    ELEVATION_MARKER, elevation_activate_commands, elevation_enabled, elevation_install_commands,
    forwarder_definition, remove_elevation_marker, resolve_executable_source, root_forwarder_path,
    unelevation_commands, verify_forwarder_destination, write_elevation_marker,
};

pub const HOSTS_BEGIN: &str = "# BEGIN WORMHOLE LOCAL";
pub const HOSTS_END: &str = "# END WORMHOLE LOCAL";

/// Supported local operating-system integration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalPlatform {
    MacOs,
    Linux,
}

impl LocalPlatform {
    pub const fn current() -> Self {
        #[cfg(target_os = "macos")]
        return Self::MacOs;
        #[cfg(target_os = "linux")]
        return Self::Linux;
    }
}

/// How a Linux distribution stores additional certificate authorities.
///
/// Debian and Red Hat families use different directories and different refresh commands, and
/// assuming one breaks `local trust` outright on the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxTrust {
    /// p11-kit `trust`, when available, handles either family.
    P11Kit,
    /// `/usr/local/share/ca-certificates` refreshed by `update-ca-certificates`.
    Debian,
    /// `/etc/pki/ca-trust/source/anchors` refreshed by `update-ca-trust`.
    RedHat,
}

pub const DEBIAN_ANCHOR: &str = "/usr/local/share/ca-certificates/wormhole-local-ca.crt";
pub const REDHAT_ANCHOR: &str = "/etc/pki/ca-trust/source/anchors/wormhole-local-ca.pem";

/// One exact external command, without shell interpretation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
    /// Whether the command must reach the terminal to prompt.
    ///
    /// `sudo` asks for a password and macOS asks to confirm a new trust root. Both prompts are
    /// only presented when the child keeps the terminal, and `security add-trusted-cert` still
    /// exits zero when it cannot ask, silently skipping the trust setting.
    pub interactive: bool,
}

impl CommandSpec {
    pub fn display(&self) -> String {
        std::iter::once(self.program.as_str())
            .chain(self.args.iter().map(String::as_str))
            .map(shell_word)
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Captured command result used by diagnostics and fake runners.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommandOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Injectable external command execution.
pub trait CommandRunner {
    fn run(&self, command: &CommandSpec) -> Result<CommandOutput, std::io::Error>;
}

pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, command: &CommandSpec) -> Result<CommandOutput, std::io::Error> {
        if command.interactive {
            let status = Command::new(&command.program).args(&command.args).status()?;
            return Ok(CommandOutput {
                success: status.success(),
                stdout: String::new(),
                stderr: String::new(),
            });
        }
        let output = Command::new(&command.program).args(&command.args).output()?;
        Ok(CommandOutput {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

pub fn trust_commands(
    platform: LocalPlatform,
    ca: &Utf8Path,
    linux: LinuxTrust,
) -> Vec<CommandSpec> {
    match platform {
        LocalPlatform::MacOs => vec![command(
            "sudo",
            &[
                "security",
                "add-trusted-cert",
                "-d",
                "-r",
                "trustRoot",
                "-k",
                "/Library/Keychains/System.keychain",
                ca.as_str(),
            ],
        )],
        LocalPlatform::Linux => match linux {
            LinuxTrust::P11Kit => vec![command("sudo", &["trust", "anchor", ca.as_str()])],
            LinuxTrust::Debian => vec![
                command("sudo", &["install", "-m", "0644", ca.as_str(), DEBIAN_ANCHOR]),
                command("sudo", &["update-ca-certificates"]),
            ],
            LinuxTrust::RedHat => vec![
                command("sudo", &["install", "-m", "0644", ca.as_str(), REDHAT_ANCHOR]),
                command("sudo", &["update-ca-trust", "extract"]),
            ],
        },
    }
}

pub fn untrust_commands(
    platform: LocalPlatform,
    ca: &Utf8Path,
    linux: LinuxTrust,
) -> Vec<CommandSpec> {
    match platform {
        LocalPlatform::MacOs => vec![command(
            "sudo",
            &[
                "security",
                "delete-certificate",
                "-c",
                "Wormhole Local CA",
                "/Library/Keychains/System.keychain",
            ],
        )],
        LocalPlatform::Linux => match linux {
            LinuxTrust::P11Kit => {
                vec![command("sudo", &["trust", "anchor", "--remove", ca.as_str()])]
            }
            LinuxTrust::Debian => vec![
                command("sudo", &["rm", "-f", DEBIAN_ANCHOR]),
                command("sudo", &["update-ca-certificates", "--fresh"]),
            ],
            LinuxTrust::RedHat => vec![
                command("sudo", &["rm", "-f", REDHAT_ANCHOR]),
                command("sudo", &["update-ca-trust", "extract"]),
            ],
        },
    }
}

/// Command whose output proves the authority is trusted, not merely present.
///
/// macOS keeps the certificate and the trust setting apart: `find-certificate` succeeds as soon as
/// the certificate is in the keychain, even when nothing trusts it, so the trust settings are what
/// must be read back.
pub fn trust_check_command(platform: LocalPlatform, linux: LinuxTrust) -> Option<CommandSpec> {
    match platform {
        LocalPlatform::MacOs => Some(command("security", &["dump-trust-settings", "-d"])),
        LocalPlatform::Linux => match linux {
            LinuxTrust::P11Kit => Some(command("trust", &["list", "--filter=ca-anchors"])),
            LinuxTrust::Debian | LinuxTrust::RedHat => None,
        },
    }
}

/// Replaces the hosts file contents in place.
///
/// `install` unlinks the destination and creates a new file, which fails outright when the hosts
/// file is a bind mount — the norm inside containers — with "Device or resource busy". `cp` writes
/// through the existing inode, so it survives that and leaves anything watching the file intact.
pub fn hosts_install_command(temporary: &Utf8Path, destination: &Utf8Path) -> CommandSpec {
    command("sudo", &["cp", temporary.as_str(), destination.as_str()])
}

pub fn prepare_hosts_file(path: &Utf8Path, hostnames: &[String]) -> Result<String, std::io::Error> {
    fs::read_to_string(path).map(|existing| render_hosts(&existing, hostnames))
}

pub fn hosts_block_state(path: &Utf8Path, tld: &str) -> Result<Vec<String>, std::io::Error> {
    let hosts = managed_hosts(&fs::read_to_string(path)?);
    let suffix = format!(".{tld}");
    Ok(hosts
        .into_iter()
        .filter(|hostname| hostname == tld || hostname.ends_with(&suffix))
        .collect())
}

pub fn trust_state<R: CommandRunner>(
    platform: LocalPlatform,
    linux: LinuxTrust,
    ca_exists: bool,
    fallback_anchor_exists: bool,
    runner: &R,
) -> (bool, String) {
    if !ca_exists {
        return (false, "local CA has not been generated".to_owned());
    }
    let Some(command) = trust_check_command(platform, linux) else {
        return if fallback_anchor_exists {
            (true, "installed anchor".to_owned())
        } else {
            (false, "not installed".to_owned())
        };
    };
    // `security dump-trust-settings` exits non-zero when no settings exist at all, so the listing
    // itself decides the answer rather than the exit status.
    match runner.run(&command) {
        Ok(output) if output.stdout.contains("Wormhole Local CA") => (true, "trusted".to_owned()),
        Ok(_) => (false, "certificate is not trusted; run `wormhole local trust`".to_owned()),
        Err(error) => (false, error.to_string()),
    }
}

pub fn render_hosts(existing: &str, hostnames: &[String]) -> String {
    let without = remove_hosts_block(existing);
    if hostnames.is_empty() {
        return ensure_final_newline(without.trim_end());
    }
    let mut names = hostnames.iter().map(|name| name.to_ascii_lowercase()).collect::<Vec<_>>();
    names.sort();
    names.dedup();
    format!(
        "{}{}\n127.0.0.1 {}\n::1 {}\n{}\n",
        ensure_final_newline(without.trim_end()),
        HOSTS_BEGIN,
        names.join(" "),
        names.join(" "),
        HOSTS_END
    )
}

pub fn managed_hosts(contents: &str) -> Vec<String> {
    let Some((_, managed)) = contents.split_once(HOSTS_BEGIN) else {
        return Vec::new();
    };
    let Some((managed, _)) = managed.split_once(HOSTS_END) else {
        return Vec::new();
    };
    let mut hosts = managed
        .lines()
        .flat_map(|line| line.split_whitespace().skip(1))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    hosts.sort();
    hosts.dedup();
    hosts
}

fn remove_hosts_block(contents: &str) -> String {
    let Some((before, rest)) = contents.split_once(HOSTS_BEGIN) else {
        return contents.to_owned();
    };
    let Some((_, after)) = rest.split_once(HOSTS_END) else {
        return contents.to_owned();
    };
    format!("{}{}", before.trim_end(), after.trim_start_matches(['\r', '\n']))
}

fn ensure_final_newline(value: &str) -> String {
    if value.is_empty() { String::new() } else { format!("{value}\n") }
}

fn command(program: &str, args: &[&str]) -> CommandSpec {
    CommandSpec {
        interactive: program == "sudo",
        program: program.to_owned(),
        args: args.iter().map(|argument| (*argument).to_owned()).collect(),
    }
}

fn shell_word(value: &str) -> String {
    if value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || "-._/:=".contains(character))
    {
        value.to_owned()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

#[cfg(test)]
#[path = "local_system_tests.rs"]
mod tests;
