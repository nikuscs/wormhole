//! Testable plans for local trust, managed hosts, and privileged port forwarding.

use std::{fs, process::Command};

use camino::{Utf8Path, Utf8PathBuf};

pub const HOSTS_BEGIN: &str = "# BEGIN WORMHOLE LOCAL";
pub const HOSTS_END: &str = "# END WORMHOLE LOCAL";
pub const ELEVATION_MARKER: &str = "local-elevation.toml";

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

/// One exact external command, without shell interpretation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
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
        let output = Command::new(&command.program).args(&command.args).output()?;
        Ok(CommandOutput {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

pub fn trust_commands(platform: LocalPlatform, ca: &Utf8Path, p11_kit: bool) -> Vec<CommandSpec> {
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
        LocalPlatform::Linux if p11_kit => {
            vec![command("sudo", &["trust", "anchor", ca.as_str()])]
        }
        LocalPlatform::Linux => vec![
            command(
                "sudo",
                &[
                    "install",
                    "-m",
                    "0644",
                    ca.as_str(),
                    "/etc/pki/ca-trust/source/anchors/wormhole-local-ca.pem",
                ],
            ),
            command("sudo", &["update-ca-trust", "extract"]),
        ],
    }
}

pub fn untrust_commands(platform: LocalPlatform, ca: &Utf8Path, p11_kit: bool) -> Vec<CommandSpec> {
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
        LocalPlatform::Linux if p11_kit => {
            vec![command("sudo", &["trust", "anchor", "--remove", ca.as_str()])]
        }
        LocalPlatform::Linux => vec![
            command(
                "sudo",
                &["rm", "-f", "/etc/pki/ca-trust/source/anchors/wormhole-local-ca.pem"],
            ),
            command("sudo", &["update-ca-trust", "extract"]),
        ],
    }
}

pub fn trust_check_command(platform: LocalPlatform, p11_kit: bool) -> Option<CommandSpec> {
    match platform {
        LocalPlatform::MacOs => Some(command(
            "security",
            &["find-certificate", "-c", "Wormhole Local CA", "/Library/Keychains/System.keychain"],
        )),
        LocalPlatform::Linux if p11_kit => Some(command("trust", &["list", "--filter=ca-anchors"])),
        LocalPlatform::Linux => None,
    }
}

pub fn elevation_commands(platform: LocalPlatform, temporary: &Utf8Path) -> Vec<CommandSpec> {
    match platform {
        LocalPlatform::MacOs => vec![
            command(
                "sudo",
                &[
                    "install",
                    "-m",
                    "0644",
                    temporary.as_str(),
                    "/Library/LaunchDaemons/dev.wormhole.local.plist",
                ],
            ),
            command(
                "sudo",
                &[
                    "launchctl",
                    "bootstrap",
                    "system",
                    "/Library/LaunchDaemons/dev.wormhole.local.plist",
                ],
            ),
        ],
        LocalPlatform::Linux => vec![
            command(
                "sudo",
                &[
                    "install",
                    "-m",
                    "0644",
                    temporary.as_str(),
                    "/etc/systemd/system/wormhole-local.service",
                ],
            ),
            command("sudo", &["systemctl", "daemon-reload"]),
            command("sudo", &["systemctl", "enable", "--now", "wormhole-local.service"]),
        ],
    }
}

pub fn hosts_install_command(temporary: &Utf8Path, destination: &Utf8Path) -> CommandSpec {
    command("sudo", &["install", "-m", "0644", temporary.as_str(), destination.as_str()])
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
    p11_kit: bool,
    ca_exists: bool,
    fallback_anchor_exists: bool,
    runner: &R,
) -> (bool, String) {
    if !ca_exists {
        return (false, "local CA has not been generated".to_owned());
    }
    let Some(command) = trust_check_command(platform, p11_kit) else {
        return if fallback_anchor_exists {
            (true, "installed anchor".to_owned())
        } else {
            (false, "not installed".to_owned())
        };
    };
    match runner.run(&command) {
        Ok(output)
            if output.success
                && (platform == LocalPlatform::MacOs
                    || output.stdout.contains("Wormhole Local CA")) =>
        {
            (true, "installed".to_owned())
        }
        Ok(output) => (false, output.stderr),
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

pub fn write_elevation_marker(directory: &Utf8Path) -> Result<Utf8PathBuf, std::io::Error> {
    fs::create_dir_all(directory)?;
    let path = directory.join(ELEVATION_MARKER);
    fs::write(&path, "enabled = true\n")?;
    Ok(path)
}

pub fn elevation_enabled(directory: &Utf8Path) -> bool {
    directory.join(ELEVATION_MARKER).is_file()
}

pub fn forwarder_definition(
    platform: LocalPlatform,
    executable: &Utf8Path,
    clear_target: u16,
    tls_target: u16,
) -> String {
    match platform {
        LocalPlatform::MacOs => launchd_plist(executable, clear_target, tls_target),
        LocalPlatform::Linux => systemd_unit(executable, clear_target, tls_target),
    }
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

fn launchd_plist(executable: &Utf8Path, clear_target: u16, tls_target: u16) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>dev.wormhole.local</string><key>ProgramArguments</key><array><string>{}</string><string>local</string><string>privileged-forward</string><string>--clear-target</string><string>{clear_target}</string><string>--tls-target</string><string>{tls_target}</string></array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/></dict></plist>\n",
        xml_escape(executable.as_str())
    )
}

fn systemd_unit(executable: &Utf8Path, clear_target: u16, tls_target: u16) -> String {
    format!(
        "[Unit]\nDescription=Wormhole local privileged port forwarder\nAfter=network.target\n\n[Service]\nExecStart={executable} local privileged-forward --clear-target={clear_target} --tls-target={tls_target}\nRestart=on-failure\nNoNewPrivileges=true\n\n[Install]\nWantedBy=multi-user.target\n"
    )
}

fn xml_escape(value: &str) -> String {
    value.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

#[cfg(test)]
#[path = "local_system_tests.rs"]
mod tests;
