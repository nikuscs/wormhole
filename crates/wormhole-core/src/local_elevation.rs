//! Root-owned local forwarder installation plans and source-path validation.

use std::{
    fs,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
};

use camino::{Utf8Path, Utf8PathBuf};

use crate::local_system::{CommandSpec, LocalPlatform};

pub const ELEVATION_MARKER: &str = "local-elevation.toml";
const MACOS_FORWARDER: &str = "/usr/local/libexec/wormhole-local-forwarder";
const LINUX_FORWARDER: &str = "/usr/local/lib/wormhole/wormhole-local-forwarder";

/// Commands that place the root-owned forwarder, without activating anything.
///
/// Kept separate from [`elevation_activate_commands`] so the destination can be verified before a
/// root service is created against it. Activating first would leave a running root service behind
/// when verification fails.
pub fn elevation_install_commands(platform: LocalPlatform, source: &Utf8Path) -> Vec<CommandSpec> {
    let (directory, owner, group) = match platform {
        LocalPlatform::MacOs => ("/usr/local/libexec", "root", "wheel"),
        LocalPlatform::Linux => ("/usr/local/lib/wormhole", "root", "root"),
    };
    vec![
        command("sudo", &["install", "-d", "-o", owner, "-g", group, "-m", "0755", directory]),
        command(
            "sudo",
            &[
                "install",
                "-o",
                owner,
                "-g",
                group,
                "-m",
                "0755",
                source.as_str(),
                root_forwarder_path(platform).as_str(),
            ],
        ),
    ]
}

/// Commands that register and start the root service, run only after the destination is verified.
pub fn elevation_activate_commands(
    platform: LocalPlatform,
    definition: &Utf8Path,
) -> Vec<CommandSpec> {
    let mut commands = Vec::new();
    match platform {
        LocalPlatform::MacOs => commands.extend([
            command(
                "sudo",
                &[
                    "install",
                    "-o",
                    "root",
                    "-g",
                    "wheel",
                    "-m",
                    "0644",
                    definition.as_str(),
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
        ]),
        LocalPlatform::Linux => commands.extend([
            command(
                "sudo",
                &[
                    "install",
                    "-o",
                    "root",
                    "-g",
                    "root",
                    "-m",
                    "0644",
                    definition.as_str(),
                    "/etc/systemd/system/wormhole-local.service",
                ],
            ),
            command("sudo", &["systemctl", "daemon-reload"]),
            command("sudo", &["systemctl", "enable", "--now", "wormhole-local.service"]),
        ]),
    }
    commands
}

pub fn unelevation_commands(platform: LocalPlatform) -> Vec<CommandSpec> {
    match platform {
        LocalPlatform::MacOs => vec![
            command("sudo", &["launchctl", "bootout", "system/dev.wormhole.local"]),
            command("sudo", &["rm", "-f", "/Library/LaunchDaemons/dev.wormhole.local.plist"]),
            command("sudo", &["rm", "-f", MACOS_FORWARDER]),
        ],
        LocalPlatform::Linux => vec![
            command("sudo", &["systemctl", "disable", "--now", "wormhole-local.service"]),
            command("sudo", &["rm", "-f", "/etc/systemd/system/wormhole-local.service"]),
            command("sudo", &["systemctl", "daemon-reload"]),
            command("sudo", &["rm", "-f", LINUX_FORWARDER]),
        ],
    }
}

pub fn write_elevation_marker(directory: &Utf8Path) -> Result<Utf8PathBuf, std::io::Error> {
    fs::create_dir_all(directory)?;
    let path = directory.join(ELEVATION_MARKER);
    fs::write(&path, "enabled = true\n")?;
    Ok(path)
}

pub fn remove_elevation_marker(directory: &Utf8Path) -> Result<(), std::io::Error> {
    match fs::remove_file(directory.join(ELEVATION_MARKER)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub fn elevation_enabled(directory: &Utf8Path) -> bool {
    directory.join(ELEVATION_MARKER).is_file()
}

pub fn forwarder_definition(
    platform: LocalPlatform,
    clear_target: u16,
    tls_target: u16,
    user_id: u32,
    group_id: u32,
) -> String {
    let executable = root_forwarder_path(platform);
    match platform {
        LocalPlatform::MacOs => {
            launchd_plist(&executable, clear_target, tls_target, user_id, group_id)
        }
        LocalPlatform::Linux => {
            systemd_unit(&executable, clear_target, tls_target, user_id, group_id)
        }
    }
}

pub fn root_forwarder_path(platform: LocalPlatform) -> Utf8PathBuf {
    Utf8PathBuf::from(match platform {
        LocalPlatform::MacOs => MACOS_FORWARDER,
        LocalPlatform::Linux => LINUX_FORWARDER,
    })
}

/// Resolves the executable to copy, and reports whether its location is user-writable.
///
/// The source only decides what is copied once, under a `sudo` the user just authorized, which is
/// the same trust assumption as any `sudo install`. Refusing here blocked every Homebrew install,
/// whose prefix is group-writable by `admin` — a group whose members can already become root, so
/// the refusal cost real usability and bought nothing. What matters is the destination the root
/// service executes, which [`verify_forwarder_destination`] checks after the copy.
pub fn resolve_executable_source(path: &Utf8Path) -> Result<(Utf8PathBuf, Option<String>), String> {
    let canonical = fs::canonicalize(path)
        .map_err(|error| format!("cannot resolve elevation executable {path}: {error}"))?;
    let canonical = Utf8PathBuf::from_path_buf(canonical)
        .map_err(|path| format!("elevation executable is not UTF-8: {}", path.display()))?;
    let metadata = fs::metadata(&canonical)
        .map_err(|error| format!("cannot inspect elevation executable {canonical}: {error}"))?;
    if !metadata.is_file() {
        return Err(format!("elevation executable is not a regular file: {canonical}"));
    }
    let warning = writable_component(&canonical)?.map(|component| {
        format!(
            "{component} is writable without root; elevation copies the file as it is right now"
        )
    });
    Ok((canonical, warning))
}

/// Rejects a forwarder the root service would execute from a path others can rewrite.
///
/// This is the check the threat model depends on: a root service must never execute a file that a
/// non-root user can replace later.
pub fn verify_forwarder_destination(path: &Utf8Path) -> Result<(), String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("cannot inspect installed forwarder {path}: {error}"))?;
    if !metadata.is_file() {
        return Err(format!("installed forwarder is not a regular file: {path}"));
    }
    writable_component(path)?.map_or(Ok(()), |component| {
        Err(format!(
            "refusing elevation: {component} is writable without root, so the root service could be replaced"
        ))
    })
}

/// First component of `path`, including itself, that a non-root user can write.
fn writable_component(path: &Utf8Path) -> Result<Option<Utf8PathBuf>, String> {
    for component in path.ancestors() {
        let metadata = fs::metadata(component)
            .map_err(|error| format!("cannot inspect {component}: {error}"))?;
        let mode = metadata.permissions().mode();
        let owner_writes_without_root = metadata.uid() != 0 && mode & 0o200 != 0;
        if owner_writes_without_root || mode & 0o022 != 0 {
            return Ok(Some(component.to_owned()));
        }
    }
    Ok(None)
}

fn command(program: &str, args: &[&str]) -> CommandSpec {
    CommandSpec {
        interactive: program == "sudo",
        program: program.to_owned(),
        args: args.iter().map(|argument| (*argument).to_owned()).collect(),
    }
}

fn launchd_plist(
    executable: &Utf8Path,
    clear_target: u16,
    tls_target: u16,
    user_id: u32,
    group_id: u32,
) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>dev.wormhole.local</string><key>UserName</key><string>root</string><key>GroupName</key><string>wheel</string><key>ProgramArguments</key><array><string>{}</string><string>local</string><string>privileged-forward</string><string>--clear-target</string><string>{clear_target}</string><string>--tls-target</string><string>{tls_target}</string><string>--drop-uid</string><string>{user_id}</string><string>--drop-gid</string><string>{group_id}</string></array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/></dict></plist>\n",
        xml_escape(executable.as_str())
    )
}

fn systemd_unit(
    executable: &Utf8Path,
    clear_target: u16,
    tls_target: u16,
    user_id: u32,
    group_id: u32,
) -> String {
    format!(
        "[Unit]\nDescription=Wormhole local privileged port forwarder\nAfter=network.target\n\n[Service]\nUser=root\nGroup=root\nExecStart={executable} local privileged-forward --clear-target={clear_target} --tls-target={tls_target} --drop-uid={user_id} --drop-gid={group_id}\nRestart=on-failure\nNoNewPrivileges=true\n\n[Install]\nWantedBy=multi-user.target\n"
    )
}

fn xml_escape(value: &str) -> String {
    value.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}
