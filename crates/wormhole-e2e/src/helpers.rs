use std::{path::Path, process::Output};

#[cfg(test)]
use std::process::{Child, Command, Stdio};

pub fn path(path: &Path) -> Result<&str, String> {
    path.to_str().ok_or_else(|| "non-UTF8 path".to_owned())
}

pub fn require_success(context: &str, output: &Output) -> Result<(), String> {
    if output.status.success() {
        Ok(())
    } else {
        Err(format!("{context}: {}", String::from_utf8_lossy(&output.stderr)))
    }
}

pub fn to_string(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
pub fn spawn_relay_request(
    relay: &crate::harness::TestRelay,
    host: &str,
    url: &str,
    extra: &[&str],
) -> Result<Child, String> {
    let resolve = format!("{host}:{}:127.0.0.1", relay.port);
    let mut command = Command::new("curl");
    command.args([
        "--silent",
        "--show-error",
        "--cacert",
        path(&relay.certificate)?,
        "--resolve",
        &resolve,
        "--write-out",
        "\n%{http_code}",
    ]);
    command.args(extra).arg(url).stdout(Stdio::piped()).stderr(Stdio::piped());
    command.spawn().map_err(to_string)
}

#[cfg(test)]
pub fn relay_command(relay: &crate::harness::TestRelay, args: &[&str]) -> Result<Output, String> {
    let binaries = crate::harness::binaries()?;
    Command::new(&binaries.wormholed)
        .args(["--config", path(relay.config())?])
        .args(args)
        .output()
        .map_err(to_string)
}

#[cfg(test)]
pub fn spawn_client(client: &crate::harness::TestClient, args: &[&str]) -> Result<Child, String> {
    let binaries = crate::harness::binaries()?;
    Command::new(&binaries.wormhole)
        .args(args)
        .current_dir(client.directory.path())
        .env("HOME", &client.home)
        .env("WORMHOLE_CONFIG", &client.config)
        .env("WORMHOLE_STATE_DIR", &client.state)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(to_string)
}

#[cfg(test)]
pub fn set_transport(path: &Path, transport: &str) -> Result<(), String> {
    let config = std::fs::read_to_string(path).map_err(to_string)?;
    let remote = format!("[remotes.test]\ntransport = \"{transport}\"");
    std::fs::write(path, config.replace("[remotes.test]", &remote)).map_err(to_string)
}

#[cfg(test)]
pub fn set_remote_port(path: &Path, port: u16) -> Result<(), String> {
    let config = std::fs::read_to_string(path).map_err(to_string)?;
    let config = config
        .lines()
        .map(|line| {
            if line.starts_with("addr = ") {
                format!("addr = \"127.0.0.1:{port}\"")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(path, config).map_err(to_string)
}
