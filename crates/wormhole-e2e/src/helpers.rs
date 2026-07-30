use std::{
    io::Read,
    path::Path,
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

#[cfg(test)]
use std::process::Child;

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
pub fn attempt_deadline(deadline: Instant) -> Instant {
    deadline.min(Instant::now() + Duration::from_secs(1))
}

pub fn curl_max_time(deadline: Instant) -> Result<String, String> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .and_then(|duration| duration.checked_sub(Duration::from_millis(1)))
        .ok_or_else(|| "request deadline elapsed".to_owned())?;
    let micros = remaining.as_micros();
    if micros == 0 {
        return Err("request deadline elapsed".to_owned());
    }
    Ok(format!("{}.{:06}", micros / 1_000_000, micros % 1_000_000))
}

pub fn output_until(
    command: &mut Command,
    deadline: Instant,
    context: &str,
) -> Result<Output, String> {
    if Instant::now() >= deadline {
        return Err(format!("{context} deadline elapsed"));
    }
    let mut child =
        command.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(to_string)?;
    let stdout = read_pipe(child.stdout.take().ok_or("missing child stdout")?);
    let stderr = read_pipe(child.stderr.take().ok_or("missing child stderr")?);
    loop {
        if let Some(status) = child.try_wait().map_err(to_string)? {
            return collect_output(status, stdout, stderr);
        }
        if Instant::now() >= deadline {
            child.kill().map_err(to_string)?;
            let status = child.wait().map_err(to_string)?;
            let _output = collect_output(status, stdout, stderr)?;
            return Err(format!("{context} timed out"));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn read_pipe(
    mut pipe: impl Read + Send + 'static,
) -> std::thread::JoinHandle<std::io::Result<Vec<u8>>> {
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        pipe.read_to_end(&mut bytes)?;
        Ok(bytes)
    })
}

fn collect_output(
    status: std::process::ExitStatus,
    stdout: std::thread::JoinHandle<std::io::Result<Vec<u8>>>,
    stderr: std::thread::JoinHandle<std::io::Result<Vec<u8>>>,
) -> Result<Output, String> {
    let stdout =
        stdout.join().map_err(|_| "stdout reader panicked".to_owned())?.map_err(to_string)?;
    let stderr =
        stderr.join().map_err(|_| "stderr reader panicked".to_owned())?.map_err(to_string)?;
    Ok(Output { status, stdout, stderr })
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
