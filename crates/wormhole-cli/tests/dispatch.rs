use std::{
    fs,
    process::{Command, Output, Stdio},
    thread,
    time::Duration,
};

#[test]
fn main_dispatch_reports_validation_errors_before_daemon_access() {
    let directory = tempfile::tempdir().expect("tempdir");
    for (args, expected) in [
        (vec!["http", "invalid-target", "--json"], "target must be PORT or HOST:PORT"),
        (vec!["tcp", "0", "--json"], "target port must be non-zero"),
        (vec!["inspect", "not-a-uuid", "--json"], "request id"),
        (vec!["replay", "not-a-uuid", "--json"], "request id"),
    ] {
        let output = command(&directory).args(&args).output().expect("command");
        assert_eq!(output.status.code(), Some(2), "{args:?}: {}", stderr(&output));
        assert!(stderr(&output).contains(expected), "{args:?}: {}", stderr(&output));
        assert!(output.stdout.is_empty(), "validation failures do not contaminate stdout");
    }
}

#[test]
fn tracing_levels_and_forced_color_preserve_structured_failures() {
    let directory = tempfile::tempdir().expect("tempdir");
    for flag in ["--quiet", "-v", "-vv", "-vvv"] {
        let output = command(&directory)
            .args(["inspect", "invalid", flag, "--json"])
            .output()
            .expect("command");
        assert_eq!(output.status.code(), Some(2), "{flag}: {}", stderr(&output));
        assert!(stderr(&output).contains("request id"));
    }
    let colored = command(&directory)
        .env("CLICOLOR_FORCE", "1")
        .args(["http", "3000", "--endpoint", "definitely-unknown", "--foreground"])
        .output()
        .expect("colored command");
    assert_eq!(colored.status.code(), Some(1));
    assert!(colored.stderr.windows(2).any(|bytes| bytes == b"\x1b["));
    assert!(stderr(&colored).contains("unknown tunnel driver"));

    let hinted = command(&directory)
        .env("CLICOLOR_FORCE", "1")
        .env("WORMHOLE_ENABLE_MOCK_DRIVER", "1")
        .args([
            "run",
            "--endpoint",
            "mock",
            "--endpoint",
            "wormhole",
            "--name",
            "partial",
            "--",
            "sh",
            "-c",
            "true",
        ])
        .output()
        .expect("hinted command");
    assert_eq!(hinted.status.code(), Some(6), "{}", stderr(&hinted));
    assert!(stderr(&hinted).contains("hint:"));
    let stopped = command(&directory).args(["daemon", "stop", "--json"]).output().expect("stop");
    assert!(stopped.status.success(), "{}", stderr(&stopped));
}

#[test]
fn following_daemon_logs_streams_appends_until_interrupted() {
    let directory = tempfile::tempdir().expect("tempdir");
    let state = directory.path().join("state");
    fs::create_dir(&state).expect("state");
    let log = state.join("daemon.log");
    fs::write(&log, b"started\n").expect("initial log");
    let child = command(&directory)
        .args(["daemon", "logs", "--follow"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("follow logs");
    thread::sleep(Duration::from_millis(100));
    fs::write(&log, b"started\nready\n").expect("append log");
    thread::sleep(Duration::from_millis(350));
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child.id().cast_signed()),
        nix::sys::signal::Signal::SIGINT,
    )
    .expect("SIGINT");
    let output = child.wait_with_output().expect("logs output");
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(output.stdout, b"started\nready\n");
}

#[test]
fn daemon_detach_rejects_invalid_lifecycle_stage() {
    let directory = tempfile::tempdir().expect("tempdir");
    let output = command(&directory)
        .env("WORMHOLE_DETACH_CHILD", "invalid")
        .args(["daemon", "run", "--detach", "--json"])
        .output()
        .expect("command");

    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("invalid stage: invalid"), "{}", stderr(&output));
    assert!(output.stdout.is_empty());
}

#[test]
fn malformed_explicit_config_fails_without_spawning_daemon() {
    let directory = tempfile::tempdir().expect("tempdir");
    let config = directory.path().join("invalid.toml");
    std::fs::write(&config, "[defaults\n").expect("config");
    let output = command(&directory)
        .arg("--config")
        .arg(config)
        .args(["http", "3000", "--json"])
        .output()
        .expect("command");

    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).to_ascii_lowercase().contains("toml"), "{}", stderr(&output));
    assert!(output.stdout.is_empty());
}

fn command(directory: &tempfile::TempDir) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_wormhole"));
    command.env("WORMHOLE_STATE_DIR", directory.path().join("state")).env("HOME", directory.path());
    command
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
