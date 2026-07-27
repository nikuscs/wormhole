use std::{
    fs,
    process::Command,
    thread,
    time::{Duration, Instant},
};

use serde_json::Value;

#[test]
fn status_auto_spawns_reuses_and_stops_daemon() {
    let directory = tempfile::tempdir().expect("tempdir");
    let state = directory.path().join("state");
    let home = directory.path().join("home");
    fs::create_dir(&home).expect("home");
    let binary = env!("CARGO_BIN_EXE_wormhole");

    let first = status(binary, &state, &home);
    let second = status(binary, &state, &home);
    assert_eq!(first["pid"], second["pid"]);

    let stopped = Command::new(binary)
        .args(["daemon", "stop", "--json"])
        .env("WORMHOLE_STATE_DIR", &state)
        .env("HOME", &home)
        .output()
        .expect("daemon stop");
    assert!(stopped.status.success(), "{}", String::from_utf8_lossy(&stopped.stderr));
    wait_until_removed(&state.join("daemon.sock"));
}

fn status(binary: &str, state: &std::path::Path, home: &std::path::Path) -> Value {
    let output = Command::new(binary)
        .args(["status", "--json"])
        .env("WORMHOLE_STATE_DIR", state)
        .env("HOME", home)
        .output()
        .expect("status");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    serde_json::from_slice(&output.stdout).expect("status JSON")
}

fn wait_until_removed(path: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while path.exists() {
        assert!(Instant::now() < deadline, "daemon socket remained after stop");
        thread::sleep(Duration::from_millis(25));
    }
}
