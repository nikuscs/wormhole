use std::{fs, process::Command};

use serde_json::Value;

#[test]
fn mock_daemon_expose_list_and_down_round_trip() {
    let directory = tempfile::tempdir().expect("tempdir");
    let state = directory.path().join("state");
    let home = directory.path().join("home");
    fs::create_dir(&home).expect("home");
    let binary = env!("CARGO_BIN_EXE_wormhole");

    let created = run(
        binary,
        &state,
        &home,
        &["http", "3000", "--endpoint", "mock", "--host", "web", "--name", "web", "--json"],
    );
    let endpoints: Value = serde_json::from_slice(&created.stdout).expect("created JSON");
    assert_eq!(endpoints[0]["urls"][0], "https://web.mock.invalid");

    let duplicate = command(
        binary,
        &state,
        &home,
        &["http", "3000", "--endpoint", "mock", "--name", "web", "--json"],
    );
    assert_eq!(duplicate.status.code(), Some(1));

    let failed =
        command(binary, &state, &home, &["http", "3001", "--endpoint", "missing", "--json"]);
    assert_eq!(failed.status.code(), Some(5));

    let listed = run(binary, &state, &home, &["ls", "--json"]);
    let endpoints: Value = serde_json::from_slice(&listed.stdout).expect("list JSON");
    assert_eq!(endpoints.as_array().expect("array").len(), 1);
    let plain = run(binary, &state, &home, &["ls"]);
    assert!(!plain.stdout.contains(&0x1b));

    run(binary, &state, &home, &["down", "web", "--json"]);
    run(
        binary,
        &state,
        &home,
        &["http", "3002", "--endpoint", "mock", "--name", "foo/bar", "--json"],
    );
    run(binary, &state, &home, &["down", "foo/bar", "--json"]);
    let empty = run(binary, &state, &home, &["ls", "--json"]);
    assert_eq!(String::from_utf8_lossy(&empty.stdout).trim(), "[]");
    run(binary, &state, &home, &["daemon", "stop", "--json"]);
}

fn run(
    binary: &str,
    state: &std::path::Path,
    home: &std::path::Path,
    args: &[&str],
) -> std::process::Output {
    let output = command(binary, state, home, args);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    output
}

fn command(
    binary: &str,
    state: &std::path::Path,
    home: &std::path::Path,
    args: &[&str],
) -> std::process::Output {
    Command::new(binary)
        .args(args)
        .env("WORMHOLE_STATE_DIR", state)
        .env("WORMHOLE_ENABLE_MOCK_DRIVER", "1")
        .env("HOME", home)
        .output()
        .expect("command")
}
