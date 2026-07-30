use std::{fs, process::Command};

#[test]
fn interfaces_keys_remotes_and_completions_are_scriptable() {
    let directory = tempfile::tempdir().expect("tempdir");
    let home = directory.path().join("home");
    fs::create_dir(&home).expect("home");
    let config = directory.path().join("config.toml");
    let state = directory.path().join("state");
    fs::create_dir(&state).expect("state");
    fs::write(state.join("daemon.log"), b"daemon ready\n").expect("log");
    let logs = run(&directory, &home, &["daemon", "logs"]);
    assert_eq!(logs.stdout, b"daemon ready\n");

    let interfaces = run(&directory, &home, &["interfaces", "--json"]);
    assert!(String::from_utf8_lossy(&interfaces.stdout).contains("localhost"));
    let doctor = run(&directory, &home, &["doctor", "--json"]);
    assert!(
        serde_json::from_slice::<serde_json::Value>(&doctor.stdout)
            .expect("doctor JSON")
            .is_array()
    );
    let requests = run(&directory, &home, &["requests", "--json"]);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&requests.stdout).expect("requests JSON"),
        serde_json::json!([])
    );
    let cleared = run(&directory, &home, &["requests", "clear", "--json"]);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&cleared.stdout).expect("clear JSON")["closed"],
        true
    );
    run(&directory, &home, &["daemon", "reload", "--json"]);

    for args in [
        &["inspect", "00000000-0000-0000-0000-000000000000", "--json"][..],
        &["replay", "00000000-0000-0000-0000-000000000000", "--json"][..],
        &["share", "missing", "--expires", "5m", "--json"][..],
    ] {
        let failed = command(&directory, &home).args(args).output().expect("failure command");
        assert_eq!(failed.status.code(), Some(1), "{args:?}");
        assert!(failed.stdout.is_empty(), "{args:?}");
    }

    let key = run(&directory, &home, &["key", "show", "--json"]);
    assert!(String::from_utf8_lossy(&key.stdout).contains("fingerprint"));
    let rotated = run(&directory, &home, &["key", "rotate", "--json"]);
    assert!(String::from_utf8_lossy(&rotated.stdout).contains("old_fingerprint"));

    let added = run_config(
        &directory,
        &home,
        &config,
        &["remote", "add", "local", "localhost:443", "--json"],
    );
    assert!(String::from_utf8_lossy(&added.stdout).contains("local"));
    let listed = run_config(&directory, &home, &config, &["remote", "ls", "--json"]);
    assert!(String::from_utf8_lossy(&listed.stdout).contains("localhost:443"));
    run_config(&directory, &home, &config, &["remote", "rm", "local", "--json"]);
    let unknown = command(&directory, &home)
        .arg("--config")
        .arg(&config)
        .args(["remote", "rm", "missing", "--json"])
        .output()
        .expect("unknown remote");
    assert_eq!(unknown.status.code(), Some(2));

    for shell in ["bash", "fish", "zsh"] {
        let completions = run(&directory, &home, &["completions", shell]);
        assert!(!completions.stdout.is_empty());
        if shell == "zsh" {
            insta::assert_snapshot!(String::from_utf8_lossy(&completions.stdout));
        }
    }
    run(&directory, &home, &["daemon", "stop", "--json"]);
}

fn run(
    directory: &tempfile::TempDir,
    home: &std::path::Path,
    args: &[&str],
) -> std::process::Output {
    let output = command(directory, home).args(args).output().expect("command");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    output
}

fn run_config(
    directory: &tempfile::TempDir,
    home: &std::path::Path,
    config: &std::path::Path,
    args: &[&str],
) -> std::process::Output {
    let output =
        command(directory, home).arg("--config").arg(config).args(args).output().expect("command");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    output
}

fn command(directory: &tempfile::TempDir, home: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_wormhole"));
    command.env("WORMHOLE_STATE_DIR", directory.path().join("state")).env("HOME", home);
    command
}
