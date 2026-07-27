use std::{fs, process::Command};

#[test]
fn project_up_list_down_round_trip() {
    let directory = tempfile::tempdir().expect("tempdir");
    fs::create_dir(directory.path().join("home")).expect("home");
    fs::write(
        directory.path().join("wormhole.toml"),
        r#"
name = "project"
[aliases]
private-target = "127.0.0.1"
[[service]]
name = "web"
target = "private-target:3000"
proto = "http"
  [[service.endpoint]]
  driver = "mock"
  host = "project"
  persist = true
"#,
    )
    .expect("project config");

    run(&directory, &["up", "--json"]);
    let listed = run(&directory, &["ls", "--json"]);
    assert!(String::from_utf8_lossy(&listed.stdout).contains("project.mock.invalid"));
    run(&directory, &["down", "--json"]);
    let listed = run(&directory, &["ls", "--json"]);
    assert_eq!(String::from_utf8_lossy(&listed.stdout).trim(), "[]");
    run(&directory, &["down", "--forget", "--json"]);
    run(&directory, &["up", "--json"]);
    let restored = run(&directory, &["ls", "--json"]);
    assert!(String::from_utf8_lossy(&restored.stdout).contains("project.mock.invalid"));
    run(&directory, &["down", "--json"]);
    fs::write(directory.path().join("wormhole.toml"), "name = \"project\"\n")
        .expect("remove service");
    run(&directory, &["down", "web", "--forget", "--json"]);
    run(&directory, &["daemon", "stop", "--json"]);
}

#[test]
fn project_down_isolated_by_canonical_worktree() {
    let root = tempfile::tempdir().expect("tempdir");
    let first = root.path().join("first");
    let second = root.path().join("second");
    let home = root.path().join("home");
    fs::create_dir(&first).expect("first");
    fs::create_dir(&second).expect("second");
    fs::create_dir(&home).expect("home");
    for (path, name) in [(&first, "first"), (&second, "second")] {
        fs::write(
            path.join("wormhole.toml"),
            format!(
                "name = \"{name}\"\n[[service]]\nname = \"web\"\ntarget = \"3000\"\nproto = \"http\"\n[[service.endpoint]]\ndriver = \"mock\"\nhost = \"{name}\"\n"
            ),
        )
        .expect("config");
    }
    let state = root.path().join("state");
    run_at(&first, &state, &home, &["up", "--json"]);
    run_at(&second, &state, &home, &["up", "--json"]);
    run_at(&first, &state, &home, &["down", "--json"]);
    let listed = run_at(&second, &state, &home, &["ls", "--json"]);
    let endpoints: serde_json::Value = serde_json::from_slice(&listed.stdout).expect("JSON");
    assert_eq!(endpoints.as_array().expect("array").len(), 1);
    run_at(&second, &state, &home, &["daemon", "stop", "--json"]);
}

fn run(directory: &tempfile::TempDir, args: &[&str]) -> std::process::Output {
    run_at(directory.path(), &directory.path().join("state"), &directory.path().join("home"), args)
}

fn run_at(
    directory: &std::path::Path,
    state: &std::path::Path,
    home: &std::path::Path,
    args: &[&str],
) -> std::process::Output {
    let output = Command::new(env!("CARGO_BIN_EXE_wormhole"))
        .args(args)
        .current_dir(directory)
        .env("WORMHOLE_STATE_DIR", state)
        .env("WORMHOLE_ENABLE_MOCK_DRIVER", "1")
        .env("HOME", home)
        .output()
        .expect("command");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    output
}
