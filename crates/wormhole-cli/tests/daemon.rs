use std::{
    fs,
    io::{Read as _, Write as _},
    os::unix::{fs::PermissionsExt as _, net::UnixStream},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use nix::{sys::signal::Signal, unistd::Pid};

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _killed = self.0.kill();
        let _waited = self.0.wait();
    }
}

#[test]
fn foreground_daemon_authenticates_locks_and_drains_sigterm() {
    let directory = tempfile::tempdir().expect("tempdir");
    let state = directory.path().join("state");
    let home = directory.path().join("home");
    fs::create_dir(&home).expect("home");
    let binary = env!("CARGO_BIN_EXE_wormhole");
    let child = Command::new(binary)
        .args(["daemon", "run"])
        .env("WORMHOLE_STATE_DIR", &state)
        .env("HOME", &home)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn daemon");
    let mut child = ChildGuard(child);
    let socket = state.join("daemon.sock");
    wait_for_path(&socket);
    let token = fs::read_to_string(state.join("api-token")).expect("token");

    let unauthorized = request(&socket, None);
    assert!(unauthorized.starts_with("HTTP/1.1 401"));
    let authorized = request(&socket, Some(&token));
    assert!(authorized.starts_with("HTTP/1.1 200"));
    assert!(authorized.contains("\"pid\""));
    assert_eq!(fs::metadata(&socket).expect("socket mode").permissions().mode() & 0o777, 0o600);

    let second = Command::new(binary)
        .args(["daemon", "run"])
        .env("WORMHOLE_STATE_DIR", &state)
        .env("HOME", &home)
        .output()
        .expect("second daemon");
    assert!(!second.status.success());

    nix::sys::signal::kill(Pid::from_raw(child.0.id().cast_signed()), Signal::SIGTERM)
        .expect("SIGTERM");
    wait_for_exit(&mut child.0);
}

fn request(socket: &std::path::Path, token: Option<&str>) -> String {
    let mut stream = UnixStream::connect(socket).expect("connect");
    let authorization =
        token.map_or_else(String::new, |token| format!("Authorization: Bearer {token}\r\n"));
    write!(
        stream,
        "GET /v1/status HTTP/1.1\r\nHost: localhost\r\n{authorization}Connection: close\r\n\r\n"
    )
    .expect("write request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");
    response
}

fn wait_for_path(path: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !path.exists() {
        assert!(Instant::now() < deadline, "daemon socket did not appear");
        thread::sleep(Duration::from_millis(25));
    }
}

fn wait_for_exit(child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if child.try_wait().expect("try_wait").is_some() {
            return;
        }
        assert!(Instant::now() < deadline, "daemon did not exit after SIGTERM");
        thread::sleep(Duration::from_millis(25));
    }
}
