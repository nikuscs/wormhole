use std::{
    fs,
    io::{Read as _, Write as _},
    net::TcpStream,
    process::Command,
};

#[test]
#[ignore = "requires Node.js and npm"]
fn run_vite_app_exposes_public_url_to_client() {
    let fixture = Fixture::new();
    fixture.copy_vite_app();
    let install = Command::new("npm")
        .args(["ci", "--ignore-scripts", "--no-audit", "--no-fund"])
        .current_dir(fixture.directory.path())
        .output()
        .expect("install Vite");
    assert!(install.status.success(), "{}", String::from_utf8_lossy(&install.stderr));

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve port");
    let port = listener.local_addr().expect("local address").port();
    drop(listener);
    let port = port.to_string();
    let child = fixture
        .command(&[
            "run",
            "--endpoint",
            "mock",
            "--name",
            "vite-url",
            "--app-port",
            &port,
            "--",
            "npm",
            "run",
            "dev",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("launch Vite");
    let source = vite_source(port.parse().expect("port"));
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child.id().cast_signed()),
        nix::sys::signal::Signal::SIGINT,
    )
    .expect("interrupt Wormhole");
    let output = child.wait_with_output().expect("wait for Vite");
    fixture.stop();

    assert!(
        source.contains("https://endpoint.mock.invalid"),
        "Vite source did not contain the Wormhole URL: {source}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn run_wraps_port_aware_child() {
    let fixture = Fixture::new();
    let script = r"import os,socket,time
s=socket.socket(); s.bind(('127.0.0.1',int(os.environ['PORT']))); s.listen(); time.sleep(.2)";
    fixture.run(&["run", "--endpoint", "mock", "--name", "aware", "--", "python3", "-c", script]);
    fixture.stop();
}

#[test]
fn run_closes_exposure_when_child_cannot_spawn() {
    let fixture = Fixture::new();
    let output = fixture
        .command(&[
            "run",
            "--endpoint",
            "mock",
            "--name",
            "missing-child",
            "--",
            "/definitely/missing/wormhole-child",
        ])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("No such file"));
    let listed = fixture.command(&["ls", "--json"]).output().expect("ls");
    assert_eq!(String::from_utf8_lossy(&listed.stdout).trim(), "[]");
    fixture.stop();
}

#[test]
fn run_returns_partial_without_starting_child() {
    let fixture = Fixture::new();
    let marker = fixture.directory.path().join("started");
    let output = fixture
        .command(&[
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
            &format!("touch {}", marker.display()),
        ])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(6));
    assert!(!marker.exists());
    fixture.stop();
}

#[test]
fn run_sigint_kills_child_and_closes_endpoint() {
    let fixture = Fixture::new();
    let pid_file = fixture.directory.path().join("child.pid");
    let grandchild_file = fixture.directory.path().join("grandchild.pid");
    let script = format!(
        "import os,socket,subprocess,time; p=subprocess.Popen(['python3','-c','import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)']); open({pid_file:?},'w').write(str(os.getpid())); open({grandchild_file:?},'w').write(str(p.pid)); s=socket.socket(); s.bind(('127.0.0.1',int(os.environ['PORT']))); s.listen(); time.sleep(30)"
    );
    let mut child = fixture
        .command(&[
            "run",
            "--endpoint",
            "mock",
            "--name",
            "interrupt",
            "--",
            "python3",
            "-c",
            &script,
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("wrapper");
    wait_for_file(&pid_file);
    wait_for_file(&grandchild_file);
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child.id().cast_signed()),
        nix::sys::signal::Signal::SIGINT,
    )
    .expect("SIGINT");
    let status = wait_for_child(&mut child);
    assert_eq!(status.code(), Some(130));
    let child_pid = fs::read_to_string(&pid_file).expect("pid").parse::<i32>().expect("pid int");
    wait_for_process_exit(child_pid);
    let grandchild_pid = fs::read_to_string(&grandchild_file)
        .expect("grandchild pid")
        .parse::<i32>()
        .expect("grandchild pid int");
    wait_for_process_exit(grandchild_pid);
    let listed = fixture.command(&["ls", "--json"]).output().expect("ls");
    assert_eq!(String::from_utf8_lossy(&listed.stdout).trim(), "[]");
    fixture.stop();
}

#[test]
fn run_mirrors_signaled_child_status() {
    let fixture = Fixture::new();
    let script = "import os,signal; os.kill(os.getpid(), signal.SIGTERM)";
    let output = fixture
        .command(&[
            "run",
            "--endpoint",
            "mock",
            "--name",
            "signaled",
            "--",
            "python3",
            "-c",
            script,
        ])
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(143));
    fixture.stop();
}

#[test]
fn natural_exit_kills_remaining_process_group() {
    let fixture = Fixture::new();
    let grandchild_file = fixture.directory.path().join("natural-grandchild.pid");
    let ready_file = fixture.directory.path().join("natural-grandchild.ready");
    let grandchild = format!(
        "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); open({ready_file:?},'w').write('ready'); time.sleep(30)"
    );
    let script = format!(
        "import os,socket,subprocess,time; s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(); p=subprocess.Popen(['python3','-c',{grandchild:?}]); open({grandchild_file:?},'w').write(str(p.pid));\nwhile not os.path.exists({ready_file:?}): time.sleep(.01)\ntime.sleep(.5)"
    );
    let output = fixture
        .command(&[
            "run",
            "--endpoint",
            "mock",
            "--name",
            "natural",
            "--",
            "python3",
            "-c",
            &script,
        ])
        .output()
        .expect("run");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let pid = fs::read_to_string(&grandchild_file)
        .expect("grandchild pid")
        .parse::<i32>()
        .expect("grandchild pid int");
    wait_for_process_exit(pid);
    fixture.stop();
}

#[test]
fn run_detects_child_that_ignores_port() {
    let fixture = Fixture::new();
    let script =
        "import socket,time; s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(); time.sleep(3)";
    fixture.run(&[
        "run",
        "--endpoint",
        "mock",
        "--name",
        "fallback",
        "--",
        "python3",
        "-c",
        script,
    ]);
    fixture.stop();
}

fn vite_source(port: u16) -> String {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        if let Ok(mut stream) = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)) {
            let _written =
                stream.write_all(b"GET /src/main.js HTTP/1.1\r\nHost: localhost\r\n\r\n");
            let mut response = String::new();
            let _read = stream.read_to_string(&mut response);
            if response.contains("200 OK") {
                return response;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    String::new()
}

fn wait_for_file(path: &std::path::Path) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while fs::metadata(path).map_or(true, |metadata| metadata.len() == 0) {
        assert!(std::time::Instant::now() < deadline, "child pid file missing");
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
}

fn wait_for_child(child: &mut std::process::Child) -> std::process::ExitStatus {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().expect("try wait") {
            return status;
        }
        assert!(std::time::Instant::now() < deadline, "wrapper did not exit");
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
}

fn wait_for_process_exit(pid: i32) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_err() {
            return;
        }
        assert!(std::time::Instant::now() < deadline, "child remained alive");
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
}

struct Fixture {
    directory: tempfile::TempDir,
}

impl Drop for Fixture {
    /// Stops the auto-spawned daemon before the isolated state directory disappears.
    ///
    /// Without this, a test that panics before calling `stop` leaves a detached daemon running
    /// against a deleted state directory, where it survives the test run indefinitely.
    fn drop(&mut self) {
        let _stopped = self
            .command(&["daemon", "stop", "--json"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("tempdir");
        fs::create_dir(directory.path().join("home")).expect("home");
        Self { directory }
    }

    fn copy_vite_app(&self) {
        let fixture =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vite-app");
        fs::create_dir(self.directory.path().join("src")).expect("create source directory");
        for path in ["package.json", "package-lock.json", "index.html", "src/main.js"] {
            fs::copy(fixture.join(path), self.directory.path().join(path))
                .expect("copy Vite fixture");
        }
    }

    fn run(&self, args: &[&str]) {
        let output = self.command(args).output().expect("run");
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        assert!(String::from_utf8_lossy(&output.stdout).contains("mock.invalid"));
    }

    fn stop(&self) {
        let output = self.command(&["daemon", "stop", "--json"]).output().expect("stop");
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_wormhole"));
        command
            .args(args)
            .current_dir(self.directory.path())
            .env("WORMHOLE_STATE_DIR", self.directory.path().join("state"))
            .env("WORMHOLE_ENABLE_MOCK_DRIVER", "1")
            .env("WORMHOLE_RUN_LISTEN_TIMEOUT_MS", "100")
            .env("WORMHOLE_RUN_DETECT_TIMEOUT_MS", "3000")
            .env("HOME", self.directory.path().join("home"));
        command
    }
}
