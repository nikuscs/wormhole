use std::{fs, process::Command};

#[test]
fn run_wraps_port_aware_child() {
    let fixture = Fixture::new();
    let script = r"import os,socket,time
s=socket.socket(); s.bind(('127.0.0.1',int(os.environ['PORT']))); s.listen(); time.sleep(.2)";
    fixture.run(&["run", "--endpoint", "mock", "--name", "aware", "--", "python3", "-c", script]);
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
        "import subprocess,time; p=subprocess.Popen(['python3','-c',{grandchild:?}]); open({grandchild_file:?},'w').write(str(p.pid));\nwhile not __import__('os').path.exists({ready_file:?}): time.sleep(.01)"
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
    let script = "python3 -m http.server 0 --bind 127.0.0.1 >/dev/null 2>&1 & p=$!; sleep 1; kill $p; wait $p || true";
    fixture.run(&["run", "--endpoint", "mock", "--name", "fallback", "--", "sh", "-c", script]);
    fixture.stop();
}

fn wait_for_file(path: &std::path::Path) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !path.exists() {
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

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("tempdir");
        fs::create_dir(directory.path().join("home")).expect("home");
        Self { directory }
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
            .env("WORMHOLE_STATE_DIR", self.directory.path().join("state"))
            .env("WORMHOLE_ENABLE_MOCK_DRIVER", "1")
            .env("WORMHOLE_RUN_LISTEN_TIMEOUT_MS", "100")
            .env("WORMHOLE_RUN_DETECT_TIMEOUT_MS", "3000")
            .env("HOME", self.directory.path().join("home"));
        command
    }
}
