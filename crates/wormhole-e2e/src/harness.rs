//! Real-binary end-to-end harness with isolated relay and client state.

use std::{
    fmt::Write as _,
    io::{Read as _, Write as _},
    net::{Ipv4Addr, SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::OnceLock,
    time::{Duration, Instant},
};

use camino::Utf8PathBuf;
use sha2::{Digest as _, Sha256};
use wormhole_proto::Identity;

use crate::helpers::{path, require_success, to_string};

#[derive(Debug, Clone)]
pub struct Binaries {
    pub wormhole: PathBuf,
    pub wormholed: PathBuf,
}

pub fn binaries() -> Result<&'static Binaries, String> {
    static BINARIES: OnceLock<Result<Binaries, String>> = OnceLock::new();
    BINARIES.get_or_init(build_binaries).as_ref().map_err(Clone::clone)
}

fn build_binaries() -> Result<Binaries, String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = Command::new(&cargo)
        .args(["build", "-p", "wormhole-cli", "-p", "wormholed"])
        .status()
        .map_err(|error| error.to_string())?;
    if !status.success() {
        return Err("building e2e binaries failed".to_owned());
    }
    let output = Command::new(cargo)
        .args(["metadata", "--format-version=1", "--no-deps"])
        .output()
        .map_err(|error| error.to_string())?;
    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).map_err(|error| error.to_string())?;
    let target = metadata
        .get("target_directory")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "metadata has no target_directory".to_owned())?;
    let suffix = std::env::consts::EXE_SUFFIX;
    Ok(Binaries {
        wormhole: PathBuf::from(target).join("debug").join(format!("wormhole{suffix}")),
        wormholed: PathBuf::from(target).join("debug").join(format!("wormholed{suffix}")),
    })
}

pub struct TestClient {
    pub(crate) directory: tempfile::TempDir,
    pub(crate) home: PathBuf,
    pub(crate) state: PathBuf,
    pub(crate) config: PathBuf,
    identity: Identity,
}

impl TestClient {
    pub fn isolated() -> Result<Self, String> {
        let directory = tempfile::tempdir().map_err(to_string)?;
        let home = directory.path().join("home");
        let state = directory.path().join("state");
        std::fs::create_dir_all(&state).map_err(to_string)?;
        let identity = Identity::generate();
        let key = home.join(".config/wormhole/keys/identity.key");
        identity
            .save(camino::Utf8Path::from_path(&key).ok_or("non-UTF8 key path")?)
            .map_err(to_string)?;
        let config = directory.path().join("client.toml");
        Ok(Self { directory, home, state, config, identity })
    }

    pub fn public_key(&self) -> String {
        self.identity.public_base64()
    }

    pub fn fingerprint(&self) -> String {
        self.identity.fingerprint()
    }

    pub fn configure(&self, relay: &TestRelay) -> Result<(), String> {
        let trusted_ca = relay.certificate.to_string_lossy().replace('\\', "\\\\");
        std::fs::write(
            &self.config,
            format!(
                "default_remote = \"test\"\n[remotes.test]\naddr = \"127.0.0.1:{}\"\nhttps_addr = \"127.0.0.1:{}\"\nserver_name = \"wormhole.test\"\ntrusted_ca = \"{trusted_ca}\"\n[defaults]\ndrivers = [\"wormhole\"]\ninspect = true\n",
                relay.quic_port,
                relay.port
            ),
        )
        .map_err(to_string)
    }

    pub fn configure_two(&self, first: &TestRelay, second: &TestRelay) -> Result<(), String> {
        let first_ca = first.certificate.to_string_lossy().replace('\\', "\\\\");
        let second_ca = second.certificate.to_string_lossy().replace('\\', "\\\\");
        std::fs::write(
            &self.config,
            format!(
                "default_remote = \"first\"\n[remotes.first]\naddr = \"127.0.0.1:{}\"\nhttps_addr = \"127.0.0.1:{}\"\nserver_name = \"wormhole.test\"\ntrusted_ca = \"{first_ca}\"\n[remotes.second]\naddr = \"127.0.0.1:{}\"\nhttps_addr = \"127.0.0.1:{}\"\nserver_name = \"wormhole.test\"\ntrusted_ca = \"{second_ca}\"\n[defaults]\ndrivers = [\"wormhole\"]\ninspect = true\n",
                first.quic_port,
                first.port,
                second.quic_port,
                second.port
            ),
        )
        .map_err(to_string)
    }

    pub fn write_project(&self, contents: &str) -> Result<(), String> {
        std::fs::write(self.directory.path().join("wormhole.toml"), contents).map_err(to_string)
    }

    pub fn command(&self, args: &[&str]) -> Result<Output, String> {
        let binaries = binaries()?;
        Command::new(&binaries.wormhole)
            .args(args)
            .current_dir(self.directory.path())
            .env("HOME", &self.home)
            .env("WORMHOLE_CONFIG", &self.config)
            .env("WORMHOLE_STATE_DIR", &self.state)
            .env("WORMHOLE_ENABLE_MOCK_DRIVER", "1")
            .output()
            .map_err(to_string)
    }

    pub fn daemon_log(&self) -> String {
        std::fs::read_to_string(self.state.join("daemon.log")).unwrap_or_default()
    }

    pub fn expose_http(
        &self,
        port: u16,
        extra: &[&str],
    ) -> Result<Vec<wormhole_core::ActiveEndpoint>, String> {
        let port = port.to_string();
        let mut args = vec!["--json", "http", port.as_str(), "--remote", "test"];
        args.extend_from_slice(extra);
        let output = self.command(&args)?;
        require_success("expose HTTP", &output)?;
        serde_json::from_slice(&output.stdout).map_err(to_string)
    }

    pub fn expose_tcp(
        &self,
        port: u16,
        public_port: u16,
    ) -> Result<Vec<wormhole_core::ActiveEndpoint>, String> {
        let port = port.to_string();
        let public_port = public_port.to_string();
        let output = self.command(&[
            "--json",
            "tcp",
            port.as_str(),
            "--remote",
            "test",
            "--public-port",
            public_port.as_str(),
        ])?;
        require_success("expose TCP", &output)?;
        serde_json::from_slice(&output.stdout).map_err(to_string)
    }

    pub fn kill_daemon(&self) -> Result<(), String> {
        let status = self.command(&["--json", "status"])?;
        require_success("daemon status", &status)?;
        let value: serde_json::Value = serde_json::from_slice(&status.stdout).map_err(to_string)?;
        let pid = value
            .get("pid")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| "daemon status has no pid".to_owned())?;
        let killed =
            Command::new("kill").args(["-9", &pid.to_string()]).output().map_err(to_string)?;
        require_success("kill daemon", &killed)
    }

    pub fn stop_daemon(&self) {
        let _ignored = self.command(&["daemon", "stop"]);
    }
}

impl Drop for TestClient {
    fn drop(&mut self) {
        self.stop_daemon();
    }
}

pub struct TestRelay {
    directory: tempfile::TempDir,
    pub(crate) process: Child,
    pub port: u16,
    pub(crate) quic_port: u16,
    pub certificate: PathBuf,
    pub(crate) config: PathBuf,
}

impl TestRelay {
    pub fn start(public_key: &str) -> Result<Self, String> {
        let binaries = binaries()?;
        let directory = tempfile::tempdir().map_err(to_string)?;
        let data_dir = directory.path().join("data");
        let keys = directory.path().join("authorized_keys");
        std::fs::create_dir_all(&data_dir).map_err(to_string)?;
        std::fs::create_dir_all(&keys).map_err(to_string)?;
        let generated = rcgen::generate_simple_self_signed(vec![
            "wormhole.test".to_owned(),
            "*.wormhole.test".to_owned(),
        ])
        .map_err(to_string)?;
        let certificate = directory.path().join("fullchain.pem");
        let private_key = directory.path().join("private-key.pem");
        std::fs::write(&certificate, generated.cert.pem()).map_err(to_string)?;
        std::fs::write(&private_key, generated.signing_key.serialize_pem()).map_err(to_string)?;
        let config = directory.path().join("wormholed.toml");
        let config_value = relay_config(&data_dir, &keys, &certificate, &private_key)?;
        std::fs::write(&config, config_value).map_err(to_string)?;
        let authorized = Command::new(&binaries.wormholed)
            .args(["--config", path(&config)?, "key", "authorize", public_key, "--name", "e2e"])
            .output()
            .map_err(to_string)?;
        require_success("authorize key", &authorized)?;
        let process = Command::new(&binaries.wormholed)
            .args(["--config", path(&config)?, "serve"])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(to_string)?;
        let mut relay = Self { directory, process, port: 0, quic_port: 0, certificate, config };
        relay.wait_ready()?;
        (relay.quic_port, relay.port) = relay.bound_ports()?;
        Ok(relay)
    }

    pub fn request(&self, host: &str, url: &str) -> Result<Output, String> {
        self.request_with(host, url, &[])
    }

    pub fn request_with(&self, host: &str, url: &str, extra: &[&str]) -> Result<Output, String> {
        let resolve = format!("{host}:{}:127.0.0.1", self.port);
        let mut command = Command::new("curl");
        command.args([
            "--silent",
            "--show-error",
            "--cacert",
            path(&self.certificate)?,
            "--resolve",
            &resolve,
            "--write-out",
            "\n%{http_code}",
        ]);
        command.args(extra).arg(url).output().map_err(to_string)
    }

    pub fn config(&self) -> &Path {
        &self.config
    }

    pub fn revoke(&self, fingerprint: &str) -> Result<(), String> {
        let binaries = binaries()?;
        let output = Command::new(&binaries.wormholed)
            .args(["--config", path(&self.config)?, "key", "revoke", fingerprint])
            .output()
            .map_err(to_string)?;
        require_success("revoke key", &output)
    }

    fn bound_ports(&self) -> Result<(u16, u16), String> {
        let binaries = binaries()?;
        let output = Command::new(&binaries.wormholed)
            .args(["--config", path(&self.config)?, "status", "--json"])
            .output()
            .map_err(to_string)?;
        require_success("relay status", &output)?;
        let status: serde_json::Value =
            serde_json::from_slice(&output.stdout).map_err(to_string)?;
        let port = |field: &str| -> Result<u16, String> {
            let address = status[field].as_str().ok_or_else(|| format!("status has no {field}"))?;
            address.parse::<SocketAddr>().map(|address| address.port()).map_err(to_string)
        };
        Ok((port("quic_addr")?, port("https_addr")?))
    }

    fn wait_ready(&mut self) -> Result<(), String> {
        let socket = self.directory.path().join("data/admin.sock");
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if socket.exists() && self.bound_ports().is_ok() {
                return Ok(());
            }
            if let Some(status) = self.process.try_wait().map_err(to_string)? {
                return Err(format!("relay exited before ready: {status}"));
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        Err("relay readiness timed out".to_owned())
    }
}

impl Drop for TestRelay {
    fn drop(&mut self) {
        let _ignored = self.process.kill();
        let _ignored = self.process.wait();
    }
}

pub struct TcpEchoServer {
    listener: TcpListener,
    address: SocketAddr,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    task: Option<std::thread::JoinHandle<()>>,
}

impl TcpEchoServer {
    pub fn start() -> Result<Self, String> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(to_string)?;
        listener.set_nonblocking(true).map_err(to_string)?;
        let address = listener.local_addr().map_err(to_string)?;
        let worker = listener.try_clone().map_err(to_string)?;
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_worker = std::sync::Arc::clone(&stop);
        let task = std::thread::spawn(move || {
            while !stop_worker.load(std::sync::atomic::Ordering::Acquire) {
                match worker.accept() {
                    Ok((mut stream, _)) => {
                        let mut bytes = Vec::new();
                        let _read = stream.read_to_end(&mut bytes);
                        let _write = stream.write_all(&bytes);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self { listener, address, stop, task: Some(task) })
    }

    pub const fn port(&self) -> u16 {
        self.address.port()
    }
}

impl Drop for TcpEchoServer {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        let _wake = std::net::TcpStream::connect(self.address);
        if let Some(task) = self.task.take() {
            let _joined = task.join();
        }
        let _ = &self.listener;
    }
}

pub struct EchoServer {
    listener: TcpListener,
    address: SocketAddr,
    requests: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    task: Option<std::thread::JoinHandle<()>>,
}

impl EchoServer {
    pub fn start() -> Result<Self, String> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(to_string)?;
        listener.set_nonblocking(true).map_err(to_string)?;
        let address = listener.local_addr().map_err(to_string)?;
        let worker = listener.try_clone().map_err(to_string)?;
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let stop_worker = std::sync::Arc::clone(&stop);
        let request_worker = std::sync::Arc::clone(&requests);
        let task = std::thread::spawn(move || serve_echo(worker, stop_worker, request_worker));
        Ok(Self { listener, address, requests, stop, task: Some(task) })
    }

    pub const fn port(&self) -> u16 {
        self.address.port()
    }

    pub fn request_count(&self) -> usize {
        self.requests.load(std::sync::atomic::Ordering::Acquire)
    }
}

impl Drop for EchoServer {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        let _wake = std::net::TcpStream::connect(self.address);
        if let Some(task) = self.task.take() {
            let _joined = task.join();
        }
        let _ = &self.listener;
    }
}

fn serve_echo(
    listener: TcpListener,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    requests: std::sync::Arc<std::sync::atomic::AtomicUsize>,
) {
    let runtime = tokio::runtime::Runtime::new().expect("echo runtime");
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::from_std(listener).expect("echo listener");
        while !stop.load(std::sync::atomic::Ordering::Acquire) {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let requests = std::sync::Arc::clone(&requests);
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |request| {
                    handle_echo(request, std::sync::Arc::clone(&requests))
                });
                let _served = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                    .await;
            });
        }
    });
}

async fn handle_echo(
    request: hyper::Request<hyper::body::Incoming>,
    requests: std::sync::Arc<std::sync::atomic::AtomicUsize>,
) -> Result<hyper::Response<http_body_util::Full<bytes::Bytes>>, std::convert::Infallible> {
    use http_body_util::BodyExt as _;
    requests.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    let (parts, body) = request.into_parts();
    let body = body
        .collect()
        .await
        .map_or_else(|_| bytes::Bytes::new(), http_body_util::Collected::to_bytes);
    let digest = Sha256::digest(&body);
    let mut hash = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut hash, "{byte:02x}").expect("writing to String cannot fail");
    }
    let body = serde_json::json!({
        "method": parts.method.as_str(),
        "uri": parts.uri.to_string(),
        "request_hash": hash,
    })
    .to_string();
    Ok(hyper::Response::new(http_body_util::Full::new(bytes::Bytes::from(body))))
}

fn relay_config(
    data_dir: &Path,
    keys: &Path,
    certificate: &Path,
    private_key: &Path,
) -> Result<String, String> {
    let data = Utf8PathBuf::from_path_buf(data_dir.to_owned()).map_err(|_| "non-UTF8 data dir")?;
    let keys = Utf8PathBuf::from_path_buf(keys.to_owned()).map_err(|_| "non-UTF8 key dir")?;
    let certificate =
        Utf8PathBuf::from_path_buf(certificate.to_owned()).map_err(|_| "non-UTF8 certificate")?;
    let private_key =
        Utf8PathBuf::from_path_buf(private_key.to_owned()).map_err(|_| "non-UTF8 private key")?;
    let config = wormholed::config::WormholedConfig {
        server: wormholed::config::ServerConfig {
            domains: vec!["wormhole.test".to_owned()],
            public_https_port: None,
            quic_addr: "127.0.0.1:0".parse().map_err(to_string)?,
            https_addr: "127.0.0.1:0".parse().map_err(to_string)?,
            http_addr: "127.0.0.1:0".parse().map_err(to_string)?,
            data_dir: data,
        },
        tls: wormholed::config::TlsConfig {
            mode: wormholed::config::TlsMode::Static,
            static_config: Some(wormholed::config::StaticTlsConfig {
                certs: vec![wormholed::config::StaticCertificate {
                    domain: "wormhole.test".to_owned(),
                    cert: certificate,
                    key: private_key,
                }],
            }),
            acme: None,
        },
        tcp: wormholed::config::TcpConfig {
            port_range: wormholed::config::PortRange { start: 24_000, end: 24_100 },
        },
        limits: wormholed::config::LimitsConfig::default(),
        auth: wormholed::config::AuthConfig { authorized_keys: keys },
    };
    toml::to_string_pretty(&config).map_err(to_string)
}
