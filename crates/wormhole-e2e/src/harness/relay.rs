use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

use camino::Utf8PathBuf;

use super::binaries;
use crate::helpers::{curl_max_time, output_until, path, require_success, to_string};

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
        Ok(relay)
    }

    pub fn request(&self, host: &str, url: &str) -> Result<Output, String> {
        self.request_with(host, url, &[])
    }

    pub fn request_with(&self, host: &str, url: &str, extra: &[&str]) -> Result<Output, String> {
        self.request_with_until(host, url, extra, Instant::now() + Duration::from_secs(30))
    }

    pub fn request_until(
        &self,
        host: &str,
        url: &str,
        deadline: Instant,
    ) -> Result<Output, String> {
        self.request_with_until(host, url, &[], deadline)
    }

    fn request_with_until(
        &self,
        host: &str,
        url: &str,
        extra: &[&str],
        deadline: Instant,
    ) -> Result<Output, String> {
        let resolve = format!("{host}:{}:127.0.0.1", self.port);
        let max_time = curl_max_time(deadline)?;
        let mut command = Command::new("curl");
        command.args([
            "--silent",
            "--show-error",
            "--max-time",
            &max_time,
            "--cacert",
            path(&self.certificate)?,
            "--resolve",
            &resolve,
            "--write-out",
            "\n%{http_code}",
        ]);
        command.args(extra).arg(url);
        output_until(&mut command, deadline, "curl request")
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

    fn bound_ports(&self, deadline: Instant) -> Result<(u16, u16), String> {
        let binaries = binaries()?;
        let mut command = Command::new(&binaries.wormholed);
        command.args(["--config", path(&self.config)?, "status", "--json"]);
        let output = output_until(&mut command, deadline, "relay status")?;
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
            if socket.exists()
                && let Ok((quic_port, port)) = self.bound_ports(deadline)
            {
                self.quic_port = quic_port;
                self.port = port;
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
