use std::{path::PathBuf, process::Output, time::Instant};

use wormhole_proto::Identity;

use super::{TestRelay, binaries};
use crate::helpers::{output_until, require_success, to_string};

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
                relay.quic_port, relay.port
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
                first.quic_port, first.port, second.quic_port, second.port
            ),
        )
        .map_err(to_string)
    }

    pub fn write_project(&self, contents: &str) -> Result<(), String> {
        std::fs::write(self.directory.path().join("wormhole.toml"), contents).map_err(to_string)
    }

    pub fn command(&self, args: &[&str]) -> Result<Output, String> {
        let binaries = binaries()?;
        std::process::Command::new(&binaries.wormhole)
            .args(args)
            .current_dir(self.directory.path())
            .env("HOME", &self.home)
            .env("WORMHOLE_CONFIG", &self.config)
            .env("WORMHOLE_STATE_DIR", &self.state)
            .env("WORMHOLE_ENABLE_MOCK_DRIVER", "1")
            .output()
            .map_err(to_string)
    }

    pub fn command_until(&self, args: &[&str], deadline: Instant) -> Result<Output, String> {
        let binaries = binaries()?;
        let mut command = std::process::Command::new(&binaries.wormhole);
        command
            .args(args)
            .current_dir(self.directory.path())
            .env("HOME", &self.home)
            .env("WORMHOLE_CONFIG", &self.config)
            .env("WORMHOLE_STATE_DIR", &self.state)
            .env("WORMHOLE_ENABLE_MOCK_DRIVER", "1");
        output_until(&mut command, deadline, "wormhole command")
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

    pub fn expose_tcp(&self, port: u16) -> Result<Vec<wormhole_core::ActiveEndpoint>, String> {
        let port = port.to_string();
        let output = self.command(&["--json", "tcp", port.as_str(), "--remote", "test"])?;
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
        let killed = std::process::Command::new("kill")
            .args(["-9", &pid.to_string()])
            .output()
            .map_err(to_string)?;
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
