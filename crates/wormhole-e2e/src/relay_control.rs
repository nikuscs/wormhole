use std::{
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use crate::{
    harness::{TestRelay, binaries},
    helpers::{path, to_string},
};

impl TestRelay {
    pub fn kill(&mut self) -> Result<(), String> {
        self.process.kill().map_err(to_string)?;
        self.process.wait().map_err(to_string)?;
        Ok(())
    }

    pub fn restart_same_ports(&mut self) -> Result<(), String> {
        let config = std::fs::read_to_string(&self.config).map_err(to_string)?;
        let config = config
            .replace(
                "quic_addr = \"127.0.0.1:0\"",
                &format!("quic_addr = \"127.0.0.1:{}\"", self.quic_port),
            )
            .replace(
                "https_addr = \"127.0.0.1:0\"",
                &format!("https_addr = \"127.0.0.1:{}\"", self.port),
            );
        std::fs::write(&self.config, config).map_err(to_string)?;
        let binaries = binaries()?;
        self.process = Command::new(&binaries.wormholed)
            .args(["--config", path(&self.config)?, "serve"])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(to_string)?;
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if std::net::TcpStream::connect(("127.0.0.1", self.port)).is_ok() {
                return Ok(());
            }
            if self.process.try_wait().map_err(to_string)?.is_some() {
                return Err("relay exited during restart".to_owned());
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        Err("relay restart timed out".to_owned())
    }
}
