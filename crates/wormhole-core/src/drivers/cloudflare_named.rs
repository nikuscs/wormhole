//! Named Cloudflare tunnel configuration helpers.

use std::{
    collections::HashSet,
    fmt::Write as _,
    fs::{File, OpenOptions},
    os::unix::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
};

use nix::fcntl::{Flock, FlockArg};

use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::{error::DriverError, model::ResolvedTarget};

#[derive(Default)]
pub struct HostClaims(parking_lot::Mutex<HashSet<String>>);

pub struct HostClaim<'a> {
    active: &'a parking_lot::Mutex<HashSet<String>>,
    host: String,
    _lock: Flock<File>,
}

impl HostClaims {
    pub fn claim<'a>(&'a self, home: &Path, host: &str) -> Result<HostClaim<'a>, DriverError> {
        if !self.0.lock().insert(host.to_owned()) {
            return Err(DriverError::Capability(format!(
                "cloudflare hostname {host} is already active in this process"
            )));
        }
        match lock_host(home, host) {
            Ok(lock) => Ok(HostClaim { active: &self.0, host: host.to_owned(), _lock: lock }),
            Err(error) => {
                self.0.lock().remove(host);
                Err(error)
            }
        }
    }
}

impl Drop for HostClaim<'_> {
    fn drop(&mut self) {
        self.active.lock().remove(&self.host);
    }
}

fn lock_host(home: &Path, host: &str) -> Result<Flock<File>, DriverError> {
    let path = home.join(format!(".{}.lock", deterministic_name(host)));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| DriverError::Transport(error.to_string()))?;
    Flock::lock(file, FlockArg::LockExclusiveNonblock).map_err(|(_, error)| {
        DriverError::Capability(format!(
            "cloudflare hostname {host} is active in another wormhole process: {error}"
        ))
    })
}

pub fn named_config(
    home: &std::path::Path,
    tunnel_id: &str,
    host: &str,
    target: ResolvedTarget,
    metrics_port: u16,
) -> String {
    let credentials = home.join(format!("{tunnel_id}.json"));
    format!(
        "tunnel: {tunnel_id}\ncredentials-file: {}\nmetrics: 127.0.0.1:{metrics_port}\ningress:\n  - hostname: {host}\n    service: http://{}\n  - service: http_status:404\n",
        credentials.display(),
        target.0
    )
}

pub fn ensure_named_login(home: &std::path::Path) -> Result<(), crate::DriverError> {
    let cert = home.join("cert.pem");
    if cert.is_file() {
        Ok(())
    } else {
        Err(crate::DriverError::Unavailable(
            "cloudflare named tunnel login missing; run `cloudflared tunnel login`".to_owned(),
        ))
    }
}

pub fn cloudflare_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from).map(|home| home.join(".cloudflared"))
}

pub fn route_is_owned(home: &std::path::Path, name: &str, host: &str) -> bool {
    std::fs::read_to_string(route_marker(home, name)).is_ok_and(|contents| {
        let mut lines = contents.lines();
        lines.next().is_some() && lines.next() == Some(host)
    })
}

pub fn forget_route(
    home: &std::path::Path,
    name: &str,
    host: &str,
) -> Result<(), crate::DriverError> {
    let marker = route_marker(home, name);
    if !route_is_owned(home, name, host) {
        return Ok(());
    }
    match std::fs::remove_file(marker) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(crate::DriverError::Transport(error.to_string())),
    }
}

pub fn record_route(
    home: &std::path::Path,
    name: &str,
    tunnel_id: &str,
    host: &str,
    target: ResolvedTarget,
) -> Result<(), crate::DriverError> {
    let marker = route_marker(home, name);
    let temporary = home.join(format!(".{name}-{}.route.tmp", uuid::Uuid::now_v7()));
    std::fs::write(&temporary, format!("{tunnel_id}\n{host}\n{}\n", target.0))
        .and_then(|()| std::fs::rename(&temporary, marker))
        .map_err(|error| crate::DriverError::Transport(error.to_string()))
}

fn route_marker(home: &std::path::Path, name: &str) -> PathBuf {
    home.join(format!("{name}.route"))
}

pub fn deterministic_name(host: &str) -> String {
    let label = host
        .chars()
        .map(|character| if character.is_ascii_alphanumeric() { character } else { '-' })
        .collect::<String>();
    let digest = Sha256::digest(host.as_bytes());
    let mut hash = String::with_capacity(12);
    for byte in &digest[..6] {
        write!(hash, "{byte:02x}").expect("writing to String cannot fail");
    }
    let max_label = 63_usize.saturating_sub("wormhole--".len() + hash.len());
    let label = label.chars().take(max_label).collect::<String>();
    format!("wormhole-{label}-{hash}")
}

pub fn find_uuid(input: &str) -> Option<String> {
    input
        .split(|character: char| !character.is_ascii_hexdigit() && character != '-')
        .find(|candidate| uuid::Uuid::parse_str(candidate).is_ok())
        .map(str::to_owned)
}

pub fn find_json_string(value: &Value, key: &str) -> Option<String> {
    value.as_array()?.first()?.get(key)?.as_str().map(str::to_owned)
}
