//! Tailscale Serve state comparison and scoped cleanup.

use std::{
    collections::HashSet,
    fmt::Write as _,
    fs::{File, OpenOptions},
    os::unix::fs::OpenOptionsExt as _,
    path::Path,
    sync::Arc,
};

use nix::fcntl::{Flock, FlockArg};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::{
    drivers::tailscale::{CommandResult, TailscaleApi},
    error::DriverError,
    model::{EndpointSpec, ResolvedTarget, ServiceProto},
};

use super::process::wait_healthy;

#[derive(Default)]
pub struct ActiveBindings(parking_lot::Mutex<HashSet<String>>);

pub struct BindingClaim<'a> {
    active: &'a parking_lot::Mutex<HashSet<String>>,
    key: String,
    _lock: Option<Flock<File>>,
}

impl ActiveBindings {
    pub fn claim(
        &self,
        directory: Option<&Path>,
        key: String,
    ) -> Result<BindingClaim<'_>, DriverError> {
        if !self.0.lock().insert(key.clone()) {
            return Err(DriverError::Capability(
                "tailscale binding is already active in this process".to_owned(),
            ));
        }
        match lock_binding(directory, &key) {
            Ok(lock) => Ok(BindingClaim { active: &self.0, key, _lock: lock }),
            Err(error) => {
                self.0.lock().remove(&key);
                Err(error)
            }
        }
    }
}

fn lock_binding(directory: Option<&Path>, key: &str) -> Result<Option<Flock<File>>, DriverError> {
    let Some(directory) = directory else {
        return Ok(None);
    };
    std::fs::create_dir_all(directory)
        .map_err(|error| DriverError::Transport(error.to_string()))?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(directory.join(format!("binding-{key}.lock")))
        .map_err(|error| DriverError::Transport(error.to_string()))?;
    Flock::lock(file, FlockArg::LockExclusiveNonblock).map(Some).map_err(|(_, error)| {
        DriverError::Capability(format!(
            "tailscale public port {key} is active in another wormhole process: {error}"
        ))
    })
}

impl Drop for BindingClaim<'_> {
    fn drop(&mut self) {
        self.active.lock().remove(&self.key);
    }
}

pub async fn serve_status(api: &Arc<dyn TailscaleApi>) -> Result<CommandResult, DriverError> {
    api.command(&strings(["serve", "status", "--json"])).await
}

pub async fn verify_install(
    api: &Arc<dyn TailscaleApi>,
    target: &str,
) -> Result<CommandResult, DriverError> {
    wait_installed(api, target).await?;
    let status = serve_status(api).await?;
    require_success(&status, "tailscale serve status")?;
    Ok(status)
}

pub async fn reject_conflict(
    api: &Arc<dyn TailscaleApi>,
    spec: &EndpointSpec,
    target: ResolvedTarget,
    owned: bool,
) -> Result<(), DriverError> {
    let status = serve_status(api).await?;
    require_success(&status, "tailscale serve status")?;
    validate_status_json(&status.stdout)?;
    let target_text = target_text(spec, target);
    if let Some(binding) = binding_snapshot(&status.stdout, spec, target) {
        if !binding.contains(&target_text) {
            return Err(DriverError::Capability(format!(
                "tailscale public binding conflicts with requested target; existing={binding}; requested={target_text}"
            )));
        }
        if !owned {
            return Err(DriverError::Capability(format!(
                "tailscale binding already exists but is not owned by wormhole: {binding}"
            )));
        }
    }
    Ok(())
}

pub fn owns_binding(
    directory: &Path,
    mode: &str,
    spec: &EndpointSpec,
    target: ResolvedTarget,
) -> bool {
    let key = ownership_key(mode, spec, target);
    std::fs::read_to_string(ownership_path(directory, &key)).is_ok_and(|stored| stored == key)
}

pub fn record_ownership(
    directory: &Path,
    mode: &str,
    spec: &EndpointSpec,
    target: ResolvedTarget,
) -> Result<(), DriverError> {
    std::fs::create_dir_all(directory)
        .map_err(|error| DriverError::Transport(error.to_string()))?;
    let key = ownership_key(mode, spec, target);
    let temporary = directory.join(format!(".{}.tmp", uuid::Uuid::now_v7()));
    std::fs::write(&temporary, &key)
        .and_then(|()| std::fs::rename(&temporary, ownership_path(directory, &key)))
        .map_err(|error| DriverError::Transport(error.to_string()))
}

pub fn forget_ownership(
    directory: &Path,
    mode: &str,
    spec: &EndpointSpec,
    target: ResolvedTarget,
) -> Result<(), DriverError> {
    let key = ownership_key(mode, spec, target);
    match std::fs::remove_file(ownership_path(directory, &key)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(DriverError::Transport(error.to_string())),
    }
}

pub async fn cleanup_if_unchanged(
    api: &Arc<dyn TailscaleApi>,
    mode: &str,
    spec: &EndpointSpec,
    target: ResolvedTarget,
    installed_state: &CommandResult,
) -> Result<bool, DriverError> {
    let status = serve_status(api).await?;
    require_success(&status, "tailscale serve status")?;
    let target_text = target_text(spec, target);
    validate_status_json(&status.stdout)?;
    let current = binding_snapshot(&status.stdout, spec, target);
    let installed = binding_snapshot(&installed_state.stdout, spec, target);
    if current.is_none() {
        return Ok(true);
    }
    if current == installed && current.is_some_and(|state| state.contains(&target_text)) {
        remove_install(api, mode, spec, target).await?;
        return Ok(true);
    }
    Ok(false)
}

pub async fn remove_install(
    api: &Arc<dyn TailscaleApi>,
    mode: &str,
    spec: &EndpointSpec,
    target: ResolvedTarget,
) -> Result<(), DriverError> {
    let args = if spec.proto == ServiceProto::Tcp {
        vec![
            mode.to_owned(),
            format!("--tcp={}", spec.public_port.unwrap_or_else(|| target.0.port())),
            "off".to_owned(),
        ]
    } else if let Some(port) = spec.public_port {
        vec![mode.to_owned(), format!("--https={port}"), "off".to_owned()]
    } else {
        vec![mode.to_owned(), target_text(spec, target), "off".to_owned()]
    };
    let mut last_error = None;
    for _attempt in 0..3 {
        match api
            .command(&args)
            .await
            .and_then(|result| require_success(&result, "tailscale cleanup"))
        {
            Ok(()) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    Err(last_error.expect("cleanup attempts always run"))
}

async fn wait_installed(api: &Arc<dyn TailscaleApi>, target: &str) -> Result<(), DriverError> {
    let api = Arc::clone(api);
    let target = target.to_owned();
    wait_healthy(std::time::Duration::from_secs(10), move || {
        let api = Arc::clone(&api);
        let target = target.clone();
        async move {
            serve_status(&api)
                .await
                .is_ok_and(|status| status.success && status.stdout.contains(&target))
        }
    })
    .await
}

pub fn ownership_key(mode: &str, spec: &EndpointSpec, target: ResolvedTarget) -> String {
    format!("{mode}|{:?}|{}|{}", spec.proto, spec.public_port.unwrap_or(0), target.0)
}

fn ownership_path(directory: &Path, key: &str) -> std::path::PathBuf {
    let digest = Sha256::digest(key.as_bytes());
    let mut name = String::with_capacity(64);
    for byte in digest {
        write!(name, "{byte:02x}").expect("writing to String cannot fail");
    }
    directory.join(format!("{name}.owned"))
}

fn target_text(spec: &EndpointSpec, target: ResolvedTarget) -> String {
    if spec.proto == ServiceProto::Tcp {
        format!("tcp://{}", target.0)
    } else {
        format!("http://{}", target.0)
    }
}

pub fn binding_snapshot(
    status: &str,
    spec: &EndpointSpec,
    target: ResolvedTarget,
) -> Option<String> {
    let value = serde_json::from_str::<Value>(status).ok()?;
    let port = if spec.proto == ServiceProto::Tcp {
        spec.public_port.unwrap_or_else(|| target.0.port())
    } else {
        spec.public_port.unwrap_or(443)
    };
    let mut bindings = Vec::new();
    collect_port_bindings(&value, &port.to_string(), spec.proto, &mut bindings);
    if !bindings.is_empty() {
        let mut snapshots = bindings.into_iter().map(ToString::to_string).collect::<Vec<_>>();
        snapshots.sort();
        return Some(snapshots.join("|"));
    }
    (value.as_object().is_some_and(|object| object.len() == 1)
        && status.contains(&target_text(spec, target)))
    .then(|| value.to_string())
}

fn collect_port_bindings<'a>(
    value: &'a Value,
    port: &str,
    proto: ServiceProto,
    found: &mut Vec<&'a Value>,
) {
    let Some(object) = value.as_object() else {
        return;
    };
    for (key, child) in object {
        if key == port || key.ends_with(&format!(":{port}")) {
            if proto == ServiceProto::Tcp || child.get("TCPForward").is_some() {
                found.push(child);
            } else if let Some(root) = child.get("Handlers").and_then(|value| value.get("/")) {
                found.push(root);
            }
        } else if !is_port_key(key) {
            collect_port_bindings(child, port, proto, found);
        }
    }
}

fn is_port_key(key: &str) -> bool {
    key.parse::<u16>().is_ok()
        || key.rsplit_once(':').is_some_and(|(_, port)| port.parse::<u16>().is_ok())
}

fn validate_status_json(status: &str) -> Result<(), DriverError> {
    serde_json::from_str::<Value>(status)
        .map(|_| ())
        .map_err(|error| DriverError::Protocol(format!("invalid tailscale serve status: {error}")))
}

fn require_success(result: &CommandResult, action: &str) -> Result<(), DriverError> {
    if result.success {
        Ok(())
    } else {
        Err(DriverError::Transport(format!("{action} failed: {}", result.stderr.trim())))
    }
}

fn strings<const N: usize>(values: [&str; N]) -> Vec<String> {
    values.into_iter().map(str::to_owned).collect()
}
