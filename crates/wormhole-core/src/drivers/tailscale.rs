//! Tailscale Serve and Funnel driver.

use std::{path::PathBuf, process::Stdio, sync::Arc};

use crate::{
    driver::{DriverCapabilities, DriverEvent, DriverHealth, TunnelDriver},
    drivers::{
        process::ManagedProcess,
        tailscale_args::{install_args, public_port, public_url},
        tailscale_process::{
            cleanup_failed_install, install_endpoint, monitor_install, preview_install,
            record_installed_ownership,
        },
        tailscale_state::{
            ActiveBindings, BindingClaim, cleanup_if_unchanged, forget_ownership, owns_binding,
            reject_conflict, verify_install,
        },
    },
    error::DriverError,
    model::{EndpointSpec, ResolvedTarget, ServiceProto},
};
use async_trait::async_trait;
use rand::RngExt as _;
use serde_json::Value;
use tokio::{process::Command, sync::mpsc};
use tokio_util::sync::CancellationToken;

const INSTALL_HINT: &str = "install: https://tailscale.com/download (or brew install tailscale)";
const FUNNEL_PORTS: [u16; 3] = [443, 8443, 10_000];
const INITIAL_BACKOFF: std::time::Duration = std::time::Duration::from_millis(250);
const MAX_BACKOFF: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct CommandResult {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

#[async_trait]
pub trait TailscaleApi: Send + Sync {
    async fn command(&self, args: &[String]) -> Result<CommandResult, DriverError>;
    fn available(&self) -> bool;
}

struct SystemTailscaleApi {
    binary: Option<PathBuf>,
}

#[async_trait]
impl TailscaleApi for SystemTailscaleApi {
    async fn command(&self, args: &[String]) -> Result<CommandResult, DriverError> {
        let binary = self
            .binary
            .as_ref()
            .ok_or_else(|| DriverError::Unavailable(INSTALL_HINT.to_owned()))?;
        let output = Command::new(binary)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .await
            .map_err(|error| DriverError::Transport(error.to_string()))?;
        Ok(CommandResult {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    fn available(&self) -> bool {
        self.binary.is_some()
    }
}

pub struct TailscaleDriver {
    api: Arc<dyn TailscaleApi>,
    binary: Option<PathBuf>,
    ownership_dir: Option<PathBuf>,
    active: ActiveBindings,
}

struct TailscaleSetup {
    mode: String,
    background: bool,
    command: Vec<String>,
    url: String,
}

impl TailscaleDriver {
    pub fn system() -> Self {
        let binary = discover_tailscale();
        let ownership_dir = directories::ProjectDirs::from("dev", "wormhole", "wormhole")
            .map(|directories| directories.data_local_dir().join("tailscale"));
        Self {
            api: Arc::new(SystemTailscaleApi { binary: binary.clone() }),
            binary,
            ownership_dir,
            active: ActiveBindings::default(),
        }
    }

    #[cfg(test)]
    pub fn with_api(api: Arc<dyn TailscaleApi>) -> Self {
        Self::with_api_and_ownership(api, None)
    }

    #[cfg(test)]
    pub fn with_api_and_ownership(
        api: Arc<dyn TailscaleApi>,
        ownership_dir: Option<PathBuf>,
    ) -> Self {
        Self { api, binary: None, ownership_dir, active: ActiveBindings::default() }
    }

    fn claim_binding<'a>(
        &'a self,
        spec: &EndpointSpec,
        target: ResolvedTarget,
    ) -> Result<BindingClaim<'a>, DriverError> {
        let port = public_port(spec, target);
        let key = port.to_string();
        self.active.claim(self.ownership_dir.as_deref(), key)
    }

    async fn status(&self) -> Result<Value, DriverError> {
        let result = self.api.command(&strings(["status", "--json"])).await?;
        require_success(&result, "tailscale status")?;
        serde_json::from_str(&result.stdout)
            .map_err(|error| DriverError::Protocol(format!("invalid tailscale status: {error}")))
    }

    async fn prepare(
        &self,
        spec: &EndpointSpec,
        target: ResolvedTarget,
        events: &mpsc::Sender<DriverEvent>,
    ) -> Result<TailscaleSetup, DriverError> {
        ensure_healthy(self.health().await)?;
        let status = self.status().await?;
        if spec.qualifier.as_deref() == Some("funnel") && !funnel_available(&status) {
            return Err(DriverError::Unavailable(
                "tailscale funnel is not enabled; grant the funnel node attribute and enable MagicDNS/HTTPS"
                    .to_owned(),
            ));
        }
        if spec.host.is_some() {
            let _log = events
                .send(DriverEvent::Log(
                    tracing::Level::WARN,
                    "tailscale ignores endpoint host".to_owned(),
                ))
                .await;
        }
        let dns = dns_name(&status)?;
        let mode = spec.qualifier.as_deref().map_or("serve", |_| "funnel").to_owned();
        let background = spec.persist == wormhole_proto::frames::Persistence::Persistent
            || self.binary.is_none();
        let command = install_args(&mode, spec, target, background);
        let public_port = public_port(spec, target);
        let url = public_url(spec.proto, &dns, public_port);
        Ok(TailscaleSetup { mode, background, command, url })
    }

    fn owns_binding(&self, mode: &str, spec: &EndpointSpec, target: ResolvedTarget) -> bool {
        self.ownership_dir
            .as_ref()
            .is_some_and(|directory| owns_binding(directory, mode, spec, target))
    }

    async fn record_ownership(
        &self,
        mode: &str,
        spec: &EndpointSpec,
        target: ResolvedTarget,
    ) -> Result<(), DriverError> {
        record_installed_ownership(self.ownership_dir.as_deref(), &self.api, mode, spec, target)
            .await
    }

    async fn preinstall(
        &self,
        mode: &str,
        spec: &EndpointSpec,
        target: ResolvedTarget,
        command: &[String],
        events: &mpsc::Sender<DriverEvent>,
    ) -> Result<(), DriverError> {
        self.reject_conflict(mode, spec, target).await?;
        preview_install(events, command).await?;
        snapshot_config(&self.api).await
    }

    async fn reject_conflict(
        &self,
        mode: &str,
        spec: &EndpointSpec,
        target: ResolvedTarget,
    ) -> Result<(), DriverError> {
        reject_conflict(&self.api, spec, target, self.owns_binding(mode, spec, target)).await
    }

    fn forget_ownership(
        &self,
        mode: &str,
        spec: &EndpointSpec,
        target: ResolvedTarget,
    ) -> Result<(), DriverError> {
        self.ownership_dir
            .as_ref()
            .map_or(Ok(()), |directory| forget_ownership(directory, mode, spec, target))
    }

    async fn cleanup_binding(
        &self,
        mode: &str,
        spec: &EndpointSpec,
        target: ResolvedTarget,
        installed: &CommandResult,
    ) -> Result<(), DriverError> {
        if !cleanup_if_unchanged(&self.api, mode, spec, target, installed).await? {
            return Err(DriverError::Transport(
                "tailscale binding changed before cleanup; ownership retained".to_owned(),
            ));
        }
        self.forget_ownership(mode, spec, target)
    }

    async fn health(&self) -> DriverHealth {
        if !self.api.available() {
            return DriverHealth::Unavailable(INSTALL_HINT.to_owned());
        }
        let version = self.api.command(&strings(["version"])).await;
        if !matches!(version, Ok(CommandResult { success: true, .. })) {
            return DriverHealth::Degraded(
                "tailscale version failed; verify the daemon is running".to_owned(),
            );
        }
        match self.status().await {
            Ok(status) if backend_running(&status) => DriverHealth::Healthy,
            Ok(_) => {
                DriverHealth::Degraded("tailscale is logged out; run `tailscale up`".to_owned())
            }
            Err(error) => DriverHealth::Degraded(error.to_string()),
        }
    }
}

#[async_trait]
impl TunnelDriver for TailscaleDriver {
    fn name(&self) -> &'static str {
        "tailscale"
    }

    fn capabilities(&self) -> DriverCapabilities {
        DriverCapabilities::default()
    }

    fn validate(&self, spec: &EndpointSpec) -> Result<(), DriverError> {
        if !matches!(spec.qualifier.as_deref(), None | Some("funnel")) {
            return Err(DriverError::Capability("tailscale qualifier must be `funnel`".to_owned()));
        }
        if spec.domain.is_some() {
            return Err(DriverError::Capability(
                "tailscale does not support custom domains".to_owned(),
            ));
        }
        if spec.proto == ServiceProto::Http
            && spec.qualifier.as_deref() != Some("funnel")
            && spec.public_port.is_some()
        {
            return Err(DriverError::Capability(
                "tailscale Serve HTTP endpoints do not accept public_port".to_owned(),
            ));
        }
        if spec.qualifier.as_deref() == Some("funnel")
            && spec.public_port.is_some_and(|port| !FUNNEL_PORTS.contains(&port))
        {
            return Err(DriverError::Capability(
                "tailscale funnel public_port must be 443, 8443, or 10000".to_owned(),
            ));
        }
        Ok(())
    }

    async fn check(&self) -> DriverHealth {
        self.health().await
    }

    async fn diagnostics(&self) -> Vec<(String, DriverHealth)> {
        let base = self.health().await;
        let funnel = if base == DriverHealth::Healthy {
            match self.status().await {
                Ok(status) if funnel_available(&status) => DriverHealth::Healthy,
                Ok(_) => DriverHealth::Degraded(
                    "funnel attribute missing; grant funnel and enable MagicDNS/HTTPS".to_owned(),
                ),
                Err(error) => DriverHealth::Degraded(error.to_string()),
            }
        } else {
            base.clone()
        };
        vec![("tailscale".to_owned(), base), ("tailscale:funnel".to_owned(), funnel)]
    }

    async fn run(
        &self,
        spec: EndpointSpec,
        target: ResolvedTarget,
        events: mpsc::Sender<DriverEvent>,
        stop: CancellationToken,
    ) -> Result<(), DriverError> {
        let (_forget_tx, forget) = tokio::sync::watch::channel(false);
        let (_preserve_tx, preserve) = tokio::sync::watch::channel(false);
        self.run_controlled(spec, target, events, stop, forget, preserve).await
    }

    async fn run_controlled(
        &self,
        spec: EndpointSpec,
        target: ResolvedTarget,
        events: mpsc::Sender<DriverEvent>,
        stop: CancellationToken,
        _forget: tokio::sync::watch::Receiver<bool>,
        preserve: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), DriverError> {
        let TailscaleSetup { mode, background, command, url } =
            self.prepare(&spec, target, &events).await?;
        let _claim = self.claim_binding(&spec, target)?;
        let mut backoff = INITIAL_BACKOFF;
        loop {
            self.preinstall(&mode, &spec, target, &command, &events).await?;
            match install_endpoint(&self.api, self.binary.as_ref(), &command, background, &events)
                .await
            {
                Ok(process) => {
                    let outcome = self
                        .handle_installed(
                            process, &mode, &spec, target, &url, &command, &events, &stop,
                            &preserve,
                        )
                        .await?;
                    if let Some(stopped) = outcome {
                        backoff = INITIAL_BACKOFF;
                        if stopped {
                            return Ok(());
                        }
                    }
                }
                Err(error) => {
                    let _log = events
                        .send(DriverEvent::Log(tracing::Level::WARN, error.to_string()))
                        .await;
                }
            }
            let _status = events
                .send(DriverEvent::StatusChanged(crate::model::EndpointStatus::Reconnecting))
                .await;
            let jitter = rand::rng().random_range(0..=backoff.as_millis() as u64);
            tokio::select! {
                () = stop.cancelled() => return Ok(()),
                () = tokio::time::sleep(std::time::Duration::from_millis(jitter)) => {}
            }
            backoff = backoff.saturating_mul(2).min(MAX_BACKOFF);
        }
    }
}

impl TailscaleDriver {
    #[allow(clippy::too_many_arguments)]
    async fn handle_installed(
        &self,
        process: Option<ManagedProcess>,
        mode: &str,
        spec: &EndpointSpec,
        target: ResolvedTarget,
        url: &str,
        command: &[String],
        events: &mpsc::Sender<DriverEvent>,
        stop: &CancellationToken,
        preserve: &tokio::sync::watch::Receiver<bool>,
    ) -> Result<Option<bool>, DriverError> {
        let target_text = command.last().cloned().unwrap_or_default();
        let installed = match verify_install(&self.api, &target_text).await {
            Ok(installed) => installed,
            Err(error) => {
                if let Some(process) = process {
                    process.terminate().await?;
                }
                cleanup_failed_install(&self.api, mode, spec, target, &error, events).await?;
                return Ok(None);
            }
        };
        self.record_ownership(mode, spec, target).await?;
        events
            .send(DriverEvent::Ready {
                urls: vec![url.to_owned()],
                bind_id: None,
                reservation: None,
            })
            .await
            .map_err(|_| DriverError::Cancelled)?;
        if !monitor_install(&self.api, process.as_ref(), spec, target, &installed, stop).await? {
            return Ok(Some(false));
        }
        if let Some(process) = process {
            process.terminate().await?;
        }
        let preserve_entry =
            spec.persist == wormhole_proto::frames::Persistence::Persistent && *preserve.borrow();
        if !preserve_entry {
            self.cleanup_binding(mode, spec, target, &installed).await?;
        }
        let _closed = events.send(DriverEvent::Closed).await;
        Ok(Some(true))
    }
}

async fn snapshot_config(api: &Arc<dyn TailscaleApi>) -> Result<(), DriverError> {
    let path =
        std::env::temp_dir().join(format!("wormhole-tailscale-{}.json", uuid::Uuid::now_v7()));
    let args = vec![
        "serve".to_owned(),
        "get-config".to_owned(),
        path.to_string_lossy().into_owned(),
        "--all".to_owned(),
    ];
    let result = api.command(&args).await?;
    let _removed = std::fs::remove_file(path);
    require_success(&result, "tailscale serve get-config")
}

fn backend_running(status: &Value) -> bool {
    status.get("BackendState").and_then(Value::as_str).is_none_or(|state| state == "Running")
}

fn funnel_available(status: &Value) -> bool {
    status
        .pointer("/Self/CapMap")
        .and_then(Value::as_object)
        .is_some_and(|caps| caps.keys().any(|key| key.contains("funnel")))
}

fn dns_name(status: &Value) -> Result<String, DriverError> {
    status
        .pointer("/Self/DNSName")
        .and_then(Value::as_str)
        .map(|name| name.trim_end_matches('.').to_owned())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| DriverError::Protocol("tailscale status lacks Self.DNSName".to_owned()))
}

fn require_success(result: &CommandResult, action: &str) -> Result<(), DriverError> {
    if result.success {
        Ok(())
    } else {
        Err(DriverError::Transport(format!("{action} failed: {}", result.stderr.trim())))
    }
}

fn ensure_healthy(health: DriverHealth) -> Result<(), DriverError> {
    match health {
        DriverHealth::Healthy => Ok(()),
        DriverHealth::Degraded(message) | DriverHealth::Unavailable(message) => {
            Err(DriverError::Unavailable(message))
        }
    }
}

fn discover_tailscale() -> Option<PathBuf> {
    discover_on_path("tailscale").or_else(|| {
        let path = PathBuf::from("/Applications/Tailscale.app/Contents/MacOS/Tailscale");
        path.is_file().then_some(path)
    })
}

fn discover_on_path(binary: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|directory| directory.join(binary))
            .find(|candidate| candidate.is_file())
    })
}

fn strings<const N: usize>(values: [&str; N]) -> Vec<String> {
    values.into_iter().map(str::to_owned).collect()
}

#[cfg(test)]
#[path = "tailscale_tests.rs"]
mod tests;
