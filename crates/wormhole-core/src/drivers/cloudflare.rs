//! Cloudflare quick and named tunnel driver.

use std::{path::PathBuf, process::Stdio, time::Duration};

use async_trait::async_trait;
use rand::RngExt as _;
use serde_json::Value;
use tokio::{
    process::Command,
    sync::{mpsc, watch},
};
use tokio_util::sync::CancellationToken;
use wormhole_proto::frames::Persistence;

use crate::{
    driver::{DriverCapabilities, DriverEvent, DriverHealth, TunnelDriver},
    drivers::{
        cloudflare_command::{
            CommandOutput, command_error, discover_cloudflared, ensure_healthy, strings, strings3,
        },
        cloudflare_metrics::{discover_quick_url, ready},
        cloudflare_named::{
            HostClaim, HostClaims, cloudflare_home, deterministic_name, ensure_named_login,
            find_json_string, find_uuid, forget_route, named_config, record_route, route_is_owned,
        },
        process::{ManagedProcess, ProcessSpec, forward_logs, wait_healthy},
    },
    error::DriverError,
    model::{EndpointSpec, ResolvedTarget, ServiceProto},
    ports::reserve_port,
};

const INSTALL_HINT: &str = "install: brew install cloudflared";
const INITIAL_BACKOFF: Duration = Duration::from_millis(250);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

pub struct CloudflareDriver {
    binary: Option<PathBuf>,
    home: Option<PathBuf>,
    named_lock: tokio::sync::Mutex<()>,
    active_hosts: HostClaims,
}

impl CloudflareDriver {
    pub fn system() -> Self {
        Self {
            binary: discover_cloudflared(),
            home: cloudflare_home(),
            named_lock: tokio::sync::Mutex::new(()),
            active_hosts: HostClaims::default(),
        }
    }

    #[cfg(test)]
    pub fn with_binary(binary: PathBuf) -> Self {
        Self {
            binary: Some(binary),
            home: cloudflare_home(),
            named_lock: tokio::sync::Mutex::new(()),
            active_hosts: HostClaims::default(),
        }
    }

    #[cfg(test)]
    pub fn with_binary_and_home(binary: PathBuf, home: PathBuf) -> Self {
        Self {
            binary: Some(binary),
            home: Some(home),
            named_lock: tokio::sync::Mutex::new(()),
            active_hosts: HostClaims::default(),
        }
    }

    fn claim_host(&self, host: &str) -> Result<HostClaim<'_>, DriverError> {
        let home = self.home.as_ref().ok_or_else(|| {
            DriverError::Unavailable("cannot find cloudflared config directory".to_owned())
        })?;
        self.active_hosts.claim(home, host)
    }

    async fn command(&self, args: &[String]) -> Result<CommandOutput, DriverError> {
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
        Ok(CommandOutput {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    async fn health(&self) -> DriverHealth {
        if self.binary.is_none() {
            return DriverHealth::Unavailable(INSTALL_HINT.to_owned());
        }
        match self.command(&strings(["--version"])).await {
            Ok(output) if output.success => DriverHealth::Healthy,
            Ok(output) => DriverHealth::Degraded(format!(
                "cloudflared --version failed: {}",
                output.stderr.trim()
            )),
            Err(error) => DriverHealth::Degraded(error.to_string()),
        }
    }

    async fn run_quick(
        &self,
        target: ResolvedTarget,
        events: mpsc::Sender<DriverEvent>,
        stop: CancellationToken,
    ) -> Result<(), DriverError> {
        let binary =
            self.binary.clone().ok_or_else(|| DriverError::Unavailable(INSTALL_HINT.to_owned()))?;
        let mut backoff = INITIAL_BACKOFF;
        loop {
            match start_quick(binary.clone(), target, &events).await {
                Ok((process, url)) => {
                    backoff = INITIAL_BACKOFF;
                    events
                        .send(DriverEvent::Ready {
                            urls: vec![url],
                            bind_id: None,
                            reservation: None,
                        })
                        .await
                        .map_err(|_| DriverError::Cancelled)?;
                    tokio::select! {
                        () = stop.cancelled() => {
                            process.terminate().await?;
                            let _closed = events.send(DriverEvent::Closed).await;
                            return Ok(());
                        }
                        result = process.wait() => {
                            let _status = result?;
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
                () = stop.cancelled() => {
                    let _closed = events.send(DriverEvent::Closed).await;
                    return Ok(());
                }
                () = tokio::time::sleep(Duration::from_millis(jitter)) => {}
            }
            backoff = backoff.saturating_mul(2).min(MAX_BACKOFF);
        }
    }

    async fn prepare_named(
        &self,
        spec: &EndpointSpec,
        target: ResolvedTarget,
        events: &mpsc::Sender<DriverEvent>,
    ) -> Result<NamedConnector, DriverError> {
        let _mutation = self.named_lock.lock().await;
        let home = self.home.as_ref().ok_or_else(|| {
            DriverError::Unavailable("cannot find cloudflared config directory".to_owned())
        })?;
        ensure_named_login(home)?;
        let host = spec.host.as_ref().expect("validated named host");
        let name = deterministic_name(host);
        let owned = route_is_owned(home, &name, host);
        let overwrite = if owned { " --overwrite-dns" } else { "" };
        events
            .send(DriverEvent::Log(
                tracing::Level::INFO,
                format!(
                    "cloudflared plan: tunnel create {name}; tunnel route dns{overwrite} {name} {host}; service=http://{}; catch-all=http_status:404",
                    target.0
                ),
            ))
            .await
            .map_err(|_| DriverError::Cancelled)?;
        let tunnel_id = self.ensure_tunnel(&name).await?;
        let mut route_args = vec!["tunnel".to_owned(), "route".to_owned(), "dns".to_owned()];
        if owned {
            route_args.push("--overwrite-dns".to_owned());
        }
        route_args.extend([name.clone(), host.clone()]);
        let route = self.command(&route_args).await?;
        if !route.success {
            return Err(command_error("cloudflared tunnel route dns", &route));
        }
        record_route(home, &name, &tunnel_id, host, target)?;
        let (metrics_port, reservation) = reserve_port(20_000..=29_999)
            .map_err(|error| DriverError::Transport(error.to_string()))?;
        let config = named_config(home, &tunnel_id, host, target, metrics_port);
        let config_path = std::env::temp_dir().join(format!("{name}-{}.yml", uuid::Uuid::now_v7()));
        std::fs::write(&config_path, config)
            .map_err(|error| DriverError::Transport(error.to_string()))?;
        let args = vec![
            "tunnel".to_owned(),
            "--no-autoupdate".to_owned(),
            "--logformat".to_owned(),
            "json".to_owned(),
            "--config".to_owned(),
            config_path.to_string_lossy().into_owned(),
            "run".to_owned(),
            name.clone(),
        ];
        let _log = events
            .send(DriverEvent::Log(
                tracing::Level::INFO,
                format!("cloudflared tunnel={name} dns={host}"),
            ))
            .await;
        drop(reservation);
        let binary =
            self.binary.clone().ok_or_else(|| DriverError::Unavailable(INSTALL_HINT.to_owned()))?;
        Ok(NamedConnector {
            binary,
            args,
            metrics_port,
            config_path,
            url: format!("https://{host}"),
        })
    }

    async fn run_named(
        &self,
        spec: &EndpointSpec,
        target: ResolvedTarget,
        events: mpsc::Sender<DriverEvent>,
        stop: CancellationToken,
        forget: Option<watch::Receiver<bool>>,
    ) -> Result<(), DriverError> {
        let host = spec.host.as_deref().expect("validated named host");
        let _claim = self.claim_host(host)?;
        let connector = self.prepare_named(spec, target, &events).await?;
        let NamedConnector { binary, args, metrics_port, config_path, url } = connector;
        let mut announced = false;
        let mut backoff = INITIAL_BACKOFF;
        loop {
            let attempt = start_named(binary.clone(), args.clone(), metrics_port, &events).await;
            if let Ok(process) = attempt {
                backoff = INITIAL_BACKOFF;
                if !announced {
                    events
                        .send(DriverEvent::Ready {
                            urls: vec![url.clone()],
                            bind_id: None,
                            reservation: None,
                        })
                        .await
                        .map_err(|_| DriverError::Cancelled)?;
                    announced = true;
                }
                tokio::select! {
                    () = stop.cancelled() => {
                        process.terminate().await?;
                        let _removed = std::fs::remove_file(&config_path);
                        self.forget_named_route(spec, forget.as_ref())?;
                        let _closed = events.send(DriverEvent::Closed).await;
                        return Ok(());
                    }
                    result = process.wait() => {
                        let _status = result?;
                    }
                }
            } else if let Err(error) = attempt {
                let _log =
                    events.send(DriverEvent::Log(tracing::Level::WARN, error.to_string())).await;
            }
            let _status = events
                .send(DriverEvent::StatusChanged(crate::model::EndpointStatus::Reconnecting))
                .await;
            let jitter = rand::rng().random_range(0..=backoff.as_millis() as u64);
            tokio::select! {
                () = stop.cancelled() => {
                    let _removed = std::fs::remove_file(&config_path);
                    self.forget_named_route(spec, forget.as_ref())?;
                    let _closed = events.send(DriverEvent::Closed).await;
                    return Ok(());
                }
                () = tokio::time::sleep(Duration::from_millis(jitter)) => {}
            }
            backoff = backoff.saturating_mul(2).min(MAX_BACKOFF);
        }
    }

    fn forget_named_route(
        &self,
        spec: &EndpointSpec,
        forget: Option<&watch::Receiver<bool>>,
    ) -> Result<(), DriverError> {
        if !forget.is_some_and(|forget| *forget.borrow()) {
            return Ok(());
        }
        let home = self.home.as_ref().ok_or_else(|| {
            DriverError::Unavailable("cannot find cloudflared config directory".to_owned())
        })?;
        let host = spec.host.as_deref().expect("validated named host");
        forget_route(home, &deterministic_name(host), host)
    }

    async fn ensure_tunnel(&self, name: &str) -> Result<String, DriverError> {
        let created = self.command(&strings3("tunnel", "create", name)).await?;
        if created.success
            && let Some(id) = find_uuid(&format!("{} {}", created.stdout, created.stderr))
        {
            return Ok(id);
        }
        let list_args = [
            "tunnel".to_owned(),
            "list".to_owned(),
            "--output".to_owned(),
            "json".to_owned(),
            "--name".to_owned(),
            name.to_owned(),
        ];
        let listed = self.command(&list_args).await?;
        if listed.success
            && let Ok(value) = serde_json::from_str::<Value>(&listed.stdout)
            && let Some(id) = find_json_string(&value, "id")
        {
            return Ok(id);
        }
        Err(command_error("cloudflared tunnel create", &created))
    }
}

#[async_trait]
impl TunnelDriver for CloudflareDriver {
    fn name(&self) -> &'static str {
        "cloudflare"
    }

    fn capabilities(&self) -> DriverCapabilities {
        DriverCapabilities::default()
    }

    fn validate(&self, spec: &EndpointSpec) -> Result<(), DriverError> {
        if spec.proto == ServiceProto::Tcp {
            return Err(DriverError::Capability(
                "cloudflare driver is HTTP-only; use wormhole or tailscale for TCP".to_owned(),
            ));
        }
        let mode = spec.qualifier.as_deref().unwrap_or("quick");
        if !matches!(mode, "quick" | "named") {
            return Err(DriverError::Capability(
                "cloudflare qualifier must be quick or named".to_owned(),
            ));
        }
        if mode == "quick" && spec.persist == Persistence::Persistent {
            return Err(DriverError::Capability(
                "cloudflare quick tunnels cannot persist; use cloudflare:named".to_owned(),
            ));
        }
        if mode == "named" && (spec.persist != Persistence::Persistent || spec.host.is_none()) {
            return Err(DriverError::Capability(
                "cloudflare:named requires host and persist=true".to_owned(),
            ));
        }
        if spec.domain.is_some() || spec.public_port.is_some() {
            return Err(DriverError::Capability(
                "cloudflare endpoints do not accept domain or public_port".to_owned(),
            ));
        }
        Ok(())
    }

    async fn check(&self) -> DriverHealth {
        self.health().await
    }

    async fn diagnostics(&self) -> Vec<(String, DriverHealth)> {
        let base = self.health().await;
        let named = if base == DriverHealth::Healthy {
            self.home.as_deref().map_or_else(
                || DriverHealth::Degraded("cloudflared config directory unavailable".to_owned()),
                |home| {
                    ensure_named_login(home).map_or_else(
                        |error| DriverHealth::Degraded(error.to_string()),
                        |()| DriverHealth::Healthy,
                    )
                },
            )
        } else {
            base.clone()
        };
        vec![("cloudflare".to_owned(), base), ("cloudflare:named".to_owned(), named)]
    }

    async fn run(
        &self,
        spec: EndpointSpec,
        target: ResolvedTarget,
        events: mpsc::Sender<DriverEvent>,
        stop: CancellationToken,
    ) -> Result<(), DriverError> {
        ensure_healthy(self.health().await)?;
        if spec.qualifier.as_deref().unwrap_or("quick") == "named" {
            self.run_named(&spec, target, events, stop, None).await
        } else {
            self.run_quick(target, events, stop).await
        }
    }

    async fn run_controlled(
        &self,
        spec: EndpointSpec,
        target: ResolvedTarget,
        events: mpsc::Sender<DriverEvent>,
        stop: CancellationToken,
        forget: watch::Receiver<bool>,
        _preserve: watch::Receiver<bool>,
    ) -> Result<(), DriverError> {
        ensure_healthy(self.health().await)?;
        if spec.qualifier.as_deref().unwrap_or("quick") == "named" {
            self.run_named(&spec, target, events, stop, Some(forget)).await
        } else {
            self.run_quick(target, events, stop).await
        }
    }
}

async fn start_named(
    binary: PathBuf,
    args: Vec<String>,
    metrics_port: u16,
    events: &mpsc::Sender<DriverEvent>,
) -> Result<ManagedProcess, DriverError> {
    let process = ManagedProcess::spawn(&ProcessSpec::new(binary, args))?;
    forward_logs(process.take_stderr().await, events.clone());
    if let Err(error) = wait_healthy(Duration::from_secs(10), || ready(metrics_port)).await {
        process.terminate().await?;
        return Err(error);
    }
    Ok(process)
}

async fn start_quick(
    binary: PathBuf,
    target: ResolvedTarget,
    events: &mpsc::Sender<DriverEvent>,
) -> Result<(ManagedProcess, String), DriverError> {
    let (metrics_port, reservation) =
        reserve_port(20_000..=29_999).map_err(|error| DriverError::Transport(error.to_string()))?;
    let args = vec![
        "tunnel".to_owned(),
        "--no-autoupdate".to_owned(),
        "--logformat".to_owned(),
        "json".to_owned(),
        "--url".to_owned(),
        format!("http://{}", target.0),
        "--metrics".to_owned(),
        format!("127.0.0.1:{metrics_port}"),
    ];
    drop(reservation);
    let process = ManagedProcess::spawn(&ProcessSpec::new(binary, args))?;
    let mut stderr = process.take_stderr().await;
    let url = discover_quick_url(metrics_port, &mut stderr, events).await?;
    wait_healthy(Duration::from_secs(10), || ready(metrics_port)).await?;
    forward_logs(stderr, events.clone());
    Ok((process, url))
}

struct NamedConnector {
    binary: PathBuf,
    args: Vec<String>,
    metrics_port: u16,
    config_path: PathBuf,
    url: String,
}

#[cfg(test)]
#[path = "cloudflare_tests.rs"]
mod tests;
