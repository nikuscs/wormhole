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
        cloudflare_named::{
            HostClaim, HostClaims, cloudflare_home, deterministic_name, ensure_named_login,
            find_json_string, find_uuid, forget_route, named_config, record_route, route_is_owned,
        },
    },
    error::DriverError,
    model::{EndpointSpec, ResolvedTarget, ServiceProto},
    ports::reserve_port,
};

const INSTALL_HINT: &str = "install: brew install cloudflared";
const INITIAL_BACKOFF: Duration = Duration::from_millis(250);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
const NAMED_DNS_TIMEOUT: Duration = Duration::from_secs(30);

#[path = "cloudflare_runtime.rs"]
mod cloudflare_runtime;

use cloudflare_runtime::{
    NamedConnector, NamedRoute, NamedTunnel, announce_named_plan, cloudflare_authoritative_dns,
    named_authoritative_dns_error, named_dns_error, named_run_args, public_dns_ready, start_named,
};

pub struct CloudflareDriver {
    binary: Option<PathBuf>,
    home: Option<PathBuf>,
    named_lock: tokio::sync::Mutex<()>,
    active_hosts: HostClaims,
    #[cfg(test)]
    named_dns_authoritative: Option<bool>,
    #[cfg(test)]
    named_dns_ready: Option<bool>,
}

impl CloudflareDriver {
    pub fn system() -> Self {
        Self {
            binary: discover_cloudflared(),
            home: cloudflare_home(),
            named_lock: tokio::sync::Mutex::new(()),
            active_hosts: HostClaims::default(),
            #[cfg(test)]
            named_dns_authoritative: None,
            #[cfg(test)]
            named_dns_ready: None,
        }
    }

    #[cfg(test)]
    pub fn with_binary(binary: PathBuf) -> Self {
        Self {
            binary: Some(binary),
            home: cloudflare_home(),
            named_lock: tokio::sync::Mutex::new(()),
            active_hosts: HostClaims::default(),
            named_dns_authoritative: Some(true),
            named_dns_ready: Some(true),
        }
    }

    #[cfg(test)]
    pub fn with_binary_and_home(binary: PathBuf, home: PathBuf) -> Self {
        Self {
            binary: Some(binary),
            home: Some(home),
            named_lock: tokio::sync::Mutex::new(()),
            active_hosts: HostClaims::default(),
            named_dns_authoritative: Some(true),
            named_dns_ready: Some(true),
        }
    }

    #[cfg(test)]
    const fn with_named_dns_authoritative(mut self, authoritative: bool) -> Self {
        self.named_dns_authoritative = Some(authoritative);
        self
    }

    #[cfg(test)]
    const fn with_named_dns_ready(mut self, ready: bool) -> Self {
        self.named_dns_ready = Some(ready);
        self
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
        let route = self.prepare_named_route(home, host, target, events).await?;
        let (metrics_port, reservation) = reserve_port(20_000..=29_999)
            .map_err(|error| DriverError::Transport(error.to_string()))?;
        let config = named_config(home, &route.tunnel_id, host, target, metrics_port);
        let config_path =
            std::env::temp_dir().join(format!("{}-{}.yml", route.name, uuid::Uuid::now_v7()));
        std::fs::write(&config_path, config)
            .map_err(|error| DriverError::Transport(error.to_string()))?;
        let args = named_run_args(&route.name, &config_path);
        let _log = events
            .send(DriverEvent::Log(
                tracing::Level::INFO,
                format!("cloudflared tunnel={} dns={host}", route.name),
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

    async fn prepare_named_route(
        &self,
        home: &std::path::Path,
        host: &str,
        target: ResolvedTarget,
        events: &mpsc::Sender<DriverEvent>,
    ) -> Result<NamedRoute, DriverError> {
        self.ensure_cloudflare_authoritative_dns(host).await?;
        let name = deterministic_name(host);
        let owned = route_is_owned(home, &name, host);
        announce_named_plan(events, &name, host, target, owned).await?;
        let tunnel = self.ensure_tunnel(&name).await?;
        let route = self.create_named_route(&name, host, owned).await;
        if let Err(error) = route {
            return self.named_setup_failed(home, &name, host, owned, &tunnel, error).await;
        }
        record_route(home, &name, &tunnel.id, host, target)?;
        if let Err(error) = self.ensure_named_dns(host).await {
            return self.named_setup_failed(home, &name, host, owned, &tunnel, error).await;
        }
        Ok(NamedRoute { name, tunnel_id: tunnel.id })
    }

    async fn create_named_route(
        &self,
        name: &str,
        host: &str,
        owned: bool,
    ) -> Result<(), DriverError> {
        let mut args = vec!["tunnel".to_owned(), "route".to_owned(), "dns".to_owned()];
        if owned {
            args.push("--overwrite-dns".to_owned());
        }
        args.extend([name.to_owned(), host.to_owned()]);
        let output = self.command(&args).await?;
        if output.success {
            Ok(())
        } else {
            Err(command_error("cloudflared tunnel route dns", &output))
        }
    }

    async fn ensure_cloudflare_authoritative_dns(&self, host: &str) -> Result<(), DriverError> {
        #[cfg(test)]
        if let Some(authoritative) = self.named_dns_authoritative {
            return authoritative.then_some(()).ok_or_else(|| named_authoritative_dns_error(host));
        }
        if cloudflare_authoritative_dns(host).await {
            Ok(())
        } else {
            Err(named_authoritative_dns_error(host))
        }
    }

    async fn ensure_named_dns(&self, host: &str) -> Result<(), DriverError> {
        #[cfg(test)]
        if let Some(ready) = self.named_dns_ready {
            return ready.then_some(()).ok_or_else(|| named_dns_error(host));
        }
        if public_dns_ready(host.to_owned()).await { Ok(()) } else { Err(named_dns_error(host)) }
    }

    async fn named_setup_failed(
        &self,
        home: &std::path::Path,
        name: &str,
        host: &str,
        owned: bool,
        tunnel: &NamedTunnel,
        error: DriverError,
    ) -> Result<NamedRoute, DriverError> {
        match self.cleanup_named_setup(home, name, host, owned, tunnel).await {
            Ok(()) => Err(error),
            Err(cleanup) => Err(DriverError::Transport(format!(
                "{error}; Cloudflare named tunnel cleanup failed: {cleanup}"
            ))),
        }
    }

    async fn cleanup_named_setup(
        &self,
        home: &std::path::Path,
        name: &str,
        host: &str,
        owned: bool,
        tunnel: &NamedTunnel,
    ) -> Result<(), DriverError> {
        if !owned {
            forget_route(home, name, host)?;
        }
        if !tunnel.created {
            return Ok(());
        }
        let args = strings(["tunnel", "delete", "--force", name]);
        let deleted = self.command(&args).await?;
        if !deleted.success {
            return Err(command_error("cloudflared tunnel delete", &deleted));
        }
        let _removed = std::fs::remove_file(home.join(format!("{}.json", tunnel.id)));
        Ok(())
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

    async fn ensure_tunnel(&self, name: &str) -> Result<NamedTunnel, DriverError> {
        let created = self.command(&strings3("tunnel", "create", name)).await?;
        if created.success
            && let Some(id) = find_uuid(&format!("{} {}", created.stdout, created.stderr))
        {
            return Ok(NamedTunnel { id, created: true });
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
            return Ok(NamedTunnel { id, created: false });
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

#[cfg(test)]
#[path = "cloudflare_tests.rs"]
mod tests;
