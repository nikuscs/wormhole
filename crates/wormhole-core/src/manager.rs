//! Driver-neutral multi-endpoint tunnel manager.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use parking_lot::RwLock;
use tokio::{
    sync::{Mutex, broadcast, mpsc},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    config::ClientConfig,
    driver::{DriverEvent, DriverRegistry, EndpointEvent, TunnelDriver},
    error::{DriverError, ManagerError},
    ifaces::IfaceResolver,
    manager_status::{apply_ready_urls, preflight_driver, validate_capabilities},
    model::{
        ActiveEndpoint, EndpointSpec, EndpointStatus, ResolvedTarget, Service, ServiceProto,
        StatusChange, Target,
    },
};

/// Coordinates services and driver-owned endpoint tasks.
pub struct TunnelManager {
    registry: Arc<DriverRegistry>,
    config: RwLock<ClientConfig>,
    ifaces: RwLock<IfaceResolver>,
    endpoints: Arc<RwLock<HashMap<Uuid, ActiveEndpoint>>>,
    tasks: Mutex<HashMap<Uuid, EndpointTask>>,
    status_tx: broadcast::Sender<StatusChange>,
    driver_events_tx: mpsc::Sender<EndpointEvent>,
    driver_events_rx: Mutex<Option<mpsc::Receiver<EndpointEvent>>>,
    external_handoff: Arc<AtomicBool>,
}

struct EndpointTask {
    service: String,
    stop: CancellationToken,
    forget: tokio::sync::watch::Sender<bool>,
    preserve: tokio::sync::watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl TunnelManager {
    /// Creates a manager from a driver registry and effective config.
    pub fn new(registry: Arc<DriverRegistry>, config: ClientConfig) -> Self {
        let ifaces = IfaceResolver::new(config.aliases.clone());
        let (status_tx, _) = broadcast::channel(256);
        let (driver_events_tx, driver_events_rx) = mpsc::channel(256);
        Self {
            registry,
            config: RwLock::new(config),
            ifaces: RwLock::new(ifaces),
            endpoints: Arc::new(RwLock::new(HashMap::new())),
            tasks: Mutex::new(HashMap::new()),
            status_tx,
            driver_events_tx,
            driver_events_rx: Mutex::new(Some(driver_events_rx)),
            external_handoff: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Returns the live driver registry used by diagnostics and reloads.
    pub fn registry(&self) -> &DriverRegistry {
        &self.registry
    }

    /// Replaces endpoint defaults and aliases without touching live endpoint tasks.
    pub fn reload_config(&self, config: ClientConfig) {
        *self.ifaces.write() = IfaceResolver::new(config.aliases.clone());
        *self.config.write() = config;
    }

    /// Exposes one service through all requested drivers concurrently.
    pub async fn expose(
        &self,
        service: Service,
        mut specs: Vec<EndpointSpec>,
    ) -> Result<Vec<Uuid>, ManagerError> {
        if specs.is_empty() {
            specs = self.default_specs(service.proto);
        }
        let target = self.resolve_target(&service.target).await?;
        let allow_partial = specs.len() > 1;
        let mut prepared = Vec::with_capacity(specs.len());
        for spec in specs {
            if spec.proto != service.proto {
                return Err(DriverError::Capability(format!(
                    "endpoint protocol {:?} does not match service protocol {:?}",
                    spec.proto, service.proto
                ))
                .into());
            }
            let driver = self
                .registry
                .get(&spec.driver)
                .ok_or_else(|| DriverError::Unknown(spec.driver.clone()))?;
            validate_capabilities(&spec, driver.capabilities())?;
            driver.validate(&spec)?;
            let driver = preflight_driver(driver, allow_partial).await?;
            prepared.push((Uuid::now_v7(), spec, driver));
        }
        let ids = prepared.iter().map(|(id, _, _)| *id).collect::<Vec<_>>();
        for (id, spec, driver) in prepared {
            self.spawn_endpoint(id, &service.name, spec, target, driver).await;
        }
        Ok(ids)
    }

    /// Closes one endpoint without affecting sibling exposures.
    pub async fn close(&self, endpoint: Uuid) -> Result<(), ManagerError> {
        self.close_with_forget(endpoint, false).await
    }

    /// Closes one endpoint and optionally drops its persistent reservation.
    pub async fn close_with_forget(
        &self,
        endpoint: Uuid,
        forget: bool,
    ) -> Result<(), ManagerError> {
        let mut task = self
            .tasks
            .lock()
            .await
            .remove(&endpoint)
            .ok_or(ManagerError::UnknownEndpoint(endpoint))?;
        if forget {
            let _changed = task.forget.send(true);
        }
        task.stop.cancel();
        if tokio::time::timeout(Duration::from_secs(10), &mut task.task).await.is_err() {
            task.task.abort();
            let _aborted = task.task.await;
            if forget {
                return Err(ManagerError::Cleanup("cleanup timed out".to_owned()));
            }
        }
        if forget
            && let Some(EndpointStatus::Error(message)) =
                self.endpoints.read().get(&endpoint).map(|active| active.status.clone())
        {
            return Err(ManagerError::Cleanup(message));
        }
        self.set_status(endpoint, EndpointStatus::Offline);
        Ok(())
    }

    /// Fails and forgets an endpoint after a daemon-side durability error.
    pub async fn fail_endpoint(&self, endpoint: Uuid, message: String) {
        let _closed = self.close_with_forget(endpoint, true).await;
        self.set_status(endpoint, EndpointStatus::Error(message));
    }

    /// Closes an endpoint and removes it from the manager snapshot.
    pub async fn discard(&self, endpoint: Uuid) {
        let _closed = self.close(endpoint).await;
        self.endpoints.write().remove(&endpoint);
    }

    /// Closes every endpoint belonging to a service.
    pub async fn close_service(&self, service: &str) {
        self.close_service_with_forget(service, false).await;
    }

    /// Closes every endpoint for a service and optionally drops reservations.
    pub async fn close_service_with_forget(&self, service: &str, forget: bool) {
        let ids = self
            .tasks
            .lock()
            .await
            .iter()
            .filter_map(|(id, task)| (task.service == service).then_some(*id))
            .collect::<Vec<_>>();
        for id in ids {
            let _closed = self.close_with_forget(id, forget).await;
        }
    }

    /// Returns a stable snapshot ordered by endpoint id.
    pub fn list(&self) -> Vec<ActiveEndpoint> {
        let mut endpoints = self.endpoints.read().values().cloned().collect::<Vec<_>>();
        endpoints.sort_by_key(|endpoint| endpoint.id);
        endpoints
    }

    /// Marks a persistent endpoint online after daemon durability acknowledgement.
    pub fn confirm_handoff(&self, endpoint: Uuid) {
        self.set_status(endpoint, EndpointStatus::Online);
    }

    /// Subscribes to status transitions.
    pub fn subscribe(&self) -> broadcast::Receiver<StatusChange> {
        self.status_tx.subscribe()
    }

    /// Takes the single reliable raw-driver event stream used by the daemon.
    pub async fn take_driver_events(&self) -> Option<mpsc::Receiver<EndpointEvent>> {
        let receiver = self.driver_events_rx.lock().await.take();
        if receiver.is_some() {
            self.external_handoff.store(true, Ordering::Release);
        }
        receiver
    }

    /// Cancels all endpoints and drops any persistent reservations.
    pub async fn shutdown_with_forget(&self) -> Result<(), ManagerError> {
        let ids = self.tasks.lock().await.keys().copied().collect::<Vec<_>>();
        let mut first_error = None;
        for id in ids {
            if let Err(error) = self.close_with_forget(id, true).await
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    /// Cancels all endpoints and drains them for up to ten seconds each.
    pub async fn shutdown(&self) {
        let mut tasks = {
            let mut tasks = self.tasks.lock().await;
            tasks.drain().collect::<Vec<_>>()
        };
        for (_, task) in &tasks {
            let _changed = task.preserve.send(true);
            task.stop.cancel();
        }
        let drain = futures::future::join_all(tasks.iter_mut().map(|(_, task)| &mut task.task));
        if tokio::time::timeout(Duration::from_secs(10), drain).await.is_err() {
            for (_, task) in &tasks {
                task.task.abort();
            }
            futures::future::join_all(tasks.iter_mut().map(|(_, task)| &mut task.task)).await;
        }
        for (id, _) in tasks {
            self.set_status(id, EndpointStatus::Offline);
        }
    }

    async fn spawn_endpoint(
        &self,
        id: Uuid,
        service: &str,
        spec: EndpointSpec,
        target: ResolvedTarget,
        driver: Arc<dyn TunnelDriver>,
    ) {
        let stop = CancellationToken::new();
        let (forget, forget_rx) = tokio::sync::watch::channel(false);
        let (preserve, preserve_rx) = tokio::sync::watch::channel(false);
        let (events_tx, events_rx) = mpsc::channel(64);
        self.endpoints.write().insert(
            id,
            ActiveEndpoint {
                id,
                service: service.to_owned(),
                driver: spec.driver.clone(),
                urls: Vec::new(),
                status: EndpointStatus::Reconnecting,
                buffered_delivered: 0,
                buffered_pending: 0,
                buffered_failed: 0,
                since: jiff::Timestamp::now(),
            },
        );
        let endpoints = Arc::clone(&self.endpoints);
        let status = self.status_tx.clone();
        let driver_events = self.driver_events_tx.clone();
        let external_handoff = Arc::clone(&self.external_handoff);
        let task_stop = stop.clone();
        let task = tokio::spawn(run_endpoint(
            id,
            driver,
            spec,
            target,
            events_tx,
            events_rx,
            task_stop,
            forget_rx,
            preserve_rx,
            endpoints,
            status,
            driver_events,
            external_handoff,
        ));
        self.tasks
            .lock()
            .await
            .insert(id, EndpointTask { service: service.to_owned(), stop, forget, preserve, task });
    }

    fn set_status(&self, id: Uuid, status: EndpointStatus) {
        update_status(&self.endpoints, &self.status_tx, id, status);
    }

    async fn resolve_target(&self, target: &Target) -> Result<ResolvedTarget, ManagerError> {
        let address = match target {
            Target::Port(port) => SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), *port),
            Target::HostPort(host, port) => SocketAddr::new(self.resolve_host(host).await?, *port),
            Target::Iface { alias, port } => {
                SocketAddr::new(self.resolve_host(alias).await?, *port)
            }
        };
        Ok(ResolvedTarget(address))
    }

    async fn resolve_host(&self, host: &str) -> Result<IpAddr, ManagerError> {
        let resolver = self.ifaces.read().clone();
        let host = host.to_owned();
        tokio::task::spawn_blocking(move || resolver.resolve(&host))
            .await
            .map_err(|error| crate::error::IfaceError::Unresolved(error.to_string()))?
            .map_err(Into::into)
    }

    fn default_specs(&self, proto: ServiceProto) -> Vec<EndpointSpec> {
        let config = self.config.read();
        config
            .defaults
            .drivers
            .iter()
            .map(|driver| EndpointSpec {
                proto,
                driver: driver.clone(),
                qualifier: None,
                remote: None,
                host: None,
                domain: None,
                public_port: None,
                persist: wormhole_proto::frames::Persistence::Temporary,
                buffer: None,
                auth: None,
                retry: None,
                inspect: config.defaults.inspect,
                inspect_assets: false,
                capture_body_max: 1024 * 1024,
                reservation: None,
            })
            .collect()
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_endpoint(
    id: Uuid,
    driver: Arc<dyn TunnelDriver>,
    spec: EndpointSpec,
    target: ResolvedTarget,
    events_tx: mpsc::Sender<DriverEvent>,
    mut events_rx: mpsc::Receiver<DriverEvent>,
    stop: CancellationToken,
    forget: tokio::sync::watch::Receiver<bool>,
    preserve: tokio::sync::watch::Receiver<bool>,
    endpoints: Arc<RwLock<HashMap<Uuid, ActiveEndpoint>>>,
    status_tx: broadcast::Sender<StatusChange>,
    driver_events_tx: mpsc::Sender<EndpointEvent>,
    external_handoff: Arc<AtomicBool>,
) {
    let driver_stop = stop.child_token();
    let run = driver.run_controlled(spec, target, events_tx, driver_stop, forget, preserve);
    tokio::pin!(run);
    loop {
        tokio::select! {
            biased;
            event = events_rx.recv() => {
                let Some(event) = event else {
                    let result = (&mut run).await;
                    let status = result.map_or_else(
                        |error| EndpointStatus::Error(error.to_string()),
                        |()| EndpointStatus::Offline,
                    );
                    update_status(&endpoints, &status_tx, id, status);
                    return;
                };
                if let DriverEvent::Handoff(barrier) = &event
                    && !external_handoff.load(Ordering::Acquire)
                {
                    barrier.notify_one();
                    continue;
                }
                let forward = driver_events_tx.send(EndpointEvent {
                    endpoint: id,
                    event: event.clone(),
                });
                tokio::pin!(forward);
                tokio::select! {
                    biased;
                    sent = &mut forward => {
                        if sent.is_err() {
                            stop.cancel();
                            let _drained = tokio::time::timeout(
                                Duration::from_secs(10),
                                &mut run,
                            ).await;
                            update_status(
                                &endpoints,
                                &status_tx,
                                id,
                                EndpointStatus::Error(
                                    "daemon event receiver closed".to_owned(),
                                ),
                            );
                            return;
                        }
                    }
                    result = &mut run => {
                        let status = result.map_or_else(
                            |error| EndpointStatus::Error(error.to_string()),
                            |()| EndpointStatus::Offline,
                        );
                        update_status(&endpoints, &status_tx, id, status);
                        return;
                    }
                }
                let awaits_durability = external_handoff.load(Ordering::Acquire)
                    && matches!(&event, DriverEvent::Ready { reservation: Some(_), .. });
                if awaits_durability {
                    apply_ready_urls(&endpoints, id, &event);
                } else {
                    apply_event(&endpoints, &status_tx, id, event);
                }
            }
            result = &mut run => {
                let status = result.map_or_else(
                    |error| EndpointStatus::Error(error.to_string()),
                    |()| EndpointStatus::Offline,
                );
                update_status(&endpoints, &status_tx, id, status);
                return;
            }
        }
    }
}

fn apply_event(
    endpoints: &RwLock<HashMap<Uuid, ActiveEndpoint>>,
    status_tx: &broadcast::Sender<StatusChange>,
    id: Uuid,
    event: DriverEvent,
) {
    match event {
        DriverEvent::Ready { urls, .. } => {
            if let Some(endpoint) = endpoints.write().get_mut(&id) {
                endpoint.urls = urls;
            }
            update_status(endpoints, status_tx, id, EndpointStatus::Online);
        }
        DriverEvent::StatusChanged(status) => update_status(endpoints, status_tx, id, status),
        DriverEvent::Closed => update_status(endpoints, status_tx, id, EndpointStatus::Offline),
        DriverEvent::Log(level, message) => match level {
            tracing::Level::ERROR => tracing::error!(endpoint = %id, %message),
            tracing::Level::WARN => tracing::warn!(endpoint = %id, %message),
            tracing::Level::INFO => tracing::info!(endpoint = %id, %message),
            tracing::Level::DEBUG => tracing::debug!(endpoint = %id, %message),
            tracing::Level::TRACE => tracing::trace!(endpoint = %id, %message),
        },
        DriverEvent::BufferedDelivery { pending, failed, delivered_delta } => {
            if let Some(endpoint) = endpoints.write().get_mut(&id) {
                endpoint.buffered_pending = pending;
                endpoint.buffered_failed = failed;
                endpoint.buffered_delivered =
                    endpoint.buffered_delivered.saturating_add(delivered_delta);
            }
        }
        DriverEvent::Handoff(_) | DriverEvent::Captured(_) => {}
    }
}

fn update_status(
    endpoints: &RwLock<HashMap<Uuid, ActiveEndpoint>>,
    status_tx: &broadcast::Sender<StatusChange>,
    id: Uuid,
    status: EndpointStatus,
) {
    if let Some(endpoint) = endpoints.write().get_mut(&id) {
        endpoint.status = status.clone();
        endpoint.since = jiff::Timestamp::now();
    }
    let _sent = status_tx.send(StatusChange { endpoint: id, status });
}

#[cfg(test)]
#[path = "manager_tests.rs"]
mod tests;
