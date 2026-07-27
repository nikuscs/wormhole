//! Reference Wormhole protocol driver with shared per-remote connections.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use dashmap::DashMap;
use rand::RngExt as _;
use tokio::sync::{Mutex, mpsc, watch};
use tokio_util::sync::CancellationToken;
use wormhole_proto::frames::Persistence;

use crate::{
    driver::{DriverCapabilities, DriverEvent, DriverHealth, TunnelDriver},
    error::DriverError,
    keys_store::IdentityStore,
    model::{EndpointSpec, EndpointStatus, ResolvedTarget},
    remotes::Remote,
    wormhole_conn::RemoteConn,
    wormhole_transport::connect_remote,
};

const INITIAL_BACKOFF: Duration = Duration::from_millis(250);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
const TEMPORARY_ATTEMPTS: u32 = 5;

/// Wormhole protocol driver sharing one QUIC connection per named remote.
pub struct WormholeDriver {
    remotes: BTreeMap<String, Remote>,
    default_remote: Option<String>,
    identities: Arc<IdentityStore>,
    connections: DashMap<String, Arc<RemoteConn>>,
    connect_locks: DashMap<String, Arc<Mutex<()>>>,
}

impl WormholeDriver {
    /// Creates a driver from effective named remotes and identity storage.
    pub fn new(
        remotes: BTreeMap<String, Remote>,
        default_remote: Option<String>,
        identities: Arc<IdentityStore>,
    ) -> Self {
        Self {
            remotes,
            default_remote,
            identities,
            connections: DashMap::new(),
            connect_locks: DashMap::new(),
        }
    }

    async fn connection(&self, name: &str) -> Result<Arc<RemoteConn>, DriverError> {
        if let Some(connection) = self.connections.get(name)
            && !connection.is_closed()
        {
            return Ok(Arc::clone(&connection));
        }
        let lock = self
            .connect_locks
            .entry(name.to_owned())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        let _lock = lock.lock().await;
        if let Some(connection) = self.connections.get(name)
            && !connection.is_closed()
        {
            return Ok(Arc::clone(&connection));
        }
        let remote = self
            .remotes
            .get(name)
            .ok_or_else(|| DriverError::Protocol(format!("unknown Wormhole remote: {name}")))?;
        let identity = self
            .identities
            .resolve_identity(remote)
            .map_err(|error| DriverError::Protocol(error.to_string()))?;
        let connection = RemoteConn::connect(remote, identity).await?;
        self.connections.insert(name.to_owned(), Arc::clone(&connection));
        Ok(connection)
    }

    /// Closes every shared remote connection immediately.
    pub async fn shutdown(&self) {
        let connections =
            self.connections.iter().map(|entry| Arc::clone(entry.value())).collect::<Vec<_>>();
        for connection in connections {
            connection.shutdown().await;
        }
    }

    async fn run_loop(
        &self,
        mut spec: EndpointSpec,
        target: ResolvedTarget,
        events: mpsc::Sender<DriverEvent>,
        stop: CancellationToken,
        forget: watch::Receiver<bool>,
    ) -> Result<(), DriverError> {
        let remote = self.remote_name(&spec)?.to_owned();
        let persistent = spec.persist == Persistence::Persistent;
        let mut attempts = 0_u32;
        let mut backoff = INITIAL_BACKOFF;
        loop {
            if stop.is_cancelled() {
                let cleanup =
                    self.forget_reservation(&remote, &spec, target, &events, &forget).await;
                let _closed = events.send(DriverEvent::Closed).await;
                return cleanup;
            }
            if attempts > 0 {
                let _status =
                    events.send(DriverEvent::StatusChanged(EndpointStatus::Reconnecting)).await;
            }
            let result = self.connection(&remote).await;
            if let Ok(connection) = result {
                match connection
                    .bind(spec.clone(), target, events.clone(), stop.child_token(), forget.clone())
                    .await
                {
                    Ok(mut lease) => {
                        attempts = 0;
                        backoff = INITIAL_BACKOFF;
                        spec.reservation = lease.reservation;
                        tokio::select! {
                            () = stop.cancelled() => {
                                connection.unbind(
                                    lease.bind,
                                    *forget.borrow() || spec.persist == Persistence::Temporary,
                                ).await?;
                                let _closed = events.send(DriverEvent::Closed).await;
                                return Ok(());
                            }
                            changed = lease.closed.changed() => {
                                if changed.is_err() || *lease.closed.borrow() {
                                    attempts = attempts.saturating_add(1);
                                }
                            }
                        }
                    }
                    Err(error) => {
                        attempts = attempts.saturating_add(1);
                        let _log = events
                            .send(DriverEvent::Log(tracing::Level::WARN, error.to_string()))
                            .await;
                    }
                }
            } else if let Err(error) = result {
                attempts = attempts.saturating_add(1);
                let _log =
                    events.send(DriverEvent::Log(tracing::Level::WARN, error.to_string())).await;
            }
            if !persistent && attempts >= TEMPORARY_ATTEMPTS {
                let _closed = events.send(DriverEvent::Closed).await;
                return Err(DriverError::Transport(format!(
                    "temporary endpoint failed after {attempts} attempts"
                )));
            }
            let max_millis = backoff.as_millis() as u64;
            let jitter = rand::rng().random_range(0..=max_millis);
            tokio::select! {
                () = stop.cancelled() => {
                    let cleanup =
                        self.forget_reservation(&remote, &spec, target, &events, &forget).await;
                    let _closed = events.send(DriverEvent::Closed).await;
                    return cleanup;
                }
                () = tokio::time::sleep(Duration::from_millis(jitter)) => {}
            }
            backoff = backoff.saturating_mul(2).min(MAX_BACKOFF);
        }
    }

    async fn forget_reservation(
        &self,
        remote: &str,
        spec: &EndpointSpec,
        _target: ResolvedTarget,
        _events: &mpsc::Sender<DriverEvent>,
        forget: &watch::Receiver<bool>,
    ) -> Result<(), DriverError> {
        if !*forget.borrow()
            || spec.persist != Persistence::Persistent
            || spec.reservation.is_none()
        {
            return Ok(());
        }
        let reservation = spec.reservation.expect("checked persistent reservation");
        let cleanup = async {
            let connection = self.connection(remote).await?;
            connection.forget_reservation(reservation).await
        };
        tokio::time::timeout(Duration::from_secs(8), cleanup).await.unwrap_or_else(|_| {
            Err(DriverError::Transport("timed out reclaiming persistent reservation".to_owned()))
        })
    }

    fn remote_name<'a>(&'a self, spec: &'a EndpointSpec) -> Result<&'a str, DriverError> {
        spec.remote
            .as_deref()
            .or(self.default_remote.as_deref())
            .ok_or_else(|| DriverError::Protocol("no Wormhole remote selected".to_owned()))
    }
}

#[async_trait]
impl TunnelDriver for WormholeDriver {
    fn name(&self) -> &'static str {
        "wormhole"
    }

    fn capabilities(&self) -> DriverCapabilities {
        DriverCapabilities::wormhole_http()
    }

    fn validate(&self, spec: &EndpointSpec) -> Result<(), DriverError> {
        if spec.qualifier.is_some() {
            return Err(DriverError::Capability(
                "Wormhole endpoints do not accept a qualifier".to_owned(),
            ));
        }
        match spec.proto {
            crate::model::ServiceProto::Http => {
                if spec.public_port.is_some() {
                    return Err(DriverError::Capability(
                        "Wormhole HTTP endpoints do not accept public_port".to_owned(),
                    ));
                }
                if let Some(host) = &spec.host
                    && !valid_label(host)
                {
                    return Err(DriverError::Capability(
                        "Wormhole host must be a lowercase DNS label".to_owned(),
                    ));
                }
            }
            crate::model::ServiceProto::Tcp => {
                if spec.buffer.is_some() {
                    return Err(DriverError::Capability(
                        "Wormhole TCP endpoints do not accept buffering".to_owned(),
                    ));
                }
                if spec.host.is_some() || spec.domain.is_some() {
                    return Err(DriverError::Capability(
                        "Wormhole TCP endpoints do not accept host or domain".to_owned(),
                    ));
                }
            }
        }
        if spec.public_port == Some(0) {
            return Err(DriverError::Capability("public_port must be non-zero".to_owned()));
        }
        Ok(())
    }

    async fn check(&self) -> DriverHealth {
        if self.remotes.is_empty() {
            DriverHealth::Unavailable("no remotes configured".to_owned())
        } else {
            DriverHealth::Healthy
        }
    }

    async fn run(
        &self,
        spec: EndpointSpec,
        target: ResolvedTarget,
        events: mpsc::Sender<DriverEvent>,
        stop: CancellationToken,
    ) -> Result<(), DriverError> {
        let (_forget_tx, forget) = watch::channel(false);
        let (internal_tx, mut internal_rx) = mpsc::channel(64);
        let forwarding = tokio::spawn(async move {
            while let Some(event) = internal_rx.recv().await {
                if let DriverEvent::Handoff(barrier) = event {
                    barrier.notify_one();
                } else if events.send(event).await.is_err() {
                    break;
                }
            }
        });
        let result = self.run_loop(spec, target, internal_tx, stop, forget).await;
        let _forwarded = forwarding.await;
        result
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
        self.run_loop(spec, target, events, stop, forget).await
    }
}

/// Performs a full authenticated remote handshake and returns its latency.
pub async fn test_remote(
    remote: &Remote,
    identity: wormhole_proto::Identity,
) -> Result<Duration, DriverError> {
    let started = std::time::Instant::now();
    let (endpoint, connection, _channel, _limits) = connect_remote(remote, identity).await?;
    connection.close(0_u32.into(), b"remote test complete");
    endpoint.wait_idle().await;
    Ok(started.elapsed())
}

fn valid_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes[0].is_ascii_alphanumeric()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

#[cfg(test)]
#[path = "wormhole_driver_tests.rs"]
mod tests;
