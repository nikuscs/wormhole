//! Reference Wormhole protocol driver with shared per-remote connections.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use dashmap::DashMap;
use rand::RngExt as _;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;
use wormhole_proto::frames::Persistence;

use crate::{
    driver::{DriverCapabilities, DriverEvent, DriverHealth, TunnelDriver},
    error::DriverError,
    keys_store::IdentityStore,
    model::{EndpointSpec, EndpointStatus, ResolvedTarget},
    remotes::Remote,
    wormhole_conn::RemoteConn,
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
        mut spec: EndpointSpec,
        target: ResolvedTarget,
        events: mpsc::Sender<DriverEvent>,
        stop: CancellationToken,
    ) -> Result<(), DriverError> {
        let remote = self.remote_name(&spec)?.to_owned();
        let persistent = spec.persist == Persistence::Persistent;
        let mut attempts = 0_u32;
        let mut backoff = INITIAL_BACKOFF;
        loop {
            if stop.is_cancelled() {
                let _closed = events.send(DriverEvent::Closed).await;
                return Ok(());
            }
            if attempts > 0 {
                let _status =
                    events.send(DriverEvent::StatusChanged(EndpointStatus::Reconnecting)).await;
            }
            let result = self.connection(&remote).await;
            if let Ok(connection) = result {
                match connection
                    .bind(spec.clone(), target, events.clone(), stop.child_token())
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
                                    spec.persist == Persistence::Temporary,
                                ).await;
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
                    let _closed = events.send(DriverEvent::Closed).await;
                    return Ok(());
                }
                () = tokio::time::sleep(Duration::from_millis(jitter)) => {}
            }
            backoff = backoff.saturating_mul(2).min(MAX_BACKOFF);
        }
    }
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
