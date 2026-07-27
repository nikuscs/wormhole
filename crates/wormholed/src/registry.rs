//! Concurrent public endpoint registry and secure reservation allocation.

use std::sync::Arc;

use dashmap::{DashMap, mapref::entry::Entry};
use parking_lot::RwLock;
use rand::RngExt;
use uuid::Uuid;
use wormhole_proto::frames::{BindSpec, BufferPolicy, EdgeAuth, Persistence};

use crate::{
    config::PortRange,
    db::{PersistedBind, PersistedBindSpec, PersistedEndpoint, RelayDb},
    registry_types::clone_request,
};

pub use crate::registry_types::{
    Allocation, AllocationRequest, BindHandle, BindState, HostKey, RegistryError, SessionCommand,
};

const ADJECTIVES: &[&str] =
    &["amber", "brisk", "calm", "eager", "lucky", "quiet", "rapid", "silver"];
const NOUNS: &[&str] =
    &["badger", "comet", "falcon", "maple", "otter", "river", "sparrow", "willow"];
const GENERATED_ATTEMPTS: usize = 64;

/// Concurrent public routing registry.
pub struct Registry {
    routes: DashMap<HostKey, Arc<BindHandle>>,
    bind_keys: DashMap<Uuid, HostKey>,
    reservations: DashMap<Uuid, Uuid>,
    domains: Vec<String>,
    https_port: u16,
    tcp_range: PortRange,
}

impl Registry {
    /// Creates an empty registry using server-controlled domains and bound ports.
    pub fn new(
        domains: Vec<String>,
        public_https_port: Option<u16>,
        bound_https_port: u16,
        tcp_range: PortRange,
    ) -> Self {
        Self {
            routes: DashMap::new(),
            bind_keys: DashMap::new(),
            reservations: DashMap::new(),
            domains,
            https_port: public_https_port.unwrap_or(bound_https_port),
            tcp_range,
        }
    }

    /// Preloads all durable reservations as offline routes.
    pub fn preload(&self, database: &RelayDb) -> Result<usize, RegistryError> {
        let binds = database.list_binds()?;
        let count = binds.len();
        for (bind_id, bind) in binds {
            self.insert_persisted(bind_id, bind)?;
        }
        Ok(count)
    }

    /// Allocates a new endpoint or securely reclaims a reservation.
    pub fn allocate(&self, request: AllocationRequest) -> Result<Allocation, RegistryError> {
        if let Some(reservation) = request.reservation {
            return self.reclaim(reservation, request);
        }
        match request.spec.clone() {
            BindSpec::Http { host, domain, persist, buffer, auth } => {
                self.allocate_http(request, host, domain, persist, buffer, auth)
            }
            BindSpec::Tcp { remote_port, persist } => {
                self.allocate_tcp(request, remote_port, persist)
            }
        }
    }

    /// Looks up a route without holding the map lock across later awaits.
    pub fn get(&self, key: &HostKey) -> Option<Arc<BindHandle>> {
        self.routes.get(key).map(|entry| Arc::clone(entry.value()))
    }

    /// Atomically flips a pending bind online.
    pub fn activate(&self, bind: Uuid) -> Result<(), RegistryError> {
        let handle = self.by_bind(bind)?;
        let mut state = handle.state.write();
        if *state != BindState::Pending {
            return Err(RegistryError::InvalidState { bind, state: *state });
        }
        *state = BindState::Online;
        drop(state);
        Ok(())
    }

    /// Disconnects one bind, retaining persistent routes offline.
    pub fn disconnect(&self, bind: Uuid) -> Result<(), RegistryError> {
        let handle = self.by_bind(bind)?;
        if handle.persist == Persistence::Persistent {
            *handle.state.write() = BindState::Offline;
            *handle.session_tx.write() = None;
            return Ok(());
        }
        self.remove(bind, true)
    }

    /// Removes a route; persistent reservations survive unless `forget` is true.
    pub fn remove(&self, bind: Uuid, forget: bool) -> Result<(), RegistryError> {
        let key = self.bind_keys.remove(&bind).ok_or(RegistryError::UnknownBind(bind))?.1;
        let handle = self.routes.remove(&key).ok_or(RegistryError::UnknownBind(bind))?.1;
        if forget && let Some(reservation) = handle.reservation {
            self.reservations.remove(&reservation);
        }
        Ok(())
    }

    fn allocate_http(
        &self,
        request: AllocationRequest,
        host: Option<String>,
        domain: Option<String>,
        persist: Persistence,
        buffer: Option<BufferPolicy>,
        auth: Option<EdgeAuth>,
    ) -> Result<Allocation, RegistryError> {
        let domain = self.select_domain(domain.as_deref())?;
        if let Some(host) = host {
            validate_label(&host)?;
            return self.insert_http(request, host, domain, persist, buffer, auth);
        }
        for _ in 0..GENERATED_ATTEMPTS {
            let generated = random_label();
            match self.insert_http(
                clone_request(&request),
                generated,
                domain.clone(),
                persist,
                buffer.clone(),
                auth.clone(),
            ) {
                Err(RegistryError::Conflict(_)) => {}
                result => return result,
            }
        }
        Err(RegistryError::AllocationExhausted)
    }

    fn insert_http(
        &self,
        request: AllocationRequest,
        host: String,
        domain: String,
        persist: Persistence,
        buffer: Option<BufferPolicy>,
        auth: Option<EdgeAuth>,
    ) -> Result<Allocation, RegistryError> {
        let hostname = format!("{host}.{domain}");
        let key = HostKey::Hostname(hostname.clone());
        let spec = PersistedBindSpec::Http {
            host: Some(host),
            domain: Some(domain),
            persist,
            buffer: buffer.clone(),
        };
        let handle = Self::new_handle(
            request,
            persist,
            buffer,
            auth,
            spec,
            PersistedEndpoint::Hostname(hostname.clone()),
        );
        self.insert_route(key, &handle)?;
        Ok(Allocation {
            bind: handle.bind_id,
            urls: vec![https_url(&hostname, self.https_port)],
            reservation: handle.reservation,
            persist,
        })
    }

    fn allocate_tcp(
        &self,
        request: AllocationRequest,
        requested: Option<u16>,
        persist: Persistence,
    ) -> Result<Allocation, RegistryError> {
        let ports: Box<dyn Iterator<Item = u16>> = if let Some(port) = requested {
            if port < self.tcp_range.start || port > self.tcp_range.end {
                return Err(RegistryError::PortOutsideRange(port));
            }
            Box::new(std::iter::once(port))
        } else {
            Box::new(self.tcp_range.start..=self.tcp_range.end)
        };
        for port in ports {
            let spec = PersistedBindSpec::Tcp { remote_port: Some(port), persist };
            let handle = Self::new_handle(
                clone_request(&request),
                persist,
                None,
                None,
                spec,
                PersistedEndpoint::TcpPort(port),
            );
            match self.insert_route(HostKey::TcpPort(port), &handle) {
                Ok(()) => {
                    return Ok(Allocation {
                        bind: handle.bind_id,
                        urls: vec![format!("tcp://{}:{port}", self.domains[0])],
                        reservation: handle.reservation,
                        persist,
                    });
                }
                Err(RegistryError::Conflict(_)) if requested.is_none() => {}
                Err(error) => return Err(error),
            }
        }
        Err(RegistryError::PortRangeExhausted)
    }

    fn new_handle(
        request: AllocationRequest,
        persist: Persistence,
        buffer_policy: Option<BufferPolicy>,
        auth: Option<EdgeAuth>,
        spec: PersistedBindSpec,
        endpoint: PersistedEndpoint,
    ) -> Arc<BindHandle> {
        Arc::new(BindHandle {
            bind_id: Uuid::now_v7(),
            key_fpr: request.key_fpr,
            persist,
            buffer_policy,
            auth,
            spec,
            endpoint,
            state: RwLock::new(BindState::Pending),
            session_tx: RwLock::new(Some(request.session_tx)),
            reservation: (persist == Persistence::Persistent).then(Uuid::now_v7),
        })
    }

    fn insert_route(&self, key: HostKey, handle: &Arc<BindHandle>) -> Result<(), RegistryError> {
        match self.routes.entry(key.clone()) {
            Entry::Occupied(_) => return Err(RegistryError::Conflict(key)),
            Entry::Vacant(entry) => entry.insert(Arc::clone(handle)),
        };
        self.bind_keys.insert(handle.bind_id, key);
        if let Some(reservation) = handle.reservation {
            self.reservations.insert(reservation, handle.bind_id);
        }
        Ok(())
    }

    fn reclaim(
        &self,
        reservation: Uuid,
        request: AllocationRequest,
    ) -> Result<Allocation, RegistryError> {
        let bind = self
            .reservations
            .get(&reservation)
            .map(|entry| *entry.value())
            .ok_or(RegistryError::UnknownReservation)?;
        let handle = self.by_bind(bind)?;
        if handle.key_fpr != request.key_fpr {
            return Err(RegistryError::ReservationOwnerMismatch);
        }
        if handle.state() == BindState::Online {
            return Err(RegistryError::AlreadyOnline(bind));
        }
        if !spec_kind_matches(&handle.spec, &request.spec) {
            return Err(RegistryError::ReservationKindMismatch);
        }
        *handle.session_tx.write() = Some(request.session_tx);
        *handle.state.write() = BindState::Pending;
        Ok(Allocation {
            bind,
            urls: vec![self.url_for(&handle.endpoint)],
            reservation: Some(reservation),
            persist: Persistence::Persistent,
        })
    }

    fn insert_persisted(&self, bind_id: Uuid, bind: PersistedBind) -> Result<(), RegistryError> {
        let key = host_key(&bind.endpoint);
        let persist = match bind.spec {
            PersistedBindSpec::Http { persist, .. } | PersistedBindSpec::Tcp { persist, .. } => {
                persist
            }
        };
        let buffer_policy = match &bind.spec {
            PersistedBindSpec::Http { buffer, .. } => buffer.clone(),
            PersistedBindSpec::Tcp { .. } => None,
        };
        let handle = Arc::new(BindHandle {
            bind_id,
            key_fpr: bind.key_fpr,
            persist,
            buffer_policy,
            auth: None,
            spec: bind.spec,
            endpoint: bind.endpoint,
            state: RwLock::new(BindState::Offline),
            session_tx: RwLock::new(None),
            reservation: Some(bind.reservation),
        });
        self.insert_route(key, &handle)
    }

    fn by_bind(&self, bind: Uuid) -> Result<Arc<BindHandle>, RegistryError> {
        let key = self
            .bind_keys
            .get(&bind)
            .map(|entry| entry.value().clone())
            .ok_or(RegistryError::UnknownBind(bind))?;
        self.get(&key).ok_or(RegistryError::UnknownBind(bind))
    }

    fn select_domain(&self, requested: Option<&str>) -> Result<String, RegistryError> {
        let domain = requested.unwrap_or(&self.domains[0]);
        self.domains
            .iter()
            .find(|candidate| candidate.as_str() == domain)
            .cloned()
            .ok_or_else(|| RegistryError::UnknownDomain(domain.to_owned()))
    }

    fn url_for(&self, endpoint: &PersistedEndpoint) -> String {
        match endpoint {
            PersistedEndpoint::Hostname(hostname) => https_url(hostname, self.https_port),
            PersistedEndpoint::TcpPort(port) => format!("tcp://{}:{port}", self.domains[0]),
        }
    }
}

fn validate_label(label: &str) -> Result<(), RegistryError> {
    let valid = !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        });
    if valid { Ok(()) } else { Err(RegistryError::InvalidHostname(label.to_owned())) }
}

fn random_label() -> String {
    let mut rng = rand::rng();
    format!(
        "{}-{}-{:04x}",
        ADJECTIVES[rng.random_range(0..ADJECTIVES.len())],
        NOUNS[rng.random_range(0..NOUNS.len())],
        rng.random::<u16>()
    )
}

fn https_url(hostname: &str, port: u16) -> String {
    if port == 443 { format!("https://{hostname}") } else { format!("https://{hostname}:{port}") }
}

fn host_key(endpoint: &PersistedEndpoint) -> HostKey {
    match endpoint {
        PersistedEndpoint::Hostname(hostname) => HostKey::Hostname(hostname.clone()),
        PersistedEndpoint::TcpPort(port) => HostKey::TcpPort(*port),
    }
}

const fn spec_kind_matches(persisted: &PersistedBindSpec, requested: &BindSpec) -> bool {
    matches!(
        (persisted, requested),
        (PersistedBindSpec::Http { .. }, BindSpec::Http { .. })
            | (PersistedBindSpec::Tcp { .. }, BindSpec::Tcp { .. })
    )
}

#[cfg(test)]
#[path = "registry_tests.rs"]
mod tests;
