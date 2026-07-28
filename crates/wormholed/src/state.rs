//! Shared relay state and global per-key session/bind counters.

use std::{
    net::SocketAddr,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
};

use dashmap::{DashMap, mapref::entry::Entry};
use jiff::Timestamp;
use tokio::sync::watch;
use uuid::Uuid;

use crate::{
    authz::AuthStore,
    config::LimitsConfig,
    db::{DbError, RelayDb},
    edge_tcp::TcpEdgeManager,
    registry::Registry,
};

#[derive(Debug, Clone, Copy)]
pub struct ListenerAddresses {
    pub quic: SocketAddr,
    pub https: SocketAddr,
    pub http: SocketAddr,
}

/// Process-wide state shared by listeners and session actors.
pub struct AppState {
    /// Public endpoint registry.
    pub registry: Arc<Registry>,
    /// Durable relay storage.
    pub database: Arc<RelayDb>,
    /// Public TCP-forward listener manager.
    pub tcp_edges: Arc<TcpEdgeManager>,
    /// Authoritative key policy.
    pub auth: Arc<AuthStore>,
    /// Configured safety limits.
    pub limits: LimitsConfig,
    /// Process start instant.
    pub started_at: Timestamp,
    counters: DashMap<String, Arc<KeyCounters>>,
    active_streams: AtomicU64,
    buffered_body_bytes: AtomicU64,
    buffered_inflight: DashMap<Uuid, u64>,
    listener_addresses: OnceLock<ListenerAddresses>,
    shutdown_tx: watch::Sender<bool>,
}

impl AppState {
    /// Creates shared state and restores durable bind counts.
    pub fn new(
        registry: Arc<Registry>,
        database: Arc<RelayDb>,
        tcp_edges: Arc<TcpEdgeManager>,
        auth: Arc<AuthStore>,
        limits: LimitsConfig,
    ) -> Result<Self, DbError> {
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);
        let state = Self {
            registry,
            database,
            tcp_edges,
            auth,
            limits,
            started_at: Timestamp::now(),
            counters: DashMap::new(),
            active_streams: AtomicU64::new(0),
            buffered_body_bytes: AtomicU64::new(0),
            buffered_inflight: DashMap::new(),
            listener_addresses: OnceLock::new(),
            shutdown_tx,
        };
        for (_, bind) in state.database.list_binds()? {
            state.counters(&bind.key_fpr).binds.fetch_add(1, Ordering::Relaxed);
        }
        Ok(state)
    }

    pub fn set_listener_addresses(&self, addresses: ListenerAddresses) {
        let _set = self.listener_addresses.set(addresses);
    }

    pub fn listener_addresses(&self) -> Option<ListenerAddresses> {
        self.listener_addresses.get().copied()
    }

    /// Attempts to reserve one globally limited session slot.
    pub fn try_open_session(&self, fingerprint: &str, limit: u32) -> bool {
        try_increment(&self.counters(fingerprint).sessions, limit)
    }

    /// Releases one session slot.
    pub fn close_session(&self, fingerprint: &str) {
        decrement(&self.counters(fingerprint).sessions);
    }

    /// Attempts to reserve one globally limited bind slot.
    pub fn try_add_bind(&self, fingerprint: &str, limit: u32) -> bool {
        try_increment(&self.counters(fingerprint).binds, limit)
    }

    /// Releases one bind slot.
    pub fn remove_bind(&self, fingerprint: &str) {
        decrement(&self.counters(fingerprint).binds);
    }

    /// Reserves process memory while an offline request body is collected.
    pub(crate) const fn reserve_buffer_memory(&self) -> BufferMemoryReservation<'_> {
        BufferMemoryReservation { counter: &self.buffered_body_bytes, reserved: 0 }
    }

    /// Claims one buffered row for delivery on its owning session.
    pub(crate) fn claim_buffered(&self, bind: Uuid, seq: u64) -> bool {
        match self.buffered_inflight.entry(bind) {
            Entry::Vacant(entry) => {
                entry.insert(seq);
                true
            }
            Entry::Occupied(_) => false,
        }
    }

    /// Completes a previously claimed buffered delivery.
    pub(crate) fn complete_buffered(&self, bind: Uuid, seq: u64) -> bool {
        self.buffered_inflight.remove_if(&bind, |_, current| *current == seq).is_some()
    }

    /// Releases the buffered claim when a bind disconnects.
    pub(crate) fn release_buffered_bind(&self, bind: Uuid) {
        self.buffered_inflight.remove(&bind);
    }

    /// Subscribes a session actor to reliable process shutdown notification.
    pub fn subscribe_shutdown(&self) -> watch::Receiver<bool> {
        self.shutdown_tx.subscribe()
    }

    /// Notifies all current and future subscribers that shutdown has begun.
    pub fn begin_shutdown(&self) {
        self.shutdown_tx.send_replace(true);
    }

    /// Returns a guard that tracks one live forwarded data stream.
    pub(crate) fn track_stream(self: &Arc<Self>) -> StreamGuard {
        self.active_streams.fetch_add(1, Ordering::AcqRel);
        StreamGuard(Arc::clone(self))
    }

    /// Returns the number of live forwarded data streams.
    pub fn active_streams(&self) -> u64 {
        self.active_streams.load(Ordering::Acquire)
    }

    /// Returns process-wide session and bind totals.
    pub fn totals(&self) -> (u32, u32) {
        self.counters.iter().fold((0, 0), |(sessions, binds), entry| {
            (
                sessions + entry.sessions.load(Ordering::Acquire),
                binds + entry.binds.load(Ordering::Acquire),
            )
        })
    }

    /// Returns current session and bind counts for administration.
    pub fn counts(&self, fingerprint: &str) -> (u32, u32) {
        let counters = self.counters(fingerprint);
        (counters.sessions.load(Ordering::Acquire), counters.binds.load(Ordering::Acquire))
    }

    fn counters(&self, fingerprint: &str) -> Arc<KeyCounters> {
        self.counters
            .entry(fingerprint.to_owned())
            .or_insert_with(|| Arc::new(KeyCounters::default()))
            .clone()
    }
}

pub(crate) struct BufferMemoryReservation<'a> {
    counter: &'a AtomicU64,
    reserved: u64,
}

impl BufferMemoryReservation<'_> {
    pub(crate) fn reserve(&mut self, additional: usize, limit: u64) -> bool {
        let Ok(additional) = u64::try_from(additional) else {
            return false;
        };
        let mut current = self.counter.load(Ordering::Acquire);
        loop {
            let Some(next) = current.checked_add(additional) else {
                return false;
            };
            if next > limit {
                return false;
            }
            match self.counter.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.reserved += additional;
                    return true;
                }
                Err(actual) => current = actual,
            }
        }
    }
}

impl Drop for BufferMemoryReservation<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(self.reserved, Ordering::AcqRel);
    }
}

pub(crate) struct StreamGuard(Arc<AppState>);

impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.0.active_streams.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Default)]
struct KeyCounters {
    sessions: AtomicU32,
    binds: AtomicU32,
}

fn try_increment(counter: &AtomicU32, limit: u32) -> bool {
    let mut current = counter.load(Ordering::Acquire);
    loop {
        if current >= limit {
            return false;
        }
        match counter.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(actual) => current = actual,
        }
    }
}

fn decrement(counter: &AtomicU32) {
    let mut current = counter.load(Ordering::Acquire);
    while current > 0 {
        match counter.compare_exchange_weak(
            current,
            current - 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return,
            Err(actual) => current = actual,
        }
    }
}

#[cfg(test)]
#[path = "state_tests.rs"]
mod tests;
