use std::{
    sync::Arc,
    sync::atomic::{AtomicU32, Ordering},
};

use jiff::Timestamp;
use tempfile::tempdir;
use uuid::Uuid;
use wormhole_proto::frames::Persistence;

use super::{AppState, BufferMemoryReservation, ListenerAddresses, decrement, try_increment};
use crate::{
    authz::{AuthStore, KeyLimits},
    config::{LimitsConfig, PortRange},
    db::{PersistedBind, PersistedBindSpec, PersistedEndpoint, RelayDb},
    edge_tcp::TcpEdgeManager,
    registry::Registry,
};

#[test]
fn atomic_limit_never_exceeds_maximum() {
    let counter = AtomicU32::new(0);

    assert!(try_increment(&counter, 2));
    assert!(try_increment(&counter, 2));
    assert!(!try_increment(&counter, 2));
    assert_eq!(counter.load(Ordering::Acquire), 2);
}

#[test]
fn aggregate_buffer_memory_is_bounded_and_released() {
    let counter = std::sync::atomic::AtomicU64::new(0);
    let mut first = BufferMemoryReservation { counter: &counter, reserved: 0 };
    let mut second = BufferMemoryReservation { counter: &counter, reserved: 0 };

    assert!(first.reserve(6, 10));
    assert!(!second.reserve(5, 10));
    assert!(second.reserve(4, 10));
    drop(first);
    assert_eq!(counter.load(Ordering::Acquire), 4);
    drop(second);
    assert_eq!(counter.load(Ordering::Acquire), 0);
}

#[test]
fn decrement_saturates_at_zero() {
    let counter = AtomicU32::new(1);

    decrement(&counter);
    decrement(&counter);

    assert_eq!(counter.load(Ordering::Acquire), 0);
}

fn state_with_database(database: Arc<RelayDb>) -> Arc<AppState> {
    let limits = LimitsConfig::default();
    let auth = Arc::new(AuthStore::new(Arc::clone(&database), KeyLimits::from(&limits)));
    let registry = Arc::new(Registry::new(
        vec!["tun.example.com".to_owned()],
        None,
        443,
        PortRange { start: 10_000, end: 10_001 },
    ));
    let tcp = Arc::new(TcpEdgeManager::new("127.0.0.1".parse().expect("IP")));
    Arc::new(AppState::new(registry, database, tcp, auth, limits).expect("state"))
}

#[test]
fn app_state_tracks_counters_addresses_streams_and_shutdown() {
    let directory = tempdir().expect("temporary directory");
    let path = camino::Utf8Path::from_path(directory.path()).expect("UTF-8");
    let state = state_with_database(Arc::new(RelayDb::open(path).expect("database")));

    assert!(state.try_open_session("key", 1));
    assert!(!state.try_open_session("key", 1));
    assert!(state.try_add_bind("key", 2));
    assert!(state.try_add_bind("key", 2));
    assert!(!state.try_add_bind("key", 2));
    assert_eq!(state.counts("key"), (1, 2));
    assert_eq!(state.totals(), (1, 2));
    state.close_session("key");
    state.remove_bind("key");
    assert_eq!(state.counts("key"), (0, 1));

    let addresses = ListenerAddresses {
        quic: "127.0.0.1:1".parse().expect("QUIC"),
        https: "127.0.0.1:2".parse().expect("HTTPS"),
        http: "127.0.0.1:3".parse().expect("HTTP"),
    };
    state.set_listener_addresses(addresses);
    state.set_listener_addresses(ListenerAddresses { quic: addresses.http, ..addresses });
    assert_eq!(state.listener_addresses().expect("addresses").quic, addresses.quic);

    let stream = state.track_stream();
    assert_eq!(state.active_streams(), 1);
    drop(stream);
    assert_eq!(state.active_streams(), 0);
    let shutdown = state.subscribe_shutdown();
    assert!(!*shutdown.borrow());
    state.begin_shutdown();
    assert!(*shutdown.borrow());
}

#[test]
fn buffered_claims_require_matching_sequence_and_can_be_released() {
    let directory = tempdir().expect("temporary directory");
    let path = camino::Utf8Path::from_path(directory.path()).expect("UTF-8");
    let state = state_with_database(Arc::new(RelayDb::open(path).expect("database")));
    let bind = Uuid::now_v7();

    assert!(state.claim_buffered(bind, 1));
    assert!(!state.claim_buffered(bind, 2));
    assert!(!state.complete_buffered(bind, 2));
    assert!(state.complete_buffered(bind, 1));
    assert!(state.claim_buffered(bind, 3));
    state.release_buffered_bind(bind);
    assert!(state.claim_buffered(bind, 4));
}

#[test]
fn persisted_bind_counts_are_restored_at_startup() {
    let directory = tempdir().expect("temporary directory");
    let path = camino::Utf8Path::from_path(directory.path()).expect("UTF-8");
    let database = Arc::new(RelayDb::open(path).expect("database"));
    let now = Timestamp::now();
    database
        .put_bind(
            Uuid::now_v7(),
            &PersistedBind {
                reservation: Uuid::now_v7(),
                spec: PersistedBindSpec::Http {
                    host: Some("hook".to_owned()),
                    domain: Some("tun.example.com".to_owned()),
                    persist: Persistence::Persistent,
                    buffer: None,
                },
                auth_verifier: None,
                endpoint: PersistedEndpoint::Hostname("hook.tun.example.com".to_owned()),
                key_fpr: "owner".to_owned(),
                created: now,
                last_seen: now,
            },
        )
        .expect("persist bind");

    let state = state_with_database(database);
    assert_eq!(state.counts("owner"), (0, 1));
}
