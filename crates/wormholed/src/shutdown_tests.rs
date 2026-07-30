use std::{future, sync::Arc, time::Duration};

use tempfile::tempdir;

use super::{select_termination, wait_for_drain};
use crate::{
    authz::{AuthStore, KeyLimits},
    config::{LimitsConfig, PortRange},
    db::RelayDb,
    edge_tcp::TcpEdgeManager,
    registry::Registry,
    state::AppState,
};

fn state() -> (tempfile::TempDir, Arc<AppState>) {
    let directory = tempdir().expect("temporary directory");
    let path = camino::Utf8Path::from_path(directory.path()).expect("UTF-8");
    let database = Arc::new(RelayDb::open(path).expect("database"));
    let limits = LimitsConfig::default();
    let auth = Arc::new(AuthStore::new(Arc::clone(&database), KeyLimits::from(&limits)));
    let registry = Arc::new(Registry::new(
        vec!["tun.example.com".to_owned()],
        None,
        443,
        PortRange { start: 10_000, end: 10_001 },
    ));
    let tcp = Arc::new(TcpEdgeManager::new("127.0.0.1".parse().expect("IP")));
    let state = Arc::new(AppState::new(registry, database, tcp, auth, limits).expect("state"));
    (directory, state)
}

#[tokio::test]
async fn termination_selection_propagates_ctrl_c_and_accepts_terminate() {
    select_termination(future::ready(Ok(())), future::pending()).await.expect("ctrl-c");
    select_termination(future::pending(), future::ready(())).await.expect("terminate");
    let error = std::io::Error::other("signal failure");
    assert_eq!(
        select_termination(future::ready(Err(error)), future::pending())
            .await
            .expect_err("signal failure")
            .kind(),
        std::io::ErrorKind::Other
    );
}

#[tokio::test]
async fn drain_notifies_and_waits_for_sessions_and_streams() {
    let (_directory, state) = state();
    assert!(state.try_open_session("owner", 1));
    let stream = state.track_stream();
    let mut shutdown = state.subscribe_shutdown();
    let drained_state = Arc::clone(&state);
    let drain = tokio::spawn(async move {
        wait_for_drain(&drained_state, Duration::from_secs(1)).await;
    });
    shutdown.changed().await.expect("shutdown notification");
    assert!(*shutdown.borrow());
    state.close_session("owner");
    drop(stream);
    drain.await.expect("drain task");
}

#[tokio::test]
async fn drain_timeout_returns_with_active_work() {
    let (_directory, state) = state();
    assert!(state.try_open_session("owner", 1));
    wait_for_drain(&state, Duration::ZERO).await;
    assert!(*state.subscribe_shutdown().borrow());
    assert_eq!(state.totals().0, 1);
}
