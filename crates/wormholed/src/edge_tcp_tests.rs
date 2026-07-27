use std::sync::Arc;

use parking_lot::RwLock;
use tokio::{
    io::AsyncReadExt,
    net::TcpStream,
    sync::mpsc,
    time::{Duration, timeout},
};
use uuid::Uuid;
use wormhole_proto::frames::Persistence;

use super::TcpEdgeManager;
use crate::{
    db::{PersistedBindSpec, PersistedEndpoint},
    registry::{BindHandle, BindState, SessionCommand},
};

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("probe listener must bind");
    listener.local_addr().expect("probe address").port()
}

#[tokio::test]
async fn offline_listener_closes_and_online_listener_dispatches() {
    let port = free_port();
    let (session_tx, mut session_rx) = mpsc::channel(4);
    let handle = Arc::new(BindHandle {
        bind_id: Uuid::now_v7(),
        key_fpr: "owner".to_owned(),
        persist: Persistence::Persistent,
        buffer_policy: None,
        auth: None,
        auth_verifier: RwLock::new(None),
        spec: PersistedBindSpec::Tcp { remote_port: Some(port), persist: Persistence::Persistent },
        endpoint: PersistedEndpoint::TcpPort(port),
        state: RwLock::new(BindState::Offline),
        session_tx: RwLock::new(Some(session_tx)),
        reservation: Some(Uuid::now_v7()),
    });
    let manager = TcpEdgeManager::new("127.0.0.1".parse().expect("valid IP"));
    manager.ensure_listener(port, Arc::clone(&handle)).await.expect("TCP listener must bind");

    let mut offline = TcpStream::connect(("127.0.0.1", port)).await.expect("offline connect");
    let mut byte = [0_u8; 1];
    assert_eq!(
        timeout(Duration::from_secs(1), offline.read(&mut byte))
            .await
            .expect("offline close timeout")
            .expect("offline read"),
        0
    );

    *handle.state.write() = BindState::Online;
    let _online = TcpStream::connect(("127.0.0.1", port)).await.expect("online connect");
    assert!(matches!(
        timeout(Duration::from_secs(1), session_rx.recv()).await.expect("dispatch timeout"),
        Some(SessionCommand::OpenTcp { .. })
    ));
    manager.remove_listener(port);
    assert!(!manager.contains(port));
}
