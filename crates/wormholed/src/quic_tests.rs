use std::{sync::Arc, time::Duration};

use super::{
    Authenticated, IDLE_TIMEOUT, KEEP_ALIVE, QuicError, QuicServer, bounded_max_streams,
    cleanup_limiter, handshake_limiter, release_failed_auth, send_handshake_step, server_config,
};
use crate::config::{
    AuthConfig, LimitsConfig, PortRange, ServerConfig, TcpConfig, TlsConfig, TlsMode,
    WormholedConfig,
};
use crate::{
    authz::{AuthStore, KeyLimits},
    certs::CertManager,
    db::RelayDb,
    edge_tcp::TcpEdgeManager,
    registry::Registry,
    state::AppState,
};
use camino::Utf8Path;
use parking_lot::Mutex;
use tempfile::tempdir;
use wormhole_proto::{
    HandshakeStep, Welcome,
    codec::ControlChannel,
    frames::{ControlFrame, DenyReason, Limits},
};

#[test]
fn websocket_advertises_no_more_streams_than_mux_enforces() {
    assert_eq!(
        bounded_max_streams(1024, wormhole_proto::mux_runtime::MAX_STREAMS),
        wormhole_proto::mux_runtime::MAX_STREAMS
    );
    assert_eq!(bounded_max_streams(8, wormhole_proto::mux_runtime::MAX_STREAMS), 8);
}

#[test]
fn thirty_first_handshake_from_one_ip_is_rate_limited() {
    let limiter = handshake_limiter(30).expect("limiter");
    let ip = "127.0.0.1".parse().expect("IP");
    for _ in 0..30 {
        assert!(limiter.check_key(&ip).is_ok());
    }
    assert!(limiter.check_key(&ip).is_err());
    assert!(limiter.check_key(&"127.0.0.2".parse().expect("other IP")).is_ok());
}

#[test]
fn limiter_cleanup_handles_empty_state_and_zero_quota_is_rejected() {
    let limiter = handshake_limiter(30).expect("limiter");
    cleanup_limiter(&limiter);
    assert_eq!(limiter.len(), 0);
    assert!(matches!(handshake_limiter(0), Err(QuicError::Config(_))));
}

#[tokio::test]
async fn stale_handshake_limiter_entries_are_evicted() {
    let limiter = handshake_limiter(6000).expect("limiter");
    assert!(limiter.check_key(&"127.0.0.1".parse().expect("IP")).is_ok());
    assert_eq!(limiter.len(), 1);
    tokio::time::sleep(Duration::from_millis(20)).await;
    cleanup_limiter(&limiter);
    assert_eq!(limiter.len(), 0);
}

#[test]
fn quic_operational_timings_match_contract() {
    assert_eq!(KEEP_ALIVE, Duration::from_secs(15));
    assert_eq!(IDLE_TIMEOUT.as_secs(), 60);
}

#[tokio::test]
async fn quic_config_uses_ready_resolver() {
    let directory = tempdir().expect("temporary directory");
    let data = Utf8Path::from_path(directory.path()).expect("UTF-8 temporary path").to_owned();
    let config = WormholedConfig {
        server: ServerConfig {
            domains: vec!["tun.example.com".to_owned()],
            public_https_port: None,
            quic_addr: "127.0.0.1:0".parse().expect("valid address"),
            https_addr: "127.0.0.1:0".parse().expect("valid address"),
            http_addr: "127.0.0.1:0".parse().expect("valid address"),
            data_dir: data.clone(),
        },
        tls: TlsConfig { mode: TlsMode::SelfSigned, static_config: None, acme: None },
        tcp: TcpConfig { port_range: PortRange { start: 10_000, end: 10_010 } },
        limits: LimitsConfig::default(),
        auth: AuthConfig { authorized_keys: data.join("keys") },
    };
    let certificates = CertManager::ready(&config).await.expect("certificates must be ready");

    server_config(&certificates).expect("QUIC server config must build");
}

#[tokio::test]
async fn quic_server_binds_reports_address_and_stops_when_closed() {
    let directory = tempdir().expect("temporary directory");
    let data = Utf8Path::from_path(directory.path()).expect("UTF-8 temporary path").to_owned();
    let config = test_config(data.clone());
    let certificates = CertManager::ready(&config).await.expect("certificates");
    let state = state(&config, &data);
    assert!(matches!(
        QuicServer::bind(
            "127.0.0.1:0".parse().expect("address"),
            Arc::clone(&state),
            &certificates,
            "tun.example.com".to_owned(),
            0,
        ),
        Err(QuicError::Config(_))
    ));
    let server = Arc::new(
        QuicServer::bind(
            "127.0.0.1:0".parse().expect("address"),
            state,
            &certificates,
            "tun.example.com".to_owned(),
            30,
        )
        .expect("bind server"),
    );
    assert_ne!(server.local_addr().expect("local address").port(), 0);
    server.endpoint().close(0_u32.into(), b"test complete");
    server.run().await;
}

fn test_config(data: camino::Utf8PathBuf) -> WormholedConfig {
    WormholedConfig {
        server: ServerConfig {
            domains: vec!["tun.example.com".to_owned()],
            public_https_port: None,
            quic_addr: "127.0.0.1:0".parse().expect("valid address"),
            https_addr: "127.0.0.1:0".parse().expect("valid address"),
            http_addr: "127.0.0.1:0".parse().expect("valid address"),
            data_dir: data.clone(),
        },
        tls: TlsConfig { mode: TlsMode::SelfSigned, static_config: None, acme: None },
        tcp: TcpConfig { port_range: PortRange { start: 10_000, end: 10_010 } },
        limits: LimitsConfig::default(),
        auth: AuthConfig { authorized_keys: data.join("keys") },
    }
}

fn state(config: &WormholedConfig, data: &Utf8Path) -> Arc<AppState> {
    let database = Arc::new(RelayDb::open(data).expect("database"));
    let auth = Arc::new(AuthStore::new(Arc::clone(&database), KeyLimits::from(&config.limits)));
    let registry =
        Arc::new(Registry::new(config.server.domains.clone(), None, 443, config.tcp.port_range));
    Arc::new(
        AppState::new(
            registry,
            database,
            Arc::new(TcpEdgeManager::new("127.0.0.1".parse().expect("IP"))),
            auth,
            config.limits.clone(),
        )
        .expect("state"),
    )
}

#[tokio::test]
async fn handshake_steps_send_replies_close_failures_and_release_open_sessions() {
    let (relay, client) = tokio::io::duplex(4096);
    let mut relay = ControlChannel::new(relay);
    let mut client = ControlChannel::new(client);
    assert!(
        send_handshake_step(&mut relay, HandshakeStep::Reply(ControlFrame::Pong { seq: 9 }))
            .await
            .expect("reply")
    );
    assert_eq!(client.recv().await.expect("reply frame"), ControlFrame::Pong { seq: 9 });
    let welcome = Welcome {
        session: uuid::Uuid::now_v7(),
        limits: Limits { max_binds: 1, max_streams: 1 },
        motd: None,
        domains: vec!["tun.example.com".to_owned()],
    };
    assert!(
        send_handshake_step(
            &mut relay,
            HandshakeStep::Done { welcome: welcome.clone(), reply: None },
        )
        .await
        .expect("done")
    );
    assert!(
        !send_handshake_step(
            &mut relay,
            HandshakeStep::Failed {
                reason: DenyReason::Limit,
                reply: Some(ControlFrame::Denied { reason: DenyReason::Limit }),
            },
        )
        .await
        .expect("failed")
    );
    assert_eq!(
        client.recv().await.expect("denied frame"),
        ControlFrame::Denied { reason: DenyReason::Limit }
    );
    assert!(client.recv().await.is_err());

    let directory = tempdir().expect("temporary directory");
    let data = Utf8Path::from_path(directory.path()).expect("UTF-8").to_owned();
    let config = test_config(data.clone());
    let state = state(&config, &data);
    assert!(state.try_open_session("owner", 1));
    let authenticated = Mutex::new(Some(Authenticated {
        fingerprint: "owner".to_owned(),
        limits: KeyLimits { max_binds: 1, max_sessions: 1, max_streams: 1 },
        session_open: true,
    }));
    release_failed_auth(&state, &authenticated);
    assert_eq!(state.totals().0, 0);
    release_failed_auth(&state, &authenticated);
}
