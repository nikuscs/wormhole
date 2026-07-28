use std::time::Duration;

use super::{
    IDLE_TIMEOUT, KEEP_ALIVE, bounded_max_streams, cleanup_limiter, handshake_limiter,
    server_config,
};
use crate::certs::CertManager;
use crate::config::{
    AuthConfig, LimitsConfig, PortRange, ServerConfig, TcpConfig, TlsConfig, TlsMode,
    WormholedConfig,
};
use camino::Utf8Path;
use tempfile::tempdir;

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
