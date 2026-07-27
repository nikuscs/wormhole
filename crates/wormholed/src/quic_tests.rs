use super::server_config;
use crate::certs::CertManager;
use crate::config::{
    AuthConfig, LimitsConfig, PortRange, ServerConfig, TcpConfig, TlsConfig, TlsMode,
    WormholedConfig,
};
use camino::Utf8Path;
use tempfile::tempdir;

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
