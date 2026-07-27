use std::fs;

use camino::{Utf8Path, Utf8PathBuf};
use tempfile::tempdir;

use super::CertManager;
use crate::config::{
    AuthConfig, LimitsConfig, PortRange, ServerConfig, StaticCertificate, StaticTlsConfig,
    TcpConfig, TlsConfig, TlsMode, WormholedConfig,
};

fn config(
    data_dir: Utf8PathBuf,
    mode: TlsMode,
    static_config: Option<StaticTlsConfig>,
) -> WormholedConfig {
    WormholedConfig {
        server: ServerConfig {
            domains: vec!["tun.example.com".to_owned()],
            public_https_port: None,
            quic_addr: "127.0.0.1:0".parse().expect("valid address"),
            https_addr: "127.0.0.1:0".parse().expect("valid address"),
            http_addr: "127.0.0.1:0".parse().expect("valid address"),
            data_dir: data_dir.clone(),
        },
        tls: TlsConfig { mode, static_config, acme: None },
        tcp: TcpConfig { port_range: PortRange { start: 10_000, end: 10_010 } },
        limits: LimitsConfig::default(),
        auth: AuthConfig { authorized_keys: data_dir.join("keys") },
    }
}

#[tokio::test]
async fn self_signed_resolver_covers_apex_and_one_label_only() {
    let directory = tempdir().expect("temporary directory");
    let data_dir = Utf8Path::from_path(directory.path()).expect("UTF-8 temporary path").to_owned();
    let manager = CertManager::ready(&config(data_dir, TlsMode::SelfSigned, None))
        .await
        .expect("self-signed certificates must load");
    let resolver = manager.resolver();

    assert!(resolver.resolve_name("tun.example.com").is_some());
    assert!(resolver.resolve_name("demo.tun.example.com").is_some());
    assert!(resolver.resolve_name("deep.demo.tun.example.com").is_none());
    assert!(resolver.resolve_name("unknown.example.com").is_none());
}

#[tokio::test]
async fn static_pem_loads_and_hot_reloads() {
    let directory = tempdir().expect("temporary directory");
    let data_dir = Utf8Path::from_path(directory.path()).expect("UTF-8 temporary path").to_owned();
    let generated = rcgen::generate_simple_self_signed(vec![
        "tun.example.com".to_owned(),
        "*.tun.example.com".to_owned(),
    ])
    .expect("certificate fixture must generate");
    let certificate = data_dir.join("fullchain.pem");
    let key = data_dir.join("private-key.pem");
    fs::write(&certificate, generated.cert.pem()).expect("certificate fixture must write");
    fs::write(&key, generated.signing_key.serialize_pem()).expect("key fixture must write");
    let static_config = StaticTlsConfig {
        certs: vec![StaticCertificate {
            domain: "tun.example.com".to_owned(),
            cert: certificate,
            key,
        }],
    };
    let manager = CertManager::ready(&config(data_dir, TlsMode::Static, Some(static_config)))
        .await
        .expect("static certificates must load");

    assert!(manager.resolver().resolve_name("demo.tun.example.com").is_some());
    manager.reload_static().expect("static certificate must reload");
}
