use std::{fs, os::unix::fs::PermissionsExt as _, sync::Arc};

use camino::{Utf8Path, Utf8PathBuf};
use rustls::sign::CertifiedKey;
use tempfile::tempdir;

use super::{
    AcmeError, cache_mapping, expires_soon, load_cached, load_or_issue, write_atomic,
    write_private, write_private_json,
};
use crate::config::{
    AuthConfig, LimitsConfig, PortRange, ServerConfig, TcpConfig, TlsConfig, TlsMode,
    WormholedConfig,
};

#[tokio::test]
async fn load_or_issue_requires_acme_configuration() {
    let directory = tempdir().expect("tempdir");
    let config = config(path(directory.path()), None);
    assert!(matches!(load_or_issue(&config).await, Err(AcmeError::Config(_))));
}

#[test]
fn cache_mapping_and_atomic_writes_use_expected_names_and_modes() {
    let directory = tempdir().expect("tempdir");
    let root = path(directory.path());
    let mapping = cache_mapping(&root, "tun.example.com");
    assert_eq!(mapping.cert, root.join("tun.example.com.pem"));
    assert_eq!(mapping.key, root.join("tun.example.com.key.pem"));

    let private = root.join("private.json");
    write_private_json(&private, &serde_json::json!({"key": "value"})).expect("private JSON");
    assert!(fs::read_to_string(&private).expect("read private").contains("value"));
    assert_eq!(fs::metadata(&private).expect("metadata").permissions().mode() & 0o777, 0o600);

    let public = root.join("certificate.pem");
    write_atomic(&public, b"certificate", 0o644).expect("atomic write");
    assert_eq!(fs::read(&public).expect("read public"), b"certificate");
    assert_eq!(fs::metadata(&public).expect("metadata").permissions().mode() & 0o777, 0o644);

    let missing_parent = root.join("missing/file");
    assert!(matches!(write_atomic(&missing_parent, b"x", 0o600), Err(AcmeError::Io { .. })));
}

#[test]
fn cached_certificate_requires_both_files_and_sufficient_lifetime() {
    let directory = tempdir().expect("tempdir");
    let root = path(directory.path());
    assert!(load_cached(&root, "tun.example.com").expect("empty cache").is_none());

    let mapping = cache_mapping(&root, "tun.example.com");
    let generated = rcgen::generate_simple_self_signed(vec![
        "tun.example.com".to_owned(),
        "*.tun.example.com".to_owned(),
    ])
    .expect("certificate");
    fs::write(&mapping.cert, generated.cert.pem()).expect("write cert");
    assert!(load_cached(&root, "tun.example.com").expect("missing key").is_none());
    fs::write(&mapping.key, generated.signing_key.serialize_pem()).expect("write key");
    let cached: Option<Arc<CertifiedKey>> = load_cached(&root, "tun.example.com").expect("cache");
    assert!(cached.is_some());
    assert!(!expires_soon(&mapping.cert).expect("expiry"));

    fs::write(&mapping.cert, "not a certificate").expect("corrupt cert");
    assert!(matches!(expires_soon(&mapping.cert), Err(AcmeError::Certificate(_))));
}

#[test]
fn empty_certificate_chain_is_rejected() {
    let directory = tempdir().expect("tempdir");
    let cert = path(directory.path()).join("empty.pem");
    fs::write(&cert, "").expect("empty PEM");
    let error = expires_soon(&cert).expect_err("empty chain");
    assert!(error.to_string().contains("certificate chain is empty"));
}

fn path(path: &std::path::Path) -> Utf8PathBuf {
    Utf8Path::from_path(path).expect("UTF-8 path").to_owned()
}

fn config(data_dir: Utf8PathBuf, acme: Option<crate::config::AcmeConfig>) -> WormholedConfig {
    WormholedConfig {
        server: ServerConfig {
            domains: vec!["tun.example.com".to_owned()],
            public_https_port: None,
            quic_addr: "127.0.0.1:0".parse().expect("address"),
            https_addr: "127.0.0.1:0".parse().expect("address"),
            http_addr: "127.0.0.1:0".parse().expect("address"),
            data_dir: data_dir.clone(),
        },
        tls: TlsConfig { mode: TlsMode::AcmeDns01, static_config: None, acme },
        tcp: TcpConfig { port_range: PortRange { start: 10_000, end: 10_010 } },
        limits: LimitsConfig::default(),
        auth: AuthConfig { authorized_keys: data_dir.join("keys") },
    }
}

#[tokio::test]
async fn missing_acme_configuration_fails_before_touching_storage() {
    let directory = tempdir().expect("temporary directory");
    let root = Utf8Path::from_path(directory.path()).expect("UTF-8 path");
    let config_path = root.join("wormholed.toml");
    crate::config::WormholedConfig::initialize(&config_path).expect("initialize config");
    let config = crate::config::WormholedConfig::load(&config_path).expect("load config");

    let error = load_or_issue(&config).await.expect_err("ACME configuration must be required");
    assert!(matches!(error, AcmeError::Config(message) if message == "tls.acme is missing"));
    assert!(!config.server.data_dir.join("certs").exists());
}

#[test]
fn cache_requires_both_files_and_reports_malformed_certificates() {
    let directory = tempdir().expect("temporary directory");
    let cert_dir = Utf8Path::from_path(directory.path()).expect("UTF-8 path");
    let mapping = cache_mapping(cert_dir, "tun.example.com");
    assert_eq!(mapping.cert, cert_dir.join("tun.example.com.pem"));
    assert_eq!(mapping.key, cert_dir.join("tun.example.com.key.pem"));
    assert!(load_cached(cert_dir, "tun.example.com").expect("missing cache").is_none());

    fs::write(&mapping.cert, "not a certificate").expect("certificate fixture");
    fs::write(&mapping.key, "not a key").expect("key fixture");
    assert!(matches!(load_cached(cert_dir, "tun.example.com"), Err(AcmeError::Certificate(_))));
}

#[test]
fn unexpired_cache_loads_and_private_writes_use_owner_only_permissions() {
    let directory = tempdir().expect("temporary directory");
    let cert_dir = Utf8Path::from_path(directory.path()).expect("UTF-8 path");
    let mapping = cache_mapping(cert_dir, "tun.example.com");
    let generated = rcgen::generate_simple_self_signed(vec![
        "tun.example.com".to_owned(),
        "*.tun.example.com".to_owned(),
    ])
    .expect("certificate fixture");
    write_atomic(&mapping.cert, generated.cert.pem().as_bytes(), 0o644).expect("certificate write");
    write_private(&mapping.key, generated.signing_key.serialize_pem().as_bytes())
        .expect("private key write");

    assert!(load_cached(cert_dir, "tun.example.com").expect("cache parse").is_some());
    assert_eq!(
        fs::metadata(&mapping.cert).expect("cert metadata").permissions().mode() & 0o777,
        0o644
    );
    assert_eq!(
        fs::metadata(&mapping.key).expect("key metadata").permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn atomic_write_does_not_replace_destination_after_open_failure() {
    let directory = tempdir().expect("temporary directory");
    let root = Utf8Path::from_path(directory.path()).expect("UTF-8 path");
    let destination = root.join("missing").join("certificate.pem");

    let error = write_atomic(&destination, b"certificate", 0o644).expect_err("missing parent");
    assert!(matches!(error, AcmeError::Io { .. }));
    assert!(!destination.exists());
}

#[tokio::test]
#[ignore = "requires pebble"]
async fn acme_dns01_flow_with_pebble_and_fake_dns() {
    // Stage 08 supplies the Pebble and fake Cloudflare DNS harness.
}
