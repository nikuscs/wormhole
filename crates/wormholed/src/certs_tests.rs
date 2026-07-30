use std::fs;

use camino::{Utf8Path, Utf8PathBuf};
use tempfile::tempdir;

use super::{CertError, CertManager, CertResolver, load_pem, validate_certificate_names};
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
    assert_eq!(manager.expiries().len(), 1);
    assert!(manager.last_renewal_error().is_none());
}

#[tokio::test]
async fn certificate_modes_reject_incomplete_configuration() {
    let directory = tempdir().expect("temporary directory");
    let data_dir = Utf8Path::from_path(directory.path()).expect("UTF-8 path").to_owned();
    let Err(missing) = CertManager::ready(&config(data_dir.clone(), TlsMode::Static, None)).await
    else {
        panic!("static mapping required");
    };
    assert!(matches!(missing, CertError::Config(_)));

    let self_signed = CertManager::ready(&config(data_dir, TlsMode::SelfSigned, None))
        .await
        .expect("self-signed manager");
    assert!(matches!(self_signed.reload_static(), Err(CertError::Config(_))));
}

#[test]
fn resolver_requires_every_configured_domain() {
    let resolver = CertResolver::new(vec!["one.example".to_owned(), "two.example".to_owned()]);
    assert!(
        matches!(resolver.require_all(), Err(CertError::MissingDomain(domain)) if domain == "one.example")
    );
    assert!(format!("{resolver:?}").contains("one.example"));
}

#[test]
fn pem_loader_rejects_empty_invalid_names_and_mismatched_keys() {
    let directory = tempdir().expect("temporary directory");
    let root = Utf8Path::from_path(directory.path()).expect("UTF-8 path");
    let cert = root.join("cert.pem");
    let key = root.join("key.pem");
    let mapping = StaticCertificate {
        domain: "tun.example.com".to_owned(),
        cert: cert.clone(),
        key: key.clone(),
    };

    fs::write(&cert, "").expect("empty cert");
    fs::write(&key, "").expect("empty key");
    assert!(matches!(load_pem(&mapping), Err(CertError::Pem(_, _))));

    let apex_only = rcgen::generate_simple_self_signed(vec!["tun.example.com".to_owned()])
        .expect("apex certificate");
    fs::write(&cert, apex_only.cert.pem()).expect("write cert");
    fs::write(&key, apex_only.signing_key.serialize_pem()).expect("write key");
    assert!(matches!(load_pem(&mapping), Err(CertError::Config(_))));

    let valid = rcgen::generate_simple_self_signed(vec![
        "tun.example.com".to_owned(),
        "*.tun.example.com".to_owned(),
    ])
    .expect("valid certificate");
    let other = rcgen::generate_simple_self_signed(vec![
        "tun.example.com".to_owned(),
        "*.tun.example.com".to_owned(),
    ])
    .expect("other certificate");
    fs::write(&cert, valid.cert.pem()).expect("write cert");
    fs::write(&key, other.signing_key.serialize_pem()).expect("write key");
    assert!(matches!(load_pem(&mapping), Err(CertError::SigningKey(_))));
}

#[test]
fn certificate_name_validation_rejects_malformed_missing_and_partial_sans() {
    let malformed = rustls::pki_types::CertificateDer::from(vec![1, 2, 3]);
    assert!(matches!(
        validate_certificate_names(&malformed, "tun.example.com"),
        Err(CertError::Pem(_, _))
    ));

    let key = rcgen::KeyPair::generate().expect("signing key");
    let no_san = rcgen::CertificateParams::new(Vec::<String>::new())
        .expect("parameters")
        .self_signed(&key)
        .expect("certificate");
    assert!(matches!(
        validate_certificate_names(no_san.der(), "tun.example.com"),
        Err(CertError::Config(message)) if message.contains("no SAN")
    ));

    for names in [
        vec!["*.tun.example.com".to_owned()],
        vec!["tun.example.com".to_owned()],
        vec!["other.example.com".to_owned(), "*.other.example.com".to_owned()],
    ] {
        let generated = rcgen::generate_simple_self_signed(names).expect("certificate");
        assert!(matches!(
            validate_certificate_names(generated.cert.der(), "tun.example.com"),
            Err(CertError::Config(message)) if message.contains("must cover")
        ));
    }
}

#[test]
fn pem_loader_reports_missing_private_key_after_valid_certificate() {
    let directory = tempdir().expect("temporary directory");
    let root = Utf8Path::from_path(directory.path()).expect("UTF-8 path");
    let generated = rcgen::generate_simple_self_signed(vec![
        "tun.example.com".to_owned(),
        "*.tun.example.com".to_owned(),
    ])
    .expect("certificate");
    let cert = root.join("cert.pem");
    let key = root.join("missing-key.pem");
    fs::write(&cert, generated.cert.pem()).expect("write certificate");
    let mapping =
        StaticCertificate { domain: "tun.example.com".to_owned(), cert, key: key.clone() };
    assert!(matches!(
        load_pem(&mapping),
        Err(CertError::Pem(path, _)) if path == key
    ));
}
