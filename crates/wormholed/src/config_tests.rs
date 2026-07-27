use std::fs;

use camino::Utf8Path;
use tempfile::tempdir;

use super::{TlsMode, WormholedConfig};

#[test]
fn initialized_config_loads_and_validates() {
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("wormholed.toml");
    let path = Utf8Path::from_path(&path).expect("UTF-8 temporary path");

    WormholedConfig::initialize(path).expect("default config must initialize");
    let config = WormholedConfig::load(path).expect("default config must load");

    config.validate().expect("default config must validate");
    assert_eq!(config.tls.mode, TlsMode::SelfSigned);
    assert!(config.server.data_dir.is_dir());
    assert!(config.auth.authorized_keys.is_dir());
    assert!(fs::read_to_string(path).expect("config must read").starts_with('#'));
}

#[test]
fn invalid_domain_is_rejected() {
    let directory = tempdir().expect("temporary directory");
    let data = Utf8Path::from_path(directory.path()).expect("UTF-8 temporary path").to_owned();
    let mut config = WormholedConfig::development(data.clone(), data.join("keys"));
    config.server.domains = vec!["Custom.EXAMPLE.com".to_owned()];

    let error = config.validate().expect_err("uppercase domain must fail");

    assert!(error.to_string().contains("invalid server domain"));
}

#[test]
fn invalid_tcp_range_is_rejected() {
    let directory = tempdir().expect("temporary directory");
    let data = Utf8Path::from_path(directory.path()).expect("UTF-8 temporary path").to_owned();
    let mut config = WormholedConfig::development(data.clone(), data.join("keys"));
    config.tcp.port_range.start = 20_000;
    config.tcp.port_range.end = 10_000;

    let error = config.validate().expect_err("reversed range must fail");

    assert!(error.to_string().contains("port_range"));
}

#[test]
fn static_mode_requires_existing_certificate_files() {
    let directory = tempdir().expect("temporary directory");
    let data = Utf8Path::from_path(directory.path()).expect("UTF-8 temporary path").to_owned();
    let mut config = WormholedConfig::development(data.clone(), data.join("keys"));
    config.tls.mode = TlsMode::Static;

    let error = config.validate().expect_err("missing static config must fail");

    assert!(error.to_string().contains("tls.static"));
}
