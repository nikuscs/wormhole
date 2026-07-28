use std::{fs, os::unix::fs::PermissionsExt};

use camino::Utf8Path;
use tempfile::tempdir;

use super::{TlsMode, WormholedConfig};

fn documented_relay_blocks() -> Vec<(String, String)> {
    let docs = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs");
    let mut blocks = Vec::new();
    for entry in fs::read_dir(docs).expect("read docs") {
        let path = entry.expect("docs entry").path();
        if path.extension().and_then(std::ffi::OsStr::to_str) != Some("md") {
            continue;
        }
        let text = fs::read_to_string(&path).expect("read markdown");
        let mut lines = text.lines();
        while let Some(line) = lines.next() {
            if line != "```toml" {
                continue;
            }
            let block =
                lines.by_ref().take_while(|line| *line != "```").collect::<Vec<_>>().join("\n");
            if block.contains("[server]") {
                blocks.push((path.display().to_string(), block));
            }
        }
    }
    blocks
}

#[test]
fn documented_relay_toml_blocks_parse() {
    let blocks = documented_relay_blocks();
    assert!(!blocks.is_empty(), "relay documentation must include TOML");
    for (path, block) in blocks {
        toml::from_str::<WormholedConfig>(&block)
            .unwrap_or_else(|error| panic!("invalid relay TOML in {path}: {error}"));
    }
}

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
    assert_eq!(fs::metadata(path).expect("config metadata").permissions().mode() & 0o777, 0o600);
    assert_eq!(
        fs::metadata(&config.server.data_dir).expect("data metadata").permissions().mode() & 0o777,
        0o700
    );
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

    config.tcp.port_range.start = 10_000;
    config.server.public_https_port = Some(0);
    let error = config.validate().expect_err("zero public port must fail");
    assert!(error.to_string().contains("public_https_port"));
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
