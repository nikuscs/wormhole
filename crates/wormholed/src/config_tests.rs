use std::{fs, os::unix::fs::PermissionsExt};

use camino::Utf8Path;
use tempfile::tempdir;

use super::{
    AcmeConfig, StaticCertificate, StaticTlsConfig, TlsMode, WormholedConfig, parse_byte_size,
};

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

#[test]
fn validation_rejects_domain_limit_and_path_edge_cases() {
    let directory = tempdir().expect("temporary directory");
    let data = Utf8Path::from_path(directory.path()).expect("UTF-8 temporary path").to_owned();
    let mut config = WormholedConfig::development(data.clone(), data.join("keys"));

    config.server.domains.clear();
    assert!(
        config.validate().expect_err("empty domains").to_string().contains("must not be empty")
    );
    config.server.domains = vec!["one.example.com".to_owned(), "one.example.com".to_owned()];
    assert!(config.validate().expect_err("duplicate domain").to_string().contains("duplicate"));
    config.server.domains = vec!["-bad.example.com".to_owned()];
    assert!(config.validate().expect_err("bad label").to_string().contains("invalid server"));
    config.server.domains = vec!["good.example.com".to_owned()];

    config.limits.max_binds_per_key = 0;
    assert!(config.validate().expect_err("zero limit").to_string().contains("non-zero"));
    config.limits.max_binds_per_key = 1;
    config.limits.buffer_max_bytes_per_key = "10MB".to_owned();
    assert!(config.validate().expect_err("bad size").to_string().contains("invalid byte size"));
    config.limits.buffer_max_bytes_per_key = "1MiB".to_owned();

    fs::write(&config.auth.authorized_keys, "not a directory").expect("key path file");
    assert!(config.validate().expect_err("key path file").to_string().contains("not a directory"));
}

#[test]
fn byte_sizes_reject_zero_invalid_and_overflow_values() {
    assert_eq!(parse_byte_size("2MiB").expect("MiB"), 2 * 1024 * 1024);
    assert_eq!(parse_byte_size("3GiB").expect("GiB"), 3 * 1024 * 1024 * 1024);
    for invalid in ["0MiB", "watGiB", "18446744073709551615GiB", "1KiB"] {
        assert!(parse_byte_size(invalid).is_err(), "accepted {invalid}");
    }
}

#[test]
fn static_and_acme_modes_validate_complete_configuration() {
    let directory = tempdir().expect("temporary directory");
    let data = Utf8Path::from_path(directory.path()).expect("UTF-8 temporary path").to_owned();
    let cert = data.join("cert.pem");
    let key = data.join("key.pem");
    let token = data.join("token");
    fs::write(&cert, "certificate").expect("cert");
    fs::write(&key, "key").expect("key");
    fs::write(&token, "token").expect("token");
    fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).expect("token mode");

    let mut config = WormholedConfig::development(data.clone(), data.join("keys"));
    config.tls.mode = TlsMode::Static;
    config.tls.static_config = Some(StaticTlsConfig { certs: Vec::new() });
    assert!(
        config.validate().expect_err("missing domain cert").to_string().contains("missing static")
    );
    config.tls.static_config = Some(StaticTlsConfig {
        certs: vec![StaticCertificate { domain: "localtest.wormhole".to_owned(), cert, key }],
    });
    config.validate().expect("complete static config");

    config.tls.mode = TlsMode::AcmeDns01;
    config.tls.acme = None;
    assert!(config.validate().expect_err("missing ACME").to_string().contains("tls.acme"));
    config.tls.acme = Some(AcmeConfig {
        contact: "admin@example.com".to_owned(),
        directory: "http://acme.example".to_owned(),
        dns_provider: "other".to_owned(),
        cloudflare_token_file: token.clone(),
    });
    assert!(config.validate().expect_err("provider").to_string().contains("cloudflare"));
    config.tls.acme.as_mut().expect("ACME").dns_provider = "cloudflare".to_owned();
    assert!(config.validate().expect_err("contact").to_string().contains("contact"));
    let acme = config.tls.acme.as_mut().expect("ACME");
    acme.contact = "mailto:admin@example.com".to_owned();
    acme.directory = "https://acme.example".to_owned();
    fs::set_permissions(&token, fs::Permissions::from_mode(0o644)).expect("unsafe token mode");
    assert!(config.validate().expect_err("token mode").to_string().contains("owner-readable"));
    fs::set_permissions(&token, fs::Permissions::from_mode(0o400)).expect("safe token mode");
    config.validate().expect("complete ACME config");
}

#[test]
fn initialize_and_load_report_existing_missing_and_malformed_files() {
    let directory = tempdir().expect("temporary directory");
    let path = Utf8Path::from_path(directory.path()).expect("UTF-8").join("relay.toml");
    WormholedConfig::initialize(&path).expect("initialize");
    assert!(
        WormholedConfig::initialize(&path)
            .expect_err("no overwrite")
            .to_string()
            .contains("overwrite")
    );

    let missing = path.with_file_name("missing.toml");
    assert!(
        WormholedConfig::load(&missing)
            .expect_err("missing")
            .to_string()
            .contains("failed to read")
    );
    let malformed = path.with_file_name("malformed.toml");
    fs::write(&malformed, "not = [toml").expect("malformed config");
    assert!(
        WormholedConfig::load(&malformed)
            .expect_err("parse")
            .to_string()
            .contains("failed to parse")
    );
}
