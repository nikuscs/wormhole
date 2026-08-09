use camino::Utf8Path;
use tempfile::tempdir;

use super::{ClientConfig, ConfigLayer};

#[test]
fn stable_worktree_urls_and_local_settings_have_portless_defaults() {
    let defaults = ClientConfig::default().defaults;
    assert!(defaults.stable_worktree_urls);
    assert_eq!(defaults.local_tld, "localhost");
    assert_eq!((defaults.local_http_port, defaults.local_https_port), (80, 443));
}

#[test]
fn project_and_explicit_layers_override_global_values() {
    let directory = tempdir().expect("temporary directory");
    let root = Utf8Path::from_path(directory.path()).expect("UTF-8 path");
    let global = root.join("global.toml");
    let project = root.join("wormhole.toml");
    std::fs::write(
        &global,
        r#"
default_remote = "global"
[remotes.global]
addr = "global.example:443"
server_name = "global.example"
[aliases]
app = "127.0.0.2"
[defaults]
drivers = ["wormhole"]
inspect = false
stable_worktree_urls = true
cloudflare_domain = "preview.example.com"
tailscale_https_port_range = { start = 21000, end = 21999 }
"#,
    )
    .expect("global config");
    std::fs::write(
        &project,
        r#"
default_remote = "project"
[remotes.project]
addr = "project.example:443"
server_name = "project.example"
[aliases]
app = "127.0.0.3"
[defaults]
inspect = true
[defaults.retry]
attempts = 5
backoff = "500ms"
max_backoff = "30s"
on = ["connect-error", "5xx"]
max_body = "1MiB"
total_deadline = "60s"
"#,
    )
    .expect("project config");
    let explicit: ConfigLayer = toml::from_str(
        r#"
default_remote = "explicit"
[remotes.explicit]
addr = "explicit.example:443"
server_name = "explicit.example"
[aliases]
app = "127.0.0.4"
"#,
    )
    .expect("explicit layer");

    let config = ClientConfig::load_from_paths(Some(&global), Some(&project), explicit)
        .expect("merged config");

    assert_eq!(config.default_remote.as_deref(), Some("explicit"));
    assert_eq!(config.aliases.get("app").map(String::as_str), Some("127.0.0.4"));
    assert!(config.defaults.inspect);
    assert!(config.defaults.stable_worktree_urls);
    assert_eq!(config.defaults.cloudflare_domain.as_deref(), Some("preview.example.com"));
    assert_eq!(
        (
            config.defaults.tailscale_https_port_range.start,
            config.defaults.tailscale_https_port_range.end
        ),
        (21_000, 21_999)
    );
    let retry = config.defaults.retry.expect("retry defaults");
    assert_eq!(retry.max_attempts, 5);
    assert!(retry.retry_5xx);
    assert_eq!(config.defaults.drivers, ["wormhole"]);
    assert_eq!(config.remotes.len(), 3);
}

#[test]
fn validation_rejects_invalid_remote_references_addresses_and_defaults() {
    let mut config =
        ClientConfig { default_remote: Some("missing".to_owned()), ..ClientConfig::default() };
    assert!(config.validate().is_err());

    config.default_remote = None;
    let remote: crate::remotes::Remote =
        toml::from_str("addr = \"localhost\"\nserver_name = \"localhost\"").expect("remote");
    config.remotes.insert("bad".to_owned(), remote);
    assert!(config.validate().is_err());

    config.remotes.clear();
    let empty_name: crate::remotes::Remote =
        toml::from_str("addr = \"localhost:443\"\nserver_name = \"\"").expect("remote");
    config.remotes.insert(String::new(), empty_name);
    assert!(config.validate().is_err());

    config.remotes.clear();
    let ipv6: crate::remotes::Remote =
        toml::from_str("addr = \"[::1]:443\"\nserver_name = \"localhost\"").expect("remote");
    config.remotes.insert("ipv6".to_owned(), ipv6);
    assert!(config.validate().is_ok());

    config.remotes.clear();
    config.defaults.drivers.clear();
    assert!(config.validate().is_err());

    config.defaults.drivers.push("wormhole".to_owned());
    config.defaults.cloudflare_domain = Some("Invalid Domain".to_owned());
    assert!(config.validate().is_err());
    config.defaults.cloudflare_domain = None;
    config.defaults.tailscale_https_port_range = super::HttpsPortRange { start: 0, end: 10 };
    assert!(config.validate().is_err());

    config.defaults.tailscale_https_port_range = super::HttpsPortRange::default();
    config.defaults.local_tld = "Invalid TLD".to_owned();
    assert!(config.validate().is_err());
    config.defaults.local_tld = "localhost".to_owned();
    config.defaults.local_http_port = 0;
    assert!(config.validate().is_err());
}

#[test]
fn local_settings_merge_across_layers() {
    let directory = tempdir().expect("temporary directory");
    let root = Utf8Path::from_path(directory.path()).expect("UTF-8 path");
    let global = root.join("global.toml");
    let project = root.join("wormhole.toml");
    std::fs::write(
        &global,
        "[defaults]\nlocal_tld = \"test\"\nlocal_http_port = 8080\nlocal_https_port = 8443\n",
    )
    .expect("global config");
    std::fs::write(&project, "[defaults]\nlocal_tld = \"localhost\"\n").expect("project config");
    let explicit = toml::from_str("[defaults]\nlocal_http_port = 9080\n").expect("layer");

    let config = ClientConfig::load_from_paths(Some(&global), Some(&project), explicit)
        .expect("merged config");

    assert_eq!(config.defaults.local_tld, "localhost");
    assert_eq!(config.defaults.local_http_port, 9080);
    assert_eq!(config.defaults.local_https_port, 8443);
}

#[test]
fn project_only_name_and_service_keys_are_not_retained_as_unknown_config() {
    let directory = tempdir().expect("temporary directory");
    let root = Utf8Path::from_path(directory.path()).expect("UTF-8 path");
    let project = root.join("wormhole.toml");
    std::fs::write(
        &project,
        "name = \"app\"\n[[service]]\nname = \"web\"\ntarget = \"3000\"\nproto = \"http\"\n",
    )
    .expect("project config");

    let config = ClientConfig::load_from_paths(None, Some(&project), ConfigLayer::default())
        .expect("client config");
    let encoded = toml::to_string(&config).expect("encode");

    assert!(!encoded.contains("name = \"app\""));
    assert!(!encoded.contains("[[service]]"));
}

#[test]
fn malformed_optional_config_is_reported() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path =
        camino::Utf8PathBuf::from_path_buf(directory.path().join("config.toml")).expect("utf8");
    std::fs::write(&path, "not = [valid").expect("write");
    assert!(ClientConfig::load_from_paths(Some(&path), None, ConfigLayer::default()).is_err());
}

#[test]
fn full_config_round_trips_with_snapshot() {
    let source = r#"default_remote = "myvps"

[remotes.myvps]
addr = "tun.example.com:443"
server_name = "tun.example.com"
trusted_ca = "/tmp/ca.pem"

[remotes.work]
addr = "wh.corp.example:443"
server_name = "wh.corp.example"
identity = "/tmp/work.key"

[aliases]
db-box = "192.168.1.40"

[defaults]
drivers = ["wormhole"]
inspect = true
"#;
    let layer: ConfigLayer = toml::from_str(source).expect("full layer");
    let config = ClientConfig::load_from_paths(None, None, layer).expect("full config");
    let encoded = toml::to_string_pretty(&config).expect("encode config");
    let decoded: ClientConfig = toml::from_str(&encoded).expect("decode config");
    assert_eq!(decoded, config);
    insta::assert_snapshot!(encoded);
}
