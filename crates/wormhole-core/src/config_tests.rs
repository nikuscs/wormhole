use camino::Utf8Path;
use tempfile::tempdir;

use super::{ClientConfig, ConfigLayer};

fn docs_toml_blocks() -> Vec<(String, String)> {
    let docs = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs");
    let mut blocks = Vec::new();
    for entry in std::fs::read_dir(docs).expect("read docs") {
        let path = entry.expect("docs entry").path();
        if path.extension().and_then(std::ffi::OsStr::to_str) != Some("md") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read markdown");
        let mut lines = text.lines();
        while let Some(line) = lines.next() {
            if line != "```toml" {
                continue;
            }
            let block =
                lines.by_ref().take_while(|line| *line != "```").collect::<Vec<_>>().join("\n");
            blocks.push((path.display().to_string(), block));
        }
    }
    blocks
}

#[test]
fn documented_client_toml_blocks_parse() {
    let blocks = docs_toml_blocks()
        .into_iter()
        .filter(|(_, block)| block.contains("[remotes."))
        .collect::<Vec<_>>();
    assert!(!blocks.is_empty(), "client documentation must include TOML");
    for (path, block) in blocks {
        toml::from_str::<ConfigLayer>(&block)
            .unwrap_or_else(|error| panic!("invalid client TOML in {path}: {error}"));
    }
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
