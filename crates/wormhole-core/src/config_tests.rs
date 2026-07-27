use camino::Utf8Path;
use tempfile::tempdir;

use super::{ClientConfig, ConfigLayer};

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
    assert_eq!(config.defaults.drivers, ["wormhole"]);
    assert_eq!(config.remotes.len(), 3);
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
