use assert_cmd::cargo::cargo_bin_cmd;
use jiff::Timestamp;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;
use std::{process::Child, time::Duration};

use tempfile::tempdir;
use uuid::Uuid;
use wormhole_proto::{
    Identity, PublicKeyRef,
    frames::{BufferPolicy, Persistence},
};
use wormholed::{
    buffer::BufferedRequest,
    config::WormholedConfig,
    db::{BufferQuotas, PersistedBind, PersistedBindSpec, PersistedEndpoint, RelayDb},
};

#[test]
fn init_then_serve_check_succeeds() {
    let directory = tempdir().expect("temporary directory");
    let config = directory.path().join("wormholed.toml");

    cargo_bin_cmd!("wormholed")
        .args(["init", "--config"])
        .arg(&config)
        .assert()
        .success()
        .stdout(contains("created"));
    cargo_bin_cmd!("wormholed")
        .args(["serve", "--check", "--config"])
        .arg(&config)
        .assert()
        .success()
        .stdout(contains("configuration valid").and(contains("error").not()));
}

#[test]
fn offline_read_commands_render_stable_json() {
    let directory = tempdir().expect("temporary directory");
    let config = directory.path().join("wormholed.toml");
    cargo_bin_cmd!("wormholed").args(["init", "--config"]).arg(&config).assert().success();

    cargo_bin_cmd!("wormholed")
        .args(["status", "--json", "--config"])
        .arg(&config)
        .assert()
        .success()
        .stdout(contains("\"sessions\": 0").and(contains("\"binds\": 0")));
    cargo_bin_cmd!("wormholed")
        .args(["binds", "ls", "--json", "--config"])
        .arg(&config)
        .assert()
        .success()
        .stdout(contains("[]"));
    cargo_bin_cmd!("wormholed")
        .args(["webhooks", "failed", "ls", "--json", "--config"])
        .arg(&config)
        .assert()
        .success()
        .stdout(contains("[]"));
}

#[test]
fn status_can_require_a_running_relay() {
    let directory = tempdir().expect("temporary directory");
    let config = directory.path().join("wormholed.toml");
    cargo_bin_cmd!("wormholed").args(["init", "--config"]).arg(&config).assert().success();

    cargo_bin_cmd!("wormholed")
        .args(["status", "--json", "--require-online", "--config"])
        .arg(&config)
        .assert()
        .failure()
        .stderr(contains("relay is offline"));
}

#[test]
fn offline_mutations_reject_missing_records() {
    let directory = tempdir().expect("temporary directory");
    let config = directory.path().join("wormholed.toml");
    let missing = uuid::Uuid::now_v7().to_string();
    cargo_bin_cmd!("wormholed").args(["init", "--config"]).arg(&config).assert().success();

    cargo_bin_cmd!("wormholed")
        .args(["binds", "rm", &missing, "--config"])
        .arg(&config)
        .assert()
        .failure()
        .stderr(contains("bind not found"));
    cargo_bin_cmd!("wormholed")
        .args(["webhooks", "failed", "rm", &missing, "1", "--config"])
        .arg(&config)
        .assert()
        .failure()
        .stderr(contains("failed webhook not found"));
}

#[test]
fn key_commands_persist_authorization_and_revocation() {
    let directory = tempdir().expect("temporary directory");
    let config = directory.path().join("wormholed.toml");
    let identity = Identity::generate();
    let public = identity.public_base64();
    let fingerprint = PublicKeyRef::parse(&public).expect("generated key must parse").fingerprint();
    cargo_bin_cmd!("wormholed").args(["init", "--config"]).arg(&config).assert().success();

    cargo_bin_cmd!("wormholed")
        .args(["key", "authorize", &public, "--name", "agent", "--config"])
        .arg(&config)
        .assert()
        .success()
        .stdout(contains(&fingerprint));
    cargo_bin_cmd!("wormholed")
        .args(["key", "ls", "--json", "--config"])
        .arg(&config)
        .assert()
        .success()
        .stdout(contains("agent").and(contains("\"revoked\": false")));
    cargo_bin_cmd!("wormholed")
        .args(["key", "revoke", &fingerprint, "--config"])
        .arg(&config)
        .assert()
        .success();
    cargo_bin_cmd!("wormholed")
        .args(["key", "ls", "--json", "--config"])
        .arg(&config)
        .assert()
        .success()
        .stdout(contains("\"revoked\": true"));
}

fn initialize(directory: &tempfile::TempDir) -> std::path::PathBuf {
    let config = directory.path().join("wormholed.toml");
    cargo_bin_cmd!("wormholed").args(["init", "--config"]).arg(&config).assert().success();
    config
}

fn open_database(config: &std::path::Path) -> (WormholedConfig, RelayDb) {
    let path = camino::Utf8Path::from_path(config).expect("UTF-8 config");
    let config = WormholedConfig::load(path).expect("load config");
    let database = RelayDb::open(&config.server.data_dir).expect("database");
    (config, database)
}

fn persist_buffered_bind(database: &RelayDb) -> (Uuid, u64) {
    let bind = Uuid::now_v7();
    let now = Timestamp::now();
    database
        .put_bind(
            bind,
            &PersistedBind {
                reservation: Uuid::now_v7(),
                spec: PersistedBindSpec::Http {
                    host: Some("hook".to_owned()),
                    domain: Some("localtest.wormhole".to_owned()),
                    persist: Persistence::Persistent,
                    buffer: Some(BufferPolicy {
                        max_requests: 4,
                        max_body_bytes: 1024,
                        ttl_secs: 60,
                    }),
                },
                auth_verifier: None,
                endpoint: PersistedEndpoint::Hostname("hook.localtest.wormhole".to_owned()),
                key_fpr: "owner".to_owned(),
                created: now,
                last_seen: now,
            },
        )
        .expect("persist bind");
    let request = BufferedRequest {
        v: 1,
        method: "POST".to_owned(),
        uri: "/hook".to_owned(),
        http_version: "HTTP/1.1".to_owned(),
        headers: Vec::new(),
        body: b"payload".to_vec(),
        seq: 0,
        received_at: now,
    };
    let seq = database
        .enqueue_buffered(
            bind,
            "owner",
            request,
            BufferQuotas { max_requests: 4, ttl_secs: 60, key_bytes: 4096, total_bytes: 4096 },
        )
        .expect("enqueue");
    database.fail_buffered(bind, seq, "delivery failed").expect("fail delivery");
    (bind, seq)
}

#[test]
fn offline_status_and_bind_list_render_human_and_json_and_remove_data() {
    let directory = tempdir().expect("temporary directory");
    let config_path = initialize(&directory);
    let (_config, database) = open_database(&config_path);
    let (bind, _seq) = persist_buffered_bind(&database);
    drop(database);

    cargo_bin_cmd!("wormholed")
        .args(["status", "--config"])
        .arg(&config_path)
        .assert()
        .success()
        .stdout(contains("Relay offline").and(contains("1 binds")));
    cargo_bin_cmd!("wormholed")
        .args(["status", "--json", "--config"])
        .arg(&config_path)
        .assert()
        .success()
        .stdout(contains("\"binds\": 1"));
    cargo_bin_cmd!("wormholed")
        .args(["binds", "--config"])
        .arg(&config_path)
        .assert()
        .success()
        .stdout(contains("hook.localtest.wormhole").and(contains("offline")));
    cargo_bin_cmd!("wormholed")
        .args(["binds", "ls", "--json", "--config"])
        .arg(&config_path)
        .assert()
        .success()
        .stdout(contains("\"buffering\": true").and(contains("\"persistent\": true")));
    cargo_bin_cmd!("wormholed")
        .args(["binds", "rm", &bind.to_string(), "--config"])
        .arg(&config_path)
        .assert()
        .success()
        .stdout(contains("removed"));
    let (_config, database) = open_database(&config_path);
    assert!(database.get_bind(bind).expect("bind lookup").is_none());
}

#[test]
fn offline_webhook_commands_list_retry_and_remove_failed_rows() {
    let directory = tempdir().expect("temporary directory");
    let config_path = initialize(&directory);
    let (_config, database) = open_database(&config_path);
    let (bind, seq) = persist_buffered_bind(&database);
    drop(database);

    cargo_bin_cmd!("wormholed")
        .args(["webhooks", "failed", "ls", "--config"])
        .arg(&config_path)
        .assert()
        .success()
        .stdout(contains("delivery failed").and(contains(bind.to_string())));
    cargo_bin_cmd!("wormholed")
        .args(["webhooks", "failed", "ls", "--json", "--config"])
        .arg(&config_path)
        .assert()
        .success()
        .stdout(contains("\"reason\": \"delivery failed\""));
    cargo_bin_cmd!("wormholed")
        .args(["webhooks", "failed", "retry", &bind.to_string(), &seq.to_string(), "--config"])
        .arg(&config_path)
        .assert()
        .success()
        .stdout(contains("queued for retry"));
    let (_config, database) = open_database(&config_path);
    database.fail_buffered(bind, seq, "failed again").expect("fail again");
    drop(database);
    cargo_bin_cmd!("wormholed")
        .args(["webhooks", "failed", "rm", &bind.to_string(), &seq.to_string(), "--config"])
        .arg(&config_path)
        .assert()
        .success()
        .stdout(contains("removed"));
    let (_config, database) = open_database(&config_path);
    assert!(database.list_failed().expect("failed rows").is_empty());
}

#[test]
fn key_file_input_and_human_empty_lists_cover_validation_paths() {
    let directory = tempdir().expect("temporary directory");
    let config_path = initialize(&directory);
    let identity = Identity::generate();
    let key_file = directory.path().join("agent.pub");
    std::fs::write(&key_file, format!("# comment\n\n{}\n", identity.public_base64()))
        .expect("public key file");

    cargo_bin_cmd!("wormholed")
        .args(["key", "ls", "--config"])
        .arg(&config_path)
        .assert()
        .success()
        .stdout(contains("No authorized keys"));
    cargo_bin_cmd!("wormholed")
        .args(["binds", "--config"])
        .arg(&config_path)
        .assert()
        .success()
        .stdout(contains("No binds"));
    cargo_bin_cmd!("wormholed")
        .args(["webhooks", "failed", "ls", "--config"])
        .arg(&config_path)
        .assert()
        .success()
        .stdout(contains("No failed webhooks"));
    cargo_bin_cmd!("wormholed")
        .args(["key", "authorize"])
        .arg(&key_file)
        .args(["--name", "from-file", "--config"])
        .arg(&config_path)
        .assert()
        .success();
    cargo_bin_cmd!("wormholed")
        .args(["key", "ls", "--config"])
        .arg(&config_path)
        .assert()
        .success()
        .stdout(contains("from-file").and(contains("allowed")));

    let empty = directory.path().join("empty.pub");
    std::fs::write(&empty, "# no key\n").expect("empty key file");
    cargo_bin_cmd!("wormholed")
        .args(["key", "authorize"])
        .arg(&empty)
        .args(["--name", "empty", "--config"])
        .arg(&config_path)
        .assert()
        .failure()
        .stderr(contains("contains no key"));
}

struct RelayProcess(Child);

impl Drop for RelayProcess {
    fn drop(&mut self) {
        let _ignored = self.0.kill();
        let _ignored = self.0.wait();
    }
}

fn start_relay(config_path: &std::path::Path) -> RelayProcess {
    let path = camino::Utf8Path::from_path(config_path).expect("UTF-8 config");
    let mut config = WormholedConfig::load(path).expect("load config");
    config.server.quic_addr = "127.0.0.1:0".parse().expect("QUIC address");
    config.server.https_addr = "127.0.0.1:0".parse().expect("HTTPS address");
    config.server.http_addr = "127.0.0.1:0".parse().expect("HTTP address");
    std::fs::write(config_path, toml::to_string_pretty(&config).expect("serialize config"))
        .expect("write config");
    let binary = cargo_bin_cmd!("wormholed");
    let child = std::process::Command::new(binary.get_program())
        .args(["serve", "--config"])
        .arg(config_path)
        .spawn()
        .expect("start relay");
    let relay = RelayProcess(child);
    let socket = config.server.data_dir.join("admin.sock");
    for _ in 0..100 {
        if socket.exists() {
            return relay;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("relay admin socket was not ready");
}

fn stop_relay(mut relay: RelayProcess) {
    let status = std::process::Command::new("kill")
        .args(["-TERM", &relay.0.id().to_string()])
        .status()
        .expect("send SIGTERM");
    assert!(status.success());
    assert!(relay.0.wait().expect("wait for relay").success());
}

#[test]
fn running_relay_routes_online_admin_commands_and_drains_on_sigterm() {
    let directory = tempdir().expect("temporary directory");
    let config_path = initialize(&directory);
    let (_config, database) = open_database(&config_path);
    let (bind, seq) = persist_buffered_bind(&database);
    drop(database);
    let relay = start_relay(&config_path);
    let identity = Identity::generate();
    let public = identity.public_base64();
    let fingerprint = PublicKeyRef::parse(&public).expect("public key").fingerprint();

    cargo_bin_cmd!("wormholed")
        .args(["status", "--config"])
        .arg(&config_path)
        .assert()
        .success()
        .stdout(contains("Relay online"));
    cargo_bin_cmd!("wormholed")
        .args(["status", "--json", "--require-online", "--config"])
        .arg(&config_path)
        .assert()
        .success()
        .stdout(contains("\"sessions\": 0").and(contains("\"binds\": 1")));
    cargo_bin_cmd!("wormholed")
        .args(["key", "authorize", &public, "--name", "online", "--config"])
        .arg(&config_path)
        .assert()
        .success()
        .stdout(contains(&fingerprint));
    cargo_bin_cmd!("wormholed")
        .args(["key", "ls", "--config"])
        .arg(&config_path)
        .assert()
        .success()
        .stdout(contains("online").and(contains("allowed")));
    cargo_bin_cmd!("wormholed")
        .args(["key", "ls", "--json", "--config"])
        .arg(&config_path)
        .assert()
        .success()
        .stdout(contains("\"name\": \"online\""));
    cargo_bin_cmd!("wormholed")
        .args(["key", "revoke", &fingerprint, "--config"])
        .arg(&config_path)
        .assert()
        .success()
        .stdout(contains("revoked"));
    cargo_bin_cmd!("wormholed")
        .args(["binds", "--json", "--config"])
        .arg(&config_path)
        .assert()
        .success()
        .stdout(contains(bind.to_string()));
    cargo_bin_cmd!("wormholed")
        .args(["webhooks", "failed", "retry", &bind.to_string(), &seq.to_string(), "--config"])
        .arg(&config_path)
        .assert()
        .success()
        .stdout(contains("queued for retry"));
    cargo_bin_cmd!("wormholed")
        .args(["binds", "rm", &bind.to_string(), "--config"])
        .arg(&config_path)
        .assert()
        .success()
        .stdout(contains("removed"));

    stop_relay(relay);
}
