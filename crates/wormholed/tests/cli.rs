use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;
use tempfile::tempdir;
use wormhole_proto::{Identity, PublicKeyRef};

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
