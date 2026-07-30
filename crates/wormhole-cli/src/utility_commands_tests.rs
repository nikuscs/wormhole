use std::os::unix::fs::PermissionsExt as _;

use super::{config_path, load, remote, remote_add_inputs, save};
use crate::cli::{Cli, Command, RemoteCommand};
use crate::remote_onboarding::authority_host;

#[test]
fn authority_and_explicit_config_paths_validate_without_io() {
    assert_eq!(authority_host("relay.example:443").expect("host"), "relay.example");
    assert_eq!(authority_host("[::1]:8443").expect("IPv6 host"), "::1");
    assert!(authority_host("missing-port").expect_err("missing port").contains("HOST:PORT"));
    assert!(authority_host("relay.example:not-a-port").is_err());

    let explicit = std::path::PathBuf::from("relative/client.toml");
    assert_eq!(
        config_path(Some(&explicit)).expect("explicit path").as_str(),
        "relative/client.toml"
    );
    assert!(config_path(None).expect("global config path").ends_with("wormhole/config.toml"));
}

#[test]
fn remote_add_requires_complete_noninteractive_input_without_prompting() {
    let error = remote_add_inputs(None, None, None, None, false).expect_err("missing arguments");
    assert!(error.to_string().contains("JSON or non-interactive mode"));

    let inputs = remote_add_inputs(
        Some("edge".to_owned()),
        Some("relay.example:443".to_owned()),
        None,
        Some("whi_secret".to_owned()),
        false,
    )
    .expect("scripted input");
    assert_eq!(inputs.name, "edge");
    assert_eq!(inputs.invite.as_deref(), Some("whi_secret"));
}

#[test]
fn remote_views_preserve_sorted_configured_identity() {
    let mut config = wormhole_core::ClientConfig::default();
    config.remotes.insert(
        "edge".to_owned(),
        wormhole_core::Remote::new(
            "relay.example:443".to_owned(),
            "relay.example".to_owned(),
            Some(camino::Utf8PathBuf::from("identity.key")),
        ),
    );
    let views = config
        .remotes
        .iter()
        .map(|(name, remote)| crate::api_types::RemoteView::from_remote(name.clone(), remote))
        .collect::<Vec<_>>();
    assert_eq!(views.len(), 1);
    assert_eq!(views[0].name, "edge");
    assert_eq!(views[0].identity.as_deref(), Some("identity.key"));
}

#[test]
fn configuration_save_is_private_atomic_and_loadable() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("nested/client.toml");
    let mut config = wormhole_core::ClientConfig::default();
    config.remotes.insert(
        "edge".to_owned(),
        wormhole_core::Remote::new(
            "relay.example:443".to_owned(),
            "relay.example".to_owned(),
            None,
        ),
    );
    config.default_remote = Some("edge".to_owned());

    save(Some(&path), &config).expect("save config");
    let loaded = load(Some(&path)).expect("load config");

    assert_eq!(loaded.default_remote.as_deref(), Some("edge"));
    assert_eq!(loaded.remotes["edge"].addr, "relay.example:443");
    assert_eq!(std::fs::metadata(&path).expect("metadata").permissions().mode() & 0o777, 0o600);
    assert!(!path.with_extension("toml.tmp").exists());
}

#[tokio::test]
async fn remote_test_rejects_unknown_name_before_identity_or_network_access() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("client.toml");
    save(Some(&path), &wormhole_core::ClientConfig::default()).expect("save config");
    let cli =
        Cli { json: true, config: Some(path), quiet: true, verbose: 0, command: Command::Status };

    let error = remote(&cli, &RemoteCommand::Test { name: "missing".to_owned() })
        .await
        .expect_err("unknown remote");

    assert!(error.to_string().contains("unknown remote: missing"));
}
