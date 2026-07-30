use std::sync::Arc;

use async_trait::async_trait;
use camino::Utf8PathBuf;
use tempfile::tempdir;

use super::{doctor_with, identity_check, transport_detail};
use crate::{
    config::ClientConfig,
    driver::{DriverEvent, DriverHealth, DriverRegistry, TunnelDriver},
    error::DriverError,
    keys_store::IdentityStore,
    model::{EndpointSpec, ResolvedTarget},
    remotes::Transport,
};

struct HealthDriver {
    name: &'static str,
    health: DriverHealth,
}

#[async_trait]
impl TunnelDriver for HealthDriver {
    fn name(&self) -> &'static str {
        self.name
    }

    async fn check(&self) -> DriverHealth {
        self.health.clone()
    }

    async fn run(
        &self,
        _spec: EndpointSpec,
        _target: ResolvedTarget,
        _events: tokio::sync::mpsc::Sender<DriverEvent>,
        _stop: tokio_util::sync::CancellationToken,
    ) -> Result<(), DriverError> {
        Ok(())
    }
}

#[tokio::test]
async fn doctor_reports_invalid_remote_identity_and_unreachable_relay() {
    let directory = tempdir().expect("temporary directory");
    let home = Utf8PathBuf::from_path_buf(directory.path().to_owned()).expect("UTF-8 home");
    let identities = IdentityStore::with_home(home.clone());
    identities.default_identity().expect("default identity");
    let mut config = ClientConfig::default();
    let remote: crate::remotes::Remote = toml::from_str(&format!(
        "addr = \"127.0.0.1:9\"\nserver_name = \"localhost\"\nidentity = \"{}\"",
        home.join("missing.key")
    ))
    .expect("remote");
    config.remotes.insert("broken".to_owned(), remote);
    let checks = doctor_with(&config, &DriverRegistry::new(), &identities).await;
    assert!(checks.iter().any(|check| check.name == "identity:broken" && !check.healthy));
    assert!(checks.iter().any(|check| check.name == "remote:broken" && !check.healthy));
}

#[tokio::test]
async fn doctor_reports_each_mock_driver_health() {
    let directory = tempdir().expect("temporary directory");
    let home = Utf8PathBuf::from_path_buf(directory.path().to_owned()).expect("UTF-8 home");
    let identities = IdentityStore::with_home(home);
    let remote: crate::remotes::Remote =
        toml::from_str("addr = \"localhost:443\"\nserver_name = \"localhost\"").expect("remote");
    identities.resolve_identity(&remote).expect("identity");
    let registry = DriverRegistry::new();
    registry.register(Arc::new(HealthDriver { name: "healthy", health: DriverHealth::Healthy }));
    registry.register(Arc::new(HealthDriver {
        name: "missing",
        health: DriverHealth::Unavailable("binary missing".to_owned()),
    }));
    registry.register(Arc::new(HealthDriver {
        name: "degraded",
        health: DriverHealth::Degraded("partial outage".to_owned()),
    }));

    let checks = doctor_with(&ClientConfig::default(), &registry, &identities).await;

    assert!(checks.iter().any(|check| check.name == "driver:healthy" && check.healthy));
    assert!(checks.iter().any(|check| check.name == "driver:missing" && !check.healthy));
    assert!(checks.iter().any(|check| {
        check.name == "driver:degraded" && !check.healthy && check.detail == "partial outage"
    }));
}

#[test]
fn identity_and_transport_details_report_exact_results() {
    let directory = tempdir().expect("temporary directory");
    let home = Utf8PathBuf::from_path_buf(directory.path().to_owned()).expect("UTF-8 home");
    let identities = IdentityStore::with_home(home);
    identities.default_identity().expect("default identity");
    let valid = identity_check("identity", identities.default_path());
    assert!(valid.healthy);
    assert_eq!(valid.detail, identities.default_path().as_str());
    let missing = identity_check("missing", &identities.default_path().with_extension("missing"));
    assert!(!missing.healthy);
    assert_eq!(transport_detail(Transport::Quic), "QUIC/TLS reachable");
    assert_eq!(transport_detail(Transport::Ws), "WebSocket/TLS reachable");
}

#[tokio::test]
async fn doctor_preserves_config_identity_and_degraded_driver_details() {
    let directory = tempdir().expect("temporary directory");
    let home = Utf8PathBuf::from_path_buf(directory.path().to_owned()).expect("UTF-8 home");
    let identities = IdentityStore::with_home(home);
    let mut config = ClientConfig::default();
    config.default_remote = Some("missing".to_owned());
    let registry = DriverRegistry::new();
    registry.register(Arc::new(HealthDriver {
        name: "degraded",
        health: DriverHealth::Degraded("login expired".to_owned()),
    }));

    let checks = doctor_with(&config, &registry, &identities).await;

    assert!(checks.iter().any(|check| {
        check.name == "config" && !check.healthy && check.detail.contains("default_remote")
    }));
    assert!(checks.iter().any(|check| check.name == "identity" && !check.healthy));
    assert!(checks.iter().any(|check| {
        check.name == "driver:degraded" && !check.healthy && check.detail == "login expired"
    }));
}
