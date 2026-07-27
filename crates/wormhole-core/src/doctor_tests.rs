use std::sync::Arc;

use async_trait::async_trait;
use camino::Utf8PathBuf;
use tempfile::tempdir;

use super::doctor_with;
use crate::{
    config::ClientConfig,
    driver::{DriverEvent, DriverHealth, DriverRegistry, TunnelDriver},
    error::DriverError,
    keys_store::IdentityStore,
    model::{EndpointSpec, ResolvedTarget},
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

    let checks = doctor_with(&ClientConfig::default(), &registry, &identities).await;

    assert!(checks.iter().any(|check| check.name == "driver:healthy" && check.healthy));
    assert!(checks.iter().any(|check| check.name == "driver:missing" && !check.healthy));
}
