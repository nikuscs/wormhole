use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

use super::{
    Capability, DriverCapabilities, DriverEvent, DriverHealth, DriverRegistry, TunnelDriver,
};
use crate::{
    error::DriverError,
    model::{EndpointSpec, ResolvedTarget},
};

struct Basic;

#[async_trait]
impl TunnelDriver for Basic {
    fn name(&self) -> &'static str {
        "basic"
    }
    async fn check(&self) -> DriverHealth {
        DriverHealth::Healthy
    }
    async fn run(
        &self,
        _spec: EndpointSpec,
        _target: ResolvedTarget,
        _events: mpsc::Sender<DriverEvent>,
        _stop: CancellationToken,
    ) -> Result<(), DriverError> {
        Ok(())
    }
}

#[tokio::test]
async fn default_driver_methods_and_registry_are_deterministic() {
    let driver: Arc<dyn TunnelDriver> = Arc::new(Basic);
    assert_eq!(driver.diagnostics().await, [("basic".to_owned(), DriverHealth::Healthy)]);
    assert!(driver.validate(&fixture_spec()).is_ok());
    let (events, _) = mpsc::channel(1);
    let (_, forget) = watch::channel(false);
    let (_, preserve) = watch::channel(false);
    driver
        .run_controlled(
            fixture_spec(),
            ResolvedTarget("127.0.0.1:1".parse().expect("target")),
            events,
            CancellationToken::new(),
            forget,
            preserve,
        )
        .await
        .expect("run");
    let registry = DriverRegistry::new();
    registry.register(Arc::clone(&driver));
    assert_eq!(registry.all()[0].name(), "basic");
}

#[test]
fn capability_bits_are_independent() {
    let all = DriverCapabilities::wormhole_http();
    for capability in [Capability::Buffer, Capability::Auth, Capability::Retry, Capability::Inspect]
    {
        assert!(all.supports(capability));
        assert!(!DriverCapabilities::default().supports(capability));
    }
}

pub fn fixture_spec() -> EndpointSpec {
    serde_json::from_str(
        r#"{"proto":"http","driver":"basic","persist":"temporary","inspect":false}"#,
    )
    .expect("spec")
}
