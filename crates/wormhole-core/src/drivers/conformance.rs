use std::{future::Future, sync::Arc, time::Duration};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::{
    driver::{DriverEvent, TunnelDriver},
    model::{EndpointSpec, ResolvedTarget},
};

pub async fn assert_lifecycle<F, Fut>(driver: Arc<dyn TunnelDriver>, spec: EndpointSpec, cleanup: F)
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = bool>,
{
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("target");
    let target = ResolvedTarget(listener.local_addr().expect("address"));
    let echo = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            drop(stream);
        }
    });
    let (events, mut receiver) = mpsc::channel(32);
    let stop = CancellationToken::new();
    let task = tokio::spawn({
        let stop = stop.clone();
        async move { driver.run(spec, target, events, stop).await }
    });
    let urls = tokio::time::timeout(Duration::from_secs(20), async {
        let mut logs = Vec::new();
        loop {
            match receiver.recv().await {
                Some(DriverEvent::Ready { urls, .. }) => break urls,
                Some(DriverEvent::Log(_, message)) => logs.push(message),
                Some(_) => {}
                None => panic!("driver closed before Ready: {logs:?}"),
            }
        }
    })
    .await
    .expect("ready timeout");
    assert!(!urls.is_empty());
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("stop timeout")
        .expect("join")
        .expect("driver stop");
    assert!(cleanup().await);
    echo.abort();
}

struct FixtureDriver;

#[async_trait::async_trait]
impl TunnelDriver for FixtureDriver {
    fn name(&self) -> &'static str {
        "fixture"
    }

    async fn check(&self) -> crate::driver::DriverHealth {
        crate::driver::DriverHealth::Healthy
    }

    async fn run(
        &self,
        _spec: EndpointSpec,
        _target: ResolvedTarget,
        events: mpsc::Sender<DriverEvent>,
        stop: CancellationToken,
    ) -> Result<(), crate::DriverError> {
        events
            .send(DriverEvent::Ready {
                urls: vec!["https://fixture.invalid".to_owned()],
                bind_id: None,
                reservation: None,
            })
            .await
            .map_err(|_| crate::DriverError::Cancelled)?;
        stop.cancelled().await;
        Ok(())
    }
}

#[tokio::test]
async fn fixture_driver_obeys_lifecycle_contract() {
    use wormhole_proto::frames::Persistence;

    assert_lifecycle(
        Arc::new(FixtureDriver),
        EndpointSpec {
            proto: crate::model::ServiceProto::Http,
            driver: "fixture".to_owned(),
            qualifier: None,
            remote: None,
            host: None,
            auto_host: false,
            domain: None,
            public_port: None,
            persist: Persistence::Temporary,
            buffer: None,
            auth: None,
            retry: None,
            inspect: false,
            inspect_assets: false,
            capture_body_max: 1024 * 1024,
            reservation: None,
        },
        || async { true },
    )
    .await;
}
