//! Endpoint event forwarding helpers for the tunnel manager.

use std::{collections::HashMap, future::Future, pin::Pin, time::Duration};

use parking_lot::RwLock;
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    driver::EndpointEvent,
    error::DriverError,
    manager::update_status,
    model::{ActiveEndpoint, EndpointStatus, StatusChange},
};

#[allow(clippy::too_many_arguments)]
pub async fn forward_event<F>(
    driver_events: &mpsc::Sender<EndpointEvent>,
    id: Uuid,
    event: &crate::driver::DriverEvent,
    stop: &CancellationToken,
    run: &mut Pin<&mut F>,
    endpoints: &RwLock<HashMap<Uuid, ActiveEndpoint>>,
    status_tx: &broadcast::Sender<StatusChange>,
) -> bool
where
    F: Future<Output = Result<(), DriverError>>,
{
    let forward = driver_events.send(EndpointEvent { endpoint: id, event: event.clone() });
    tokio::pin!(forward);
    tokio::select! {
        biased;
        sent = &mut forward => {
            if sent.is_ok() {
                return true;
            }
            stop.cancel();
            let _drained = tokio::time::timeout(Duration::from_secs(10), run.as_mut()).await;
            update_status(
                endpoints,
                status_tx,
                id,
                EndpointStatus::Error("daemon event receiver closed".to_owned()),
            );
        }
        result = run.as_mut() => {
            let status = result.map_or_else(
                |error| EndpointStatus::Error(error.to_string()),
                |()| EndpointStatus::Offline,
            );
            update_status(endpoints, status_tx, id, status);
        }
    }
    false
}

#[cfg(test)]
#[path = "manager_events_tests.rs"]
mod tests;
