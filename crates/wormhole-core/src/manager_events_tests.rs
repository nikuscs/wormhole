use std::{collections::HashMap, future};

use parking_lot::RwLock;
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::forward_event;
use crate::{
    driver::{DriverEvent, EndpointEvent},
    error::DriverError,
    model::{ActiveEndpoint, EndpointStatus},
};

#[tokio::test]
async fn forwards_driver_event_without_changing_endpoint_status() {
    let id = Uuid::now_v7();
    let endpoints = endpoints(id);
    let (status_tx, _) = broadcast::channel(4);
    let (event_tx, mut event_rx) = mpsc::channel::<EndpointEvent>(1);
    let stop = CancellationToken::new();
    let run = future::pending::<Result<(), DriverError>>();
    tokio::pin!(run);
    let event = DriverEvent::StatusChanged(EndpointStatus::Reconnecting);

    assert!(forward_event(&event_tx, id, &event, &stop, &mut run, &endpoints, &status_tx,).await);
    let forwarded = event_rx.recv().await.expect("forwarded event");
    assert_eq!(forwarded.endpoint, id);
    assert!(matches!(forwarded.event, DriverEvent::StatusChanged(EndpointStatus::Reconnecting)));
    assert!(!stop.is_cancelled());
}

#[tokio::test]
async fn closed_daemon_receiver_cancels_driver_and_records_error() {
    let id = Uuid::now_v7();
    let endpoints = endpoints(id);
    let (status_tx, mut statuses) = broadcast::channel(4);
    let (event_tx, event_rx) = mpsc::channel::<EndpointEvent>(1);
    drop(event_rx);
    let stop = CancellationToken::new();
    let run_stop = stop.clone();
    let run = async move {
        run_stop.cancelled().await;
        Ok(())
    };
    tokio::pin!(run);

    assert!(
        !forward_event(
            &event_tx,
            id,
            &DriverEvent::Closed,
            &stop,
            &mut run,
            &endpoints,
            &status_tx,
        )
        .await
    );
    assert!(stop.is_cancelled());
    assert!(matches!(
        endpoints.read().get(&id).map(|endpoint| &endpoint.status),
        Some(EndpointStatus::Error(message)) if message == "daemon event receiver closed"
    ));
    assert!(matches!(statuses.recv().await.expect("status").status, EndpointStatus::Error(_)));
}

#[tokio::test]
async fn driver_completion_wins_while_event_channel_is_backpressured() {
    let id = Uuid::now_v7();
    let endpoints = endpoints(id);
    let (status_tx, mut statuses) = broadcast::channel(4);
    let (event_tx, _event_rx) = mpsc::channel::<EndpointEvent>(1);
    event_tx
        .send(EndpointEvent { endpoint: id, event: DriverEvent::Closed })
        .await
        .expect("fill channel");
    let stop = CancellationToken::new();
    let run = future::ready(Err(DriverError::Transport("driver exited".to_owned())));
    tokio::pin!(run);

    assert!(
        !forward_event(
            &event_tx,
            id,
            &DriverEvent::Closed,
            &stop,
            &mut run,
            &endpoints,
            &status_tx,
        )
        .await
    );
    assert!(matches!(
        endpoints.read().get(&id).map(|endpoint| &endpoint.status),
        Some(EndpointStatus::Error(message)) if message.contains("driver exited")
    ));
    assert!(matches!(statuses.recv().await.expect("status").status, EndpointStatus::Error(_)));
}

fn endpoints(id: Uuid) -> RwLock<HashMap<Uuid, ActiveEndpoint>> {
    RwLock::new(HashMap::from([(
        id,
        ActiveEndpoint {
            id,
            service: "fixture".to_owned(),
            driver: "fixture".to_owned(),
            urls: Vec::new(),
            status: EndpointStatus::Online,
            buffered_delivered: 0,
            buffered_pending: 0,
            buffered_failed: 0,
            since: jiff::Timestamp::now(),
        },
    )]))
}
