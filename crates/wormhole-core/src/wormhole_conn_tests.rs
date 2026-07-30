use std::{sync::Arc, time::Duration};

use dashmap::DashMap;
use tokio::sync::{Semaphore, mpsc, watch};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use wormhole_proto::{
    codec::ControlChannel,
    frames::{BindSpec, ControlFrame, EventKind, Persistence},
};

use super::{
    ConnCommand, RemoteConn, bind_spec, control_keepalive, run_actor, should_forget_bind,
    should_forget_cancelled,
};
use crate::{
    driver::DriverEvent,
    error::DriverError,
    model::{EndpointSpec, ResolvedTarget, ServiceProto},
    wormhole_transport::BoxControlIo,
};

#[test]
fn websocket_control_heartbeats_are_less_frequent() {
    assert_eq!(control_keepalive(true), Duration::from_secs(20));
    assert_eq!(control_keepalive(false), Duration::from_mins(1));
}

#[test]
fn bind_specs_preserve_http_and_tcp_options() {
    let mut spec: EndpointSpec = serde_json::from_str(
        r#"{"proto":"http","driver":"wormhole","host":"app","domain":"example.com","persist":"persistent","inspect":false}"#,
    )
    .expect("HTTP spec");
    assert!(matches!(
        bind_spec(&spec),
        BindSpec::Http { host: Some(host), domain: Some(domain), persist: Persistence::Persistent, .. }
            if host == "app" && domain == "example.com"
    ));
    spec.proto = ServiceProto::Tcp;
    spec.public_port = Some(5432);
    assert!(matches!(
        bind_spec(&spec),
        BindSpec::Tcp { remote_port: Some(5432), persist: Persistence::Persistent }
    ));
}

#[test]
fn cancelled_reclaim_preserves_existing_reservation() {
    assert!(should_forget_cancelled(None));
    assert!(!should_forget_cancelled(Some(Uuid::now_v7())));
    assert!(should_forget_bind(false, true));
    assert!(should_forget_bind(true, false));
    assert!(!should_forget_bind(false, false));
}

#[tokio::test]
async fn administrative_commands_wait_for_actor_acknowledgements() {
    let (connection, mut commands) = command_connection();
    let bind = Uuid::now_v7();
    let reservation = Uuid::now_v7();
    let actor = tokio::spawn(async move {
        match commands.recv().await.expect("unbind command") {
            ConnCommand::Unbind { bind: actual, forget, reply } => {
                assert_eq!(actual, bind);
                assert!(forget);
                reply.send(()).expect("unbind acknowledgement");
            }
            _ => panic!("unexpected first command"),
        }
        match commands.recv().await.expect("forget command") {
            ConnCommand::ForgetReservation { reservation: actual, reply } => {
                assert_eq!(actual, reservation);
                reply.send(()).expect("forget acknowledgement");
            }
            _ => panic!("unexpected second command"),
        }
        assert!(matches!(commands.recv().await, Some(ConnCommand::Shutdown)));
    });

    connection.unbind(bind, true).await.expect("unbind");
    connection.forget_reservation(reservation).await.expect("forget reservation");
    connection.shutdown().await;
    actor.await.expect("actor");
}

#[tokio::test]
async fn administrative_commands_report_closed_actor_channels() {
    let (connection, commands) = command_connection();
    drop(commands);
    let bind_error = connection.unbind(Uuid::now_v7(), false).await.expect_err("closed actor");
    assert!(bind_error.to_string().contains("remote connection closed"));
    let forget_error =
        connection.forget_reservation(Uuid::now_v7()).await.expect_err("closed actor");
    assert!(forget_error.to_string().contains("remote connection closed"));
    connection.shutdown().await;
}

#[tokio::test]
async fn bind_reports_closed_actor_and_honors_cancellation() {
    let endpoint: EndpointSpec = serde_json::from_str(
        r#"{"proto":"http","driver":"wormhole","persist":"temporary","inspect":false}"#,
    )
    .expect("endpoint");
    let target = ResolvedTarget("127.0.0.1:3000".parse().expect("target"));
    let (events, _event_rx) = mpsc::channel::<DriverEvent>(1);
    let (_forget_tx, forget) = watch::channel(false);

    let (closed, commands) = command_connection();
    drop(commands);
    let result = closed
        .bind(
            endpoint.clone(),
            target,
            events.clone(),
            tokio_util::sync::CancellationToken::new(),
            forget.clone(),
        )
        .await;
    let Err(error) = result else { panic!("closed actor must fail") };
    assert!(error.to_string().contains("remote connection closed"));

    let (connection, mut commands) = command_connection();
    let stop = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn({
        let stop = stop.clone();
        async move { connection.bind(endpoint, target, events, stop, forget).await }
    });
    let command = commands.recv().await.expect("bind command");
    assert!(matches!(&command, ConnCommand::Bind { .. }));
    stop.cancel();
    assert!(matches!(task.await.expect("bind task"), Err(crate::error::DriverError::Cancelled)));
    drop(command);
}

fn command_connection() -> (RemoteConn, mpsc::Receiver<ConnCommand>) {
    let (commands, receiver) = mpsc::channel(4);
    let (_closed_tx, closed) = watch::channel(false);
    (RemoteConn { _endpoint: None, commands, closed }, receiver)
}

#[tokio::test]
async fn actor_covers_bind_events_buffering_and_administrative_commands() {
    let (connection, mut relay, mut closed) = actor();
    let (events, mut event_rx) = mpsc::channel(16);
    let stop = CancellationToken::new();
    let (_forget_tx, forget) = watch::channel(false);
    let bind_task = tokio::spawn({
        let connection = Arc::clone(&connection);
        async move { connection.bind(tcp_spec(), target(), events, stop, forget).await }
    });

    let request = match relay.recv().await.expect("bind frame") {
        ControlFrame::Bind { request, reservation: None, .. } => request,
        frame => panic!("expected bind, got {frame:?}"),
    };
    let bind = Uuid::now_v7();
    let reservation = Uuid::now_v7();
    relay
        .send(&ControlFrame::Bound {
            request,
            bind,
            urls: vec!["tcp://relay.example:1234".to_owned()],
            persist: Persistence::Temporary,
            reservation: Some(reservation),
            pending_buffered: 2,
            failed_buffered: 1,
        })
        .await
        .expect("bound");
    assert!(
        matches!(relay.recv().await.expect("ready"), ControlFrame::BindReady { bind: id } if id == bind)
    );
    assert!(matches!(
        event_rx.recv().await,
        Some(DriverEvent::BufferedDelivery { pending: 2, failed: 1, delivered_delta: 0 })
    ));

    relay
        .send(&ControlFrame::BufferedStatus { bind, pending: 4, failed: 3 })
        .await
        .expect("buffered status");
    relay
        .send(&ControlFrame::Event { kind: EventKind::Warning, msg: "relay warning".to_owned() })
        .await
        .expect("event");
    relay.send(&ControlFrame::Pong { seq: 7 }).await.expect("pong");
    assert!(matches!(
        event_rx.recv().await,
        Some(DriverEvent::BufferedDelivery { pending: 4, failed: 3, delivered_delta: 0 })
    ));
    assert!(
        matches!(event_rx.recv().await, Some(DriverEvent::Log(_, message)) if message.contains("relay warning"))
    );

    relay.send(&ControlFrame::BindActive { bind }).await.expect("active");
    assert!(
        matches!(event_rx.recv().await, Some(DriverEvent::Ready { bind_id: Some(id), .. }) if id == bind)
    );
    match event_rx.recv().await.expect("handoff") {
        DriverEvent::Handoff(barrier) => barrier.notify_one(),
        event => panic!("expected handoff, got {event:?}"),
    }
    let lease = bind_task.await.expect("bind task").expect("lease");
    assert_eq!(lease.bind, bind);
    assert_eq!(lease.reservation, Some(reservation));

    assert_administrative_commands(&connection, &mut relay, &mut event_rx, bind, reservation).await;
    connection.shutdown().await;
    closed.changed().await.expect("actor closed signal");
    assert!(connection.is_closed());
}

async fn assert_administrative_commands(
    connection: &Arc<RemoteConn>,
    relay: &mut ControlChannel<tokio::io::DuplexStream>,
    event_rx: &mut mpsc::Receiver<DriverEvent>,
    bind: Uuid,
    reservation: Uuid,
) {
    connection
        .commands
        .send(ConnCommand::BufferedResult { bind, seq: 8, result: Ok(()) })
        .await
        .expect("buffered success");
    assert!(
        matches!(relay.recv().await.expect("ack"), ControlFrame::AckBuffered { bind: id, seq: 8 } if id == bind)
    );
    assert!(matches!(
        event_rx.recv().await,
        Some(DriverEvent::BufferedDelivery { delivered_delta: 1, .. })
    ));
    connection
        .commands
        .send(ConnCommand::BufferedResult {
            bind,
            seq: 9,
            result: Err("delivery failed".to_owned()),
        })
        .await
        .expect("buffered failure");
    assert!(
        matches!(relay.recv().await.expect("nack"), ControlFrame::NackBuffered { bind: id, seq: 9, reason } if id == bind && reason == "delivery failed")
    );
    assert!(matches!(event_rx.recv().await, Some(DriverEvent::BufferedDelivery { failed: 4, .. })));

    let forget_task = tokio::spawn({
        let connection = Arc::clone(connection);
        async move { connection.forget_reservation(reservation).await }
    });
    assert!(
        matches!(relay.recv().await.expect("forget"), ControlFrame::ForgetReservation { reservation: id } if id == reservation)
    );
    relay.send(&ControlFrame::ForgotReservation { reservation }).await.expect("forgot");
    forget_task.await.expect("forget task").expect("forget result");

    let unbind_task = tokio::spawn({
        let connection = Arc::clone(connection);
        async move { connection.unbind(bind, true).await }
    });
    assert!(
        matches!(relay.recv().await.expect("unbind"), ControlFrame::Unbind { bind: id, forget: true } if id == bind)
    );
    relay.send(&ControlFrame::Unbound { bind }).await.expect("unbound");
    unbind_task.await.expect("unbind task").expect("unbind result");
}

#[tokio::test]
async fn cancelled_pending_bind_is_unbound_and_closed_channels_error() {
    let (connection, mut relay, mut closed) = actor();
    let (events, _event_rx) = mpsc::channel(4);
    let stop = CancellationToken::new();
    let (_forget_tx, forget) = watch::channel(true);
    let bind_task = tokio::spawn({
        let connection = Arc::clone(&connection);
        let child = stop.clone();
        async move { connection.bind(tcp_spec(), target(), events, child, forget).await }
    });
    let request = match relay.recv().await.expect("bind") {
        ControlFrame::Bind { request, .. } => request,
        frame => panic!("expected bind, got {frame:?}"),
    };
    stop.cancel();
    let bind = Uuid::now_v7();
    relay
        .send(&ControlFrame::Bound {
            request,
            bind,
            urls: Vec::new(),
            persist: Persistence::Temporary,
            reservation: None,
            pending_buffered: 0,
            failed_buffered: 0,
        })
        .await
        .expect("bound");
    assert!(matches!(bind_task.await.expect("bind task"), Err(DriverError::Cancelled)));
    assert!(
        matches!(relay.recv().await.expect("cancel unbind"), ControlFrame::Unbind { bind: id, forget: true } if id == bind)
    );
    connection.shutdown().await;
    closed.changed().await.expect("closed");

    let (commands, command_rx) = mpsc::channel(1);
    drop(command_rx);
    let (_closed_tx, closed) = watch::channel(true);
    let disconnected = RemoteConn { _endpoint: None, commands, closed };
    let (events, _events_rx) = mpsc::channel(1);
    let (_forget_tx, forget) = watch::channel(false);
    assert!(matches!(
        disconnected.bind(tcp_spec(), target(), events, CancellationToken::new(), forget).await,
        Err(DriverError::Transport(message)) if message.contains("closed")
    ));
    assert!(matches!(
        disconnected.unbind(Uuid::now_v7(), false).await,
        Err(DriverError::Transport(message)) if message.contains("closed")
    ));
    assert!(matches!(
        disconnected.forget_reservation(Uuid::now_v7()).await,
        Err(DriverError::Transport(message)) if message.contains("closed")
    ));
}

fn actor() -> (Arc<RemoteConn>, ControlChannel<tokio::io::DuplexStream>, watch::Receiver<bool>) {
    let (client, relay) = tokio::io::duplex(16 * 1024);
    let (commands, command_rx) = mpsc::channel(32);
    let (closed_tx, closed) = watch::channel(false);
    tokio::spawn(run_actor(
        None,
        ControlChannel::new(Box::new(client) as BoxControlIo),
        command_rx,
        commands.clone(),
        Arc::new(DashMap::new()),
        Arc::new(Semaphore::new(8)),
        Duration::from_mins(1),
        closed_tx,
    ));
    (
        Arc::new(RemoteConn { _endpoint: None, commands, closed: closed.clone() }),
        ControlChannel::new(relay),
        closed,
    )
}

fn tcp_spec() -> EndpointSpec {
    serde_json::from_str(
        r#"{"proto":"tcp","driver":"wormhole","public_port":1234,"persist":"temporary","inspect":false}"#,
    )
    .expect("TCP spec")
}

fn target() -> ResolvedTarget {
    ResolvedTarget("127.0.0.1:8080".parse().expect("target"))
}
