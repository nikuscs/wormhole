//! Shared authenticated QUIC connection actor for one named remote.

use std::{collections::HashMap, sync::Arc, time::Duration};

use dashmap::DashMap;
use tokio::sync::{Semaphore, mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use wormhole_proto::{
    Identity,
    codec::ControlChannel,
    frames::{BindSpec, ControlFrame, EventKind},
};

use crate::{
    driver::DriverEvent,
    error::DriverError,
    model::{EndpointSpec, EndpointStatus, ResolvedTarget, ServiceProto},
    remotes::Remote,
    wormhole_stream::accept_streams,
    wormhole_transport::{QuicIo, connect_remote},
};

pub struct EndpointHandle {
    pub target: ResolvedTarget,
    pub semaphore: Arc<Semaphore>,
    pub stop: CancellationToken,
    pub events: mpsc::Sender<DriverEvent>,
    pub inspect: bool,
}

pub struct BindLease {
    pub bind: Uuid,
    pub reservation: Option<Uuid>,
    pub closed: watch::Receiver<bool>,
}

pub struct RemoteConn {
    _endpoint: quinn::Endpoint,
    commands: mpsc::Sender<ConnCommand>,
    closed: watch::Receiver<bool>,
}

impl RemoteConn {
    pub async fn connect(remote: &Remote, identity: Identity) -> Result<Arc<Self>, DriverError> {
        let (endpoint, connection, channel, limits) = connect_remote(remote, identity).await?;
        let binds = Arc::new(DashMap::new());
        let (commands, command_rx) = mpsc::channel(128);
        let (closed_tx, closed) = watch::channel(false);
        let stream_slots = Arc::new(Semaphore::new(limits.max_streams as usize));
        tokio::spawn(accept_streams(connection.clone(), Arc::clone(&binds)));
        tokio::spawn(run_actor(
            connection,
            channel,
            command_rx,
            commands.clone(),
            Arc::clone(&binds),
            stream_slots,
            closed_tx,
        ));
        Ok(Arc::new(Self { _endpoint: endpoint, commands, closed }))
    }

    pub fn is_closed(&self) -> bool {
        *self.closed.borrow()
    }

    pub async fn bind(
        &self,
        spec: EndpointSpec,
        target: ResolvedTarget,
        events: mpsc::Sender<DriverEvent>,
        stop: CancellationToken,
    ) -> Result<BindLease, DriverError> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(ConnCommand::Bind {
                spec: Box::new(spec),
                target,
                events,
                stop: stop.clone(),
                reply,
            })
            .await
            .map_err(|_| DriverError::Transport("remote connection closed".to_owned()))?;
        tokio::select! {
            biased;
            result = response => result
                .map_err(|_| DriverError::Transport("remote connection closed".to_owned()))?,
            () = stop.cancelled() => Err(DriverError::Cancelled),
        }
    }

    pub async fn unbind(&self, bind: Uuid, forget: bool) {
        let _sent = self.commands.send(ConnCommand::Unbind { bind, forget }).await;
    }

    pub async fn shutdown(&self) {
        let _sent = self.commands.send(ConnCommand::Shutdown).await;
    }
}

enum ConnCommand {
    Bind {
        spec: Box<EndpointSpec>,
        target: ResolvedTarget,
        events: mpsc::Sender<DriverEvent>,
        stop: CancellationToken,
        reply: oneshot::Sender<Result<BindLease, DriverError>>,
    },
    Unbind {
        bind: Uuid,
        forget: bool,
    },
    ShutdownIfIdle,
    Shutdown,
}

struct PendingBind {
    handle: Arc<EndpointHandle>,
    forget_on_cancel: bool,
    reply: oneshot::Sender<Result<BindLease, DriverError>>,
}

struct ActivatingBind {
    urls: Vec<String>,
    reservation: Option<Uuid>,
    forget_on_cancel: bool,
    reply: oneshot::Sender<Result<BindLease, DriverError>>,
}

#[allow(clippy::too_many_arguments)]
async fn run_actor(
    connection: quinn::Connection,
    mut channel: ControlChannel<QuicIo>,
    mut commands: mpsc::Receiver<ConnCommand>,
    command_tx: mpsc::Sender<ConnCommand>,
    binds: Arc<DashMap<Uuid, Arc<EndpointHandle>>>,
    stream_slots: Arc<Semaphore>,
    closed_tx: watch::Sender<bool>,
) {
    let result = control_loop(
        &mut channel,
        &mut commands,
        &command_tx,
        &binds,
        stream_slots,
        closed_tx.subscribe(),
    )
    .await;
    if let Err(error) = result {
        tracing::debug!(%error, "remote connection actor stopped");
    }
    for entry in binds.iter() {
        let _sent = entry.events.try_send(DriverEvent::StatusChanged(EndpointStatus::Reconnecting));
    }
    binds.clear();
    closed_tx.send_replace(true);
    connection.close(0_u32.into(), b"client connection closed");
}

async fn control_loop(
    channel: &mut ControlChannel<QuicIo>,
    commands: &mut mpsc::Receiver<ConnCommand>,
    command_tx: &mpsc::Sender<ConnCommand>,
    binds: &DashMap<Uuid, Arc<EndpointHandle>>,
    stream_slots: Arc<Semaphore>,
    closed: watch::Receiver<bool>,
) -> Result<(), DriverError> {
    let mut pending = HashMap::<Uuid, PendingBind>::new();
    let mut activating = HashMap::<Uuid, ActivatingBind>::new();
    let mut keepalive = tokio::time::interval(Duration::from_secs(20));
    keepalive.tick().await;
    let mut ping_seq = 0_u64;
    let mut missed_pongs = 0_u8;
    loop {
        tokio::select! {
            frame = channel.recv() => {
                let frame = frame.map_err(|error| DriverError::Protocol(error.to_string()))?;
                handle_frame(
                    channel, frame, binds, &mut pending, &mut activating, closed.clone(),
                    &mut missed_pongs,
                ).await?;
            }
            command = commands.recv() => {
                let Some(command) = command else { return Ok(()) };
                if handle_command(
                    channel, command, command_tx, binds, &mut pending, Arc::clone(&stream_slots),
                ).await? {
                    return Ok(());
                }
            }
            _ = keepalive.tick() => {
                if missed_pongs >= 2 {
                    return Err(DriverError::Transport("two keepalive pongs were missed".to_owned()));
                }
                ping_seq = ping_seq.wrapping_add(1);
                channel.send(&ControlFrame::Ping { seq: ping_seq }).await
                    .map_err(|error| DriverError::Protocol(error.to_string()))?;
                missed_pongs = missed_pongs.saturating_add(1);
            }
        }
    }
}

async fn handle_command(
    channel: &mut ControlChannel<QuicIo>,
    command: ConnCommand,
    command_tx: &mpsc::Sender<ConnCommand>,
    binds: &DashMap<Uuid, Arc<EndpointHandle>>,
    pending: &mut HashMap<Uuid, PendingBind>,
    stream_slots: Arc<Semaphore>,
) -> Result<bool, DriverError> {
    match command {
        ConnCommand::Bind { spec, target, events, stop, reply } => {
            let request = Uuid::now_v7();
            let reservation = spec.reservation;
            let forget_on_cancel = should_forget_cancelled(reservation);
            let bind_spec = bind_spec(&spec);
            let handle = Arc::new(EndpointHandle {
                target,
                semaphore: stream_slots,
                stop,
                events,
                inspect: spec.inspect,
            });
            pending.insert(request, PendingBind { handle, forget_on_cancel, reply });
            channel
                .send(&ControlFrame::Bind { request, spec: bind_spec, reservation })
                .await
                .map_err(|error| DriverError::Protocol(error.to_string()))?;
        }
        ConnCommand::Unbind { bind, forget } => {
            binds.remove(&bind);
            channel
                .send(&ControlFrame::Unbind { bind, forget })
                .await
                .map_err(|error| DriverError::Protocol(error.to_string()))?;
            if binds.is_empty() {
                let commands = command_tx.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    let _sent = commands.send(ConnCommand::ShutdownIfIdle).await;
                });
            }
        }
        ConnCommand::ShutdownIfIdle => return Ok(binds.is_empty()),
        ConnCommand::Shutdown => return Ok(true),
    }
    Ok(false)
}

async fn handle_frame(
    channel: &mut ControlChannel<QuicIo>,
    frame: ControlFrame,
    binds: &DashMap<Uuid, Arc<EndpointHandle>>,
    pending: &mut HashMap<Uuid, PendingBind>,
    activating: &mut HashMap<Uuid, ActivatingBind>,
    closed: watch::Receiver<bool>,
    missed_pongs: &mut u8,
) -> Result<(), DriverError> {
    match frame {
        ControlFrame::Bound { request, bind, urls, reservation, .. } => {
            handle_bound(channel, (request, bind, urls, reservation), binds, pending, activating)
                .await?;
        }
        ControlFrame::BindActive { bind } => {
            handle_active(channel, bind, binds, activating, closed).await?;
        }
        ControlFrame::BindError { request, reason } => {
            if let Some(pending) = pending.remove(&request) {
                let _sent = pending.reply.send(Err(DriverError::Protocol(reason)));
            }
        }
        ControlFrame::Pong { .. } => *missed_pongs = 0,
        ControlFrame::Event { kind: EventKind::Shutdown, msg } => {
            return Err(DriverError::Transport(msg));
        }
        ControlFrame::Event { kind, msg } => {
            for handle in binds {
                let _sent = handle
                    .events
                    .try_send(DriverEvent::Log(tracing::Level::INFO, format!("{kind:?}: {msg}")));
            }
        }
        unexpected => {
            return Err(DriverError::Protocol(format!(
                "unexpected control frame after handshake: {unexpected:?}"
            )));
        }
    }
    Ok(())
}

async fn handle_bound(
    channel: &mut ControlChannel<QuicIo>,
    details: (Uuid, Uuid, Vec<String>, Option<Uuid>),
    binds: &DashMap<Uuid, Arc<EndpointHandle>>,
    pending: &mut HashMap<Uuid, PendingBind>,
    activating: &mut HashMap<Uuid, ActivatingBind>,
) -> Result<(), DriverError> {
    let (request, bind, urls, reservation) = details;
    let pending = pending
        .remove(&request)
        .ok_or_else(|| DriverError::Protocol(format!("Bound has unknown request id: {request}")))?;
    if pending.handle.stop.is_cancelled() {
        channel
            .send(&ControlFrame::Unbind { bind, forget: pending.forget_on_cancel })
            .await
            .map_err(|error| DriverError::Protocol(error.to_string()))?;
        let _sent = pending.reply.send(Err(DriverError::Cancelled));
        return Ok(());
    }
    binds.insert(bind, pending.handle);
    activating.insert(
        bind,
        ActivatingBind {
            urls,
            reservation,
            forget_on_cancel: pending.forget_on_cancel,
            reply: pending.reply,
        },
    );
    channel
        .send(&ControlFrame::BindReady { bind })
        .await
        .map_err(|error| DriverError::Protocol(error.to_string()))
}

async fn handle_active(
    channel: &mut ControlChannel<QuicIo>,
    bind: Uuid,
    binds: &DashMap<Uuid, Arc<EndpointHandle>>,
    activating: &mut HashMap<Uuid, ActivatingBind>,
    closed: watch::Receiver<bool>,
) -> Result<(), DriverError> {
    let active = activating
        .remove(&bind)
        .ok_or_else(|| DriverError::Protocol(format!("BindActive has unknown bind id: {bind}")))?;
    let handle = binds
        .get(&bind)
        .map(|handle| Arc::clone(&handle))
        .ok_or_else(|| DriverError::Protocol(format!("BindActive has no local route: {bind}")))?;
    if handle.stop.is_cancelled() {
        return cancel_active(channel, bind, binds, active).await;
    }
    if handle
        .events
        .send(DriverEvent::Ready {
            urls: active.urls.clone(),
            bind_id: Some(bind),
            reservation: active.reservation,
        })
        .await
        .is_err()
    {
        return cancel_active(channel, bind, binds, active).await;
    }
    let barrier = Arc::new(tokio::sync::Notify::new());
    if handle.events.send(DriverEvent::Handoff(Arc::clone(&barrier))).await.is_err() {
        return cancel_active(channel, bind, binds, active).await;
    }
    tokio::select! {
        biased;
        () = barrier.notified() => {
            let _sent = active.reply.send(Ok(BindLease {
                bind,
                reservation: active.reservation,
                closed,
            }));
            Ok(())
        }
        () = handle.stop.cancelled() => cancel_active(channel, bind, binds, active).await,
    }
}

async fn cancel_active(
    channel: &mut ControlChannel<QuicIo>,
    bind: Uuid,
    binds: &DashMap<Uuid, Arc<EndpointHandle>>,
    active: ActivatingBind,
) -> Result<(), DriverError> {
    binds.remove(&bind);
    channel
        .send(&ControlFrame::Unbind { bind, forget: active.forget_on_cancel })
        .await
        .map_err(|error| DriverError::Protocol(error.to_string()))?;
    let _sent = active.reply.send(Err(DriverError::Cancelled));
    Ok(())
}

const fn should_forget_cancelled(reservation: Option<Uuid>) -> bool {
    reservation.is_none()
}

fn bind_spec(spec: &EndpointSpec) -> BindSpec {
    match spec.proto {
        ServiceProto::Http => BindSpec::Http {
            host: spec.host.clone(),
            domain: spec.domain.clone(),
            persist: spec.persist,
            buffer: spec.buffer.clone(),
            auth: spec.auth.clone(),
        },
        ServiceProto::Tcp => BindSpec::Tcp { remote_port: spec.public_port, persist: spec.persist },
    }
}

#[cfg(test)]
#[path = "wormhole_conn_tests.rs"]
mod tests;
