//! Tokio runtime for the WebSocket channel multiplexer.

use tokio::{
    io::DuplexStream,
    sync::{Semaphore, mpsc, oneshot},
};

pub use crate::mux_runtime_io::reset_network_frame;
use crate::{
    frames::StreamHeader,
    mux::{MAX_CONTROL_PAYLOAD, MAX_PAYLOAD, MuxControl, WsMessage},
    mux_runtime_actor::run_actor,
    mux_runtime_io::spawn_half_reader,
    mux_runtime_types::{ActorIo, Command},
};

pub(crate) const CONTROL_DATA: u8 = 0;
pub(crate) const CONTROL_MUX: u8 = 1;
/// Maximum concurrent data streams supported by one WebSocket mux session.
pub const MAX_STREAMS: u32 = 32;
pub(crate) const RUNTIME_QUEUE: usize = 32;
pub(crate) const CHANNEL_BUFFER: usize = 32 * 1024;
const CONTROL_BUFFER: usize = 1024 * 1024;
const DATA_WRITER_BUDGET: usize = 2 * 1024 * 1024;
const CONNECTION_QUEUE_LIMIT: usize = 16 * 1024 * 1024;
pub(crate) const CONTROL_WRITER_CAPACITY: usize = 17;
pub(crate) const DATA_WRITER_CAPACITY: usize = 4;
const MAX_CHANNELS: usize = MAX_STREAMS as usize;
// Payload-bearing queues, both directions of every duplex, and active writer data stay bounded
// below the advertised connection-wide limit. Small frame/channel metadata is covered by margin.
const CONNECTION_PAYLOAD_CAPACITY: usize = crate::mux::MAX_QUEUED_BYTES
    + (RUNTIME_QUEUE * MAX_PAYLOAD)
    + (2 * RUNTIME_QUEUE * MAX_CONTROL_PAYLOAD)
    + DATA_WRITER_BUDGET
    + (2 * MAX_CHANNELS * CHANNEL_BUFFER)
    + (2 * CONTROL_BUFFER)
    + ((CONTROL_WRITER_CAPACITY + 1) * MAX_PAYLOAD);
const _: () = assert!(CONNECTION_PAYLOAD_CAPACITY < CONNECTION_QUEUE_LIMIT);

#[derive(Debug, Clone, Copy)]
pub enum MuxRole {
    Client,
    Server,
}

pub struct MuxEndpoint {
    pub control: DuplexStream,
    pub incoming: mpsc::Receiver<DuplexStream>,
    pub opener: MuxOpener,
}

#[derive(Clone)]
pub struct MuxOpener {
    commands: mpsc::Sender<Command>,
}

impl MuxOpener {
    pub async fn open(&self, header: StreamHeader) -> Result<DuplexStream, MuxRuntimeError> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(Command::Open { header, reply })
            .await
            .map_err(|_| MuxRuntimeError::Closed)?;
        response.await.map_err(|_| MuxRuntimeError::Closed)?
    }
}

impl MuxEndpoint {
    pub fn spawn(role: MuxRole) -> (Self, mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>) {
        let (application_control, runtime_control) = tokio::io::duplex(CONTROL_BUFFER);
        let (incoming_tx, incoming) = mpsc::channel(MAX_CHANNELS);
        let (network_tx, network_rx) = mpsc::channel(RUNTIME_QUEUE);
        let (outbound_tx, outbound) = mpsc::channel(RUNTIME_QUEUE);
        let (commands, command_rx) = mpsc::channel(RUNTIME_QUEUE);
        let (control_reader, control_writer) = tokio::io::split(runtime_control);
        let writer_budget = std::sync::Arc::new(Semaphore::new(DATA_WRITER_BUDGET));
        let outbound_budget = std::sync::Arc::new(Semaphore::new(crate::mux::MAX_QUEUED_BYTES));
        let control_ready = std::sync::Arc::new(tokio::sync::Notify::new());
        let reader_abort = spawn_half_reader(
            0,
            control_reader,
            commands.clone(),
            std::sync::Arc::clone(&control_ready),
            None,
            std::sync::Arc::clone(&outbound_budget),
        );
        tokio::spawn(run_actor(
            role,
            control_writer,
            control_ready,
            reader_abort,
            command_rx,
            ActorIo {
                commands: commands.clone(),
                network: network_rx,
                outbound: outbound_tx,
                incoming: incoming_tx,
                writer_budget,
                outbound_budget,
            },
        ));
        (
            Self { control: application_control, incoming, opener: MuxOpener { commands } },
            network_tx,
            outbound,
        )
    }
}

pub(crate) async fn send_control(
    outbound: &mpsc::Sender<Vec<u8>>,
    control: &MuxControl,
) -> Result<(), MuxRuntimeError> {
    let mut payload = vec![CONTROL_MUX];
    payload.extend_from_slice(&serde_json::to_vec(control).map_err(|_| MuxRuntimeError::Protocol)?);
    send_ws(outbound, WsMessage { channel: 0, payload }).await
}

pub(crate) async fn send_ws(
    outbound: &mpsc::Sender<Vec<u8>>,
    message: WsMessage,
) -> Result<(), MuxRuntimeError> {
    outbound
        .send(message.encode().map_err(|_| MuxRuntimeError::Protocol)?)
        .await
        .map_err(|_| MuxRuntimeError::Closed)
}

#[derive(Debug, thiserror::Error)]
pub enum MuxRuntimeError {
    #[error("mux connection closed")]
    Closed,
    #[error("mux protocol queue is full")]
    QueueFull,
    #[error("mux protocol violation")]
    Protocol,
}

#[cfg(test)]
#[path = "mux_runtime_tests.rs"]
mod tests;
