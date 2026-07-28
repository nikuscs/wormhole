//! Tokio runtime for the WebSocket channel multiplexer.

use std::collections::{HashMap, VecDeque};

use tokio::{
    io::DuplexStream,
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot},
};

pub use crate::mux_runtime_io::reset_network_frame;
use crate::{
    mux_runtime_io::{spawn_half_reader, spawn_writer},
    mux_runtime_types::{ActorIo, ChannelRuntime, Command, WriterCommand},
};

use crate::{
    frames::StreamHeader,
    mux::{Direction, INITIAL_WINDOW, MAX_PAYLOAD, MuxControl, MuxState, WsMessage},
};

const CONTROL_DATA: u8 = 0;
pub(crate) const CONTROL_MUX: u8 = 1;
const MAX_CHANNELS: usize = 32;
const RUNTIME_QUEUE: usize = 32;
const CHANNEL_BUFFER: usize = 32 * 1024;
const CONTROL_BUFFER: usize = 1024 * 1024;
const DATA_WRITER_BUDGET: usize = 2 * 1024 * 1024;
const CONNECTION_QUEUE_LIMIT: usize = 16 * 1024 * 1024;
pub(crate) const CONTROL_WRITER_CAPACITY: usize = 17;
pub(crate) const DATA_WRITER_CAPACITY: usize = 4;
// Payload-bearing queues, both directions of every duplex, and active writer data stay bounded
// below the advertised connection-wide limit. Small frame/channel metadata is covered by margin.
const CONNECTION_PAYLOAD_CAPACITY: usize = crate::mux::MAX_QUEUED_BYTES
    + (3 * RUNTIME_QUEUE * MAX_PAYLOAD)
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

async fn run_actor(
    role: MuxRole,
    control_writer: tokio::io::WriteHalf<DuplexStream>,
    control_ready: std::sync::Arc<tokio::sync::Notify>,
    reader_abort: tokio::task::AbortHandle,
    mut commands: mpsc::Receiver<Command>,
    mut io: ActorIo,
) {
    let mut state = MuxState::default();
    let (control_writer, writer_task) =
        spawn_writer(0, control_writer, io.outbound.clone(), io.commands.clone());
    let mut channels = HashMap::from([(
        0,
        ChannelRuntime {
            writer: control_writer,
            writer_task,
            reader_abort,
            ready: control_ready,
            send_credit: None,
            writer_closed: false,
        },
    )]);
    let mut outbound_permits = HashMap::<u32, VecDeque<OwnedSemaphorePermit>>::new();
    let mut next = match role {
        MuxRole::Client => 1,
        MuxRole::Server => 2,
    };
    loop {
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else { break };
                if handle_command(
                    command,
                    &mut next,
                    &mut state,
                    &mut channels,
                    &io,
                    &mut outbound_permits,
                ).await.is_err() {
                    break;
                }
            }
            message = io.network.recv() => {
                let Some(message) = message else { break };
                if handle_network(
                    message,
                    role,
                    &mut state,
                    &mut channels,
                    &io,
                    &mut outbound_permits,
                ).await.is_err() {
                    break;
                }
            }
        }
        while let Some(message) = state.next_message() {
            let permit = outbound_permits.get_mut(&message.channel).and_then(VecDeque::pop_front);
            if send_ws(&io.outbound, message).await.is_err() {
                return;
            }
            drop(permit);
        }
    }
    let mut writer_tasks = Vec::with_capacity(channels.len());
    for (_, runtime) in channels.drain() {
        runtime.reader_abort.abort();
        drop(runtime.writer);
        writer_tasks.push(runtime.writer_task);
    }
    drop(channels);
    for mut task in writer_tasks {
        if tokio::time::timeout(std::time::Duration::from_millis(100), &mut task).await.is_err() {
            task.abort();
        }
    }
    state.close();
}

async fn handle_command(
    command: Command,
    next: &mut u32,
    state: &mut MuxState,
    channels: &mut HashMap<u32, ChannelRuntime>,
    io: &ActorIo,
    outbound_permits: &mut HashMap<u32, VecDeque<OwnedSemaphorePermit>>,
) -> Result<(), MuxRuntimeError> {
    match command {
        Command::Open { header, reply } => {
            if channels.len() > MAX_CHANNELS {
                let _sent = reply.send(Err(MuxRuntimeError::QueueFull));
                return Ok(());
            }
            let channel = *next;
            *next = next.checked_add(2).ok_or(MuxRuntimeError::Protocol)?;
            state.open(channel).map_err(|_| MuxRuntimeError::Protocol)?;
            let application = add_channel(
                channel,
                channels,
                io.commands.clone(),
                io.outbound.clone(),
                std::sync::Arc::clone(&io.outbound_budget),
            );
            send_control(&io.outbound, &MuxControl::Open { channel, header }).await?;
            let _sent = reply.send(Ok(application));
        }
        Command::Data { channel: 0, payload, budget: _ } => {
            let mut framed = Vec::with_capacity(payload.len() + 1);
            framed.push(CONTROL_DATA);
            framed.extend_from_slice(&payload);
            send_ws(&io.outbound, WsMessage { channel: 0, payload: framed }).await?;
        }
        Command::Data { channel, payload, budget } => {
            if state.enqueue(channel, payload).is_err() {
                outbound_permits.remove(&channel);
                state.reset(channel);
                remove_channel(channel, channels);
                send_control(&io.outbound, &MuxControl::Reset { channel }).await?;
            } else if let Some(budget) = budget {
                outbound_permits.entry(channel).or_default().push_back(budget);
            }
        }
        Command::Fin { channel: 0 } => return Err(MuxRuntimeError::Closed),
        Command::Fin { channel } => {
            if state.finish(channel, Direction::Send).is_ok() {
                send_control(
                    &io.outbound,
                    &MuxControl::Fin { channel, direction: Direction::Send },
                )
                .await?;
                remove_finished(channel, state, channels);
            }
        }
        Command::WriterClosed { channel, failed } => {
            if channel == 0 && failed {
                return Err(MuxRuntimeError::Closed);
            }
            if failed {
                state.reset(channel);
                remove_channel(channel, channels);
                outbound_permits.remove(&channel);
                send_control(&io.outbound, &MuxControl::Reset { channel }).await?;
            } else {
                if let Some(runtime) = channels.get_mut(&channel) {
                    runtime.writer_closed = true;
                }
                remove_finished(channel, state, channels);
            }
        }
    }
    Ok(())
}

async fn handle_network(
    encoded: Vec<u8>,
    role: MuxRole,
    state: &mut MuxState,
    channels: &mut HashMap<u32, ChannelRuntime>,
    io: &ActorIo,
    outbound_permits: &mut HashMap<u32, VecDeque<OwnedSemaphorePermit>>,
) -> Result<(), MuxRuntimeError> {
    if encoded.len() > MAX_PAYLOAD + 4 {
        let channel =
            u32::from_be_bytes(encoded[..4].try_into().map_err(|_| MuxRuntimeError::Protocol)?);
        if channel == 0 {
            return Err(MuxRuntimeError::Protocol);
        }
        state.reset(channel);
        remove_channel(channel, channels);
        outbound_permits.remove(&channel);
        send_control(&io.outbound, &MuxControl::Reset { channel }).await?;
        return Ok(());
    }
    let message = WsMessage::decode(&encoded).map_err(|_| MuxRuntimeError::Protocol)?;
    if message.channel == 0 {
        return handle_control(message.payload, role, state, channels, io, outbound_permits).await;
    }
    let channel = message.channel;
    if !channels.contains_key(&channel) {
        send_control(&io.outbound, &MuxControl::Reset { channel }).await?;
        return Ok(());
    }
    let permits = message.payload.len().try_into().map_err(|_| MuxRuntimeError::QueueFull)?;
    let Ok(permit) = std::sync::Arc::clone(&io.writer_budget).try_acquire_many_owned(permits)
    else {
        state.reset(channel);
        remove_channel(channel, channels);
        send_control(&io.outbound, &MuxControl::Reset { channel }).await?;
        return Ok(());
    };
    let runtime = channels.get(&channel).expect("checked channel");
    if runtime.writer.try_send(WriterCommand::Data(message.payload, Some(permit))).is_err() {
        state.reset(channel);
        remove_channel(channel, channels);
        send_control(&io.outbound, &MuxControl::Reset { channel }).await?;
    }
    Ok(())
}

async fn handle_control(
    payload: Vec<u8>,
    role: MuxRole,
    state: &mut MuxState,
    channels: &mut HashMap<u32, ChannelRuntime>,
    io: &ActorIo,
    outbound_permits: &mut HashMap<u32, VecDeque<OwnedSemaphorePermit>>,
) -> Result<(), MuxRuntimeError> {
    let Some((&kind, payload)) = payload.split_first() else {
        return Err(MuxRuntimeError::Protocol);
    };
    if kind == CONTROL_DATA {
        let channel = channels.get(&0).ok_or(MuxRuntimeError::Protocol)?;
        return channel
            .writer
            .send(WriterCommand::Data(payload.to_vec(), None))
            .await
            .map_err(|_| MuxRuntimeError::Closed);
    }
    if kind != CONTROL_MUX {
        return Err(MuxRuntimeError::Protocol);
    }
    let control: MuxControl =
        serde_json::from_slice(payload).map_err(|_| MuxRuntimeError::Protocol)?;
    match control {
        MuxControl::Open { channel, header } => {
            let expected_even = matches!(role, MuxRole::Client);
            if channel == 0
                || channel.is_multiple_of(2) != expected_even
                || channels.len() > MAX_CHANNELS
            {
                return Err(MuxRuntimeError::Protocol);
            }
            state.open(channel).map_err(|_| MuxRuntimeError::Protocol)?;
            let application = add_channel(
                channel,
                channels,
                io.commands.clone(),
                io.outbound.clone(),
                std::sync::Arc::clone(&io.outbound_budget),
            );
            state.acknowledge(channel).map_err(|_| MuxRuntimeError::Protocol)?;
            let (ready, writer) = {
                let runtime = channels.get(&channel).expect("new channel");
                (std::sync::Arc::clone(&runtime.ready), runtime.writer.clone())
            };
            ready.notify_one();
            writer
                .try_send(WriterCommand::Header(header))
                .map_err(|_| MuxRuntimeError::QueueFull)?;
            io.incoming.send(application).await.map_err(|_| MuxRuntimeError::Closed)?;
            send_control(&io.outbound, &MuxControl::Ack { channel }).await?;
        }
        MuxControl::Ack { channel } => {
            state.acknowledge(channel).map_err(|_| MuxRuntimeError::Protocol)?;
            channels.get(&channel).ok_or(MuxRuntimeError::Protocol)?.ready.notify_one();
        }
        MuxControl::Fin { channel, direction: Direction::Send } => {
            if state.finish(channel, Direction::Receive).is_ok() {
                channels
                    .get(&channel)
                    .ok_or(MuxRuntimeError::Protocol)?
                    .writer
                    .send(WriterCommand::Shutdown)
                    .await
                    .map_err(|_| MuxRuntimeError::Closed)?;
            }
        }
        MuxControl::Fin { channel, direction: Direction::Receive } => {
            if state.finish(channel, Direction::Send).is_ok() {
                remove_finished(channel, state, channels);
            }
        }
        MuxControl::Reset { channel } => {
            state.reset(channel);
            remove_channel(channel, channels);
            outbound_permits.remove(&channel);
        }
        MuxControl::Window { channel, bytes } => apply_window(state, channels, channel, bytes),
    }
    Ok(())
}

fn apply_window(
    state: &mut MuxState,
    channels: &HashMap<u32, ChannelRuntime>,
    channel: u32,
    bytes: u32,
) {
    if state.add_window(channel, bytes).is_ok()
        && let Some(credit) =
            channels.get(&channel).and_then(|runtime| runtime.send_credit.as_ref())
    {
        credit.add_permits(bytes as usize);
    }
}

fn remove_finished(
    channel: u32,
    state: &mut MuxState,
    channels: &mut HashMap<u32, ChannelRuntime>,
) {
    if state.is_finished(channel)
        && channels.get(&channel).is_some_and(|runtime| runtime.writer_closed)
    {
        state.reset(channel);
        remove_channel(channel, channels);
    }
}

fn remove_channel(channel: u32, channels: &mut HashMap<u32, ChannelRuntime>) {
    if let Some(runtime) = channels.remove(&channel) {
        runtime.writer_task.abort();
        runtime.reader_abort.abort();
    }
}

fn add_channel(
    channel: u32,
    channels: &mut HashMap<u32, ChannelRuntime>,
    commands: mpsc::Sender<Command>,
    outbound: mpsc::Sender<Vec<u8>>,
    outbound_budget: std::sync::Arc<Semaphore>,
) -> DuplexStream {
    let (application, runtime) = tokio::io::duplex(CHANNEL_BUFFER);
    let (reader, writer) = tokio::io::split(runtime);
    let ready = std::sync::Arc::new(tokio::sync::Notify::new());
    let send_credit = std::sync::Arc::new(Semaphore::new(INITIAL_WINDOW as usize));
    let reader_abort = spawn_half_reader(
        channel,
        reader,
        commands.clone(),
        std::sync::Arc::clone(&ready),
        Some(std::sync::Arc::clone(&send_credit)),
        outbound_budget,
    );
    let (writer, writer_task) = spawn_writer(channel, writer, outbound, commands);
    channels.insert(
        channel,
        ChannelRuntime {
            writer,
            writer_task,
            reader_abort,
            ready,
            send_credit: Some(send_credit),
            writer_closed: false,
        },
    );
    application
}

pub(crate) async fn send_control(
    outbound: &mpsc::Sender<Vec<u8>>,
    control: &MuxControl,
) -> Result<(), MuxRuntimeError> {
    let mut payload = vec![CONTROL_MUX];
    payload.extend_from_slice(&serde_json::to_vec(control).map_err(|_| MuxRuntimeError::Protocol)?);
    send_ws(outbound, WsMessage { channel: 0, payload }).await
}

async fn send_ws(
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
