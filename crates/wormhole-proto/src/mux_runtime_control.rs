use std::collections::{HashMap, VecDeque};

use tokio::{
    io::DuplexStream,
    sync::{OwnedSemaphorePermit, Semaphore},
};

use crate::{
    mux::{Direction, INITIAL_WINDOW, MuxControl, MuxState},
    mux_runtime::{
        CHANNEL_BUFFER, CONTROL_DATA, CONTROL_MUX, MAX_STREAMS, MuxRole, MuxRuntimeError,
        send_control,
    },
    mux_runtime_io::{spawn_half_reader, spawn_writer},
    mux_runtime_types::{ActorIo, ChannelRuntime, WriterCommand},
};

pub type Channels = HashMap<u32, ChannelRuntime>;
pub type OutboundPermits = HashMap<u32, VecDeque<OwnedSemaphorePermit>>;

pub async fn handle_control(
    payload: Vec<u8>,
    role: MuxRole,
    state: &mut MuxState,
    channels: &mut Channels,
    io: &ActorIo,
    outbound_permits: &mut OutboundPermits,
) -> Result<(), MuxRuntimeError> {
    let Some((&kind, payload)) = payload.split_first() else {
        return Err(MuxRuntimeError::Protocol);
    };
    if kind == CONTROL_DATA {
        return write_control_data(payload, channels).await;
    }
    if kind != CONTROL_MUX {
        return Err(MuxRuntimeError::Protocol);
    }
    match serde_json::from_slice(payload).map_err(|_| MuxRuntimeError::Protocol)? {
        MuxControl::Open { channel, header } => {
            open_remote_channel(channel, header, role, state, channels, io).await?;
        }
        MuxControl::Ack { channel } => acknowledge(channel, state, channels)?,
        MuxControl::Fin { channel, direction } => {
            handle_remote_fin(channel, direction, state, channels).await?;
        }
        MuxControl::Reset { channel } => {
            reset_channel(channel, state, channels);
            outbound_permits.remove(&channel);
        }
        MuxControl::Window { channel, bytes } => apply_window(state, channels, channel, bytes),
    }
    Ok(())
}

async fn write_control_data(payload: &[u8], channels: &Channels) -> Result<(), MuxRuntimeError> {
    channels
        .get(&0)
        .ok_or(MuxRuntimeError::Protocol)?
        .writer
        .send(WriterCommand::Data(payload.to_vec(), None))
        .await
        .map_err(|_| MuxRuntimeError::Closed)
}

async fn open_remote_channel(
    channel: u32,
    header: crate::frames::StreamHeader,
    role: MuxRole,
    state: &mut MuxState,
    channels: &mut Channels,
    io: &ActorIo,
) -> Result<(), MuxRuntimeError> {
    let expected_even = matches!(role, MuxRole::Client);
    if channel == 0
        || channel.is_multiple_of(2) != expected_even
        || data_channel_count(channels) >= MAX_STREAMS as usize
    {
        return Err(MuxRuntimeError::Protocol);
    }
    state.open(channel).map_err(|_| MuxRuntimeError::Protocol)?;
    let application = add_channel(channel, channels, io);
    state.acknowledge(channel).map_err(|_| MuxRuntimeError::Protocol)?;
    channels.get(&channel).expect("new channel").ready.notify_one();
    let writer = channels.get(&channel).expect("new channel").writer.clone();
    writer.try_send(WriterCommand::Header(header)).map_err(|_| MuxRuntimeError::QueueFull)?;
    io.incoming.send(application).await.map_err(|_| MuxRuntimeError::Closed)?;
    send_control(&io.outbound, &MuxControl::Ack { channel }).await
}

fn acknowledge(
    channel: u32,
    state: &mut MuxState,
    channels: &Channels,
) -> Result<(), MuxRuntimeError> {
    state.acknowledge(channel).map_err(|_| MuxRuntimeError::Protocol)?;
    channels.get(&channel).ok_or(MuxRuntimeError::Protocol)?.ready.notify_one();
    Ok(())
}

async fn handle_remote_fin(
    channel: u32,
    direction: Direction,
    state: &mut MuxState,
    channels: &mut Channels,
) -> Result<(), MuxRuntimeError> {
    match direction {
        Direction::Send if state.finish(channel, Direction::Receive).is_ok() => {
            let writer = channels.get(&channel).map(|runtime| runtime.writer.clone());
            if let Some(writer) = &writer {
                let _delivered = writer.send(WriterCommand::Shutdown).await;
            }
            drop(writer);
            remove_finished(channel, state, channels);
        }
        Direction::Receive if state.finish(channel, Direction::Send).is_ok() => {
            remove_finished(channel, state, channels);
        }
        Direction::Send | Direction::Receive => {}
    }
    Ok(())
}

fn apply_window(state: &mut MuxState, channels: &Channels, channel: u32, bytes: u32) {
    if state.add_window(channel, bytes).is_ok()
        && let Some(credit) =
            channels.get(&channel).and_then(|runtime| runtime.send_credit.as_ref())
    {
        credit.add_permits(bytes as usize);
    }
}

pub fn remove_finished(channel: u32, state: &mut MuxState, channels: &mut Channels) {
    if state.is_finished(channel)
        && channels.get(&channel).is_some_and(|runtime| runtime.writer_closed)
    {
        reset_channel(channel, state, channels);
    }
}

pub fn reset_channel(channel: u32, state: &mut MuxState, channels: &mut Channels) {
    state.reset(channel);
    if let Some(runtime) = channels.remove(&channel) {
        runtime.writer_task.abort();
        runtime.reader_abort.abort();
    }
}

pub fn data_channel_count(channels: &Channels) -> usize {
    channels.len().saturating_sub(1)
}

pub fn add_channel(channel: u32, channels: &mut Channels, io: &ActorIo) -> DuplexStream {
    let (application, runtime) = tokio::io::duplex(CHANNEL_BUFFER);
    let (reader, writer) = tokio::io::split(runtime);
    let ready = std::sync::Arc::new(tokio::sync::Notify::new());
    let send_credit = std::sync::Arc::new(Semaphore::new(INITIAL_WINDOW as usize));
    let reader_abort = spawn_half_reader(
        channel,
        reader,
        io.commands.clone(),
        std::sync::Arc::clone(&ready),
        Some(std::sync::Arc::clone(&send_credit)),
        std::sync::Arc::clone(&io.outbound_budget),
    );
    let (writer, writer_task) =
        spawn_writer(channel, writer, io.outbound.clone(), io.commands.clone());
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
