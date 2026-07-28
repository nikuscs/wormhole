use std::collections::{HashMap, VecDeque};

use tokio::{
    io::DuplexStream,
    sync::{OwnedSemaphorePermit, mpsc},
};

use crate::{
    mux::{Direction, MuxControl, MuxState, WsMessage},
    mux_runtime::{CONTROL_DATA, MAX_STREAMS, MuxRole, MuxRuntimeError, send_control, send_ws},
    mux_runtime_control::{
        add_channel, data_channel_count, handle_control, remove_finished, reset_channel,
    },
    mux_runtime_io::spawn_writer,
    mux_runtime_types::{ActorIo, ChannelRuntime, Command, WriterCommand},
};

type Channels = HashMap<u32, ChannelRuntime>;
type OutboundPermits = HashMap<u32, VecDeque<OwnedSemaphorePermit>>;

pub async fn run_actor(
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
    let mut outbound_permits = OutboundPermits::new();
    let mut next = if matches!(role, MuxRole::Client) { 1 } else { 2 };
    actor_loop(
        role,
        &mut next,
        &mut state,
        &mut channels,
        &mut commands,
        &mut io,
        &mut outbound_permits,
    )
    .await;
    close_channels(&mut state, &mut channels).await;
}

async fn actor_loop(
    role: MuxRole,
    next: &mut u32,
    state: &mut MuxState,
    channels: &mut Channels,
    commands: &mut mpsc::Receiver<Command>,
    io: &mut ActorIo,
    outbound_permits: &mut OutboundPermits,
) {
    loop {
        let result = tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else { break };
                handle_command(command, next, state, channels, io, outbound_permits).await
            }
            message = io.network.recv() => {
                let Some(message) = message else { break };
                handle_network(message, role, state, channels, io, outbound_permits).await
            }
        };
        if result.is_err() || flush_outbound(state, io, outbound_permits).await.is_err() {
            break;
        }
    }
}

async fn flush_outbound(
    state: &mut MuxState,
    io: &ActorIo,
    outbound_permits: &mut OutboundPermits,
) -> Result<(), MuxRuntimeError> {
    while let Some(message) = state.next_message() {
        let permit = outbound_permits.get_mut(&message.channel).and_then(VecDeque::pop_front);
        send_ws(&io.outbound, message).await?;
        drop(permit);
    }
    Ok(())
}

async fn close_channels(state: &mut MuxState, channels: &mut Channels) {
    let mut writer_tasks = Vec::with_capacity(channels.len());
    for (_, runtime) in channels.drain() {
        runtime.reader_abort.abort();
        drop(runtime.writer);
        writer_tasks.push(runtime.writer_task);
    }
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
    channels: &mut Channels,
    io: &ActorIo,
    outbound_permits: &mut OutboundPermits,
) -> Result<(), MuxRuntimeError> {
    match command {
        Command::Open { header, reply } => {
            if data_channel_count(channels) >= MAX_STREAMS as usize {
                let _sent = reply.send(Err(MuxRuntimeError::QueueFull));
                return Ok(());
            }
            let channel = *next;
            *next = next.checked_add(2).ok_or(MuxRuntimeError::Protocol)?;
            state.open(channel).map_err(|_| MuxRuntimeError::Protocol)?;
            let application = add_channel(channel, channels, io);
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
            handle_data_command(channel, payload, budget, state, channels, io, outbound_permits)
                .await?;
        }
        Command::Fin { channel: 0 } => return Err(MuxRuntimeError::Closed),
        Command::Fin { channel } => finish_send(channel, state, channels, io).await?,
        Command::WriterClosed { channel, failed } => {
            handle_writer_closed(channel, failed, state, channels, io, outbound_permits).await?;
        }
    }
    Ok(())
}

async fn handle_data_command(
    channel: u32,
    payload: Vec<u8>,
    budget: Option<OwnedSemaphorePermit>,
    state: &mut MuxState,
    channels: &mut Channels,
    io: &ActorIo,
    outbound_permits: &mut OutboundPermits,
) -> Result<(), MuxRuntimeError> {
    if state.enqueue(channel, payload).is_err() {
        outbound_permits.remove(&channel);
        reset_channel(channel, state, channels);
        send_control(&io.outbound, &MuxControl::Reset { channel }).await?;
    } else if let Some(budget) = budget {
        outbound_permits.entry(channel).or_default().push_back(budget);
    }
    Ok(())
}

async fn finish_send(
    channel: u32,
    state: &mut MuxState,
    channels: &mut Channels,
    io: &ActorIo,
) -> Result<(), MuxRuntimeError> {
    if state.finish(channel, Direction::Send).is_ok() {
        send_control(&io.outbound, &MuxControl::Fin { channel, direction: Direction::Send })
            .await?;
        remove_finished(channel, state, channels);
    }
    Ok(())
}

async fn handle_writer_closed(
    channel: u32,
    failed: bool,
    state: &mut MuxState,
    channels: &mut Channels,
    io: &ActorIo,
    outbound_permits: &mut OutboundPermits,
) -> Result<(), MuxRuntimeError> {
    if channel == 0 && failed {
        return Err(MuxRuntimeError::Closed);
    }
    if failed {
        reset_channel(channel, state, channels);
        outbound_permits.remove(&channel);
        send_control(&io.outbound, &MuxControl::Reset { channel }).await?;
    } else {
        if let Some(runtime) = channels.get_mut(&channel) {
            runtime.writer_closed = true;
        }
        remove_finished(channel, state, channels);
    }
    Ok(())
}

async fn handle_network(
    encoded: Vec<u8>,
    role: MuxRole,
    state: &mut MuxState,
    channels: &mut Channels,
    io: &ActorIo,
    outbound_permits: &mut OutboundPermits,
) -> Result<(), MuxRuntimeError> {
    let Ok(message) = WsMessage::decode(&encoded) else {
        return reject_oversized_network(&encoded, state, channels, io, outbound_permits).await;
    };
    if message.channel == 0 {
        return handle_control(message.payload, role, state, channels, io, outbound_permits).await;
    }
    let channel = message.channel;
    if !channels.contains_key(&channel) {
        send_control(&io.outbound, &MuxControl::Reset { channel }).await?;
        return Ok(());
    }
    write_network_data(message, state, channels, io).await
}

async fn reject_oversized_network(
    encoded: &[u8],
    state: &mut MuxState,
    channels: &mut Channels,
    io: &ActorIo,
    outbound_permits: &mut OutboundPermits,
) -> Result<(), MuxRuntimeError> {
    let channel = u32::from_be_bytes(
        encoded.get(..4).ok_or(MuxRuntimeError::Protocol)?.try_into().expect("four bytes"),
    );
    if channel == 0 {
        return Err(MuxRuntimeError::Protocol);
    }
    reset_channel(channel, state, channels);
    outbound_permits.remove(&channel);
    send_control(&io.outbound, &MuxControl::Reset { channel }).await
}

async fn write_network_data(
    message: WsMessage,
    state: &mut MuxState,
    channels: &mut Channels,
    io: &ActorIo,
) -> Result<(), MuxRuntimeError> {
    let channel = message.channel;
    let permits = message.payload.len().try_into().map_err(|_| MuxRuntimeError::QueueFull)?;
    let Ok(permit) = std::sync::Arc::clone(&io.writer_budget).try_acquire_many_owned(permits)
    else {
        reset_channel(channel, state, channels);
        send_control(&io.outbound, &MuxControl::Reset { channel }).await?;
        return Ok(());
    };
    let runtime = channels.get(&channel).expect("checked channel");
    if runtime.writer.try_send(WriterCommand::Data(message.payload, Some(permit))).is_err() {
        reset_channel(channel, state, channels);
        send_control(&io.outbound, &MuxControl::Reset { channel }).await?;
    }
    Ok(())
}
