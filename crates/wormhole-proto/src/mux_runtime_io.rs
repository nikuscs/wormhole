use std::sync::Arc;

use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream},
    sync::{Semaphore, mpsc},
};

use crate::{
    codec::write_stream_header,
    mux::{MAX_PAYLOAD, MuxControl, WsMessage},
    mux_runtime::{CONTROL_WRITER_CAPACITY, DATA_WRITER_CAPACITY, MuxRuntimeError, send_control},
    mux_runtime_types::{Command, WriterCommand},
};

pub fn spawn_writer(
    channel: u32,
    mut writer: tokio::io::WriteHalf<DuplexStream>,
    outbound: mpsc::Sender<Vec<u8>>,
    commands: mpsc::Sender<Command>,
) -> (mpsc::Sender<WriterCommand>, tokio::task::JoinHandle<()>) {
    let capacity = if channel == 0 { CONTROL_WRITER_CAPACITY } else { DATA_WRITER_CAPACITY };
    let (sender, mut receiver) = mpsc::channel(capacity);
    let task = tokio::spawn(async move {
        let mut writer_failed = false;
        while let Some(command) = receiver.recv().await {
            let (failed, shutdown) = match command {
                WriterCommand::Data(payload, _permit) => {
                    let result = writer.write_all(&payload).await;
                    if result.is_ok() && channel != 0 {
                        let bytes = payload.len().try_into().unwrap_or(u32::MAX);
                        let _sent =
                            send_control(&outbound, &MuxControl::Window { channel, bytes }).await;
                    }
                    (result.is_err(), false)
                }
                WriterCommand::Header(header) => {
                    (write_stream_header(&mut writer, &header).await.is_err(), false)
                }
                WriterCommand::Shutdown => (writer.shutdown().await.is_err(), true),
            };
            if failed || shutdown {
                writer_failed = failed;
                break;
            }
        }
        if channel != 0 {
            let _sent =
                commands.send(Command::WriterClosed { channel, failed: writer_failed }).await;
        }
    });
    (sender, task)
}

pub fn spawn_half_reader(
    channel: u32,
    mut reader: tokio::io::ReadHalf<DuplexStream>,
    commands: mpsc::Sender<Command>,
    ready: Arc<tokio::sync::Notify>,
    send_credit: Option<Arc<Semaphore>>,
    outbound_budget: Arc<Semaphore>,
) -> tokio::task::AbortHandle {
    let task = tokio::spawn(async move {
        if channel != 0 {
            ready.notified().await;
        }
        loop {
            let capacity = if channel == 0 { MAX_PAYLOAD - 1 } else { MAX_PAYLOAD };
            let mut credit_permit = if let Some(credit) = &send_credit {
                match Arc::clone(credit)
                    .acquire_many_owned(capacity.try_into().expect("payload fits u32"))
                    .await
                {
                    Ok(permit) => Some(permit),
                    Err(_) => return,
                }
            } else {
                None
            };
            let mut budget = if channel == 0 {
                None
            } else {
                match Arc::clone(&outbound_budget)
                    .acquire_many_owned(capacity.try_into().expect("payload fits u32"))
                    .await
                {
                    Ok(permit) => Some(permit),
                    Err(_) => return,
                }
            };
            let mut payload = vec![0_u8; capacity];
            match reader.read(&mut payload).await {
                Ok(0) => {
                    let _sent = commands.send(Command::Fin { channel }).await;
                    return;
                }
                Ok(length) => {
                    if let Some(permit) = credit_permit.take() {
                        permit.forget();
                        if let Some(credit) = &send_credit {
                            credit.add_permits(capacity - length);
                        }
                    }
                    drop(credit_permit);
                    if let Some(permit) = &mut budget {
                        drop(permit.split(capacity - length));
                    }
                    payload.truncate(length);
                    if commands.send(Command::Data { channel, payload, budget }).await.is_err() {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    });
    task.abort_handle()
}

pub fn reset_network_frame(channel: u32) -> Result<Vec<u8>, MuxRuntimeError> {
    if channel == 0 {
        return Err(MuxRuntimeError::Protocol);
    }
    let mut payload = vec![crate::mux_runtime::CONTROL_MUX];
    payload.extend_from_slice(
        &serde_json::to_vec(&MuxControl::Reset { channel })
            .map_err(|_| MuxRuntimeError::Protocol)?,
    );
    WsMessage { channel: 0, payload }.encode().map_err(|_| MuxRuntimeError::Protocol)
}
