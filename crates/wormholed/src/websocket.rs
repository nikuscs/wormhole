//! WebSocket fallback transport over the public TLS listener.

use std::sync::Arc;

use futures::{SinkExt as _, StreamExt as _};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::protocol::{Message, Role, WebSocketConfig},
};
use wormhole_proto::{
    mux::{MAX_CONTROL_PAYLOAD, MAX_PAYLOAD, WsMessage},
    mux_runtime::{MuxEndpoint, MuxRole, reset_network_frame},
};

use crate::{quic::run_io_session, session_streams::DataOpener, state::AppState};

pub async fn run(upgraded: Upgraded, state: Arc<AppState>, server_name: String) {
    let socket = WebSocketStream::from_raw_socket(
        TokioIo::new(upgraded),
        Role::Server,
        Some(websocket_config()),
    )
    .await;
    let (endpoint, network, outbound) = MuxEndpoint::spawn(MuxRole::Server);
    let bridge = tokio::spawn(bridge(socket, network, outbound));
    let result = run_io_session(
        endpoint.control,
        DataOpener::Mux(endpoint.opener.clone()),
        state,
        &server_name,
    )
    .await;
    bridge.abort();
    if let Err(error) = result {
        tracing::debug!(%error, "WebSocket session ended");
    }
}

fn websocket_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .read_buffer_size(MAX_PAYLOAD)
        .write_buffer_size(MAX_PAYLOAD)
        .max_write_buffer_size(4 * MAX_PAYLOAD)
        .max_message_size(Some(MAX_CONTROL_PAYLOAD + 4))
        .max_frame_size(Some(MAX_CONTROL_PAYLOAD + 4))
}

fn oversized_data_channel(payload: &[u8]) -> Option<u32> {
    let channel = u32::from_be_bytes(payload.get(..4)?.try_into().ok()?);
    (channel != 0).then_some(channel)
}

async fn bridge<S>(
    socket: WebSocketStream<S>,
    network: tokio::sync::mpsc::Sender<Vec<u8>>,
    mut outbound: tokio::sync::mpsc::Receiver<Vec<u8>>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut sink, mut source) = socket.split();
    let mut keepalive = tokio::time::interval(std::time::Duration::from_secs(20));
    keepalive.tick().await;
    loop {
        tokio::select! {
            incoming = source.next() => {
                match incoming {
                    Some(Ok(Message::Binary(payload))) => {
                        if WsMessage::decode(&payload).is_err() {
                            let Some(channel) = oversized_data_channel(&payload) else { return };
                            let Ok(reset) = reset_network_frame(channel) else { return };
                            if sink.send(Message::Binary(reset.clone().into())).await.is_err()
                                || network.send(reset).await.is_err()
                            {
                                return;
                            }
                        } else if network.send(payload.to_vec()).await.is_err() {
                            return;
                        }
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        if sink.send(Message::Pong(payload)).await.is_err() {
                            return;
                        }
                    }
                    Some(Ok(Message::Close(_)) | Err(_)) | None => return,
                    Some(Ok(_)) => {}
                }
            }
            message = outbound.recv() => {
                let Some(message) = message else { return };
                if WsMessage::decode(&message).is_err()
                    || sink.send(Message::Binary(message.into())).await.is_err()
                {
                    return;
                }
            }
            _ = keepalive.tick() => {
                if sink.send(Message::Ping(Vec::new().into())).await.is_err() {
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "websocket_tests.rs"]
mod tests;
