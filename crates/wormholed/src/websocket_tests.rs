use futures::{SinkExt as _, StreamExt as _};
use tokio::{io::DuplexStream, sync::mpsc, time::timeout};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::protocol::{Message, Role},
};
use wormhole_proto::mux::{MAX_CONTROL_PAYLOAD, MAX_PAYLOAD, WsMessage};

use super::{bridge, oversized_data_channel, websocket_config};

#[test]
fn websocket_limits_match_mux_envelopes() {
    let config = websocket_config();
    assert_eq!(config.read_buffer_size, MAX_PAYLOAD);
    assert_eq!(config.write_buffer_size, MAX_PAYLOAD);
    assert_eq!(config.max_write_buffer_size, 4 * MAX_PAYLOAD);
    assert_eq!(config.max_message_size, Some(MAX_CONTROL_PAYLOAD + 4));
    assert_eq!(config.max_frame_size, Some(MAX_CONTROL_PAYLOAD + 4));
    assert_eq!(oversized_data_channel(&[]), None);
    assert_eq!(oversized_data_channel(&0_u32.to_be_bytes()), None);
    assert_eq!(oversized_data_channel(&7_u32.to_be_bytes()), Some(7));
}

#[test]
fn first_wave_websocket_limits_match_mux_envelopes() {
    let config = websocket_config();
    assert_eq!(config.read_buffer_size, MAX_PAYLOAD);
    assert_eq!(config.write_buffer_size, MAX_PAYLOAD);
    assert_eq!(config.max_message_size, Some(MAX_CONTROL_PAYLOAD + 4));
    assert_eq!(config.max_frame_size, Some(MAX_CONTROL_PAYLOAD + 4));
    assert_eq!(oversized_data_channel(&[0, 0, 0, 7, 1]), Some(7));
    assert_eq!(oversized_data_channel(&[0, 0, 0, 0, 1]), None);
    assert_eq!(oversized_data_channel(&[1, 2, 3]), None);
}

#[tokio::test]
async fn bridge_forwards_binary_messages_and_answers_ping() {
    let (mut client, server) = sockets().await;
    let (network_tx, mut network_rx) = mpsc::channel(4);
    let (_outbound_tx, outbound_rx) = mpsc::channel(4);
    let task = tokio::spawn(bridge(server, network_tx, outbound_rx));
    let encoded = WsMessage { channel: 3, payload: b"hello".to_vec() }.encode().expect("encode");

    client.send(Message::Text("ignored".into())).await.expect("send text");
    client.send(Message::Binary(encoded.clone().into())).await.expect("send binary");
    assert_eq!(network_rx.recv().await.expect("network frame"), encoded);
    client.send(Message::Ping(b"ping".to_vec().into())).await.expect("send ping");
    let response = timeout(std::time::Duration::from_secs(1), client.next())
        .await
        .expect("pong timeout")
        .expect("pong item")
        .expect("pong frame");
    assert_eq!(response, Message::Pong(b"ping".to_vec().into()));
    client.close(None).await.expect("close");
    task.await.expect("bridge task");
}

#[tokio::test]
async fn oversized_data_is_reset_on_both_transports() {
    let (mut client, server) = sockets().await;
    let (network_tx, mut network_rx) = mpsc::channel(4);
    let (_outbound_tx, outbound_rx) = mpsc::channel(4);
    let task = tokio::spawn(bridge(server, network_tx, outbound_rx));
    let mut oversized = 9_u32.to_be_bytes().to_vec();
    oversized.resize(MAX_PAYLOAD + 5, 1);
    client.send(Message::Binary(oversized.into())).await.expect("send oversized data");

    let reset = network_rx.recv().await.expect("network reset");
    let decoded = WsMessage::decode(&reset).expect("decode reset");
    assert_eq!(decoded.channel, 0);
    let socket_reset = timeout(std::time::Duration::from_secs(1), client.next())
        .await
        .expect("reset timeout")
        .expect("reset item")
        .expect("reset frame");
    assert_eq!(socket_reset, Message::Binary(reset.into()));
    client.close(None).await.expect("close");
    task.await.expect("bridge task");
}

#[tokio::test]
async fn outbound_frames_are_validated_and_channel_zero_oversize_stops_bridge() {
    let (mut client, server) = sockets().await;
    let (network_tx, _network_rx) = mpsc::channel(1);
    let (outbound_tx, outbound_rx) = mpsc::channel(4);
    let task = tokio::spawn(bridge(server, network_tx, outbound_rx));
    let encoded = WsMessage { channel: 2, payload: b"response".to_vec() }.encode().expect("encode");
    outbound_tx.send(encoded.clone()).await.expect("queue outbound");
    assert_eq!(
        client.next().await.expect("socket item").expect("socket frame"),
        Message::Binary(encoded.into())
    );
    outbound_tx.send(vec![1, 2, 3]).await.expect("queue invalid outbound");
    task.await.expect("bridge task");

    let (mut client, server) = sockets().await;
    let (network_tx, _network_rx) = mpsc::channel(1);
    let (_outbound_tx, outbound_rx) = mpsc::channel(1);
    let task = tokio::spawn(bridge(server, network_tx, outbound_rx));
    let mut invalid = 0_u32.to_be_bytes().to_vec();
    invalid.resize(MAX_CONTROL_PAYLOAD + 5, 0);
    client.send(Message::Binary(invalid.into())).await.expect("send invalid control");
    task.await.expect("bridge task");
}

#[tokio::test]
async fn closed_channels_stop_bridge_without_panics() {
    let (client, server) = sockets().await;
    let (network_tx, network_rx) = mpsc::channel(1);
    drop(network_rx);
    let (_outbound_tx, outbound_rx) = mpsc::channel(1);
    let task = tokio::spawn(bridge(server, network_tx, outbound_rx));
    drop(client);
    task.await.expect("bridge task");

    let (_client, server) = sockets().await;
    let (network_tx, _network_rx) = mpsc::channel(1);
    let (outbound_tx, outbound_rx) = mpsc::channel(1);
    drop(outbound_tx);
    bridge(server, network_tx, outbound_rx).await;
}

async fn sockets() -> (WebSocketStream<DuplexStream>, WebSocketStream<DuplexStream>) {
    let (client_io, server_io) = tokio::io::duplex(2 * (MAX_CONTROL_PAYLOAD + 4));
    let client = WebSocketStream::from_raw_socket(client_io, Role::Client, None).await;
    let server =
        WebSocketStream::from_raw_socket(server_io, Role::Server, Some(websocket_config())).await;
    (client, server)
}

#[tokio::test]
async fn bridge_forwards_valid_binary_messages_in_both_directions() {
    let (server_io, client_io) = tokio::io::duplex(4096);
    let server =
        WebSocketStream::from_raw_socket(server_io, Role::Server, Some(websocket_config()));
    let client = WebSocketStream::from_raw_socket(client_io, Role::Client, None);
    let (server, mut client) = tokio::join!(server, client);
    let (network_tx, mut network_rx) = tokio::sync::mpsc::channel(2);
    let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(2);
    let task = tokio::spawn(bridge(server, network_tx, outbound_rx));
    let incoming = WsMessage { channel: 3, payload: b"incoming".to_vec() }.encode().expect("frame");

    client.send(Message::Binary(incoming.clone().into())).await.expect("client send");
    assert_eq!(network_rx.recv().await.expect("network frame"), incoming);

    let outgoing = WsMessage { channel: 4, payload: b"outgoing".to_vec() }.encode().expect("frame");
    outbound_tx.send(outgoing.clone()).await.expect("outbound send");
    assert_eq!(
        client.next().await.expect("message").expect("websocket"),
        Message::Binary(outgoing.into())
    );

    drop(outbound_tx);
    task.await.expect("bridge task");
}

#[tokio::test]
async fn oversized_data_frame_resets_only_its_channel() {
    let (server_io, client_io) = tokio::io::duplex(MAX_PAYLOAD * 3);
    let server =
        WebSocketStream::from_raw_socket(server_io, Role::Server, Some(websocket_config()));
    let client = WebSocketStream::from_raw_socket(client_io, Role::Client, None);
    let (server, mut client) = tokio::join!(server, client);
    let (network_tx, mut network_rx) = tokio::sync::mpsc::channel(2);
    let (_outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(1);
    let task = tokio::spawn(bridge(server, network_tx, outbound_rx));
    let mut oversized = 9_u32.to_be_bytes().to_vec();
    oversized.extend(vec![1_u8; MAX_PAYLOAD + 1]);

    client.send(Message::Binary(oversized.into())).await.expect("oversized send");
    let reset = network_rx.recv().await.expect("network reset");
    assert_eq!(WsMessage::decode(&reset).expect("reset envelope").channel, 0);
    assert_eq!(
        client.next().await.expect("reset message").expect("websocket"),
        Message::Binary(reset.into())
    );

    task.abort();
    let _cancelled = task.await;
}
