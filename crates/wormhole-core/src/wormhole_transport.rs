//! QUIC/TLS setup and signed client handshake for Wormhole remotes.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use futures::{SinkExt as _, StreamExt as _, stream::FuturesUnordered};
use rustls::{
    ClientConfig as RustlsClientConfig, RootCertStore,
    pki_types::{CertificateDer, pem::PemObject},
};
use tokio_tungstenite::{
    Connector, client_async_tls_with_config,
    tungstenite::{
        client::IntoClientRequest as _,
        protocol::{Message, WebSocketConfig},
    },
};
use wormhole_proto::{
    ALPN, ClientHandshake, HandshakeStep, Identity,
    codec::ControlChannel,
    frames::Limits,
    mux::{MAX_CONTROL_PAYLOAD, MAX_PAYLOAD, WsMessage},
    mux_runtime::{MuxEndpoint, MuxRole, reset_network_frame},
};

use crate::{error::DriverError, remotes::Remote};

pub trait ControlIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> ControlIo for T {}
pub type BoxControlIo = Box<dyn ControlIo>;

const QUIC_KEEP_ALIVE: Duration = Duration::from_secs(3);
const QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn connect_remote(
    remote: &Remote,
    identity: &Identity,
) -> Result<(quinn::Endpoint, quinn::Connection, ControlChannel<BoxControlIo>, Limits), DriverError>
{
    let addresses =
        remote.resolve_addrs().await.map_err(|error| DriverError::Transport(error.to_string()))?;
    connect_remote_addresses(remote, identity, addresses).await
}

pub type WsConnect =
    (ControlChannel<BoxControlIo>, Limits, tokio::sync::mpsc::Receiver<tokio::io::DuplexStream>);

pub async fn connect_remote_ws(
    remote: &Remote,
    identity: &Identity,
) -> Result<WsConnect, DriverError> {
    let addresses = remote
        .resolve_https_addrs()
        .await
        .map_err(|error| DriverError::Transport(error.to_string()))?;
    connect_remote_ws_addresses(remote, identity, addresses).await
}

async fn connect_remote_addresses(
    remote: &Remote,
    identity: &Identity,
    addresses: Vec<SocketAddr>,
) -> Result<(quinn::Endpoint, quinn::Connection, ControlChannel<BoxControlIo>, Limits), DriverError>
{
    let mut attempts = addresses
        .into_iter()
        .map(|address| connect_remote_address(remote, identity, address))
        .collect::<FuturesUnordered<_>>();
    let mut last_error = None;
    while let Some(result) = attempts.next().await {
        match result {
            Ok(connected) => return Ok(connected),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.expect("remote resolution returns at least one address"))
}

async fn connect_remote_ws_addresses(
    remote: &Remote,
    identity: &Identity,
    addresses: Vec<SocketAddr>,
) -> Result<WsConnect, DriverError> {
    let mut attempts = addresses
        .into_iter()
        .map(|address| connect_remote_ws_address(remote, identity, address))
        .collect::<FuturesUnordered<_>>();
    let mut last_error = None;
    while let Some(result) = attempts.next().await {
        match result {
            Ok(connected) => return Ok(connected),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.expect("remote resolution returns at least one address"))
}

async fn connect_remote_address(
    remote: &Remote,
    identity: &Identity,
    address: SocketAddr,
) -> Result<(quinn::Endpoint, quinn::Connection, ControlChannel<BoxControlIo>, Limits), DriverError>
{
    let endpoint = client_endpoint(address.ip(), remote)?;
    let connection = endpoint
        .connect(address, &remote.server_name)
        .map_err(|error| DriverError::Transport(error.to_string()))?
        .await
        .map_err(|error| DriverError::Transport(error.to_string()))?;
    let (channel, limits) = authenticate(&connection, identity, &remote.server_name).await?;
    Ok((endpoint, connection, channel, limits))
}

async fn connect_remote_ws_address(
    remote: &Remote,
    identity: &Identity,
    address: SocketAddr,
) -> Result<WsConnect, DriverError> {
    let url = format!("wss://{}:{}/_wormhole/ws", remote.server_name, address.port());
    let request =
        url.into_client_request().map_err(|error| DriverError::Transport(error.to_string()))?;
    let stream = tokio::net::TcpStream::connect(address)
        .await
        .map_err(|error| DriverError::Transport(error.to_string()))?;
    let tls = websocket_tls(remote)?;
    let (socket, _response) = client_async_tls_with_config(
        request,
        stream,
        Some(websocket_config()),
        Some(Connector::Rustls(Arc::new(tls))),
    )
    .await
    .map_err(|error| DriverError::Transport(error.to_string()))?;
    let (endpoint, network, outbound) = MuxEndpoint::spawn(MuxRole::Client);
    tokio::spawn(websocket_bridge(socket, network, outbound));
    let io: BoxControlIo = Box::new(endpoint.control);
    let (channel, limits) = authenticate_io(io, identity, &remote.server_name).await?;
    Ok((channel, limits, endpoint.incoming))
}

async fn websocket_bridge(
    socket: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    network: tokio::sync::mpsc::Sender<Vec<u8>>,
    mut outbound: tokio::sync::mpsc::Receiver<Vec<u8>>,
) {
    let (mut sink, mut source) = socket.split();
    let mut keepalive = tokio::time::interval(Duration::from_secs(20));
    keepalive.tick().await;
    loop {
        tokio::select! {
            incoming = source.next() => match incoming {
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
                    if sink.send(Message::Pong(payload)).await.is_err() { return; }
                }
                Some(Ok(Message::Close(_)) | Err(_)) | None => return,
                Some(Ok(_)) => {}
            },
            message = outbound.recv() => {
                let Some(message) = message else { return };
                if WsMessage::decode(&message).is_err()
                    || sink.send(Message::Binary(message.into())).await.is_err()
                {
                    return;
                }
            }
            _ = keepalive.tick() => {
                if sink.send(Message::Ping(Vec::new().into())).await.is_err() { return; }
            }
        }
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

async fn authenticate(
    connection: &quinn::Connection,
    identity: &Identity,
    server_name: &str,
) -> Result<(ControlChannel<BoxControlIo>, Limits), DriverError> {
    let (send, recv) =
        connection.open_bi().await.map_err(|error| DriverError::Transport(error.to_string()))?;
    let io: BoxControlIo = Box::new(tokio::io::join(recv, send));
    authenticate_io(io, identity, server_name).await
}

async fn authenticate_io(
    io: BoxControlIo,
    identity: &Identity,
    server_name: &str,
) -> Result<(ControlChannel<BoxControlIo>, Limits), DriverError> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut channel = ControlChannel::new(io);
        let mut handshake = ClientHandshake::new(identity, server_name, "wormhole-core");
        channel
            .send(&handshake.hello())
            .await
            .map_err(|error| DriverError::Protocol(error.to_string()))?;
        let challenge =
            channel.recv().await.map_err(|error| DriverError::Protocol(error.to_string()))?;
        let auth = match handshake
            .step(&challenge)
            .map_err(|error| DriverError::Protocol(error.to_string()))?
        {
            HandshakeStep::Reply(auth) => auth,
            HandshakeStep::Failed { reason, .. } => {
                return Err(DriverError::Denied(format!("relay denied client: {reason:?}")));
            }
            HandshakeStep::Done { .. } => {
                return Err(DriverError::Protocol(
                    "relay skipped client authentication".to_owned(),
                ));
            }
        };
        channel.send(&auth).await.map_err(|error| DriverError::Protocol(error.to_string()))?;
        let welcome =
            channel.recv().await.map_err(|error| DriverError::Protocol(error.to_string()))?;
        match handshake.step(&welcome).map_err(|error| DriverError::Protocol(error.to_string()))? {
            HandshakeStep::Done { welcome, .. } => Ok((channel, welcome.limits)),
            HandshakeStep::Failed { reason, .. } => {
                Err(DriverError::Denied(format!("relay denied client: {reason:?}")))
            }
            HandshakeStep::Reply(_) => {
                Err(DriverError::Protocol("relay repeated challenge".to_owned()))
            }
        }
    })
    .await
    .map_err(|_| DriverError::Transport("remote handshake timed out".to_owned()))?
}

fn websocket_tls(remote: &Remote) -> Result<RustlsClientConfig, DriverError> {
    let _provider = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let roots = root_store(remote)?;
    let mut tls = RustlsClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(tls)
}

fn client_endpoint(remote_ip: IpAddr, remote: &Remote) -> Result<quinn::Endpoint, DriverError> {
    let _provider = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let roots = root_store(remote)?;
    let mut tls = RustlsClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|error| DriverError::Transport(error.to_string()))?;
    let mut client = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(QUIC_KEEP_ALIVE));
    transport.max_idle_timeout(Some(
        QUIC_IDLE_TIMEOUT
            .try_into()
            .map_err(|error| DriverError::Transport(format!("invalid idle timeout: {error}")))?,
    ));
    transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(1024));
    client.transport_config(Arc::new(transport));
    let bind_ip = match remote_ip {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let mut endpoint = quinn::Endpoint::client(SocketAddr::new(bind_ip, 0))
        .map_err(|error| DriverError::Transport(error.to_string()))?;
    endpoint.set_default_client_config(client);
    Ok(endpoint)
}

#[cfg(test)]
#[path = "wormhole_transport_tests.rs"]
mod tests;

fn root_store(remote: &Remote) -> Result<RootCertStore, DriverError> {
    let mut roots = RootCertStore::empty();
    if let Some(path) = &remote.trusted_ca {
        let certificates = CertificateDer::pem_file_iter(path)
            .map_err(|error| DriverError::Transport(error.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| DriverError::Transport(error.to_string()))?;
        if certificates.is_empty() {
            return Err(DriverError::Transport("trusted_ca contains no certificates".to_owned()));
        }
        for certificate in certificates {
            roots.add(certificate).map_err(|error| DriverError::Transport(error.to_string()))?;
        }
    } else {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    Ok(roots)
}
