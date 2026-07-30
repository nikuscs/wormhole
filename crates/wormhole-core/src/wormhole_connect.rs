//! Selection and fallback between QUIC and WebSocket relay transports.

use std::time::Duration;

use tokio::sync::mpsc;
use wormhole_proto::{Identity, codec::ControlChannel, frames::Limits};

use crate::{
    error::DriverError,
    remotes::{Remote, Transport},
    wormhole_transport::{
        BoxControlIo, connect_remote, connect_remote_with_invite, connect_remote_ws,
        connect_remote_ws_with_invite,
    },
};

pub struct ConnectedTransport {
    pub endpoint: Option<quinn::Endpoint>,
    pub connection: Option<quinn::Connection>,
    pub channel: ControlChannel<BoxControlIo>,
    pub limits: Limits,
    pub domains: Vec<String>,
    pub mux_streams: Option<mpsc::Receiver<tokio::io::DuplexStream>>,
}

/// Authenticates once with a transient invite, including over WebSocket-only relays.
pub async fn enroll_remote(
    remote: &Remote,
    identity: &Identity,
    invite: &str,
) -> Result<(), DriverError> {
    match remote.transport {
        Transport::Quic => {
            let (_endpoint, connection, _channel, _welcome) =
                connect_remote_with_invite(remote, identity, invite).await?;
            connection.close(0_u32.into(), b"enrollment complete");
        }
        Transport::Ws => {
            let _connected = connect_remote_ws_with_invite(remote, identity, Some(invite)).await?;
        }
        Transport::Auto => {
            match tokio::time::timeout(
                Duration::from_secs(3),
                connect_remote_with_invite(remote, identity, invite),
            )
            .await
            {
                Ok(Ok((_endpoint, connection, _channel, _welcome))) => {
                    connection.close(0_u32.into(), b"enrollment complete");
                }
                Ok(Err(error @ (DriverError::Denied(_) | DriverError::Protocol(_)))) => {
                    return Err(error);
                }
                Ok(Err(_)) | Err(_) => {
                    let _connected =
                        connect_remote_ws_with_invite(remote, identity, Some(invite)).await?;
                }
            }
        }
    }
    Ok(())
}

pub async fn connect_transport(
    remote: &Remote,
    identity: &Identity,
) -> Result<ConnectedTransport, DriverError> {
    match remote.transport {
        Transport::Quic => quic(remote, identity).await,
        Transport::Ws => websocket(remote, identity).await,
        Transport::Auto => {
            match tokio::time::timeout(Duration::from_secs(3), connect_remote(remote, identity))
                .await
            {
                Ok(Ok((endpoint, connection, channel, welcome))) => Ok(ConnectedTransport {
                    endpoint: Some(endpoint),
                    connection: Some(connection),
                    channel,
                    limits: welcome.limits,
                    domains: welcome.domains,
                    mux_streams: None,
                }),
                Ok(Err(error @ (DriverError::Denied(_) | DriverError::Protocol(_)))) => Err(error),
                Ok(Err(_)) | Err(_) => websocket(remote, identity).await,
            }
        }
    }
}

async fn quic(remote: &Remote, identity: &Identity) -> Result<ConnectedTransport, DriverError> {
    let (endpoint, connection, channel, welcome) = connect_remote(remote, identity).await?;
    Ok(ConnectedTransport {
        endpoint: Some(endpoint),
        connection: Some(connection),
        channel,
        limits: welcome.limits,
        domains: welcome.domains,
        mux_streams: None,
    })
}

/// Probes the configured transport, including automatic QUIC-to-WebSocket fallback.
pub async fn probe_remote(remote: &Remote, identity: &Identity) -> Result<Transport, DriverError> {
    let connected = connect_transport(remote, identity).await?;
    let transport = if connected.endpoint.is_some() { Transport::Quic } else { Transport::Ws };
    if let Some(connection) = connected.connection {
        connection.close(0_u32.into(), b"doctor probe");
    }
    Ok(transport)
}

async fn websocket(
    remote: &Remote,
    identity: &Identity,
) -> Result<ConnectedTransport, DriverError> {
    let (channel, welcome, mux_streams) = connect_remote_ws(remote, identity).await?;
    Ok(ConnectedTransport {
        endpoint: None,
        connection: None,
        channel,
        limits: welcome.limits,
        domains: welcome.domains,
        mux_streams: Some(mux_streams),
    })
}
