//! Selection and fallback between QUIC and WebSocket relay transports.

use std::time::Duration;

use tokio::sync::mpsc;
use wormhole_proto::{Identity, codec::ControlChannel, frames::Limits};

use crate::{
    error::DriverError,
    remotes::{Remote, Transport},
    wormhole_transport::{BoxControlIo, connect_remote, connect_remote_ws},
};

pub struct ConnectedTransport {
    pub endpoint: Option<quinn::Endpoint>,
    pub connection: Option<quinn::Connection>,
    pub channel: ControlChannel<BoxControlIo>,
    pub limits: Limits,
    pub mux_streams: Option<mpsc::Receiver<tokio::io::DuplexStream>>,
}

pub async fn connect_transport(
    remote: &Remote,
    identity: Identity,
) -> Result<ConnectedTransport, DriverError> {
    match remote.transport {
        Transport::Quic => quic(remote, identity).await,
        Transport::Ws => websocket(remote, identity).await,
        Transport::Auto => {
            match tokio::time::timeout(Duration::from_secs(3), connect_remote(remote, &identity))
                .await
            {
                Ok(Ok((endpoint, connection, channel, limits))) => Ok(ConnectedTransport {
                    endpoint: Some(endpoint),
                    connection: Some(connection),
                    channel,
                    limits,
                    mux_streams: None,
                }),
                Ok(Err(error @ (DriverError::Denied(_) | DriverError::Protocol(_)))) => Err(error),
                Ok(Err(_)) | Err(_) => websocket(remote, identity).await,
            }
        }
    }
}

async fn quic(remote: &Remote, identity: Identity) -> Result<ConnectedTransport, DriverError> {
    let (endpoint, connection, channel, limits) = connect_remote(remote, &identity).await?;
    Ok(ConnectedTransport {
        endpoint: Some(endpoint),
        connection: Some(connection),
        channel,
        limits,
        mux_streams: None,
    })
}

async fn websocket(remote: &Remote, identity: Identity) -> Result<ConnectedTransport, DriverError> {
    let (channel, limits, mux_streams) = connect_remote_ws(remote, &identity).await?;
    Ok(ConnectedTransport {
        endpoint: None,
        connection: None,
        channel,
        limits,
        mux_streams: Some(mux_streams),
    })
}
