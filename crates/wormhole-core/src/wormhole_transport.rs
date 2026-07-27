//! QUIC/TLS setup and signed client handshake for Wormhole remotes.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use rustls::{
    ClientConfig as RustlsClientConfig, RootCertStore,
    pki_types::{CertificateDer, pem::PemObject},
};
use wormhole_proto::{
    ALPN, ClientHandshake, HandshakeStep, Identity, codec::ControlChannel, frames::Limits,
};

use crate::{error::DriverError, remotes::Remote};

pub type QuicIo = tokio::io::Join<quinn::RecvStream, quinn::SendStream>;

pub async fn connect_remote(
    remote: &Remote,
    identity: Identity,
) -> Result<(quinn::Endpoint, quinn::Connection, ControlChannel<QuicIo>, Limits), DriverError> {
    let address =
        remote.resolve_addr().await.map_err(|error| DriverError::Transport(error.to_string()))?;
    let endpoint = client_endpoint(address.ip(), remote)?;
    let connection = endpoint
        .connect(address, &remote.server_name)
        .map_err(|error| DriverError::Transport(error.to_string()))?
        .await
        .map_err(|error| DriverError::Transport(error.to_string()))?;
    let (channel, limits) = authenticate(&connection, identity, &remote.server_name).await?;
    Ok((endpoint, connection, channel, limits))
}

pub async fn probe_remote(remote: &Remote) -> Result<(), DriverError> {
    let address =
        remote.resolve_addr().await.map_err(|error| DriverError::Transport(error.to_string()))?;
    let endpoint = client_endpoint(address.ip(), remote)?;
    let connection = endpoint
        .connect(address, &remote.server_name)
        .map_err(|error| DriverError::Transport(error.to_string()))?
        .await
        .map_err(|error| DriverError::Transport(error.to_string()))?;
    connection.close(0_u32.into(), b"doctor probe");
    Ok(())
}

async fn authenticate(
    connection: &quinn::Connection,
    identity: Identity,
    server_name: &str,
) -> Result<(ControlChannel<QuicIo>, Limits), DriverError> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(|error| DriverError::Transport(error.to_string()))?;
        let mut channel = ControlChannel::new(tokio::io::join(recv, send));
        let mut handshake = ClientHandshake::new(identity, server_name, "wormhole-core");
        channel
            .send(&handshake.hello())
            .await
            .map_err(|error| DriverError::Protocol(error.to_string()))?;
        let challenge =
            channel.recv().await.map_err(|error| DriverError::Protocol(error.to_string()))?;
        let HandshakeStep::Reply(auth) =
            handshake.step(&challenge).map_err(|error| DriverError::Protocol(error.to_string()))?
        else {
            return Err(DriverError::Protocol("relay did not challenge client".to_owned()));
        };
        channel.send(&auth).await.map_err(|error| DriverError::Protocol(error.to_string()))?;
        let welcome =
            channel.recv().await.map_err(|error| DriverError::Protocol(error.to_string()))?;
        match handshake.step(&welcome).map_err(|error| DriverError::Protocol(error.to_string()))? {
            HandshakeStep::Done { welcome, .. } => Ok((channel, welcome.limits)),
            HandshakeStep::Failed { reason, .. } => {
                Err(DriverError::Protocol(format!("relay denied client: {reason:?}")))
            }
            HandshakeStep::Reply(_) => {
                Err(DriverError::Protocol("relay repeated challenge".to_owned()))
            }
        }
    })
    .await
    .map_err(|_| DriverError::Transport("remote handshake timed out".to_owned()))?
}

fn client_endpoint(remote_ip: IpAddr, remote: &Remote) -> Result<quinn::Endpoint, DriverError> {
    let roots = root_store(remote)?;
    let mut tls = RustlsClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|error| DriverError::Transport(error.to_string()))?;
    let client = quinn::ClientConfig::new(Arc::new(crypto));
    let bind_ip = match remote_ip {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let mut endpoint = quinn::Endpoint::client(SocketAddr::new(bind_ip, 0))
        .map_err(|error| DriverError::Transport(error.to_string()))?;
    endpoint.set_default_client_config(client);
    Ok(endpoint)
}

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
