//! QUIC listener, per-IP admission control, and authenticated session startup.

use std::{
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
    sync::Arc,
    time::Duration,
};

use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DashMapStateStore};
use parking_lot::Mutex;
use quinn::{Endpoint, Incoming};
use rustls::ServerConfig as RustlsServerConfig;
use tokio::time::timeout;
use wormhole_proto::{
    ALPN, HandshakeStep, KeyDecision as ProtoKeyDecision, ServerHandshake,
    codec::ControlChannel,
    frames::{ControlFrame, DenyReason, Limits},
};

use crate::{
    authz::{KeyDecision, KeyLimits},
    certs::CertManager,
    session::SessionActor,
    session_streams::DataOpener,
    state::AppState,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const KEEP_ALIVE: Duration = Duration::from_secs(15);
const IDLE_TIMEOUT: Duration = Duration::from_mins(1);
const LIMITER_CLEANUP_INTERVAL: Duration = Duration::from_mins(10);

type IpRateLimiter = RateLimiter<IpAddr, DashMapStateStore<IpAddr>, DefaultClock>;
type QuicIo = tokio::io::Join<quinn::RecvStream, quinn::SendStream>;

/// Bound QUIC listener ready to accept authenticated clients.
pub struct QuicServer {
    endpoint: Endpoint,
    state: Arc<AppState>,
    server_name: String,
    limiter: IpRateLimiter,
}

impl QuicServer {
    /// Binds the UDP listener after certificates are ready.
    pub fn bind(
        address: SocketAddr,
        state: Arc<AppState>,
        certificates: &CertManager,
        server_name: String,
        handshakes_per_minute: u32,
    ) -> Result<Self, QuicError> {
        let server_config = server_config(certificates)?;
        let endpoint = Endpoint::server(server_config, address)?;
        let limiter = handshake_limiter(handshakes_per_minute)?;
        Ok(Self { endpoint, state, server_name, limiter })
    }

    /// Returns the actual bound UDP address, including a selected port for `:0`.
    pub fn local_addr(&self) -> Result<SocketAddr, QuicError> {
        Ok(self.endpoint.local_addr()?)
    }

    /// Returns a clone used by tests and shutdown coordination.
    pub fn endpoint(&self) -> Endpoint {
        self.endpoint.clone()
    }

    /// Accepts connections until the endpoint is closed.
    pub async fn run(&self) {
        let mut cleanup = tokio::time::interval(LIMITER_CLEANUP_INTERVAL);
        cleanup.tick().await;
        loop {
            tokio::select! {
                incoming = self.endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        return;
                    };
                    self.accept(incoming);
                }
                _ = cleanup.tick() => cleanup_limiter(&self.limiter),
            }
        }
    }

    fn accept(&self, incoming: Incoming) {
        let remote_ip = incoming.remote_address().ip();
        if self.limiter.check_key(&remote_ip).is_err() {
            incoming.refuse();
            return;
        }
        let state = Arc::clone(&self.state);
        let server_name = self.server_name.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_connection(incoming, state, &server_name).await {
                tracing::warn!(%error, %remote_ip, "QUIC client session ended");
            }
        });
    }
}

fn cleanup_limiter(limiter: &IpRateLimiter) {
    limiter.retain_recent();
    limiter.shrink_to_fit();
}

fn handshake_limiter(handshakes_per_minute: u32) -> Result<IpRateLimiter, QuicError> {
    let quota = Quota::per_minute(
        NonZeroU32::new(handshakes_per_minute)
            .ok_or_else(|| QuicError::Config("handshake rate must be non-zero".to_owned()))?,
    );
    Ok(RateLimiter::keyed(quota))
}

fn server_config(certificates: &CertManager) -> Result<quinn::ServerConfig, QuicError> {
    let mut tls = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(certificates.resolver());
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|error| QuicError::Config(error.to_string()))?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(KEEP_ALIVE));
    transport.max_idle_timeout(Some(
        IDLE_TIMEOUT
            .try_into()
            .map_err(|error| QuicError::Config(format!("invalid idle timeout: {error}")))?,
    ));
    server.transport_config(Arc::new(transport));
    Ok(server)
}

async fn handle_connection(
    incoming: Incoming,
    state: Arc<AppState>,
    server_name: &str,
) -> Result<(), QuicError> {
    let connection = incoming.await?;
    let authenticated = Arc::new(Mutex::new(None));
    let handshake = timeout(
        HANDSHAKE_TIMEOUT,
        authenticate(&connection, Arc::clone(&state), server_name, Arc::clone(&authenticated)),
    )
    .await;
    let handshake = match handshake {
        Ok(Ok(handshake)) => handshake,
        Ok(Err(error)) => {
            release_failed_auth(&state, &authenticated);
            return Err(error);
        }
        Err(_) => {
            release_failed_auth(&state, &authenticated);
            return Err(QuicError::HandshakeTimeout);
        }
    };
    let Some((channel, identity)) = handshake else {
        tokio::time::sleep(Duration::from_millis(100)).await;
        return Ok(());
    };
    let fingerprint = identity.fingerprint.clone();
    let result = SessionActor::new(
        channel,
        DataOpener::Quic(connection.clone()),
        Arc::clone(&state),
        fingerprint.clone(),
        identity.limits,
    )
    .run()
    .await;
    state.close_session(&fingerprint);
    result.map_err(QuicError::Session)
}

pub(crate) async fn run_io_session<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    io: S,
    opener: DataOpener,
    state: Arc<AppState>,
    server_name: &str,
) -> Result<(), QuicError> {
    let authenticated = Arc::new(Mutex::new(None));
    let max_streams = bounded_max_streams(
        state.limits.max_streams_per_session,
        wormhole_proto::mux_runtime::MAX_STREAMS,
    );
    let handshake = timeout(
        HANDSHAKE_TIMEOUT,
        authenticate_channel(
            ControlChannel::new(io),
            Arc::clone(&state),
            server_name,
            Arc::clone(&authenticated),
            max_streams,
        ),
    )
    .await;
    let handshake = match handshake {
        Ok(Ok(handshake)) => handshake,
        Ok(Err(error)) => {
            release_failed_auth(&state, &authenticated);
            return Err(error);
        }
        Err(_) => {
            release_failed_auth(&state, &authenticated);
            return Err(QuicError::HandshakeTimeout);
        }
    };
    let Some((channel, identity)) = handshake else {
        return Ok(());
    };
    let fingerprint = identity.fingerprint.clone();
    let result = SessionActor::new(
        channel,
        opener,
        Arc::clone(&state),
        fingerprint.clone(),
        identity.limits,
    )
    .run()
    .await;
    state.close_session(&fingerprint);
    result.map_err(QuicError::Session)
}

const fn bounded_max_streams(configured: u32, transport_limit: u32) -> u32 {
    if configured < transport_limit { configured } else { transport_limit }
}

async fn authenticate(
    connection: &quinn::Connection,
    state: Arc<AppState>,
    server_name: &str,
    authenticated: Arc<Mutex<Option<Authenticated>>>,
) -> Result<Option<(ControlChannel<QuicIo>, Authenticated)>, QuicError> {
    let (send, recv) = connection.accept_bi().await?;
    let max_streams = state.limits.max_streams_per_session;
    authenticate_channel(
        ControlChannel::new(tokio::io::join(recv, send)),
        state,
        server_name,
        authenticated,
        max_streams,
    )
    .await
}

async fn authenticate_channel<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut channel: ControlChannel<S>,
    state: Arc<AppState>,
    server_name: &str,
    authenticated: Arc<Mutex<Option<Authenticated>>>,
    max_streams: u32,
) -> Result<Option<(ControlChannel<S>, Authenticated)>, QuicError> {
    let limits = Limits { max_binds: state.limits.max_binds_per_key, max_streams };
    let callback_state = Arc::clone(&state);
    let callback_result = Arc::clone(&authenticated);
    let mut handshake = ServerHandshake::new(server_name, limits, None, move |public_key| {
        authorize_key(&callback_state, &callback_result, public_key, max_streams)
    });
    let hello = channel.recv().await?;
    if !send_handshake_step(&mut channel, handshake.step(&hello)?).await? {
        release_failed_auth(&state, &authenticated);
        return Ok(None);
    }
    let auth = channel.recv().await?;
    let step = handshake.step(&auth)?;
    if matches!(step, HandshakeStep::Done { .. }) {
        let fingerprint =
            authenticated.lock().as_ref().map(|identity| identity.fingerprint.clone()).ok_or_else(
                || QuicError::Protocol("verified handshake lacks identity".to_owned()),
            )?;
        let max_sessions = authenticated
            .lock()
            .as_ref()
            .map(|identity| identity.limits.max_sessions)
            .ok_or_else(|| QuicError::Protocol("verified handshake lacks limits".to_owned()))?;
        if !state.try_open_session(&fingerprint, max_sessions) {
            channel.send(&ControlFrame::Denied { reason: DenyReason::Limit }).await?;
            channel.close().await?;
            authenticated.lock().take();
            return Ok(None);
        }
        if let Some(identity) = authenticated.lock().as_mut() {
            identity.session_open = true;
        }
    }
    match send_handshake_step(&mut channel, step).await {
        Ok(true) => {}
        Ok(false) => {
            release_failed_auth(&state, &authenticated);
            return Ok(None);
        }
        Err(error) => {
            release_failed_auth(&state, &authenticated);
            return Err(error);
        }
    }
    let identity = authenticated
        .lock()
        .take()
        .ok_or_else(|| QuicError::Protocol("handshake completed without identity".to_owned()))?;
    Ok(Some((channel, identity)))
}

fn authorize_key(
    state: &AppState,
    authenticated: &Mutex<Option<Authenticated>>,
    public_key: &str,
    max_streams: u32,
) -> ProtoKeyDecision {
    match state.auth.is_authorized(public_key) {
        Ok(KeyDecision::Allowed { fingerprint, mut limits, .. }) => {
            limits.max_streams = limits.max_streams.min(max_streams);
            *authenticated.lock() =
                Some(Authenticated { fingerprint, limits, session_open: false });
            ProtoKeyDecision::Authorized
        }
        Ok(KeyDecision::Revoked) => ProtoKeyDecision::Revoked,
        Ok(KeyDecision::Unknown) | Err(_) => ProtoKeyDecision::Unknown,
    }
}

async fn send_handshake_step<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    channel: &mut ControlChannel<S>,
    step: HandshakeStep,
) -> Result<bool, QuicError> {
    match step {
        HandshakeStep::Reply(reply) => {
            channel.send(&reply).await?;
            Ok(true)
        }
        HandshakeStep::Done { reply, .. } => {
            if let Some(reply) = reply {
                channel.send(&reply).await?;
            }
            Ok(true)
        }
        HandshakeStep::Failed { reply, .. } => {
            if let Some(reply) = reply {
                channel.send(&reply).await?;
            }
            channel.close().await?;
            Ok(false)
        }
    }
}

fn release_failed_auth(state: &AppState, authenticated: &Mutex<Option<Authenticated>>) {
    let identity = authenticated.lock().take();
    if let Some(identity) = identity
        && identity.session_open
    {
        state.close_session(&identity.fingerprint);
    }
}

struct Authenticated {
    fingerprint: String,
    limits: KeyLimits,
    session_open: bool,
}

/// QUIC setup, transport, handshake, or session failure.
#[derive(Debug, thiserror::Error)]
pub enum QuicError {
    /// Listener or connection I/O failed.
    #[error(transparent)]
    Connection(#[from] quinn::ConnectionError),
    /// Endpoint setup failed.
    #[error(transparent)]
    Endpoint(#[from] std::io::Error),
    /// Protocol framing or handshake failed.
    #[error(transparent)]
    ProtocolIo(#[from] wormhole_proto::ProtoError),
    /// Session actor failed.
    #[error(transparent)]
    Session(#[from] crate::session::SessionError),
    /// Handshake exceeded five seconds.
    #[error("QUIC handshake timed out")]
    HandshakeTimeout,
    /// TLS or transport configuration is invalid.
    #[error("invalid QUIC configuration: {0}")]
    Config(String),
    /// Handshake reached an impossible state.
    #[error("QUIC protocol error: {0}")]
    Protocol(String),
}

#[cfg(test)]
#[path = "quic_tests.rs"]
mod tests;
