//! Process-wide local HTTP Host router shared by local-driver endpoints.

use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, OnceLock},
};

use parking_lot::RwLock;
use rustls::ServerConfig;
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    sync::Mutex,
    task::JoinHandle,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::{DriverError, local_ca::LocalCertResolver};

const MAX_REQUEST_HEAD: usize = 64 * 1024;

type Routes = Arc<RwLock<HashMap<String, SocketAddr>>>;

static ROUTER: OnceLock<Arc<LocalRouter>> = OnceLock::new();

/// Returns the router shared by every local driver in this process.
pub fn shared() -> Arc<LocalRouter> {
    Arc::clone(ROUTER.get_or_init(|| Arc::new(LocalRouter::new())))
}

/// Coordinates one listener per configured protocol/port and all registered hosts.
pub struct LocalRouter {
    listeners: Mutex<HashMap<ListenerKey, ListenerState>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ListenerKey {
    protocol: ListenerProtocol,
    port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ListenerProtocol {
    Http,
    Https,
}

struct ListenerState {
    address: SocketAddr,
    routes: Routes,
    stop: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
}

/// Registration removed explicitly when its owning driver stops.
pub struct RouteRegistration {
    router: Arc<LocalRouter>,
    key: ListenerKey,
    hostname: String,
}

impl LocalRouter {
    /// Creates an isolated router. Production callers should use [`shared`].
    pub fn new() -> Self {
        Self { listeners: Mutex::new(HashMap::new()) }
    }

    /// Registers a hostname on the shared HTTP listener.
    pub async fn register(
        self: &Arc<Self>,
        port: u16,
        hostname: &str,
        target: SocketAddr,
    ) -> Result<RouteRegistration, DriverError> {
        let key = ListenerKey { protocol: ListenerProtocol::Http, port };
        self.register_route(key, hostname, target, None).await
    }

    /// Registers a hostname on the shared HTTPS listener.
    pub async fn register_https(
        self: &Arc<Self>,
        port: u16,
        hostname: &str,
        target: SocketAddr,
        resolver: Arc<LocalCertResolver>,
    ) -> Result<RouteRegistration, DriverError> {
        let key = ListenerKey { protocol: ListenerProtocol::Https, port };
        self.register_route(key, hostname, target, Some(resolver)).await
    }

    async fn register_route(
        self: &Arc<Self>,
        key: ListenerKey,
        hostname: &str,
        target: SocketAddr,
        resolver: Option<Arc<LocalCertResolver>>,
    ) -> Result<RouteRegistration, DriverError> {
        let hostname = normalize_hostname(hostname)?;
        let mut listeners = self.listeners.lock().await;
        if let std::collections::hash_map::Entry::Vacant(entry) = listeners.entry(key) {
            entry.insert(bind_listener(key, resolver).await?);
        }
        {
            let state = listeners.get_mut(&key).expect("listener inserted");
            let mut routes = state.routes.write();
            if routes.contains_key(&hostname) {
                return Err(DriverError::Capability(format!(
                    "local hostname is already registered: {hostname}"
                )));
            }
            routes.insert(hostname.clone(), target);
        }
        drop(listeners);
        Ok(RouteRegistration { router: Arc::clone(self), key, hostname })
    }

    #[cfg(test)]
    pub(crate) async fn listener_count(&self) -> usize {
        self.listeners.lock().await.len()
    }

    async fn deregister(&self, key: ListenerKey, hostname: &str) {
        let mut listeners = self.listeners.lock().await;
        let should_stop = listeners.get_mut(&key).is_some_and(|state| {
            state.routes.write().remove(hostname);
            state.routes.read().is_empty()
        });
        if should_stop && let Some(state) = listeners.remove(&key) {
            state.stop.cancel();
            for task in state.tasks {
                let _joined = task.await;
            }
        }
    }
}

impl Default for LocalRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl RouteRegistration {
    /// Actual bound listener address, including an allocated port when configured with port zero.
    pub async fn listener_address(&self) -> Option<SocketAddr> {
        self.router.listeners.lock().await.get(&self.key).map(|state| state.address)
    }

    /// Removes the route and releases the listener when this was its last route.
    pub async fn close(self) {
        self.router.deregister(self.key, &self.hostname).await;
    }
}

async fn bind_listener(
    key: ListenerKey,
    resolver: Option<Arc<LocalCertResolver>>,
) -> Result<ListenerState, DriverError> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, key.port))
        .await
        .map_err(|error| bind_error(key, error))?;
    let address = listener.local_addr().map_err(|error| {
        DriverError::Transport(format!("local listener address failed: {error}"))
    })?;
    // `*.localhost` resolves to ::1 before 127.0.0.1 on macOS. Serving only IPv4 leaves clients to
    // fall back, which plain HTTP survives but a TLS handshake does not, so bind both loopbacks on
    // the same port. IPv6 is best effort because a host may have it disabled entirely.
    let listeners = std::iter::once(listener)
        .chain(TcpListener::bind((Ipv6Addr::LOCALHOST, address.port())).await.ok())
        .collect::<Vec<_>>();
    let routes = Arc::new(RwLock::new(HashMap::new()));
    let stop = CancellationToken::new();
    let acceptor = match key.protocol {
        ListenerProtocol::Http => None,
        ListenerProtocol::Https => Some(tls_acceptor(resolver.ok_or_else(|| {
            DriverError::Protocol("local HTTPS listener requires a certificate resolver".to_owned())
        })?)),
    };
    let tasks = listeners
        .into_iter()
        .map(|listener| match acceptor.clone() {
            None => tokio::spawn(accept_loop(listener, Arc::clone(&routes), stop.child_token())),
            Some(acceptor) => tokio::spawn(accept_tls_loop(
                listener,
                Arc::clone(&routes),
                stop.child_token(),
                acceptor,
            )),
        })
        .collect();
    Ok(ListenerState { address, routes, stop, tasks })
}

fn bind_error(key: ListenerKey, error: std::io::Error) -> DriverError {
    let config_key = match key.protocol {
        ListenerProtocol::Http => "defaults.local_http_port",
        ListenerProtocol::Https => "defaults.local_https_port",
    };
    if error.kind() == std::io::ErrorKind::PermissionDenied {
        DriverError::Transport(format!(
            "{config_key} {} requires privileged binding; configure an unprivileged port or enable the explicit local elevation opt-in",
            key.port
        ))
    } else {
        DriverError::Transport(format!("local listener bind failed on port {}: {error}", key.port))
    }
}

fn tls_acceptor(resolver: Arc<LocalCertResolver>) -> TlsAcceptor {
    let mut config = ServerConfig::builder().with_no_client_auth().with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    TlsAcceptor::from(Arc::new(config))
}

async fn accept_loop(listener: TcpListener, routes: Routes, stop: CancellationToken) {
    loop {
        tokio::select! {
            () = stop.cancelled() => return,
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { return };
                tokio::spawn(route_connection(stream, Arc::clone(&routes)));
            }
        }
    }
}

async fn accept_tls_loop(
    listener: TcpListener,
    routes: Routes,
    stop: CancellationToken,
    acceptor: TlsAcceptor,
) {
    loop {
        tokio::select! {
            () = stop.cancelled() => return,
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { return };
                let routes = Arc::clone(&routes);
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(stream) = acceptor.accept(stream).await {
                        route_connection(stream, routes).await;
                    }
                });
            }
        }
    }
}

async fn route_connection<S>(mut incoming: S, routes: Routes)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // A connection stays with its first Host; browsers pool HTTP/1 connections per origin.
    let Ok((buffered, hostname)) = read_request_head(&mut incoming).await else {
        return;
    };
    let target = routes.read().get(&hostname).copied();
    let Some(target) = target else {
        let _written = incoming
            .write_all(b"HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            .await;
        return;
    };
    let Ok(mut outgoing) = TcpStream::connect(target).await else {
        let _written = incoming
            .write_all(
                b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            )
            .await;
        return;
    };
    if outgoing.write_all(&buffered).await.is_ok() {
        let _copied = tokio::io::copy_bidirectional(&mut incoming, &mut outgoing).await;
    }
}

async fn read_request_head<S>(stream: &mut S) -> Result<(Vec<u8>, String), ()>
where
    S: AsyncRead + Unpin,
{
    let mut buffered = Vec::with_capacity(1024);
    let mut search_from = 0;
    loop {
        if let Some(offset) =
            buffered[search_from..].windows(4).position(|bytes| bytes == b"\r\n\r\n")
        {
            let head_end = search_from + offset + 4;
            let hostname = host_header(&buffered[..head_end]).ok_or(())?;
            return Ok((buffered, hostname));
        }
        if buffered.len() >= MAX_REQUEST_HEAD {
            return Err(());
        }
        search_from = buffered.len().saturating_sub(3);
        let remaining = MAX_REQUEST_HEAD - buffered.len();
        let mut chunk = [0_u8; 2048];
        let read_limit = remaining.min(chunk.len());
        let read = stream.read(&mut chunk[..read_limit]).await.map_err(|_| ())?;
        if read == 0 {
            return Err(());
        }
        buffered.extend_from_slice(&chunk[..read]);
    }
}

fn host_header(head: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(head).ok()?;
    text.split("\r\n").skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("host")
            .then(|| value.trim().split(':').next().unwrap_or_default().to_ascii_lowercase())
            .filter(|host| !host.is_empty())
    })
}

fn normalize_hostname(hostname: &str) -> Result<String, DriverError> {
    let hostname = hostname.trim_end_matches('.').to_ascii_lowercase();
    if hostname.is_empty() || hostname.contains(':') {
        return Err(DriverError::Capability(
            "local hostname must be a DNS name without a port".to_owned(),
        ));
    }
    Ok(hostname)
}

#[cfg(test)]
#[path = "local_router_tests.rs"]
mod tests;
