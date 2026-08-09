//! Process-wide local HTTP Host router shared by local-driver endpoints.

use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, OnceLock},
};

use parking_lot::RwLock;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    sync::Mutex,
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use crate::DriverError;

const MAX_REQUEST_HEAD: usize = 64 * 1024;

type Routes = Arc<RwLock<HashMap<String, SocketAddr>>>;

static ROUTER: OnceLock<Arc<LocalRouter>> = OnceLock::new();

/// Returns the router shared by every local driver in this process.
pub fn shared() -> Arc<LocalRouter> {
    Arc::clone(ROUTER.get_or_init(|| Arc::new(LocalRouter::new())))
}

/// Coordinates one listener per configured HTTP port and all registered hosts.
pub struct LocalRouter {
    listeners: Mutex<HashMap<u16, ListenerState>>,
}

struct ListenerState {
    address: SocketAddr,
    routes: Routes,
    stop: CancellationToken,
    task: JoinHandle<()>,
}

/// Registration removed explicitly when its owning driver stops.
pub struct RouteRegistration {
    router: Arc<LocalRouter>,
    port: u16,
    hostname: String,
}

impl LocalRouter {
    /// Creates an isolated router. Production callers should use [`shared`].
    pub fn new() -> Self {
        Self { listeners: Mutex::new(HashMap::new()) }
    }

    /// Registers a hostname and starts its port listener when needed.
    pub async fn register(
        self: &Arc<Self>,
        port: u16,
        hostname: &str,
        target: SocketAddr,
    ) -> Result<RouteRegistration, DriverError> {
        let hostname = normalize_hostname(hostname)?;
        let mut listeners = self.listeners.lock().await;
        if let std::collections::hash_map::Entry::Vacant(entry) = listeners.entry(port) {
            entry.insert(bind_listener(port).await?);
        }
        {
            let state = listeners.get_mut(&port).expect("listener inserted");
            let mut routes = state.routes.write();
            if routes.contains_key(&hostname) {
                return Err(DriverError::Capability(format!(
                    "local hostname is already registered: {hostname}"
                )));
            }
            routes.insert(hostname.clone(), target);
        }
        drop(listeners);
        Ok(RouteRegistration { router: Arc::clone(self), port, hostname })
    }

    async fn deregister(&self, port: u16, hostname: &str) {
        let mut listeners = self.listeners.lock().await;
        let should_stop = listeners.get_mut(&port).is_some_and(|state| {
            state.routes.write().remove(hostname);
            state.routes.read().is_empty()
        });
        if should_stop && let Some(state) = listeners.remove(&port) {
            state.stop.cancel();
            let _joined = state.task.await;
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
        self.router.listeners.lock().await.get(&self.port).map(|state| state.address)
    }

    /// Removes the route and releases the listener when this was its last route.
    pub async fn close(self) {
        self.router.deregister(self.port, &self.hostname).await;
    }
}

async fn bind_listener(port: u16) -> Result<ListenerState, DriverError> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await.map_err(|error| {
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            DriverError::Transport(format!(
                "defaults.local_http_port {port} requires privileged binding; configure an unprivileged port or enable the explicit local elevation opt-in"
            ))
        } else {
            DriverError::Transport(format!("local listener bind failed on port {port}: {error}"))
        }
    })?;
    let address = listener.local_addr().map_err(|error| {
        DriverError::Transport(format!("local listener address failed: {error}"))
    })?;
    let routes = Arc::new(RwLock::new(HashMap::new()));
    let stop = CancellationToken::new();
    let task = tokio::spawn(accept_loop(listener, Arc::clone(&routes), stop.child_token()));
    Ok(ListenerState { address, routes, stop, task })
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

async fn route_connection(mut incoming: TcpStream, routes: Routes) {
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

async fn read_request_head(stream: &mut TcpStream) -> Result<(Vec<u8>, String), ()> {
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
