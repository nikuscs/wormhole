//! Public TCP-forward listeners that remain reserved for persistent offline binds.

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use dashmap::{DashMap, mapref::entry::Entry};
use tokio::{net::TcpListener, task::JoinHandle};
use wormhole_proto::frames::StreamHeader;

use crate::registry::{BindHandle, BindState, SessionCommand};

/// Owns one accept task per allocated public TCP port.
pub struct TcpEdgeManager {
    bind_ip: IpAddr,
    listeners: DashMap<u16, JoinHandle<()>>,
}

impl TcpEdgeManager {
    /// Creates a listener manager bound to the configured public interface.
    pub fn new(bind_ip: IpAddr) -> Self {
        Self { bind_ip, listeners: DashMap::new() }
    }

    /// Ensures the bind's public port is listening exactly once.
    pub async fn ensure_listener(
        &self,
        port: u16,
        handle: Arc<BindHandle>,
    ) -> Result<(), std::io::Error> {
        if self.listeners.contains_key(&port) {
            return Ok(());
        }
        let listener = TcpListener::bind(SocketAddr::new(self.bind_ip, port)).await?;
        let task = tokio::spawn(run_listener(listener, handle));
        match self.listeners.entry(port) {
            Entry::Vacant(entry) => {
                entry.insert(task);
            }
            Entry::Occupied(_) => task.abort(),
        }
        Ok(())
    }

    /// Stops and releases a temporary or forgotten TCP listener.
    pub fn remove_listener(&self, port: u16) {
        if let Some((_, task)) = self.listeners.remove(&port) {
            task.abort();
        }
    }

    /// Returns whether a public port is currently reserved by this process.
    pub fn contains(&self, port: u16) -> bool {
        self.listeners.contains_key(&port)
    }
}

async fn run_listener(listener: TcpListener, handle: Arc<BindHandle>) {
    while let Ok((stream, peer)) = listener.accept().await {
        if handle.state() != BindState::Online {
            drop(stream);
            continue;
        }
        let Some(session) = handle.session() else {
            drop(stream);
            continue;
        };
        let command = SessionCommand::OpenTcp {
            header: StreamHeader::Tcp { bind: handle.bind_id, peer },
            stream,
        };
        if session.send(command).await.is_err() {
            return;
        }
    }
}

impl Drop for TcpEdgeManager {
    fn drop(&mut self) {
        for entry in &self.listeners {
            entry.value().abort();
        }
    }
}

#[cfg(test)]
#[path = "edge_tcp_tests.rs"]
mod tests;
