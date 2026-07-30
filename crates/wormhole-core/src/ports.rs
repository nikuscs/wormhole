//! Free-port allocation, listener readiness, and child listener detection.

use std::{collections::HashSet, net::SocketAddr, ops::RangeInclusive, time::Duration};

use jiff::Timestamp;
use listeners::{Protocol, SocketState};
use sysinfo::System;

use crate::error::PortError;

/// Returns the first currently bindable loopback port in a range.
pub fn alloc_port(range: RangeInclusive<u16>) -> Result<u16, PortError> {
    let (port, listener) = reserve_port(range)?;
    drop(listener);
    Ok(port)
}

/// Reserves the first bindable loopback port until the caller is ready to spawn its listener.
pub fn reserve_port(range: RangeInclusive<u16>) -> Result<(u16, std::net::TcpListener), PortError> {
    for port in range {
        if let Ok(listener) = std::net::TcpListener::bind(("127.0.0.1", port)) {
            return Ok((port, listener));
        }
    }
    Err(PortError::Exhausted)
}

/// Polls until a TCP listener accepts connections or the timeout expires.
pub async fn wait_for_listener(addr: SocketAddr, timeout: Duration) -> Result<(), PortError> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(PortError::Timeout);
        }
        let remaining = deadline - now;
        let interval = Duration::from_millis(150);
        let attempt =
            tokio::time::timeout(remaining.min(interval), tokio::net::TcpStream::connect(addr))
                .await;
        if matches!(attempt, Ok(Ok(_))) {
            return Ok(());
        }
        let elapsed = now.elapsed();
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        tokio::time::sleep(remaining.min(interval.saturating_sub(elapsed))).await;
    }
}

/// Finds a TCP listening port owned by a process or descendant started after `since`.
pub fn detect_child_port(pid: u32, since: Timestamp) -> Option<u16> {
    let descendants = descendant_pids(pid, since);
    listeners::get_all()
        .ok()?
        .into_iter()
        .filter_map(|listener| {
            (listener.protocol == Protocol::TCP
                && listener.state == SocketState::Listen
                && descendants.contains(&listener.process.pid))
            .then_some(listener.socket.port())
        })
        .min()
}

fn descendant_pids(root: u32, since: Timestamp) -> HashSet<u32> {
    let system = System::new_all();
    let mut descendants = HashSet::from([root]);
    let earliest = since.as_second().max(0) as u64;
    loop {
        let before = descendants.len();
        for (pid, process) in system.processes() {
            let Some(parent) = process.parent() else {
                continue;
            };
            if descendants.contains(&parent.as_u32()) && process.start_time() >= earliest {
                descendants.insert(pid.as_u32());
            }
        }
        if descendants.len() == before {
            return descendants;
        }
    }
}

#[cfg(test)]
#[path = "ports_tests.rs"]
mod tests;
