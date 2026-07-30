use std::collections::HashMap;

use futures::channel::{mpsc, oneshot};
use serde::{Deserialize, Serialize};

use crate::storage;

const MAX_BIND_CACHE: usize = 256;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) enum SocketAttachment {
    Unauthenticated,
    Pending(storage::AuthRow),
    Authenticated { fingerprint: String },
    Retired,
}

#[derive(Default)]
pub struct Runtime {
    pub(super) control: HashMap<String, Vec<u8>>,
    pub(super) next_channel: HashMap<String, u32>,
    pub(super) pending: HashMap<(String, u32), PendingHttp>,
    pub(super) binds: HashMap<String, storage::BindRow>,
}

impl Runtime {
    pub(super) fn cache_bind(&mut self, bind: &storage::BindRow) {
        if self.binds.len() >= MAX_BIND_CACHE && !self.binds.contains_key(&bind.hostname) {
            self.binds.clear();
        }
        self.binds.insert(bind.hostname.clone(), bind.clone());
    }

    pub(super) fn invalidate_bind(&mut self, bind: &str) {
        self.binds.retain(|_, row| row.bind_id != bind);
    }

    pub(super) fn invalidate_connection(&mut self, connection: &str) {
        self.binds.retain(|_, row| row.connection_id.as_deref() != Some(connection));
    }

    pub(super) fn invalidate_fingerprint(&mut self, fingerprint: &str) {
        self.binds.retain(|_, row| row.fingerprint != fingerprint);
    }

    pub(super) fn invalidate_reservation(&mut self, reservation: &str) {
        self.binds.retain(|_, row| row.reservation.as_deref() != Some(reservation));
    }
}

pub(super) struct PendingHttp {
    pub(super) head: Option<
        oneshot::Sender<std::result::Result<wormhole_proto::frames::HttpResponseHead, String>>,
    >,
    pub(super) body: mpsc::Sender<std::result::Result<Vec<u8>, worker::Error>>,
    pub(super) buffer: Vec<u8>,
    pub(super) head_received: bool,
    pub(super) credit: mpsc::UnboundedSender<u32>,
    pub(super) upgrade: bool,
}

#[cfg(test)]
#[path = "session_runtime_tests.rs"]
mod tests;
