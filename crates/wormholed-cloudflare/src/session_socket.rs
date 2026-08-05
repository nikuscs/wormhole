use serde::Deserialize;
use worker::{Result, SqlStorage, State, WebSocket};

use super::{SocketAttachment, protocol_error};
use crate::storage;

pub(super) fn socket_attachment(
    sql: &SqlStorage,
    ws: &WebSocket,
    connection: &str,
) -> Result<SocketAttachment> {
    if let Some(attachment) = ws.deserialize_attachment()? {
        return Ok(attachment);
    }
    let attachment = if let Some(auth) = storage::pending_auth(sql, connection)? {
        SocketAttachment::Pending(auth)
    } else if let Some(fingerprint) = session_fingerprint(sql, connection)? {
        SocketAttachment::Authenticated { fingerprint }
    } else {
        SocketAttachment::Unauthenticated
    };
    ws.serialize_attachment(attachment.clone())?;
    Ok(attachment)
}

fn session_fingerprint(sql: &SqlStorage, connection: &str) -> Result<Option<String>> {
    #[derive(Deserialize)]
    struct Row {
        fingerprint: String,
    }
    Ok(sql
        .exec("SELECT fingerprint FROM sessions WHERE connection_id=?", vec![connection.into()])?
        .to_array::<Row>()?
        .into_iter()
        .next()
        .map(|row| row.fingerprint))
}

pub(super) fn session_connections(sql: &SqlStorage, fingerprint: &str) -> Result<Vec<String>> {
    #[derive(Deserialize)]
    struct Row {
        connection_id: String,
    }
    Ok(sql
        .exec("SELECT connection_id FROM sessions WHERE fingerprint=?", vec![fingerprint.into()])?
        .to_array::<Row>()?
        .into_iter()
        .map(|row| row.connection_id)
        .collect())
}

/// Whether a recorded connection still has a live socket.
///
/// A connection whose socket is gone left its rows behind, and those rows must not keep owning
/// hostnames or count as a live session.
pub(super) fn connection_is_live(state: &State, connection: &str) -> bool {
    socket_for(state, connection).is_some()
}

pub(super) fn connection_id(state: &State, ws: &WebSocket) -> Result<String> {
    state
        .get_tags(ws)
        .into_iter()
        .find_map(|tag| tag.strip_prefix("conn:").map(str::to_owned))
        .ok_or_else(|| protocol_error("WebSocket connection tag missing"))
}

pub(super) fn socket_for(state: &State, connection: &str) -> Option<WebSocket> {
    state.get_websockets_with_tag(&format!("conn:{connection}")).into_iter().next()
}
