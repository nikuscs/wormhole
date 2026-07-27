//! Durable offline webhook buffering and ordered replay.

use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use http_body_util::BodyExt as _;
use hyper::{Request, body::Incoming};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use wormhole_proto::frames::{HeaderField, HttpRequestHead, StreamHeader};

use crate::{
    db::{BufferQuotas, DbError},
    edge_types::EdgeError,
    registry::{BindHandle, BindState, SessionCommand},
    state::AppState,
};

/// Versioned request retained after an offline edge delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BufferedRequest {
    pub v: u8,
    pub method: String,
    pub uri: String,
    pub http_version: String,
    pub headers: Vec<HeaderField>,
    pub body: Vec<u8>,
    pub seq: u64,
    pub received_at: jiff::Timestamp,
}

/// Accepts and commits one offline webhook before returning its sequence.
pub async fn buffer_request(
    request: Request<Incoming>,
    bind: &BindHandle,
    state: &AppState,
) -> Result<u64, BufferError> {
    let policy = bind.buffer_policy.as_ref().ok_or(BufferError::Unavailable)?;
    let (parts, mut body) = request.into_parts();
    let read = async {
        let mut collected = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|error| BufferError::Body(error.to_string()))?;
            if let Ok(data) = frame.into_data() {
                if collected.len().saturating_add(data.len()) as u64 > policy.max_body_bytes {
                    return Err(BufferError::BodyTooLarge);
                }
                collected.extend_from_slice(&data);
            }
        }
        Ok::<_, BufferError>(collected)
    };
    let body = tokio::time::timeout(Duration::from_secs(30), read)
        .await
        .map_err(|_| BufferError::Deadline)??;
    let headers = parts
        .headers
        .iter()
        .map(|(name, value)| HeaderField {
            name: name.as_str().to_owned(),
            value_b64: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                value.as_bytes(),
            ),
        })
        .collect();
    let buffered = BufferedRequest {
        v: 1,
        method: parts.method.to_string(),
        uri: parts.uri.path_and_query().map_or("/", http::uri::PathAndQuery::as_str).to_owned(),
        http_version: "HTTP/1.1".to_owned(),
        headers,
        body,
        seq: 0,
        received_at: jiff::Timestamp::now(),
    };
    let key_limit = crate::config::parse_byte_size(&state.limits.buffer_max_bytes_per_key)
        .map_err(|error| BufferError::Quota(error.to_string()))?;
    let total_limit = crate::config::parse_byte_size(&state.limits.buffer_max_bytes_total)
        .map_err(|error| BufferError::Quota(error.to_string()))?;
    state
        .database
        .enqueue_buffered(
            bind.bind_id,
            &bind.key_fpr,
            buffered,
            BufferQuotas {
                max_requests: policy.max_requests,
                ttl_secs: policy.ttl_secs,
                key_bytes: key_limit,
                total_bytes: total_limit,
            },
        )
        .map_err(BufferError::Database)
}

/// Starts daily TTL cleanup for active and quarantined webhook rows.
pub fn spawn_janitor(state: Arc<AppState>) {
    tokio::spawn(async move {
        loop {
            if let Err(error) = state.database.prune_all_expired() {
                tracing::warn!(%error, "webhook TTL cleanup failed");
            }
            tokio::time::sleep(Duration::from_hours(24)).await;
        }
    });
}

/// Starts one strict-order drain after the bind activation barrier.
pub fn spawn_drain(state: Arc<AppState>, handle: Arc<BindHandle>) {
    tokio::spawn(async move {
        if let Err(error) = drain(&state, &handle).await {
            tracing::warn!(bind = %handle.bind_id, %error, "buffered webhook drain stopped");
        }
    });
}

async fn drain(state: &AppState, handle: &BindHandle) -> Result<(), BufferError> {
    if handle.state() != BindState::Online {
        return Ok(());
    }
    if let Some(policy) = &handle.buffer_policy {
        state.database.prune_expired(handle.bind_id, policy.ttl_secs)?;
    }
    let Some(request) = state.database.first_buffered(handle.bind_id)? else {
        return Ok(());
    };
    if !state.claim_buffered(handle.bind_id, request.seq) {
        return Ok(());
    }
    if let Err(error) = deliver(handle, &request).await {
        tracing::warn!(bind = %handle.bind_id, seq = request.seq, %error, "buffered delivery remains pending");
    }
    Ok(())
}

async fn deliver(handle: &BindHandle, request: &BufferedRequest) -> Result<(), BufferError> {
    let session = handle.session().ok_or(BufferError::Unavailable)?;
    let (body_tx, body_rx) = mpsc::channel(1);
    body_tx
        .send(Ok(Bytes::copy_from_slice(&request.body)))
        .await
        .map_err(|_| BufferError::Unavailable)?;
    drop(body_tx);
    let (reply, response) = oneshot::channel();
    session
        .send(SessionCommand::OpenHttp {
            header: StreamHeader::Http {
                bind: handle.bind_id,
                peer: "127.0.0.1:0".parse().expect("buffer peer"),
                request: HttpRequestHead {
                    method: request.method.clone(),
                    uri: request.uri.clone(),
                    version: request.http_version.clone(),
                    headers: request.headers.clone(),
                },
                buffered: Some(request.seq),
            },
            body: body_rx,
            upgrade: false,
            reply,
        })
        .await
        .map_err(|_| BufferError::Unavailable)?;
    let mut response =
        response.await.map_err(|_| BufferError::Unavailable)?.map_err(BufferError::Body)?;
    while let Some(chunk) = response.body.recv().await {
        chunk.map_err(BufferError::Body)?;
    }
    Ok(())
}

/// Offline buffering failure mapped to stable edge statuses.
#[derive(Debug, thiserror::Error)]
pub enum BufferError {
    #[error("buffering is unavailable")]
    Unavailable,
    #[error("buffered request body exceeds the endpoint limit")]
    BodyTooLarge,
    #[error("buffered request read deadline exceeded")]
    Deadline,
    #[error("buffered request body failed: {0}")]
    Body(String),
    #[error("buffer quota exceeded: {0}")]
    Quota(String),
    #[error(transparent)]
    Database(#[from] DbError),
}

impl From<BufferError> for EdgeError {
    fn from(error: BufferError) -> Self {
        Self::Tunnel(error.to_string())
    }
}

#[cfg(test)]
#[path = "buffer_tests.rs"]
mod tests;
