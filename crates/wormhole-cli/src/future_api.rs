//! Request inspection and replay local API.

use std::time::Duration;

use axum::{
    Json,
    extract::{Path, Query, State},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use wormhole_core::{CapturedRequest, Target};

use crate::api_types::{ApiError, ApiState, ClosedResponse};

#[derive(Debug, Deserialize)]
pub struct RequestQuery {
    endpoint: Option<Uuid>,
    limit: Option<usize>,
    since: Option<String>,
}

#[utoipa::path(get, path = "/v1/requests", tag = "Requests", summary = "List captured requests", params(("endpoint" = Option<Uuid>, Query), ("limit" = Option<u32>, Query), ("since" = Option<String>, Query)), responses((status = 200, body = [CapturedRequest])))]
pub async fn requests(
    State(state): State<ApiState>,
    Query(query): Query<RequestQuery>,
) -> Result<Json<Vec<CapturedRequest>>, ApiError> {
    let since = query
        .since
        .map(|value| value.parse::<jiff::Timestamp>())
        .transpose()
        .map_err(|error| ApiError::invalid(format!("invalid since timestamp: {error}")))?;
    Ok(Json(state.captures.read().await.list(
        query.endpoint,
        since,
        query.limit.unwrap_or(100).min(1000),
    )))
}

#[utoipa::path(get, path = "/v1/requests/{id}", tag = "Requests", summary = "Get a captured request", params(("id" = Uuid, Path)), responses((status = 200, body = CapturedRequest), (status = 404)))]
pub async fn request(
    State(state): State<ApiState>,
    Path(id): Path<Uuid>,
) -> Result<Json<CapturedRequest>, ApiError> {
    state
        .captures
        .read()
        .await
        .get(id)
        .map(Json)
        .ok_or_else(|| ApiError::not_found("capture not found"))
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ReplayResponse {
    pub status: u16,
    pub duration_ms: u64,
}

#[utoipa::path(post, path = "/v1/requests/{id}/replay", tag = "Requests", summary = "Replay a captured request", params(("id" = Uuid, Path)), responses((status = 200, body = ReplayResponse), (status = 400), (status = 404)))]
pub async fn replay(
    State(state): State<ApiState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ReplayResponse>, ApiError> {
    let capture = state
        .captures
        .read()
        .await
        .get(id)
        .ok_or_else(|| ApiError::not_found("capture not found"))?;
    if capture.body_truncated {
        return Err(ApiError::invalid("body_truncated captures cannot be replayed"));
    }
    let endpoint =
        capture.endpoint_id.ok_or_else(|| ApiError::invalid("capture has no endpoint"))?;
    let (key, _) = state
        .bindings
        .read()
        .await
        .get(&endpoint)
        .cloned()
        .ok_or_else(|| ApiError::not_found("endpoint is no longer active"))?;
    let target = state
        .desired
        .read()
        .await
        .get(&key)
        .map(|desired| desired.service.target.clone())
        .ok_or_else(|| ApiError::not_found("service is no longer active"))?;
    let aliases = state.config.read().await.aliases.clone();
    let address = target_address(&target, aliases).await?;
    let started = std::time::Instant::now();
    let status = tokio::time::timeout(Duration::from_secs(30), replay_to(address, &capture))
        .await
        .map_err(|_| ApiError::unavailable("replay timed out"))??;
    Ok(Json(ReplayResponse {
        status,
        duration_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
    }))
}

async fn replay_to(
    address: std::net::SocketAddr,
    capture: &CapturedRequest,
) -> Result<u16, ApiError> {
    let stream = tokio::net::TcpStream::connect(address)
        .await
        .map_err(|error| ApiError::unavailable(error.to_string()))?;
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|error| ApiError::unavailable(error.to_string()))?;
    tokio::spawn(async move {
        let _completed = connection.await;
    });
    let mut builder = hyper::Request::builder().method(capture.method.as_str()).uri(&capture.uri);
    if let Some(headers) = builder.headers_mut() {
        for header in &capture.headers {
            if is_redacted(&header.name) {
                continue;
            }
            let Ok(name) = http::HeaderName::from_bytes(header.name.as_bytes()) else {
                continue;
            };
            let Ok(raw) = STANDARD.decode(&header.value_b64) else {
                continue;
            };
            if let Ok(value) = http::HeaderValue::from_bytes(&raw) {
                headers.append(name, value);
            }
        }
    }
    let request = builder
        .body(Full::new(Bytes::copy_from_slice(&capture.body)))
        .map_err(|error| ApiError::invalid(error.to_string()))?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|error| ApiError::unavailable(error.to_string()))?;
    let status = response.status().as_u16();
    response
        .into_body()
        .collect()
        .await
        .map_err(|error| ApiError::unavailable(error.to_string()))?;
    Ok(status)
}

async fn target_address(
    target: &Target,
    aliases: std::collections::BTreeMap<String, String>,
) -> Result<std::net::SocketAddr, ApiError> {
    match target {
        Target::Port(port) => Ok(([127, 0, 0, 1], *port).into()),
        Target::HostPort(host, port) => tokio::net::lookup_host((host.as_str(), *port))
            .await
            .map_err(|error| ApiError::invalid(format!("target address: {error}")))?
            .next()
            .ok_or_else(|| ApiError::invalid("target hostname resolved to no addresses")),
        Target::Iface { alias, port } => {
            let alias = alias.clone();
            let ip = tokio::task::spawn_blocking(move || {
                wormhole_core::ifaces::IfaceResolver::new(aliases).resolve(&alias)
            })
            .await
            .map_err(|error| ApiError::unavailable(error.to_string()))?
            .map_err(|error| ApiError::invalid(error.to_string()))?;
            Ok((ip, *port).into())
        }
    }
}

fn is_redacted(name: &str) -> bool {
    ["authorization", "cookie", "set-cookie", "x-api-key"]
        .iter()
        .any(|secret| name.eq_ignore_ascii_case(secret))
}

#[utoipa::path(delete, path = "/v1/requests", tag = "Requests", summary = "Clear captured requests", responses((status = 200, body = ClosedResponse)))]
pub async fn clear_requests(State(state): State<ApiState>) -> Json<ClosedResponse> {
    state.captures.write().await.clear();
    Json(ClosedResponse { closed: true })
}

#[cfg(test)]
#[path = "future_api_tests.rs"]
mod tests;
