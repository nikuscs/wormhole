//! Local signed-link minting API.

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::api_types::{ApiError, ApiErrorBody, ApiState};

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ShareRequest {
    pub target: String,
    pub expires: String,
    pub path: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ShareResponse {
    pub url: String,
    pub expires_unix: i64,
}

#[utoipa::path(post, path = "/v1/share", tag = "Sharing", summary = "Create an expiring share link", request_body = ShareRequest, responses((status = 200, body = ShareResponse), (status = 400, body = ApiErrorBody), (status = 404, body = ApiErrorBody)))]
pub async fn share(
    State(state): State<ApiState>,
    Json(request): Json<ShareRequest>,
) -> Result<Json<ShareResponse>, ApiError> {
    let duration = humantime::parse_duration(&request.expires)
        .map_err(|error| ApiError::invalid(error.to_string()))?;
    if duration.is_zero() || duration > std::time::Duration::from_hours(7 * 24) {
        return Err(ApiError::invalid("share expiry must be between 1 second and 7 days"));
    }
    if !request.path.starts_with('/') || request.path.parse::<http::uri::PathAndQuery>().is_err() {
        return Err(ApiError::invalid("share path must be an absolute URI path"));
    }
    let expiry = jiff::Timestamp::now()
        .as_second()
        .saturating_add(duration.as_secs().try_into().unwrap_or(i64::MAX));
    let endpoint_id = request.target.parse::<Uuid>().ok();
    let active = state.manager.list();
    let bindings = state.bindings.read().await.clone();
    let desired = state.desired.read().await.clone();
    let mut matches = Vec::new();
    for endpoint in &active {
        let Some((key, index)) = bindings.get(&endpoint.id) else {
            continue;
        };
        let Some(service) = desired.get(key) else {
            continue;
        };
        let priority = if endpoint_id == Some(endpoint.id) {
            0
        } else if endpoint_id.is_some() {
            continue;
        } else if key.matches_project_target(&request.target) {
            1
        } else if service.service.name == request.target {
            2
        } else {
            continue;
        };
        let Some(spec) = service.endpoints.get(*index) else {
            continue;
        };
        let Some(link_key) = spec.auth.as_ref().and_then(|auth| auth.link_key.as_deref()) else {
            continue;
        };
        let Some(public_url) = endpoint.urls.first() else {
            continue;
        };
        matches.push((priority, endpoint.id, public_url, link_key));
    }
    let priorities = matches.iter().map(|candidate| candidate.0).collect::<Vec<_>>();
    let selected = select_unique_priority(&priorities)?;
    let (_, _, public_url, link_key) = matches[selected];
    let url = wormhole_core::share::mint_share_url(public_url, &request.path, link_key, expiry)
        .map_err(|error| ApiError::invalid(error.to_string()))?;
    Ok(Json(ShareResponse { url, expires_unix: expiry }))
}

fn select_unique_priority(priorities: &[u8]) -> Result<usize, ApiError> {
    let Some(priority) = priorities.iter().copied().min() else {
        return Err(ApiError::not_found("link-enabled endpoint not found"));
    };
    let mut matches = priorities
        .iter()
        .enumerate()
        .filter_map(|(index, candidate)| (*candidate == priority).then_some(index));
    let selected = matches.next().expect("minimum priority must have a match");
    if matches.next().is_some() {
        return Err(ApiError::conflict(
            "share target is ambiguous; use an endpoint UUID or project/service identity",
        ));
    }
    Ok(selected)
}

#[cfg(test)]
#[path = "share_api_tests.rs"]
mod tests;
