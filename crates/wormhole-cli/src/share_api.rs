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

#[utoipa::path(post, path = "/v1/share", request_body = ShareRequest, responses((status = 200, body = ShareResponse), (status = 400, body = ApiErrorBody), (status = 404, body = ApiErrorBody)))]
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
    for endpoint in active {
        let Some((key, index)) = bindings.get(&endpoint.id) else {
            continue;
        };
        let Some(service) = desired.get(key) else {
            continue;
        };
        if endpoint_id != Some(endpoint.id) && service.service.name != request.target {
            continue;
        }
        let Some(spec) = service.endpoints.get(*index) else {
            continue;
        };
        let Some(link_key) = spec.auth.as_ref().and_then(|auth| auth.link_key.as_deref()) else {
            continue;
        };
        let Some(public_url) = endpoint.urls.first() else {
            continue;
        };
        let url = wormhole_core::share::mint_share_url(public_url, &request.path, link_key, expiry)
            .map_err(|error| ApiError::invalid(error.to_string()))?;
        return Ok(Json(ShareResponse { url, expires_unix: expiry }));
    }
    Err(ApiError::not_found("link-enabled endpoint not found"))
}
