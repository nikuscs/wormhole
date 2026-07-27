//! Reserved Stage 07 local API handlers.

use crate::api_types::ClosedResponse;
use axum::{Json, http::StatusCode};

#[utoipa::path(
    get,
    path = "/v1/requests",
    params(
        ("endpoint" = Option<uuid::Uuid>, Query),
        ("limit" = Option<u32>, Query),
        ("since" = Option<String>, Query)
    ),
    responses((status = 200, description = "Captures"))
)]
pub async fn requests() -> Json<Vec<serde_json::Value>> {
    Json(Vec::new())
}

#[utoipa::path(
    get,
    path = "/v1/requests/{id}",
    params(("id" = uuid::Uuid, Path)),
    responses((status = 501, description = "Stage 07"))
)]
pub async fn request() -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

#[utoipa::path(
    post,
    path = "/v1/requests/{id}/replay",
    params(("id" = uuid::Uuid, Path)),
    responses((status = 501, description = "Stage 07"))
)]
pub async fn replay() -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

#[utoipa::path(delete, path = "/v1/requests", responses((status = 200, body = ClosedResponse)))]
pub async fn clear_requests() -> Json<ClosedResponse> {
    Json(ClosedResponse { closed: true })
}
