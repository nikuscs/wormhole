//! Daemon status endpoint.

use axum::{Json, extract::State};

use crate::api_types::{ApiState, StatusResponse};

#[utoipa::path(get, path = "/v1/status", tag = "Status", summary = "Get daemon status", responses((status = 200, body = StatusResponse)))]
pub async fn status(State(state): State<ApiState>) -> Json<StatusResponse> {
    let endpoints = state.manager.list();
    Json(StatusResponse {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        uptime_seconds: jiff::Timestamp::now().as_second() - state.started.as_second(),
        pid: std::process::id(),
        services: state.desired.read().await.values().filter(|service| service.active).count(),
        endpoints: endpoints.len(),
    })
}
