//! Stable local API request, response, error, and shared state types.

use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use axum::{Json, http::StatusCode, response::Response};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};
use tokio_util::sync::CancellationToken;
use utoipa::ToSchema;
use uuid::Uuid;
use wormhole_core::{
    ActiveEndpoint, ClientConfig, EndpointSpec, Remote, Service, TunnelManager,
    keys_store::IdentityStore,
};

use crate::state_db::{DesiredService, StateDb};

#[derive(Clone)]
pub struct ApiState {
    pub manager: Arc<TunnelManager>,
    pub config: Arc<RwLock<ClientConfig>>,
    pub config_path: Option<std::path::PathBuf>,
    pub identities: Arc<IdentityStore>,
    pub database: Arc<StateDb>,
    pub desired: Arc<RwLock<BTreeMap<String, DesiredService>>>,
    pub bindings: Arc<RwLock<HashMap<Uuid, (String, usize)>>>,
    pub persistence_lock: Arc<Mutex<()>>,
    pub expose_lock: Arc<Mutex<()>>,
    pub started: jiff::Timestamp,
    pub shutdown: CancellationToken,
    pub token: Arc<str>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct StatusResponse {
    pub version: String,
    pub uptime_seconds: i64,
    pub pid: u32,
    pub services: usize,
    pub endpoints: usize,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CreateServiceRequest {
    pub project_id: Option<String>,
    pub remotes: Option<BTreeMap<String, Remote>>,
    pub default_remote: Option<String>,
    pub service: Service,
    pub endpoints: Vec<EndpointSpec>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ServiceView {
    pub project_id: String,
    pub service: Service,
    pub endpoints: Vec<ActiveEndpoint>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ClosedResponse {
    pub closed: bool,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiErrorBody {
    pub error: ApiErrorDetail,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiErrorDetail {
    pub code: String,
    pub message: String,
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ApiError {
    pub fn conflict(message: impl Into<String>) -> Self {
        Self { status: StatusCode::CONFLICT, code: "conflict", message: message.into() }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal",
            message: message.into(),
        }
    }

    pub fn unavailable(message: impl Into<String>) -> Self {
        Self { status: StatusCode::BAD_GATEWAY, code: "endpoint_failed", message: message.into() }
    }
}

impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ApiErrorBody {
                error: ApiErrorDetail { code: self.code.to_owned(), message: self.message },
            }),
        )
            .into_response()
    }
}
