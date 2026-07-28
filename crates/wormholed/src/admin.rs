//! Root-only Unix-socket administration API and `OpenAPI` document.

use std::{
    fs::{self, File, OpenOptions, Permissions},
    os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};

use axum::{
    Json, Router,
    extract::{Path as AxumPath, State},
    http::StatusCode,
    routing::{delete, get, post},
};
use camino::Utf8Path;
use nix::fcntl::{Flock, FlockArg};
use serde::{Deserialize, Serialize};
use tokio::net::UnixListener;
use utoipa::{OpenApi, ToSchema};
use utoipa_scalar::{Scalar, Servable};
use uuid::Uuid;

use crate::{
    certs::CertManager,
    db::PersistedEndpoint,
    registry::{BindState, HostKey, SessionCommand},
    state::AppState,
};

/// Bound administration service. Its lock prevents unsafe stale-socket removal.
pub struct AdminServer {
    listener: UnixListener,
    router: Router,
    lock: Flock<File>,
    socket_path: PathBuf,
}

impl AdminServer {
    /// Exclusively locks and binds `<data_dir>/admin.sock` with mode 0600.
    pub fn bind(
        data_dir: &Utf8Path,
        state: Arc<AppState>,
        certificates: Arc<CertManager>,
    ) -> Result<Self, AdminError> {
        fs::create_dir_all(data_dir)?;
        let lock_file = open_lock(data_dir.join("admin.lock").as_std_path())?;
        let lock = Flock::lock(lock_file, FlockArg::LockExclusiveNonblock)
            .map_err(|_| AdminError::AlreadyRunning)?;
        let socket_path = data_dir.join("admin.sock").into_std_path_buf();
        remove_stale_socket(&socket_path)?;
        let listener = UnixListener::bind(&socket_path)?;
        fs::set_permissions(&socket_path, Permissions::from_mode(0o600))?;
        let router = router(AdminState { state, certificates });
        Ok(Self { listener, router, lock, socket_path })
    }

    /// Serves requests until the task is cancelled.
    pub async fn run(self) -> Result<(), AdminError> {
        let Self { listener, router, lock, socket_path } = self;
        let _lock = lock;
        let _cleanup = SocketCleanup(socket_path);
        axum::serve(listener, router).await.map_err(AdminError::Io)
    }
}

#[derive(Clone)]
struct AdminState {
    state: Arc<AppState>,
    certificates: Arc<CertManager>,
}

fn router(state: AdminState) -> Router {
    let openapi = AdminApi::openapi();
    Router::new()
        .route("/v1/status", get(status))
        .route("/v1/binds", get(list_binds))
        .route("/v1/binds/{id}", delete(delete_bind))
        .route("/v1/webhooks/failed", get(list_failed_webhooks))
        .route("/v1/webhooks/failed/{bind}/{seq}", delete(delete_failed_webhook))
        .route("/v1/webhooks/failed/{bind}/{seq}/retry", post(retry_failed_webhook))
        .route("/v1/keys", get(list_keys).post(authorize_key))
        .route("/v1/keys/{fingerprint}", delete(revoke_key))
        .route("/v1/openapi.json", get(openapi_json))
        .merge(Scalar::with_url("/docs", openapi))
        .with_state(state)
}

#[utoipa::path(get, path = "/v1/status", responses((status = 200, body = StatusResponse)))]
async fn status(State(admin): State<AdminState>) -> Json<StatusResponse> {
    let (sessions, _) = admin.state.totals();
    let addresses = admin.state.listener_addresses();
    Json(StatusResponse {
        uptime_seconds: (jiff::Timestamp::now().as_second() - admin.state.started_at.as_second())
            .max(0),
        sessions,
        binds: admin.state.registry.len(),
        streams: admin.state.active_streams(),
        quic_addr: addresses.map(|value| value.quic.to_string()),
        https_addr: addresses.map(|value| value.https.to_string()),
        http_addr: addresses.map(|value| value.http.to_string()),
        certificate_expiries: admin
            .certificates
            .expiries()
            .into_iter()
            .map(|(domain, expires_unix)| CertificateExpiry { domain, expires_unix })
            .collect(),
        certificate_error: admin.certificates.last_renewal_error(),
    })
}

#[utoipa::path(get, path = "/v1/binds", responses((status = 200, body = [BindResponse])))]
async fn list_binds(State(admin): State<AdminState>) -> Json<Vec<BindResponse>> {
    let binds = admin
        .state
        .registry
        .routes()
        .into_iter()
        .map(|(key, handle)| BindResponse {
            id: handle.bind_id,
            endpoint: endpoint_name(&key),
            state: state_name(handle.state()).to_owned(),
            persistent: matches!(handle.persist, wormhole_proto::frames::Persistence::Persistent),
            key_fingerprint: handle.key_fpr.clone(),
            authentication: handle.auth.is_some() || handle.auth_verifier().is_some(),
            buffering: handle.buffer_policy.is_some(),
        })
        .collect();
    Json(binds)
}

#[utoipa::path(delete, path = "/v1/binds/{id}", params(("id" = Uuid, Path)), responses((status = 204), (status = 404)))]
async fn delete_bind(
    State(admin): State<AdminState>,
    AxumPath(id): AxumPath<Uuid>,
) -> Result<StatusCode, AdminResponseError> {
    let handle = admin
        .state
        .registry
        .routes()
        .into_iter()
        .find_map(|(_, handle)| (handle.bind_id == id).then_some(handle))
        .ok_or_else(|| not_found("bind not found"))?;
    let session_notified = if let Some(session) = handle.session() {
        session.send(SessionCommand::RemoveBind { bind: id }).await.is_ok()
    } else {
        false
    };
    admin.state.registry.remove(id, true).map_err(internal)?;
    admin.state.database.delete_bind_data(id).map_err(internal)?;
    if !session_notified {
        admin.state.remove_bind(&handle.key_fpr);
    }
    if let PersistedEndpoint::TcpPort(port) = handle.endpoint {
        admin.state.tcp_edges.remove_listener(port);
    }
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(get, path = "/v1/webhooks/failed", responses((status = 200, body = [FailedWebhookResponse])))]
async fn list_failed_webhooks(
    State(admin): State<AdminState>,
) -> Result<Json<Vec<FailedWebhookResponse>>, AdminResponseError> {
    let rows = admin
        .state
        .database
        .list_failed()
        .map_err(internal)?
        .into_iter()
        .map(|(bind, seq, failed)| FailedWebhookResponse {
            bind,
            seq,
            reason: failed.reason,
            failed_at: failed.failed_at.to_string(),
        })
        .collect();
    Ok(Json(rows))
}

#[utoipa::path(post, path = "/v1/webhooks/failed/{bind}/{seq}/retry", params(("bind" = Uuid, Path), ("seq" = u64, Path)), responses((status = 204), (status = 404)))]
async fn retry_failed_webhook(
    State(admin): State<AdminState>,
    AxumPath((bind, seq)): AxumPath<(Uuid, u64)>,
) -> Result<StatusCode, AdminResponseError> {
    if !admin.state.database.retry_failed(bind, seq).map_err(internal)? {
        return Err(not_found("failed webhook not found"));
    }
    notify_buffer_status(&admin.state, bind).await?;
    if let Some(handle) = admin.state.registry.get_bind(bind) {
        crate::buffer::spawn_drain(Arc::clone(&admin.state), handle);
    }
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(delete, path = "/v1/webhooks/failed/{bind}/{seq}", params(("bind" = Uuid, Path), ("seq" = u64, Path)), responses((status = 204), (status = 404)))]
async fn delete_failed_webhook(
    State(admin): State<AdminState>,
    AxumPath((bind, seq)): AxumPath<(Uuid, u64)>,
) -> Result<StatusCode, AdminResponseError> {
    if !admin.state.database.delete_failed(bind, seq).map_err(internal)? {
        return Err(not_found("failed webhook not found"));
    }
    notify_buffer_status(&admin.state, bind).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(get, path = "/v1/keys", responses((status = 200, body = [KeyResponse])))]
async fn list_keys(
    State(admin): State<AdminState>,
) -> Result<Json<Vec<KeyResponse>>, AdminResponseError> {
    let keys = admin
        .state
        .auth
        .list()
        .map_err(internal)?
        .into_iter()
        .map(|(fingerprint, key)| KeyResponse {
            fingerprint,
            name: key.name,
            created: key.created.to_string(),
            revoked: key.revoked,
        })
        .collect();
    Ok(Json(keys))
}

#[utoipa::path(post, path = "/v1/keys", request_body = AuthorizeKeyRequest, responses((status = 201, body = KeyFingerprint)))]
async fn authorize_key(
    State(admin): State<AdminState>,
    Json(request): Json<AuthorizeKeyRequest>,
) -> Result<(StatusCode, Json<KeyFingerprint>), AdminResponseError> {
    let fingerprint =
        admin.state.auth.authorize(&request.public_key, &request.name).map_err(bad_request)?;
    Ok((StatusCode::CREATED, Json(KeyFingerprint { fingerprint })))
}

#[utoipa::path(delete, path = "/v1/keys/{fingerprint}", params(("fingerprint" = String, Path)), responses((status = 204), (status = 400)))]
async fn revoke_key(
    State(admin): State<AdminState>,
    AxumPath(fingerprint): AxumPath<String>,
) -> Result<StatusCode, AdminResponseError> {
    admin.state.auth.revoke(&fingerprint).map_err(bad_request)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn notify_buffer_status(state: &Arc<AppState>, bind: Uuid) -> Result<(), AdminResponseError> {
    let Some(handle) = state.registry.get_bind(bind) else {
        return Ok(());
    };
    let Some(session) = handle.session() else {
        return Ok(());
    };
    let (pending, failed) = state.database.buffered_counts(bind).map_err(internal)?;
    session
        .send(SessionCommand::BufferedStatus { bind, pending, failed })
        .await
        .map_err(|_| internal("owning session closed"))
}

async fn openapi_json() -> Json<utoipa::openapi::OpenApi> {
    Json(AdminApi::openapi())
}

fn endpoint_name(key: &HostKey) -> String {
    match key {
        HostKey::Hostname(host) => host.clone(),
        HostKey::TcpPort(port) => format!("tcp:{port}"),
    }
}

const fn state_name(state: BindState) -> &'static str {
    match state {
        BindState::Pending => "pending",
        BindState::Online => "online",
        BindState::Offline => "offline",
    }
}

fn open_lock(path: &Path) -> Result<File, AdminError> {
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)?)
}

fn remove_stale_socket(path: &Path) -> Result<(), AdminError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            fs::remove_file(path).map_err(Into::into)
        }
        Ok(_) => Err(AdminError::UnsafeSocket(path.to_path_buf())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

struct SocketCleanup(PathBuf);

impl Drop for SocketCleanup {
    fn drop(&mut self) {
        let _removed = fs::remove_file(&self.0);
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct StatusResponse {
    pub uptime_seconds: i64,
    pub sessions: u32,
    pub binds: usize,
    pub streams: u64,
    pub quic_addr: Option<String>,
    pub https_addr: Option<String>,
    pub http_addr: Option<String>,
    pub certificate_expiries: Vec<CertificateExpiry>,
    pub certificate_error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CertificateExpiry {
    pub domain: String,
    pub expires_unix: i64,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct BindResponse {
    pub id: Uuid,
    pub endpoint: String,
    pub state: String,
    pub persistent: bool,
    pub key_fingerprint: String,
    pub authentication: bool,
    pub buffering: bool,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct FailedWebhookResponse {
    pub bind: Uuid,
    pub seq: u64,
    pub reason: String,
    pub failed_at: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct KeyResponse {
    pub fingerprint: String,
    pub name: String,
    pub created: String,
    pub revoked: bool,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AuthorizeKeyRequest {
    pub public_key: String,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct KeyFingerprint {
    pub fingerprint: String,
}

#[derive(Debug, Serialize, ToSchema)]
struct ErrorResponse {
    error: String,
}

type AdminResponseError = (StatusCode, Json<ErrorResponse>);

fn internal(error: impl std::fmt::Display) -> AdminResponseError {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: error.to_string() }))
}

fn bad_request(error: impl std::fmt::Display) -> AdminResponseError {
    (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: error.to_string() }))
}

fn not_found(message: &str) -> AdminResponseError {
    (StatusCode::NOT_FOUND, Json(ErrorResponse { error: message.to_owned() }))
}

#[derive(OpenApi)]
#[openapi(
    paths(
        status, list_binds, delete_bind, list_failed_webhooks, retry_failed_webhook,
        delete_failed_webhook, list_keys, authorize_key, revoke_key
    ),
    components(schemas(
        StatusResponse, CertificateExpiry, BindResponse, FailedWebhookResponse, KeyResponse,
        AuthorizeKeyRequest, KeyFingerprint, ErrorResponse
    )),
    tags((name = "admin", description = "Local relay administration"))
)]
pub struct AdminApi;

/// Admin socket setup or serving failure.
#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("another wormholed process holds the administration lock")]
    AlreadyRunning,
    #[error("refusing to replace non-socket admin path: {0}")]
    UnsafeSocket(PathBuf),
}

#[cfg(test)]
#[path = "admin_tests.rs"]
mod tests;
