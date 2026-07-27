//! Token-authenticated local HTTP API handlers.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use crate::{
    api_expose::{expose_desired, prepare_forget_bindings, restore_reservations, wait_ready},
    state_db::DesiredService,
};
use axum::{
    Json, Router,
    extract::{Path, Query, Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use serde::Deserialize;
use subtle::ConstantTimeEq as _;
use utoipa::{Modify, OpenApi};
use utoipa_scalar::{Scalar, Servable as _};
use uuid::Uuid;
use wormhole_core::{
    ActiveEndpoint,
    doctor::doctor_with,
    ifaces::{IfaceAlias, IfaceResolver},
    model::{DoctorCheck, EndpointStatus},
};

pub use crate::api_types::{
    ApiError, ApiErrorBody, ApiErrorDetail, ApiState, ClosedResponse, CreateServiceRequest,
    ServiceView, StatusResponse,
};

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        use utoipa::openapi::security::{
            Http, HttpAuthScheme, SecurityRequirement, SecurityScheme,
        };
        openapi.components.get_or_insert_default().add_security_scheme(
            "bearer_auth",
            SecurityScheme::Http(Http::new(HttpAuthScheme::Bearer)),
        );
        openapi.security =
            Some(vec![SecurityRequirement::new("bearer_auth", Vec::<String>::new())]);
    }
}

#[derive(OpenApi)]
#[openapi(modifiers(&SecurityAddon), paths(
    crate::api_status::status,
    services,
    create_service,
    delete_service,
    endpoints,
    delete_endpoint,
    interfaces,
    doctor,
    shutdown,
    reload,
    openapi_json,
    crate::future_api::requests,
    crate::future_api::request,
    crate::future_api::replay,
    crate::future_api::clear_requests
))]
pub struct LocalApi;

pub fn router(state: ApiState) -> Router {
    let openapi = LocalApi::openapi();
    Router::new()
        .route("/v1/status", get(crate::api_status::status))
        .route("/v1/services", get(services).post(create_service))
        .route("/v1/services/{name}", delete(delete_service))
        .route("/v1/endpoints", get(endpoints))
        .route("/v1/endpoints/{id}", delete(delete_endpoint))
        .route("/v1/interfaces", get(interfaces))
        .route("/v1/doctor", get(doctor))
        .route(
            "/v1/requests",
            get(crate::future_api::requests).delete(crate::future_api::clear_requests),
        )
        .route("/v1/requests/{id}", get(crate::future_api::request))
        .route("/v1/requests/{id}/replay", post(crate::future_api::replay))
        .route("/v1/shutdown", post(shutdown))
        .route("/v1/reload", post(reload))
        .route("/v1/openapi.json", get(openapi_json))
        .merge(Scalar::with_url("/docs", openapi))
        .layer(middleware::from_fn_with_state(state.clone(), authorize))
        .with_state(state)
}

async fn authorize(State(state): State<ApiState>, request: Request, next: Next) -> Response {
    let supplied = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let accepted = supplied.is_some_and(|value| {
        value.len() == state.token.len() && value.as_bytes().ct_eq(state.token.as_bytes()).into()
    });
    if accepted {
        next.run(request).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(ApiErrorBody {
                error: ApiErrorDetail {
                    code: "unauthorized".to_owned(),
                    message: "missing or invalid bearer token".to_owned(),
                },
            }),
        )
            .into_response()
    }
}

#[utoipa::path(
    get,
    path = "/v1/services",
    params(("watch" = Option<bool>, Query, description = "Wait for the next status change")),
    responses((status = 200, body = [ServiceView]), (status = 401, body = ApiErrorBody))
)]
async fn services(
    State(state): State<ApiState>,
    Query(query): Query<ServiceQuery>,
) -> Json<Vec<ServiceView>> {
    if query.watch {
        let mut changes = state.manager.subscribe();
        let _change = tokio::time::timeout(Duration::from_secs(30), changes.recv()).await;
    }
    let desired = state.desired.read().await;
    let bindings = state.bindings.read().await;
    let active = state.manager.list();
    Json(
        desired
            .iter()
            .filter(|(_, desired)| desired.active)
            .map(|(key, desired)| {
                let ids = bindings
                    .iter()
                    .filter_map(|(id, (binding_key, _))| (binding_key == key).then_some(*id))
                    .collect::<Vec<_>>();
                ServiceView {
                    project_id: desired.project_id.clone(),
                    service: desired.service.clone(),
                    endpoints: active
                        .iter()
                        .filter(|endpoint| ids.contains(&endpoint.id))
                        .cloned()
                        .collect(),
                }
            })
            .collect(),
    )
}

#[derive(Debug, Default, Deserialize)]
struct ServiceQuery {
    #[serde(default)]
    watch: bool,
}

#[utoipa::path(
    post,
    path = "/v1/services",
    request_body = CreateServiceRequest,
    responses(
        (status = 201, body = [ActiveEndpoint]),
        (status = 207, body = [ActiveEndpoint]),
        (status = 409, body = ApiErrorBody),
        (status = 502, body = ApiErrorBody)
    )
)]
async fn create_service(
    State(state): State<ApiState>,
    Json(request): Json<CreateServiceRequest>,
) -> Result<(StatusCode, Json<Vec<ActiveEndpoint>>), ApiError> {
    let project_id = request.project_id.unwrap_or_default();
    let desired_key = format!("{project_id}:{}", request.service.name);
    let previous = state.desired.read().await.get(&desired_key).cloned();
    if previous.as_ref().is_some_and(|desired| desired.active) {
        return Err(ApiError::conflict(format!(
            "service already exists: {}",
            request.service.name
        )));
    }
    let request_remotes = request.remotes;
    let request_default_remote = request.default_remote;
    let mut endpoints = request.endpoints;
    if let Some(cached) = &previous {
        let mut cached_endpoints = cached.endpoints.clone();
        cached_endpoints.extend(cached.disabled_endpoints.clone());
        let has_reservations =
            cached_endpoints.iter().any(|endpoint| endpoint.reservation.is_some());
        let same_remote =
            cached.remotes == request_remotes && cached.default_remote == request_default_remote;
        if !restore_reservations(&mut endpoints, &cached_endpoints)
            || (has_reservations && !same_remote)
        {
            return Err(ApiError::conflict(
                "stopped service configuration changed; run down --forget first",
            ));
        }
    }
    let desired = DesiredService {
        active: true,
        project_id,
        remotes: request_remotes.clone(),
        default_remote: request_default_remote.clone(),
        service: request.service,
        endpoints,
        disabled_endpoints: Vec::new(),
    };
    {
        let _persistence = state.persistence_lock.lock().await;
        state.database.put(&desired).map_err(|error| ApiError::internal(error.to_string()))?;
        state.desired.write().await.insert(desired_key.clone(), desired.clone());
    }
    let ids = match expose_desired(&state, &desired).await {
        Ok(ids) => ids,
        Err(error) => {
            let _persistence = state.persistence_lock.lock().await;
            if let Some(previous) = previous {
                state.database.put(&previous).map_err(|rollback| {
                    ApiError::internal(format!("{error}; rollback failed: {rollback}"))
                })?;
                state.desired.write().await.insert(desired_key.clone(), previous);
            } else {
                state.database.delete(&desired_key).map_err(|rollback| {
                    ApiError::internal(format!("{error}; rollback failed: {rollback}"))
                })?;
                state.desired.write().await.remove(&desired_key);
            }
            return Err(ApiError::unavailable(error.to_string()));
        }
    };
    for (index, id) in ids.iter().copied().enumerate() {
        state.bindings.write().await.insert(id, (desired_key.clone(), index));
    }
    let endpoints = wait_ready(&state.manager, &ids).await;
    let status = if endpoints.iter().all(|endpoint| endpoint.status == EndpointStatus::Online) {
        StatusCode::CREATED
    } else {
        StatusCode::MULTI_STATUS
    };
    Ok((status, Json(endpoints)))
}

#[derive(Debug, Deserialize)]
struct DeleteQuery {
    #[serde(default)]
    forget: u8,
    #[serde(default)]
    project_id: String,
}

#[utoipa::path(
    delete,
    path = "/v1/services/{name}",
    params(
        ("name" = String, Path),
        ("forget" = Option<u8>, Query),
        ("project_id" = Option<String>, Query)
    ),
    responses((status = 200, body = ClosedResponse), (status = 502, body = ApiErrorBody))
)]
async fn delete_service(
    State(state): State<ApiState>,
    Path(name): Path<String>,
    Query(query): Query<DeleteQuery>,
) -> Result<Json<ClosedResponse>, ApiError> {
    let key = format!("{}:{name}", query.project_id);
    let mut desired = state.desired.read().await.get(&key).cloned();
    let mut bindings = state
        .bindings
        .read()
        .await
        .iter()
        .filter_map(|(id, (binding_key, index))| (binding_key == &key).then_some((*id, *index)))
        .collect::<Vec<_>>();
    if query.forget != 0 {
        bindings = prepare_forget_bindings(&state, &key, &mut desired, bindings).await?;
    }
    let mut failures = Vec::new();
    for (id, index) in &bindings {
        if let Err(error) = state.manager.close_with_forget(*id, query.forget != 0).await {
            failures.push((*index, error));
        }
    }
    if let (Some((_, error)), Some(mut desired)) = (failures.first(), desired.clone()) {
        if query.forget != 0 {
            desired.endpoints = failures
                .iter()
                .filter_map(|(index, _)| desired.endpoints.get(*index).cloned())
                .collect();
        }
        {
            let _persistence = state.persistence_lock.lock().await;
            state
                .database
                .put(&desired)
                .map_err(|failure| ApiError::internal(failure.to_string()))?;
            state.desired.write().await.insert(key.clone(), desired.clone());
        }
        state.bindings.write().await.retain(|_, (binding_key, _)| binding_key != &key);
        if let Ok(restarted) = expose_desired(&state, &desired).await {
            for (index, id) in restarted.into_iter().enumerate() {
                state.bindings.write().await.insert(id, (key.clone(), index));
            }
        }
        return Err(ApiError::unavailable(error.to_string()));
    }
    let _persistence = state.persistence_lock.lock().await;
    state.bindings.write().await.retain(|_, (binding_key, _)| binding_key != &key);
    if query.forget == 0
        && let Some(mut desired) = desired
    {
        desired.active = false;
        state.database.put(&desired).map_err(|error| ApiError::internal(error.to_string()))?;
        state.desired.write().await.insert(key, desired);
        return Ok(Json(ClosedResponse { closed: true }));
    }
    state.database.delete(&key).map_err(|error| ApiError::internal(error.to_string()))?;
    let removed = state.desired.write().await.remove(&key).is_some();
    Ok(Json(ClosedResponse { closed: removed }))
}

#[utoipa::path(
    get,
    path = "/v1/endpoints",
    params(("service" = Option<String>, Query)),
    responses((status = 200, body = [ActiveEndpoint]))
)]
async fn endpoints(
    State(state): State<ApiState>,
    Query(query): Query<BTreeMap<String, String>>,
) -> Json<Vec<ActiveEndpoint>> {
    let service = query.get("service");
    Json(
        state
            .manager
            .list()
            .into_iter()
            .filter(|endpoint| service.is_none_or(|name| &endpoint.service == name))
            .collect(),
    )
}

#[utoipa::path(
    delete,
    path = "/v1/endpoints/{id}",
    params(("id" = Uuid, Path), ("forget" = Option<u8>, Query)),
    responses((status = 200, body = ClosedResponse), (status = 502, body = ApiErrorBody))
)]
async fn delete_endpoint(
    State(state): State<ApiState>,
    Path(id): Path<Uuid>,
    Query(query): Query<DeleteQuery>,
) -> Result<Json<ClosedResponse>, ApiError> {
    let binding = state.bindings.read().await.get(&id).cloned();
    if let Err(error) = state.manager.close_with_forget(id, query.forget != 0).await {
        if let Some((key, index)) = binding
            && let Some(desired) = state.desired.read().await.get(&key).cloned()
            && let Some(spec) = desired.endpoints.get(index).cloned()
        {
            let mut retry = desired;
            retry.endpoints = vec![spec];
            if let Ok(mut restarted) = expose_desired(&state, &retry).await
                && let Some(restarted) = restarted.pop()
            {
                state.bindings.write().await.remove(&id);
                state.bindings.write().await.insert(restarted, (key, index));
            }
        }
        return Err(ApiError::unavailable(error.to_string()));
    }
    remove_desired_endpoint(&state, id, query.forget != 0).await?;
    Ok(Json(ClosedResponse { closed: true }))
}

async fn remove_desired_endpoint(state: &ApiState, id: Uuid, forget: bool) -> Result<(), ApiError> {
    let _persistence = state.persistence_lock.lock().await;
    let Some((name, index)) = state.bindings.read().await.get(&id).cloned() else {
        return Ok(());
    };
    let Some(mut updated) = state.desired.read().await.get(&name).cloned() else {
        return Ok(());
    };
    if index >= updated.endpoints.len() {
        return Ok(());
    }
    let removed = updated.endpoints.remove(index);
    if !forget && removed.reservation.is_some() {
        updated.disabled_endpoints.push(removed);
    }
    if updated.endpoints.is_empty() {
        updated.active = false;
    }
    if updated.endpoints.is_empty() && updated.disabled_endpoints.is_empty() {
        state.database.delete(&name).map_err(|error| ApiError::internal(error.to_string()))?;
        state.desired.write().await.remove(&name);
    } else {
        state.database.put(&updated).map_err(|error| ApiError::internal(error.to_string()))?;
        state.desired.write().await.insert(name.clone(), updated);
    }
    let mut bindings = state.bindings.write().await;
    bindings.remove(&id);
    for (binding_name, binding_index) in bindings.values_mut() {
        if binding_name == &name && *binding_index > index {
            *binding_index -= 1;
        }
    }
    drop(bindings);
    Ok(())
}

#[utoipa::path(get, path = "/v1/interfaces", responses((status = 200, body = [IfaceAlias])))]
async fn interfaces(State(state): State<ApiState>) -> Json<Vec<IfaceAlias>> {
    Json(IfaceResolver::new(state.config.read().await.aliases.clone()).discover())
}

#[utoipa::path(get, path = "/v1/doctor", responses((status = 200, body = [DoctorCheck])))]
async fn doctor(State(state): State<ApiState>) -> Json<Vec<DoctorCheck>> {
    let config = state.config.read().await.clone();
    Json(doctor_with(&config, state.manager.registry(), &state.identities).await)
}

#[utoipa::path(post, path = "/v1/shutdown", responses((status = 200, body = ClosedResponse)))]
async fn shutdown(State(state): State<ApiState>) -> Json<ClosedResponse> {
    state.shutdown.cancel();
    Json(ClosedResponse { closed: true })
}

#[utoipa::path(post, path = "/v1/reload", responses((status = 200, body = ClosedResponse)))]
async fn reload(State(state): State<ApiState>) -> Result<Json<ClosedResponse>, ApiError> {
    let _expose = state.expose_lock.lock().await;
    let config = crate::daemon::load_config(state.config_path.as_ref())
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let driver = wormhole_core::wormhole_driver::WormholeDriver::new(
        config.remotes.clone(),
        config.default_remote.clone(),
        Arc::clone(&state.identities),
    );
    state.manager.registry().register(Arc::new(driver));
    state.manager.reload_config(config.clone());
    *state.config.write().await = config;
    Ok(Json(ClosedResponse { closed: true }))
}

#[utoipa::path(get, path = "/v1/openapi.json", responses((status = 200, description = "OpenAPI")))]
async fn openapi_json() -> Json<utoipa::openapi::OpenApi> {
    Json(LocalApi::openapi())
}

#[cfg(test)]
#[path = "local_api_tests.rs"]
mod tests;
