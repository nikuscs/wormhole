use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use wormhole_core::enroll_remote;

use crate::{
    api_types::{ApiError, ApiState, RemoteAddRequest, RemoteView},
    remote_onboarding::{apply_add, apply_remove, prepare, views},
    utility_commands::save,
};

#[utoipa::path(
    get,
    path = "/v1/remotes",
    tag = "Remotes",
    summary = "List configured relays",
    responses((status = 200, body = [RemoteView]), (status = 401, body = crate::api_types::ApiErrorBody))
)]
pub async fn list(State(state): State<ApiState>) -> Json<Vec<RemoteView>> {
    let config = state.config.read().await;
    Json(views(&config))
}

#[utoipa::path(
    post,
    path = "/v1/remotes",
    tag = "Remotes",
    summary = "Add or enroll a relay",
    request_body = RemoteAddRequest,
    responses(
        (status = 201, body = RemoteView),
        (status = 400, body = crate::api_types::ApiErrorBody),
        (status = 502, body = crate::api_types::ApiErrorBody)
    )
)]
pub async fn add(
    State(state): State<ApiState>,
    Json(request): Json<RemoteAddRequest>,
) -> Result<(StatusCode, Json<RemoteView>), ApiError> {
    let prepared = prepare(request).map_err(ApiError::invalid)?;
    let _mutation = state.mutation_lock.lock().await;
    if let Some(invite) = prepared.invite.as_deref() {
        let identity = state.identities.resolve_identity(&prepared.remote).map_err(invalid)?;
        enroll_remote(&prepared.remote, &identity, invite)
            .await
            .map_err(|error| ApiError::unavailable(error.to_string()))?;
    }
    let response = RemoteView::from_remote(prepared.name.clone(), &prepared.remote);
    let mut config = state.config.read().await.clone();
    apply_add(&mut config, prepared.name, prepared.remote);
    persist_and_apply(&state, config).await?;
    Ok((StatusCode::CREATED, Json(response)))
}

#[utoipa::path(
    delete,
    path = "/v1/remotes/{name}",
    tag = "Remotes",
    summary = "Remove a configured relay",
    params(("name" = String, Path)),
    responses(
        (status = 200, body = crate::api_types::ClosedResponse),
        (status = 404, body = crate::api_types::ApiErrorBody)
    )
)]
pub async fn remove(
    State(state): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<crate::api_types::ClosedResponse>, ApiError> {
    let _mutation = state.mutation_lock.lock().await;
    let mut config = state.config.read().await.clone();
    apply_remove(&mut config, &name).map_err(ApiError::not_found)?;
    persist_and_apply(&state, config).await?;
    Ok(Json(crate::api_types::ClosedResponse { closed: true }))
}

async fn persist_and_apply(
    state: &ApiState,
    config: wormhole_core::ClientConfig,
) -> Result<(), ApiError> {
    save(state.config_path.as_ref(), &config)
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let registry = wormhole_core::drivers::build_registry(&config, state.identities.clone());
    for driver in registry.all().into_iter().filter(|driver| driver.name() == "wormhole") {
        state.manager.registry().register(driver);
    }
    state.manager.reload_config(config.clone());
    *state.config.write().await = config;
    Ok(())
}

fn invalid(error: impl std::fmt::Display) -> ApiError {
    ApiError::invalid(error.to_string())
}
