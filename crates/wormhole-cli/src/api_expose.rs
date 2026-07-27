//! Shared daemon exposure helpers.

use std::{sync::Arc, time::Duration};

use uuid::Uuid;
use wormhole_core::{ActiveEndpoint, EndpointSpec, TunnelManager, model::EndpointStatus};

use crate::{
    api_types::{ApiError, ApiState},
    state_db::DesiredService,
};

pub fn restore_reservations(endpoints: &mut [EndpointSpec], cached: &[EndpointSpec]) -> bool {
    let mut cached = cached
        .iter()
        .filter(|endpoint| endpoint.reservation.is_some())
        .cloned()
        .collect::<Vec<_>>();
    for endpoint in endpoints {
        let mut comparable = endpoint.clone();
        comparable.reservation = None;
        if let Some(index) = cached.iter().position(|candidate| {
            let mut candidate = candidate.clone();
            candidate.reservation = None;
            candidate == comparable
        }) {
            endpoint.reservation = cached.remove(index).reservation;
        }
    }
    cached.is_empty()
}

pub async fn expose_desired(
    state: &ApiState,
    desired: &DesiredService,
) -> Result<Vec<Uuid>, wormhole_core::ManagerError> {
    let expose_guard = state.expose_lock.lock().await;
    if let Some(remotes) = desired.remotes.clone() {
        state.manager.registry().register(Arc::new(
            wormhole_core::wormhole_driver::WormholeDriver::new(
                remotes,
                desired.default_remote.clone(),
                Arc::clone(&state.identities),
            ),
        ));
    }
    let result = state.manager.expose(desired.service.clone(), desired.endpoints.clone()).await;
    if desired.remotes.is_some() {
        let config = state.config.read().await;
        state.manager.registry().register(Arc::new(
            wormhole_core::wormhole_driver::WormholeDriver::new(
                config.remotes.clone(),
                config.default_remote.clone(),
                Arc::clone(&state.identities),
            ),
        ));
    }
    drop(expose_guard);
    result
}

pub async fn prepare_forget_bindings(
    state: &ApiState,
    key: &str,
    desired: &mut Option<DesiredService>,
    mut bindings: Vec<(Uuid, usize)>,
) -> Result<Vec<(Uuid, usize)>, ApiError> {
    if let Some(cached) = desired.as_mut()
        && !cached.disabled_endpoints.is_empty()
    {
        cached.endpoints.append(&mut cached.disabled_endpoints);
        let _persistence = state.persistence_lock.lock().await;
        state.database.put(cached).map_err(|error| ApiError::internal(error.to_string()))?;
        state.desired.write().await.insert(key.to_owned(), cached.clone());
    }
    let Some(cached) = desired else {
        return Ok(bindings);
    };
    let missing = cached
        .endpoints
        .iter()
        .enumerate()
        .filter(|(index, _)| !bindings.iter().any(|(_, bound)| bound == index))
        .map(|(index, spec)| (index, spec.clone()))
        .collect::<Vec<_>>();
    if missing.is_empty() {
        return Ok(bindings);
    }
    let mut retry = cached.clone();
    retry.endpoints = missing.iter().map(|(_, spec)| spec.clone()).collect();
    let restarted = expose_desired(state, &retry)
        .await
        .map_err(|error| ApiError::unavailable(error.to_string()))?;
    for ((index, _), id) in missing.into_iter().zip(restarted) {
        bindings.push((id, index));
        state.bindings.write().await.insert(id, (key.to_owned(), index));
    }
    let ids = bindings.iter().map(|(id, _)| *id).collect::<Vec<_>>();
    let _ready = wait_ready(&state.manager, &ids).await;
    Ok(bindings)
}

pub async fn wait_ready(manager: &TunnelManager, ids: &[Uuid]) -> Vec<ActiveEndpoint> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let endpoints = manager
            .list()
            .into_iter()
            .filter(|endpoint| ids.contains(&endpoint.id))
            .collect::<Vec<_>>();
        if endpoints.len() == ids.len()
            && endpoints.iter().all(|endpoint| {
                matches!(endpoint.status, EndpointStatus::Online | EndpointStatus::Error(_))
            })
        {
            return endpoints;
        }
        if tokio::time::Instant::now() >= deadline {
            return endpoints;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
