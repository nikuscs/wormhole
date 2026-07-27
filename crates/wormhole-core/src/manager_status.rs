//! Endpoint status mutation helpers.

use std::collections::HashMap;

use parking_lot::RwLock;
use uuid::Uuid;

use crate::{driver::DriverEvent, model::ActiveEndpoint};

pub fn apply_ready_urls(
    endpoints: &RwLock<HashMap<Uuid, ActiveEndpoint>>,
    id: Uuid,
    event: &DriverEvent,
) {
    if let DriverEvent::Ready { urls, .. } = event
        && let Some(endpoint) = endpoints.write().get_mut(&id)
    {
        endpoint.urls.clone_from(urls);
    }
}
