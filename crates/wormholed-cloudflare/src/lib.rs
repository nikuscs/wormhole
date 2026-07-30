#![forbid(unsafe_code)]

use std::{cell::RefCell, rc::Rc};

use worker::{
    DurableObject, Env, Method, Request, Response, Result, State, WebSocket,
    WebSocketIncomingMessage, durable_object, event,
};

mod admin;
mod api;
mod edge_auth;
mod session;
mod storage;
mod websocket_wire;
mod wire;

const OBJECT_NAME: &str = "relay";
const OBJECT_BINDING: &str = "RELAY";

#[derive(Debug, PartialEq, Eq)]
enum DirectRoute {
    Health,
    NotFound,
    DurableObject,
}

#[event(fetch)]
pub async fn main(request: Request, env: Env, _context: worker::Context) -> Result<Response> {
    route_to_object(request, &env)
        .await
        .or_else(|_| api::error(500, "internal_error", "relay request failed"))
}

async fn route_to_object(request: Request, env: &Env) -> Result<Response> {
    let public_domain = configured_domain(env, "RELAY_DOMAIN")?;
    let control_domain = configured_domain(env, "CONTROL_DOMAIN")?;
    let hostname = request
        .url()?
        .host_str()
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| worker::Error::RustError("request hostname missing".to_owned()))?;
    if !valid_hostname(&hostname, &control_domain, &public_domain) {
        return api::error(421, "unknown_domain", "request hostname is outside this relay domain");
    }
    match direct_route(&hostname, &control_domain, &request.path(), request.method() == Method::Get)
    {
        DirectRoute::Health => return Response::ok("ok"),
        DirectRoute::NotFound => {
            return api::error(404, "not_found", "relay control endpoint not found");
        }
        DirectRoute::DurableObject => {}
    }
    let namespace = env.durable_object(OBJECT_BINDING)?;
    namespace.get_by_name(OBJECT_NAME)?.fetch_with_request(request).await
}

fn valid_hostname(hostname: &str, control_domain: &str, public_domain: &str) -> bool {
    hostname == control_domain || hostname.ends_with(&format!(".{public_domain}"))
}

fn configured_domain(env: &Env, name: &str) -> Result<String> {
    Ok(env.var(name)?.to_string().trim_end_matches('.').to_ascii_lowercase())
}

fn direct_route(hostname: &str, control_domain: &str, path: &str, is_get: bool) -> DirectRoute {
    if hostname != control_domain {
        return DirectRoute::DurableObject;
    }
    if path == "/health" && is_get {
        return DirectRoute::Health;
    }
    if path == "/_wormhole/ws" || path.starts_with("/_wormhole/admin/") {
        DirectRoute::DurableObject
    } else {
        DirectRoute::NotFound
    }
}

#[durable_object]
pub struct RelayDurableObject {
    state: State,
    env: Env,
    runtime: Rc<RefCell<session::Runtime>>,
}

impl DurableObject for RelayDurableObject {
    fn new(state: State, env: Env) -> Self {
        storage::initialize(&state.storage().sql())
            .unwrap_or_else(|error| panic!("relay schema initialization failed: {error}"));
        Self { state, env, runtime: Rc::new(RefCell::new(session::Runtime::default())) }
    }

    async fn fetch(&self, request: Request) -> Result<Response> {
        let control_domain = configured_domain(&self.env, "CONTROL_DOMAIN")?;
        let hostname = request
            .url()?
            .host_str()
            .map(str::to_ascii_lowercase)
            .ok_or_else(|| worker::Error::RustError("request hostname missing".to_owned()))?;
        let path = request.path();
        if hostname == control_domain && path == "/_wormhole/ws" {
            if request.method() != Method::Get
                || !request
                    .headers()
                    .get("upgrade")?
                    .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
            {
                return api::error(426, "websocket_required", "Upgrade: websocket is required");
            }
            return session::accept(&self.state);
        }
        if hostname == control_domain && path.starts_with("/_wormhole/admin/") {
            return admin::handle(request, &self.env, &self.state.storage().sql()).await;
        }
        session::forward_http(
            &self.state,
            &self.env,
            &self.runtime,
            &self.state.storage().sql(),
            request,
            &hostname,
        )
        .await
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        match message {
            WebSocketIncomingMessage::Binary(bytes) => {
                session::message(&self.state, &self.env, &self.runtime, ws, bytes)
            }
            WebSocketIncomingMessage::String(_) => {
                ws.close(Some(1003), Some("binary messages required"))
            }
        }
    }

    async fn websocket_close(
        &self,
        ws: WebSocket,
        _code: usize,
        _reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        session::closed(&self.state, &self.runtime, &ws)
    }

    async fn websocket_error(&self, ws: WebSocket, _error: worker::Error) -> Result<()> {
        session::closed(&self.state, &self.runtime, &ws)
    }
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
