use std::{
    collections::{BTreeMap, HashMap},
    fs,
    sync::Arc,
};

use axum::{
    Json,
    body::Body,
    extract::State,
    http::{Method, Request, StatusCode, header},
    response::IntoResponse,
};
use http_body_util::BodyExt as _;
use tokio::sync::{Mutex, RwLock};
use tokio_util::sync::CancellationToken;
use utoipa::OpenApi as _;
use uuid::Uuid;
use wormhole_core::{
    ClientConfig, EndpointSpec, Service, Target, TunnelManager, driver::DriverRegistry,
    keys_store::IdentityStore, model::ServiceProto,
};
use wormhole_proto::frames::{EdgeAuth, Persistence};

use super::{
    ApiError, ApiState, CreateServiceRequest, LocalApi, create_service, remove_desired_endpoint,
    rollback_failed_create, router,
};
use crate::{capture_store::CaptureStore, mock_driver::MockDriver, state_db::StateDb};

#[test]
fn committed_openapi_is_current() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/local-api.openapi.json");
    let generated = serde_json::to_string_pretty(&LocalApi::openapi()).expect("serialize");
    if std::env::var_os("UPDATE_LOCAL_API_OPENAPI").is_some() {
        fs::write(&path, format!("{generated}\n")).expect("write OpenAPI");
    }
    let committed = fs::read_to_string(path).expect("committed OpenAPI");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&committed).expect("committed JSON"),
        serde_json::from_str::<serde_json::Value>(&generated).expect("generated JSON")
    );
}

#[tokio::test]
async fn remote_routes_add_list_persist_and_remove_without_secret_fields() {
    let state = test_state();
    let config_path = state.config_path.clone().expect("test config path");
    let app = router(state.clone());
    let body = serde_json::json!({
        "name": "edge",
        "addr": "relay.example:443",
        "server_name": null,
        "identity": null,
        "invite": null
    });

    let added = send(&app, Method::POST, "/v1/remotes", Some(body), true).await;
    assert_eq!(added.0, StatusCode::CREATED);
    assert_eq!(added.1["server_name"], "relay.example");
    let listed = send(&app, Method::GET, "/v1/remotes", None, true).await;
    assert_eq!(listed.1.as_array().expect("remote list").len(), 1);
    let persisted = fs::read_to_string(config_path).expect("persisted config");
    assert!(persisted.contains("relay.example:443"));
    assert!(!persisted.contains("invite"));

    let removed = send(&app, Method::DELETE, "/v1/remotes/edge", None, true).await;
    assert_eq!(removed.0, StatusCode::OK);
    assert!(state.config.read().await.remotes.is_empty());
}

#[tokio::test]
async fn internal_api_errors_keep_stable_status_code_and_message() {
    let response = ApiError::internal("database unavailable").into_response();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = response.into_body().collect().await.expect("body").to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).expect("JSON");
    assert_eq!(json["error"]["code"], "internal");
    assert_eq!(json["error"]["message"], "database unavailable");
}

#[tokio::test]
async fn concurrent_same_service_creates_have_one_winner() {
    let state = test_state();
    let (first, second) = tokio::join!(
        create_service(State(state.clone()), Json(request())),
        create_service(State(state.clone()), Json(request()))
    );
    let statuses = [first.map(|value| value.0), second.map(|value| value.0)];
    let successes = statuses.iter().filter(|result| result.is_ok()).count();
    let conflicts = statuses
        .into_iter()
        .filter_map(Result::err)
        .map(IntoResponse::into_response)
        .filter(|response| response.status() == axum::http::StatusCode::CONFLICT)
        .count();

    assert_eq!((successes, conflicts), (1, 1));
    assert_eq!(state.bindings.read().await.len(), 1);
    assert_eq!(state.manager.list().len(), 1);
    state.manager.shutdown().await;
}

#[tokio::test]
async fn documentation_is_public_while_management_port_targets_are_rejected() {
    let app = router(test_state());
    let openapi = send(&app, Method::GET, "/v1/openapi.json", None, false).await;
    assert_eq!(openapi.0, StatusCode::OK);
    assert_eq!(openapi.1["openapi"], "3.1.0");

    let mut reserved = request();
    reserved.service.target = Target::Port(crate::runtime::LOCAL_API_PORT);
    let rejected = send(
        &app,
        Method::POST,
        "/v1/services",
        Some(serde_json::to_value(reserved).expect("request JSON")),
        true,
    )
    .await;
    assert_eq!(rejected.0, StatusCode::BAD_REQUEST);
    assert!(rejected.1["error"]["message"].as_str().expect("message").contains("reserved"));
}

#[tokio::test]
async fn authenticated_routes_create_status_share_stop_restart_and_forget() {
    let state = test_state();
    let app = router(state.clone());

    let unauthorized = send(&app, Method::GET, "/v1/status", None, false).await;
    assert_eq!(unauthorized.0, StatusCode::UNAUTHORIZED);
    assert_eq!(unauthorized.1["error"]["code"], "unauthorized");

    let mut create = request();
    create.endpoints[0].auth = Some(EdgeAuth {
        basic: None,
        bearer: None,
        link_key: Some(wormhole_core::share::generate_link_key()),
    });
    let created = send(
        &app,
        Method::POST,
        "/v1/services",
        Some(serde_json::to_value(&create).expect("create JSON")),
        true,
    )
    .await;
    assert_eq!(created.0, StatusCode::CREATED, "{created:?}");
    let endpoint_id = created.1[0]["id"].as_str().expect("endpoint id");
    assert_eq!(created.1[0]["status"], "online");

    let status = send(&app, Method::GET, "/v1/status", None, true).await;
    assert_eq!(status.0, StatusCode::OK);
    assert_eq!((status.1["services"].as_u64(), status.1["endpoints"].as_u64()), (Some(1), Some(1)));
    let services = send(&app, Method::GET, "/v1/services", None, true).await;
    assert_eq!(services.1[0]["project_id"], "project");
    let endpoints = send(&app, Method::GET, "/v1/endpoints?service=web", None, true).await;
    assert_eq!(endpoints.1.as_array().expect("endpoints").len(), 1);

    let share = send(
        &app,
        Method::POST,
        "/v1/share",
        Some(serde_json::json!({"target": endpoint_id, "expires": "1h", "path": "/hook?source=test"})),
        true,
    )
    .await;
    assert_eq!(share.0, StatusCode::OK, "{share:?}");
    let url = share.1["url"].as_str().expect("share URL");
    assert!(url.starts_with("https://web.mock.invalid/hook?"));
    assert!(url.contains("source=test"));

    let stopped =
        send(&app, Method::DELETE, "/v1/services/web?project_id=project", None, true).await;
    assert_eq!(stopped.0, StatusCode::OK);
    assert_eq!(stopped.1["closed"], true);
    assert!(
        send(&app, Method::GET, "/v1/services", None, true)
            .await
            .1
            .as_array()
            .expect("services")
            .is_empty()
    );

    let restarted = send(
        &app,
        Method::POST,
        "/v1/services",
        Some(serde_json::to_value(&create).expect("create JSON")),
        true,
    )
    .await;
    assert_eq!(restarted.0, StatusCode::CREATED, "{restarted:?}");
    let forgotten =
        send(&app, Method::DELETE, "/v1/services/web?project_id=project&forget=1", None, true)
            .await;
    assert_eq!(forgotten.0, StatusCode::OK, "{forgotten:?}");
    assert!(state.desired.read().await.is_empty());
    assert!(state.database.list().expect("database").is_empty());
    state.manager.shutdown().await;
}

#[tokio::test]
async fn stopped_service_requires_reservation_compatible_restart() {
    let state = test_state();
    let key = crate::state_db::DesiredKey::new("project".to_owned(), "web".to_owned())
        .expect("desired key");
    let mut cached_endpoint = request().endpoints.remove(0);
    cached_endpoint.persist = Persistence::Persistent;
    cached_endpoint.reservation = Some(Uuid::now_v7());
    let cached = crate::state_db::DesiredService {
        active: false,
        project_id: "project".to_owned(),
        remotes: None,
        default_remote: None,
        service: request().service,
        endpoints: vec![cached_endpoint.clone()],
        disabled_endpoints: Vec::new(),
    };
    state.database.put(&cached).expect("persist stopped service");
    state.desired.write().await.insert(key.clone(), cached.clone());

    let mut incompatible = request();
    incompatible.endpoints[0].persist = Persistence::Persistent;
    incompatible.endpoints[0].host = Some("changed".to_owned());
    let conflict = create_service(State(state.clone()), Json(incompatible))
        .await
        .expect_err("changed reservation identity");
    assert_eq!(conflict.into_response().status(), StatusCode::CONFLICT);

    let mut compatible = request();
    compatible.endpoints[0].persist = Persistence::Persistent;
    let restarted = create_service(State(state.clone()), Json(compatible)).await.expect("restart");
    assert_eq!(restarted.0, StatusCode::CREATED);
    assert_eq!(
        state.desired.read().await.get(&key).expect("desired").endpoints[0].reservation,
        cached_endpoint.reservation
    );
    state.manager.shutdown().await;
}

#[tokio::test]
async fn failed_create_rollback_restores_previous_or_removes_new_desired_state() {
    let state = test_state();
    let key = crate::state_db::DesiredKey::new("project".to_owned(), "web".to_owned())
        .expect("desired key");
    let previous = crate::state_db::DesiredService {
        active: false,
        project_id: "project".to_owned(),
        remotes: None,
        default_remote: None,
        service: request().service,
        endpoints: request().endpoints,
        disabled_endpoints: Vec::new(),
    };
    let endpoint = Uuid::now_v7();
    state.bindings.write().await.insert(endpoint, (key.clone(), 0));
    rollback_failed_create(&state, &[endpoint], &key, Some(previous.clone()))
        .await
        .expect("restore previous");
    assert!(!state.desired.read().await.get(&key).expect("previous").active);
    assert!(state.bindings.read().await.is_empty());

    state.desired.write().await.insert(key.clone(), previous.clone());
    state.database.put(&previous).expect("persist temporary desired");
    rollback_failed_create(&state, &[], &key, None).await.expect("remove new desired");
    assert!(state.desired.read().await.get(&key).is_none());
    assert!(state.database.list().expect("database").is_empty());
    state.manager.shutdown().await;
}

#[tokio::test]
async fn desired_endpoint_removal_preserves_reservations_reindexes_and_forgets() {
    let state = test_state();
    let key = crate::state_db::DesiredKey::new("project".to_owned(), "web".to_owned())
        .expect("desired key");
    let first_id = Uuid::now_v7();
    let second_id = Uuid::now_v7();
    let mut first = request().endpoints.remove(0);
    first.persist = Persistence::Persistent;
    first.reservation = Some(Uuid::now_v7());
    let mut second = first.clone();
    second.host = Some("second".to_owned());
    second.reservation = Some(Uuid::now_v7());
    let desired = crate::state_db::DesiredService {
        active: true,
        project_id: "project".to_owned(),
        remotes: None,
        default_remote: None,
        service: request().service,
        endpoints: vec![first, second],
        disabled_endpoints: Vec::new(),
    };
    state.database.put(&desired).expect("persist desired");
    state.desired.write().await.insert(key.clone(), desired);
    state
        .bindings
        .write()
        .await
        .extend([(first_id, (key.clone(), 0)), (second_id, (key.clone(), 1))]);

    remove_desired_endpoint(&state, Uuid::now_v7(), false).await.expect("missing binding");
    remove_desired_endpoint(&state, first_id, false).await.expect("disable first");
    let stopped = state.desired.read().await.get(&key).cloned().expect("desired state");
    assert_eq!(stopped.endpoints.len(), 1);
    assert_eq!(stopped.disabled_endpoints.len(), 1);
    assert_eq!(state.bindings.read().await.get(&second_id).expect("second binding").1, 0);

    remove_desired_endpoint(&state, second_id, true).await.expect("forget second");
    let disabled = state.desired.read().await.get(&key).cloned().expect("disabled reservation");
    assert!(!disabled.active);
    assert!(disabled.endpoints.is_empty());
    assert_eq!(disabled.disabled_endpoints.len(), 1);

    let mut final_desired = disabled;
    final_desired.endpoints = std::mem::take(&mut final_desired.disabled_endpoints);
    final_desired.active = true;
    state.database.put(&final_desired).expect("persist final endpoint");
    state.desired.write().await.insert(key.clone(), final_desired);
    state.bindings.write().await.insert(first_id, (key.clone(), 0));
    remove_desired_endpoint(&state, first_id, true).await.expect("forget reservation");
    assert!(state.desired.read().await.get(&key).is_none());
    assert!(state.database.list().expect("database").is_empty());
    state.manager.shutdown().await;
}

#[tokio::test]
async fn desired_endpoint_removal_ignores_stale_binding_indexes_and_missing_state() {
    let state = test_state();
    let key = crate::state_db::DesiredKey::new("project".to_owned(), "web".to_owned())
        .expect("desired key");
    let endpoint = Uuid::now_v7();
    state.bindings.write().await.insert(endpoint, (key.clone(), 3));
    remove_desired_endpoint(&state, endpoint, false).await.expect("missing desired state");

    let desired = crate::state_db::DesiredService {
        active: true,
        project_id: "project".to_owned(),
        remotes: None,
        default_remote: None,
        service: request().service,
        endpoints: vec![request().endpoints.remove(0)],
        disabled_endpoints: Vec::new(),
    };
    state.desired.write().await.insert(key, desired);
    remove_desired_endpoint(&state, endpoint, false).await.expect("stale index");
    assert!(state.bindings.read().await.contains_key(&endpoint));
    state.manager.shutdown().await;
}

#[tokio::test]
async fn close_failures_restart_desired_service_and_endpoint_bindings() {
    let state = test_state();
    let app = router(state.clone());
    let key = crate::state_db::DesiredKey::new("project".to_owned(), "web".to_owned())
        .expect("desired key");
    let desired = crate::state_db::DesiredService {
        active: true,
        project_id: "project".to_owned(),
        remotes: None,
        default_remote: None,
        service: request().service,
        endpoints: request().endpoints,
        disabled_endpoints: Vec::new(),
    };
    state.database.put(&desired).expect("persist desired");
    state.desired.write().await.insert(key.clone(), desired);
    let missing = Uuid::now_v7();
    state.bindings.write().await.insert(missing, (key.clone(), 0));

    let endpoint_failure =
        send(&app, Method::DELETE, &format!("/v1/endpoints/{missing}"), None, true).await;
    assert_eq!(endpoint_failure.0, StatusCode::BAD_GATEWAY);
    assert!(!state.bindings.read().await.contains_key(&missing));
    let restarted = *state.bindings.read().await.keys().next().expect("restarted endpoint");
    state.manager.discard(restarted).await;
    state.bindings.write().await.clear();
    state.bindings.write().await.insert(missing, (key, 0));

    let service_failure =
        send(&app, Method::DELETE, "/v1/services/web?project_id=project", None, true).await;
    assert_eq!(service_failure.0, StatusCode::BAD_GATEWAY);
    assert_eq!(state.bindings.read().await.len(), 1);
    assert!(state.desired.read().await.values().next().expect("desired").active);
    state.manager.shutdown().await;
}

#[tokio::test]
async fn routes_reject_conflicts_invalid_targets_and_missing_share_endpoints() {
    let state = test_state();
    let app = router(state.clone());
    let create = serde_json::to_value(request()).expect("create JSON");
    assert_eq!(
        send(&app, Method::POST, "/v1/services", Some(create.clone()), true).await.0,
        StatusCode::CREATED
    );
    let conflict = send(&app, Method::POST, "/v1/services", Some(create), true).await;
    assert_eq!(conflict.0, StatusCode::CONFLICT);
    assert_eq!(conflict.1["error"]["code"], "conflict");

    let invalid = send(
        &app,
        Method::POST,
        "/v1/share",
        Some(serde_json::json!({"target": "web", "expires": "0s", "path": "relative"})),
        true,
    )
    .await;
    assert_eq!(invalid.0, StatusCode::BAD_REQUEST);
    let missing = send(
        &app,
        Method::POST,
        "/v1/share",
        Some(serde_json::json!({"target": "missing", "expires": "5m", "path": "/"})),
        true,
    )
    .await;
    assert_eq!(missing.0, StatusCode::NOT_FOUND);

    let unknown = uuid::Uuid::now_v7();
    let deleted = send(&app, Method::DELETE, &format!("/v1/endpoints/{unknown}"), None, true).await;
    assert_eq!(deleted.0, StatusCode::BAD_GATEWAY);
    assert_eq!(deleted.1["error"]["code"], "endpoint_failed");
    state.manager.shutdown().await;
}

#[tokio::test]
async fn failed_exposure_removes_new_state_or_restores_stopped_service_transactionally() {
    let state = test_state();
    let mut invalid = request();
    invalid.endpoints[0].proto = ServiceProto::Tcp;

    let error =
        create_service(State(state.clone()), Json(invalid)).await.expect_err("protocol mismatch");

    assert_eq!(error.into_response().status(), StatusCode::BAD_GATEWAY);
    assert!(state.desired.read().await.is_empty());
    assert!(state.database.list().expect("database").is_empty());
    assert!(state.bindings.read().await.is_empty());

    let key = crate::state_db::DesiredKey::new("project".to_owned(), "web".to_owned())
        .expect("desired key");
    let previous = crate::state_db::DesiredService {
        active: false,
        project_id: "project".to_owned(),
        remotes: None,
        default_remote: None,
        service: request().service,
        endpoints: request().endpoints,
        disabled_endpoints: Vec::new(),
    };
    state.database.put(&previous).expect("persist stopped service");
    state.desired.write().await.insert(key.clone(), previous);
    let mut invalid = request();
    invalid.endpoints[0].proto = ServiceProto::Tcp;

    let error = create_service(State(state.clone()), Json(invalid))
        .await
        .expect_err("protocol mismatch after stopped service");

    assert_eq!(error.into_response().status(), StatusCode::BAD_GATEWAY);
    assert!(!state.desired.read().await.get(&key).expect("restored service").active);
    assert_eq!(state.database.list().expect("database").len(), 1);
    state.manager.shutdown().await;
}

#[tokio::test]
async fn authenticated_operational_routes_reload_delete_and_shutdown() {
    let mut state = test_state();
    let directory = tempfile::tempdir().expect("config directory");
    let config_path = directory.path().join("client.toml");
    fs::write(&config_path, "[defaults]\ninspect = true\n").expect("valid config");
    state.config_path = Some(config_path.clone());
    let app = router(state.clone());

    let interfaces = send(&app, Method::GET, "/v1/interfaces", None, true).await;
    assert_eq!(interfaces.0, StatusCode::OK);
    assert!(interfaces.1.as_array().is_some());
    let doctor = send(&app, Method::GET, "/v1/doctor", None, true).await;
    assert_eq!(doctor.0, StatusCode::OK);
    assert!(
        doctor.1.as_array().expect("doctor checks").iter().any(|check| check["name"] == "config")
    );
    let openapi = send(&app, Method::GET, "/v1/openapi.json", None, false).await;
    assert_eq!(openapi.0, StatusCode::OK);
    assert_eq!(openapi.1["info"]["title"], "Wormhole Local API");

    let reloaded = send(&app, Method::POST, "/v1/reload", None, true).await;
    assert_eq!(reloaded.0, StatusCode::OK, "{reloaded:?}");
    assert!(state.config.read().await.defaults.inspect);
    fs::write(&config_path, "not = [valid").expect("invalid config");
    let invalid_reload = send(&app, Method::POST, "/v1/reload", None, true).await;
    assert_eq!(invalid_reload.0, StatusCode::INTERNAL_SERVER_ERROR);

    let created = send(
        &app,
        Method::POST,
        "/v1/services",
        Some(serde_json::to_value(request()).expect("request JSON")),
        true,
    )
    .await;
    let id = created.1[0]["id"].as_str().expect("endpoint id");
    let deleted = send(&app, Method::DELETE, &format!("/v1/endpoints/{id}"), None, true).await;
    assert_eq!(deleted.0, StatusCode::OK, "{deleted:?}");
    assert!(state.desired.read().await.is_empty());

    let shutdown = send(&app, Method::POST, "/v1/shutdown", None, true).await;
    assert_eq!(shutdown.1["closed"], true);
    assert!(state.shutdown.is_cancelled());
    state.manager.shutdown().await;
}

#[tokio::test]
async fn forget_close_failure_retains_only_failed_desired_endpoints() {
    let state = test_state();
    let app = router(state.clone());
    let key = crate::state_db::DesiredKey::new("project".to_owned(), "web".to_owned())
        .expect("desired key");
    let missing = Uuid::now_v7();
    let desired = crate::state_db::DesiredService {
        active: true,
        project_id: "project".to_owned(),
        remotes: None,
        default_remote: None,
        service: request().service,
        endpoints: request().endpoints,
        disabled_endpoints: Vec::new(),
    };
    state.database.put(&desired).expect("persist desired");
    state.desired.write().await.insert(key.clone(), desired);
    state.bindings.write().await.insert(missing, (key, 0));

    let failed =
        send(&app, Method::DELETE, "/v1/services/web?project_id=project&forget=1", None, true)
            .await;

    assert_eq!(failed.0, StatusCode::BAD_GATEWAY);
    assert_eq!(state.desired.read().await.values().next().expect("desired").endpoints.len(), 1);
    assert_eq!(state.bindings.read().await.len(), 1);
    state.manager.shutdown().await;
}

async fn send(
    app: &axum::Router,
    method: Method,
    uri: &str,
    json: Option<serde_json::Value>,
    authorize: bool,
) -> (StatusCode, serde_json::Value) {
    use tower::ServiceExt as _;

    let has_json = json.is_some();
    let body = json.map_or_else(Body::empty, |value| Body::from(value.to_string()));
    let mut request = Request::builder().method(method).uri(uri);
    if authorize {
        request = request.header(header::AUTHORIZATION, "Bearer test");
    }
    if has_json {
        request = request.header(header::CONTENT_TYPE, "application/json");
    }
    let response =
        app.clone().oneshot(request.body(body).expect("request")).await.expect("response");
    let status = response.status();
    let bytes = response.into_body().collect().await.expect("body").to_bytes();
    let value = serde_json::from_slice(&bytes).expect("JSON response");
    (status, value)
}

fn test_state() -> ApiState {
    let directory = tempfile::tempdir().expect("tempdir").keep();
    let path = camino::Utf8PathBuf::from_path_buf(directory).expect("utf8");
    let registry = DriverRegistry::new();
    registry.register(Arc::new(MockDriver));
    let config = ClientConfig::default();
    ApiState {
        manager: Arc::new(TunnelManager::new(Arc::new(registry), config.clone())),
        config: Arc::new(RwLock::new(config)),
        config_path: Some(path.join("client.toml").into_std_path_buf()),
        identities: Arc::new(IdentityStore::with_home(path.clone())),
        database: Arc::new(StateDb::open(&path).expect("database")),
        desired: Arc::new(RwLock::new(BTreeMap::new())),
        bindings: Arc::new(RwLock::new(HashMap::new())),
        persistence_lock: Arc::new(Mutex::new(())),
        mutation_lock: Arc::new(Mutex::new(())),
        expose_lock: Arc::new(Mutex::new(())),
        captures: Arc::new(RwLock::new(CaptureStore::default())),
        started: jiff::Timestamp::now(),
        shutdown: CancellationToken::new(),
        token: Arc::from("test"),
    }
}

fn request() -> CreateServiceRequest {
    CreateServiceRequest {
        project_id: Some("project".to_owned()),
        remotes: None,
        default_remote: None,
        service: Service {
            name: "web".to_owned(),
            target: Target::Port(3000),
            proto: ServiceProto::Http,
        },
        endpoints: vec![EndpointSpec {
            proto: ServiceProto::Http,
            driver: "mock".to_owned(),
            qualifier: None,
            remote: None,
            host: Some("web".to_owned()),
            auto_host: false,
            domain: None,
            public_port: None,
            persist: Persistence::Temporary,
            buffer: None,
            auth: None,
            retry: None,
            inspect: false,
            inspect_assets: false,
            capture_body_max: 1024,
            reservation: None,
        }],
    }
}
