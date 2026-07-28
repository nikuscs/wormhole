use std::{
    collections::{BTreeMap, HashMap},
    fs,
    sync::Arc,
};

use axum::{Json, extract::State, response::IntoResponse};
use tokio::sync::{Mutex, RwLock};
use tokio_util::sync::CancellationToken;
use utoipa::OpenApi as _;
use wormhole_core::{
    ClientConfig, EndpointSpec, Service, Target, TunnelManager, driver::DriverRegistry,
    keys_store::IdentityStore, model::ServiceProto,
};
use wormhole_proto::frames::Persistence;

use super::{ApiState, CreateServiceRequest, LocalApi, create_service};
use crate::{capture_store::CaptureStore, mock_driver::MockDriver, state_db::StateDb};

#[test]
fn committed_openapi_is_current() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/local-api.openapi.json");
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

fn test_state() -> ApiState {
    let directory = tempfile::tempdir().expect("tempdir").keep();
    let path = camino::Utf8PathBuf::from_path_buf(directory).expect("utf8");
    let registry = DriverRegistry::new();
    registry.register(Arc::new(MockDriver));
    let config = ClientConfig::default();
    ApiState {
        manager: Arc::new(TunnelManager::new(Arc::new(registry), config.clone())),
        config: Arc::new(RwLock::new(config)),
        config_path: None,
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
