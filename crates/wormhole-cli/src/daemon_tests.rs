use std::{
    collections::{BTreeMap, HashMap},
    fs,
    os::unix::fs::PermissionsExt as _,
    sync::Arc,
};

use tempfile::tempdir;
use tokio::sync::{Mutex, RwLock};
use tokio_util::sync::CancellationToken;
use wormhole_core::{
    ClientConfig, EndpointSpec, Service, Target, TunnelManager, driver::DriverRegistry,
    keys_store::IdentityStore, model::ServiceProto,
};
use wormhole_proto::frames::Persistence;

use crate::{
    api_types::ApiState,
    capture_store::CaptureStore,
    runtime::RuntimePaths,
    state_db::{DesiredKey, DesiredService, StateDb},
};

use super::{
    DaemonError, SocketCleanup, load_config, persist_reservation, read_token, remove_stale_socket,
    restore, start_persistence, write_token,
};

#[test]
fn token_is_private_and_round_trips() {
    let directory = tempdir().expect("tempdir");
    let paths = runtime_paths(&directory);

    let written = write_token(&paths).expect("write token");

    assert_eq!(read_token(&paths).expect("read token"), written);
    let mode = fs::metadata(&paths.token).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn token_and_config_errors_retain_actionable_context() {
    let directory = tempdir().expect("tempdir");
    let paths = runtime_paths(&directory);
    assert_eq!(read_token(&paths).expect("new token file"), "");

    let config = directory.path().join("invalid.toml");
    fs::write(&config, "[defaults\n").expect("config");
    let error = load_config(Some(&config)).expect_err("invalid config");
    assert!(error.to_string().contains("TOML") || error.to_string().contains("toml"));
}

#[test]
fn stale_socket_cleanup_refuses_regular_files_and_ignores_missing_paths() {
    let directory = tempdir().expect("tempdir");
    let path =
        camino::Utf8PathBuf::from_path_buf(directory.path().join("daemon.sock")).expect("utf8");

    remove_stale_socket(&path).expect("missing socket is harmless");
    fs::write(&path, b"not a socket").expect("file");
    assert!(remove_stale_socket(&path).is_err());
    assert!(path.exists());
}

#[test]
fn socket_cleanup_removes_owned_path_on_drop() {
    let directory = tempdir().expect("tempdir");
    let path =
        camino::Utf8PathBuf::from_path_buf(directory.path().join("daemon.sock")).expect("utf8");
    fs::write(&path, b"placeholder").expect("file");
    drop(SocketCleanup(path.clone()));
    assert!(!path.exists());
}

#[tokio::test]
async fn reservation_persistence_rejects_missing_desired_service() {
    let directory = tempdir().expect("tempdir");
    let state_dir = camino::Utf8Path::from_path(directory.path()).expect("utf8");
    let database = StateDb::open(state_dir).expect("database");
    let endpoint = uuid::Uuid::now_v7();
    let key = DesiredKey::new("project".to_owned(), "web".to_owned()).expect("key");
    let bindings = RwLock::new(HashMap::from([(endpoint, (key, 0))]));
    let desired = RwLock::new(std::collections::BTreeMap::new());

    let error = persist_reservation(
        &Mutex::new(()),
        &desired,
        &bindings,
        &database,
        endpoint,
        uuid::Uuid::now_v7(),
    )
    .await
    .expect_err("missing desired state");
    assert_eq!(error, "desired service disappeared");
}

#[tokio::test]
async fn reservation_persistence_updates_memory_and_database_and_rejects_stale_index() {
    let directory = tempdir().expect("tempdir");
    let state_dir = camino::Utf8Path::from_path(directory.path()).expect("utf8");
    let database = StateDb::open(state_dir).expect("database");
    let desired_service = desired_service("web", "mock", Persistence::Persistent, true);
    let key = desired_service.key().expect("key");
    database.put(&desired_service).expect("persist desired");
    let endpoint = uuid::Uuid::now_v7();
    let reservation = uuid::Uuid::now_v7();
    let bindings = RwLock::new(HashMap::from([(endpoint, (key.clone(), 0))]));
    let desired = RwLock::new(BTreeMap::from([(key.clone(), desired_service)]));

    persist_reservation(&Mutex::new(()), &desired, &bindings, &database, endpoint, reservation)
        .await
        .expect("persist reservation");
    assert_eq!(desired.read().await[&key].endpoints[0].reservation, Some(reservation));
    assert_eq!(database.list().expect("database")[0].endpoints[0].reservation, Some(reservation));

    bindings.write().await.insert(endpoint, (key, 4));
    let error = persist_reservation(
        &Mutex::new(()),
        &desired,
        &bindings,
        &database,
        endpoint,
        uuid::Uuid::now_v7(),
    )
    .await
    .expect_err("stale endpoint index");
    assert_eq!(error, "desired endpoint disappeared");
}

#[tokio::test]
async fn restore_filters_temporary_state_and_recovers_active_and_stopped_services() {
    let directory = tempdir().expect("tempdir");
    let path = camino::Utf8PathBuf::from_path_buf(directory.path().to_owned()).expect("utf8");
    let registry = DriverRegistry::new();
    registry.register(Arc::new(crate::mock_driver::MockDriver));
    let config = ClientConfig::default();
    let database = Arc::new(StateDb::open(&path).expect("database"));
    let state = ApiState {
        manager: Arc::new(TunnelManager::new(Arc::new(registry), config.clone())),
        config: Arc::new(RwLock::new(config)),
        config_path: None,
        identities: Arc::new(IdentityStore::with_home(path)),
        database: Arc::clone(&database),
        desired: Arc::new(RwLock::new(BTreeMap::new())),
        bindings: Arc::new(RwLock::new(HashMap::new())),
        persistence_lock: Arc::new(Mutex::new(())),
        mutation_lock: Arc::new(Mutex::new(())),
        expose_lock: Arc::new(Mutex::new(())),
        captures: Arc::new(RwLock::new(CaptureStore::default())),
        started: jiff::Timestamp::now(),
        shutdown: CancellationToken::new(),
        token: Arc::from("test"),
    };
    for desired in [
        desired_service("temporary", "mock", Persistence::Temporary, true),
        desired_service("stopped", "mock", Persistence::Persistent, false),
        desired_service("active", "mock", Persistence::Persistent, true),
        desired_service("failed", "missing", Persistence::Persistent, true),
    ] {
        database.put(&desired).expect("persist desired state");
    }

    restore(&state).await;

    let desired = state.desired.read().await;
    assert!(!desired.keys().any(|key| key.matches_project_target("project:temporary")));
    assert!(desired.keys().any(|key| key.matches_project_target("project:stopped")));
    assert!(desired.keys().any(|key| key.matches_project_target("project:active")));
    assert!(desired.keys().any(|key| key.matches_project_target("project:failed")));
    drop(desired);
    assert_eq!(database.list().expect("database").len(), 3);
    assert_eq!(state.bindings.read().await.len(), 1);

    start_persistence(&state).await.expect("start persistence listener");
    assert!(matches!(
        start_persistence(&state).await.expect_err("event receiver already taken"),
        DaemonError::EventReceiverTaken
    ));
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            let persisted = state
                .desired
                .read()
                .await
                .values()
                .find(|service| service.service.name == "active")
                .and_then(|service| service.endpoints[0].reservation);
            if persisted.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("reservation persisted");
    state.manager.shutdown().await;
}

fn desired_service(
    name: &str,
    driver: &str,
    persistence: Persistence,
    active: bool,
) -> DesiredService {
    DesiredService {
        active,
        project_id: "project".to_owned(),
        remotes: None,
        default_remote: None,
        service: Service {
            name: name.to_owned(),
            target: Target::Port(3000),
            proto: ServiceProto::Http,
        },
        endpoints: vec![EndpointSpec {
            proto: ServiceProto::Http,
            driver: driver.to_owned(),
            qualifier: None,
            remote: None,
            host: Some(name.to_owned()),
            auto_host: false,
            domain: None,
            public_port: None,
            persist: persistence,
            buffer: None,
            auth: None,
            retry: None,
            inspect: false,
            inspect_assets: false,
            capture_body_max: 1024,
            reservation: None,
        }],
        disabled_endpoints: Vec::new(),
    }
}

fn runtime_paths(directory: &tempfile::TempDir) -> RuntimePaths {
    let state_dir = camino::Utf8PathBuf::from_path_buf(directory.path().to_owned()).expect("utf8");
    RuntimePaths {
        socket: state_dir.join("daemon.sock"),
        lock: state_dir.join("daemon.lock"),
        token: state_dir.join("api-token"),
        log: state_dir.join("daemon.log"),
        state_dir,
    }
}
