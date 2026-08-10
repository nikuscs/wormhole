//! Per-user daemon lifecycle, lock ownership, restore, and UDS serving.

use std::{
    collections::{BTreeMap, HashMap},
    fmt::Write as _,
    fs::{self, File},
    io::{Read as _, Seek as _, SeekFrom, Write as _},
    net::Ipv4Addr,
    os::unix::fs::{FileTypeExt as _, PermissionsExt as _},
    path::PathBuf,
    process::{Command, Stdio},
    sync::Arc,
};

use camino::Utf8PathBuf;
use nix::fcntl::{Flock, FlockArg};
use rand::RngExt as _;
use tokio::{
    net::{TcpListener, UnixListener},
    sync::RwLock,
};
use tokio_util::sync::CancellationToken;
use wormhole_core::{
    ClientConfig, DriverEvent, TunnelManager, config::ConfigLayer, drivers::build_registry,
    keys_store::IdentityStore, wormhole_driver::WormholeDriver,
};
use wormhole_proto::frames::Persistence;

use crate::{
    local_api::{ApiState, router},
    runtime::{LOCAL_API_PORT, RuntimePaths, open_private},
    state_db::{DesiredKey, StateDb},
};

const DETACH_CHILD: &str = "WORMHOLE_DETACH_CHILD";
const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;

pub async fn run(config_path: Option<&PathBuf>, detach: bool) -> Result<(), DaemonError> {
    if detach {
        match std::env::var(DETACH_CHILD).ok().as_deref() {
            None => {
                spawn_detached(config_path)?;
                return Ok(());
            }
            Some("1") => {
                nix::unistd::setsid().map_err(|error| DaemonError::Detach(error.to_string()))?;
                spawn_detach_grandchild()?;
                return Ok(());
            }
            Some("2") => {}
            Some(stage) => return Err(DaemonError::Detach(format!("invalid stage: {stage}"))),
        }
    }
    DaemonServer::bind(config_path).await?.run().await
}

pub struct DaemonServer {
    listener: UnixListener,
    tcp_listener: TcpListener,
    state: ApiState,
    lock: Flock<File>,
    socket: Utf8PathBuf,
}

impl DaemonServer {
    pub async fn bind(config_path: Option<&PathBuf>) -> Result<Self, DaemonError> {
        let paths = RuntimePaths::discover()?;
        paths.prepare()?;
        let lock_file = open_private(&paths.lock, false)?;
        let lock = Flock::lock(lock_file, FlockArg::LockExclusiveNonblock)
            .map_err(|_| DaemonError::AlreadyRunning)?;
        remove_stale_socket(&paths.socket)?;
        let token = write_token(&paths)?;
        let listener = UnixListener::bind(&paths.socket)?;
        fs::set_permissions(&paths.socket, fs::Permissions::from_mode(0o600))?;
        let tcp_listener = bind_loopback_api().await?;
        let config = load_config(config_path)?;
        let identities = Arc::new(IdentityStore::from_environment()?);
        let registry = build_registry(
            &config,
            Arc::clone(&identities),
            config_path.and_then(|path| camino::Utf8Path::from_path(path)),
        );
        #[cfg(debug_assertions)]
        if std::env::var_os("WORMHOLE_ENABLE_MOCK_DRIVER").as_deref()
            == Some(std::ffi::OsStr::new("1"))
        {
            registry.register(Arc::new(crate::mock_driver::MockDriver));
        }
        let manager = Arc::new(TunnelManager::new(Arc::new(registry), config.clone()));
        let database = Arc::new(StateDb::open(&paths.state_dir)?);
        let desired = Arc::new(RwLock::new(BTreeMap::new()));
        let bindings = Arc::new(RwLock::new(HashMap::new()));
        let persistence_lock = Arc::new(tokio::sync::Mutex::new(()));
        let mutation_lock = Arc::new(tokio::sync::Mutex::new(()));
        let expose_lock = Arc::new(tokio::sync::Mutex::new(()));
        let state = ApiState {
            manager,
            config: Arc::new(RwLock::new(config)),
            config_path: config_path.cloned(),
            identities,
            database,
            desired,
            bindings,
            persistence_lock,
            mutation_lock,
            expose_lock,
            captures: Arc::new(RwLock::new(crate::capture_store::CaptureStore::default())),
            started: jiff::Timestamp::now(),
            shutdown: CancellationToken::new(),
            token: Arc::from(token),
        };
        start_persistence(&state).await?;
        restore(&state).await;
        Ok(Self { listener, tcp_listener, state, lock, socket: paths.socket })
    }

    pub async fn run(self) -> Result<(), DaemonError> {
        let Self { listener, tcp_listener, state, lock, socket } = self;
        let _lock = lock;
        let _cleanup = SocketCleanup(socket);
        let shutdown = state.shutdown.clone();
        let signal_shutdown = shutdown.clone();
        tokio::spawn(async move {
            shutdown_signal(signal_shutdown.clone()).await;
            signal_shutdown.cancel();
        });
        let uds_shutdown = shutdown.clone();
        let tcp_shutdown = shutdown.clone();
        let uds = axum::serve(listener, router(state.clone()))
            .with_graceful_shutdown(async move { uds_shutdown.cancelled().await });
        let tcp = axum::serve(tcp_listener, router(state.clone()))
            .with_graceful_shutdown(async move { tcp_shutdown.cancelled().await });
        tokio::try_join!(uds, tcp)?;
        state.manager.shutdown().await;
        persist_all(&state).await?;
        Ok(())
    }
}

async fn bind_loopback_api() -> std::io::Result<TcpListener> {
    match TcpListener::bind((Ipv4Addr::LOCALHOST, local_api_port())).await {
        Ok(listener) => Ok(listener),
        #[cfg(debug_assertions)]
        Err(error)
            if error.kind() == std::io::ErrorKind::AddrInUse
                && std::env::var_os("WORMHOLE_STATE_DIR").is_some() =>
        {
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await
        }
        Err(error) => Err(error),
    }
}

#[cfg(debug_assertions)]
fn local_api_port() -> u16 {
    std::env::var("WORMHOLE_API_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(LOCAL_API_PORT)
}

#[cfg(not(debug_assertions))]
const fn local_api_port() -> u16 {
    LOCAL_API_PORT
}

async fn restore(state: &ApiState) {
    let Ok(services) = state.database.list() else {
        tracing::error!("failed to read daemon desired state");
        return;
    };
    for mut desired in services {
        desired.endpoints.retain(|endpoint| endpoint.persist == Persistence::Persistent);
        desired.disabled_endpoints.retain(|endpoint| endpoint.persist == Persistence::Persistent);
        let key = match desired.key() {
            Ok(key) => key,
            Err(error) => {
                tracing::error!(%error, service = %desired.service.name, "invalid desired state");
                continue;
            }
        };
        if desired.endpoints.is_empty() && desired.disabled_endpoints.is_empty() {
            if let Err(error) = state.database.delete(&key) {
                tracing::error!(%error, service = %desired.service.name, "temporary state cleanup failed");
            }
            continue;
        }
        state.desired.write().await.insert(key.clone(), desired.clone());
        if !desired.active {
            continue;
        }
        if let Some(remotes) = desired.remotes.clone() {
            state.manager.registry().register(Arc::new(WormholeDriver::new(
                remotes,
                desired.default_remote.clone(),
                Arc::clone(&state.identities),
            )));
        }
        let restored =
            state.manager.expose(desired.service.clone(), desired.endpoints.clone()).await;
        if desired.remotes.is_some() {
            let config = state.config.read().await;
            state.manager.registry().register(Arc::new(WormholeDriver::new(
                config.remotes.clone(),
                config.default_remote.clone(),
                Arc::clone(&state.identities),
            )));
        }
        match restored {
            Ok(ids) => {
                for (index, id) in ids.into_iter().enumerate() {
                    state.bindings.write().await.insert(id, (key.clone(), index));
                }
            }
            Err(error) => {
                tracing::error!(service = %desired.service.name, %error, "restore failed");
            }
        }
    }
}

async fn start_persistence(state: &ApiState) -> Result<(), DaemonError> {
    let Some(mut events) = state.manager.take_driver_events().await else {
        return Err(DaemonError::EventReceiverTaken);
    };
    let desired = Arc::clone(&state.desired);
    let bindings = Arc::clone(&state.bindings);
    let database = Arc::clone(&state.database);
    let manager = Arc::clone(&state.manager);
    let persistence_lock = Arc::clone(&state.persistence_lock);
    let captures = Arc::clone(&state.captures);
    tokio::spawn(async move {
        let mut failed = std::collections::HashSet::new();
        while let Some(event) = events.recv().await {
            match event.event {
                DriverEvent::Ready { reservation: Some(reservation), .. } => {
                    if let Err(error) = persist_reservation(
                        &persistence_lock,
                        &desired,
                        &bindings,
                        &database,
                        event.endpoint,
                        reservation,
                    )
                    .await
                    {
                        tracing::error!(%error, endpoint = %event.endpoint, "reservation persistence failed");
                        failed.insert(event.endpoint);
                        manager.fail_endpoint(event.endpoint, error).await;
                    }
                }
                DriverEvent::Handoff(barrier) if !failed.contains(&event.endpoint) => {
                    manager.confirm_handoff(event.endpoint);
                    barrier.notify_one();
                }
                DriverEvent::Captured(capture) => {
                    captures.write().await.insert(event.endpoint, *capture);
                }
                _ => {}
            }
        }
    });
    Ok(())
}

async fn persist_reservation(
    persistence_lock: &tokio::sync::Mutex<()>,
    desired: &RwLock<BTreeMap<DesiredKey, crate::state_db::DesiredService>>,
    bindings: &RwLock<HashMap<uuid::Uuid, (DesiredKey, usize)>>,
    database: &StateDb,
    endpoint: uuid::Uuid,
    reservation: uuid::Uuid,
) -> Result<(), String> {
    let (name, index) = wait_for_binding(bindings, endpoint).await?;
    let _persistence = persistence_lock.lock().await;
    let mut guard = desired.write().await;
    let service = guard.get_mut(&name).ok_or_else(|| "desired service disappeared".to_owned())?;
    let mut updated = service.clone();
    updated
        .endpoints
        .get_mut(index)
        .ok_or_else(|| "desired endpoint disappeared".to_owned())?
        .reservation = Some(reservation);
    database.put(&updated).map_err(|error| error.to_string())?;
    service
        .endpoints
        .get_mut(index)
        .ok_or_else(|| "desired endpoint disappeared".to_owned())?
        .reservation = Some(reservation);
    drop(guard);
    Ok(())
}

async fn wait_for_binding(
    bindings: &RwLock<HashMap<uuid::Uuid, (DesiredKey, usize)>>,
    endpoint: uuid::Uuid,
) -> Result<(DesiredKey, usize), String> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        let binding = bindings.read().await.get(&endpoint).cloned();
        if let Some(binding) = binding {
            return Ok(binding);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("endpoint has no desired-state binding".to_owned());
        }
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
}

async fn persist_all(state: &ApiState) -> Result<(), DaemonError> {
    for desired in state.desired.read().await.values() {
        state.database.put(desired)?;
    }
    Ok(())
}

async fn shutdown_signal(shutdown: CancellationToken) {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("SIGTERM handler must install");
        tokio::select! {
            () = shutdown.cancelled() => {}
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    tokio::select! {
        () = shutdown.cancelled() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}

pub fn load_config(path: Option<&PathBuf>) -> Result<ClientConfig, DaemonError> {
    load_config_with_project(path, None)
}

pub fn load_config_with_project(
    path: Option<&PathBuf>,
    project: Option<&camino::Utf8Path>,
) -> Result<ClientConfig, DaemonError> {
    let global = path
        .map(|path| Utf8PathBuf::from_path_buf(path.clone()).map_err(|_| DaemonError::NonUtf8))
        .transpose()?;
    if let Some(path) = global.as_deref() {
        Ok(ClientConfig::load_from_paths(Some(path), project, ConfigLayer::default())?)
    } else {
        Ok(ClientConfig::load(project, ConfigLayer::default())?)
    }
}

fn spawn_detached(config_path: Option<&PathBuf>) -> Result<(), DaemonError> {
    let paths = RuntimePaths::discover()?;
    paths.prepare()?;
    let truncate = fs::metadata(&paths.log).is_ok_and(|metadata| metadata.len() >= MAX_LOG_BYTES);
    let log = open_private(&paths.log, truncate)?;
    let mut command = Command::new(std::env::current_exe()?);
    if let Some(path) = config_path {
        command.arg("--config").arg(path);
    }
    command
        .args(["daemon", "run", "--detach"])
        .env(DETACH_CHILD, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log));
    command.spawn()?;
    Ok(())
}

fn spawn_detach_grandchild() -> Result<(), DaemonError> {
    let mut command = Command::new(std::env::current_exe()?);
    command.args(std::env::args_os().skip(1)).env(DETACH_CHILD, "2").stdin(Stdio::null());
    command.spawn()?;
    Ok(())
}

fn write_token(paths: &RuntimePaths) -> Result<String, DaemonError> {
    let bytes = rand::rng().random::<[u8; 32]>();
    let mut token = String::with_capacity(64);
    for byte in bytes {
        write!(token, "{byte:02x}").expect("writing to String cannot fail");
    }
    let mut file = open_private(&paths.token, true)?;
    file.write_all(token.as_bytes())?;
    file.sync_all()?;
    Ok(token)
}

pub fn read_token(paths: &RuntimePaths) -> Result<String, DaemonError> {
    let mut file = open_private(&paths.token, false)?;
    file.seek(SeekFrom::Start(0))?;
    let mut token = String::new();
    file.read_to_string(&mut token)?;
    Ok(token)
}

fn remove_stale_socket(path: &camino::Utf8Path) -> Result<(), DaemonError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => fs::remove_file(path)?,
        Ok(_) => return Err(DaemonError::UnsafeSocket(path.to_owned())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

struct SocketCleanup(Utf8PathBuf);

impl Drop for SocketCleanup {
    fn drop(&mut self) {
        let _removed = fs::remove_file(&self.0);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("daemon is already running")]
    AlreadyRunning,
    #[error("unsafe daemon socket path: {0}")]
    UnsafeSocket(Utf8PathBuf),
    #[error("configuration path is not valid UTF-8")]
    NonUtf8,
    #[error("daemon event receiver was already taken")]
    EventReceiverTaken,
    #[error("daemon detach failed: {0}")]
    Detach(String),
    #[error(transparent)]
    Runtime(#[from] crate::runtime::RuntimeError),
    #[error(transparent)]
    Config(#[from] wormhole_core::ConfigError),
    #[error(transparent)]
    Identity(#[from] wormhole_core::IdentityError),
    #[error(transparent)]
    State(#[from] crate::state_db::StateDbError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
#[path = "daemon_tests.rs"]
mod tests;
