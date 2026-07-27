//! Versioned daemon desired-state persistence.

use std::{fs, io, os::unix::fs::PermissionsExt};

use camino::Utf8Path;
use redb::{Database, Durability, ReadableDatabase as _, ReadableTable as _, TableDefinition};
use serde::{Deserialize, Serialize};
use wormhole_core::{EndpointSpec, Remote, Service};

const CURRENT_SCHEMA: u64 = 1;
const META: TableDefinition<&str, u64> = TableDefinition::new("meta");
const SERVICES: TableDefinition<&str, &[u8]> = TableDefinition::new("services");
const SCHEMA_KEY: &str = "schema_version";

/// One desired service restored by the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesiredService {
    #[serde(default = "default_active")]
    pub active: bool,
    pub project_id: String,
    #[serde(default)]
    pub remotes: Option<std::collections::BTreeMap<String, Remote>>,
    #[serde(default)]
    pub default_remote: Option<String>,
    pub service: Service,
    pub endpoints: Vec<EndpointSpec>,
    #[serde(default)]
    pub disabled_endpoints: Vec<EndpointSpec>,
}

const fn default_active() -> bool {
    true
}

impl DesiredService {
    pub fn key(&self) -> String {
        format!("{}:{}", self.project_id, self.service.name)
    }
}

pub struct StateDb {
    database: Database,
}

impl StateDb {
    pub fn open(state_dir: &Utf8Path) -> Result<Self, StateDbError> {
        fs::create_dir_all(state_dir).map_err(|source| io_error(state_dir, source))?;
        set_mode(state_dir, 0o700)?;
        let path = state_dir.join("state.redb");
        if !path.exists() {
            let database = Database::create(&path).map_err(db_error)?;
            initialize(&database)?;
            set_mode(&path, 0o600)?;
            return Ok(Self { database });
        }
        set_mode(&path, 0o600)?;
        let database = Database::create(&path).map_err(db_error)?;
        let schema = schema_version(&database)?;
        drop(database);
        if schema > CURRENT_SCHEMA {
            return Err(StateDbError::NewerSchema(schema));
        }
        if schema < CURRENT_SCHEMA {
            migrate(&path, state_dir, schema)?;
        }
        Ok(Self { database: Database::create(&path).map_err(db_error)? })
    }

    pub fn put(&self, desired: &DesiredService) -> Result<(), StateDbError> {
        let encoded = serde_json::to_vec(desired).map_err(data_error)?;
        let mut transaction = self.database.begin_write().map_err(db_error)?;
        transaction.set_durability(Durability::Immediate).map_err(db_error)?;
        {
            let mut table = transaction.open_table(SERVICES).map_err(db_error)?;
            table.insert(desired.key().as_str(), encoded.as_slice()).map_err(db_error)?;
        }
        transaction.commit().map_err(db_error)
    }

    pub fn delete(&self, name: &str) -> Result<bool, StateDbError> {
        let mut transaction = self.database.begin_write().map_err(db_error)?;
        transaction.set_durability(Durability::Immediate).map_err(db_error)?;
        let removed = {
            let mut table = transaction.open_table(SERVICES).map_err(db_error)?;
            table.remove(name).map_err(db_error)?.is_some()
        };
        transaction.commit().map_err(db_error)?;
        Ok(removed)
    }

    pub fn list(&self) -> Result<Vec<DesiredService>, StateDbError> {
        let transaction = self.database.begin_read().map_err(db_error)?;
        let table = transaction.open_table(SERVICES).map_err(db_error)?;
        let mut services = Vec::new();
        for entry in table.iter().map_err(db_error)? {
            let (_, value) = entry.map_err(db_error)?;
            services.push(serde_json::from_slice(value.value()).map_err(data_error)?);
        }
        Ok(services)
    }
}

fn initialize(database: &Database) -> Result<(), StateDbError> {
    let mut transaction = database.begin_write().map_err(db_error)?;
    transaction.set_durability(Durability::Immediate).map_err(db_error)?;
    {
        transaction.open_table(SERVICES).map_err(db_error)?;
        let mut meta = transaction.open_table(META).map_err(db_error)?;
        meta.insert(SCHEMA_KEY, CURRENT_SCHEMA).map_err(db_error)?;
    }
    transaction.commit().map_err(db_error)
}

fn schema_version(database: &Database) -> Result<u64, StateDbError> {
    let transaction = database.begin_read().map_err(db_error)?;
    let table = match transaction.open_table(META) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
        Err(error) => return Err(db_error(error)),
    };
    Ok(table.get(SCHEMA_KEY).map_err(db_error)?.map_or(0, |value| value.value()))
}

fn migrate(path: &Utf8Path, state_dir: &Utf8Path, old: u64) -> Result<(), StateDbError> {
    let backups = state_dir.join("backups");
    fs::create_dir_all(&backups).map_err(|source| io_error(&backups, source))?;
    let stamp = jiff::Timestamp::now().as_second();
    let backup = backups.join(format!("state-v{old}-{stamp}.redb"));
    copy_synced(path, &backup)?;
    retain_two(&backups)?;
    let temporary = state_dir.join(format!(".state-migrate-{stamp}.redb"));
    copy_synced(path, &temporary)?;
    let database = Database::create(&temporary).map_err(db_error)?;
    initialize(&database)?;
    drop(database);
    fs::rename(&temporary, path).map_err(|source| io_error(path, source))?;
    sync_dir(state_dir)
}

fn copy_synced(from: &Utf8Path, to: &Utf8Path) -> Result<(), StateDbError> {
    fs::copy(from, to).map_err(|source| io_error(to, source))?;
    fs::File::open(to).and_then(|file| file.sync_all()).map_err(|source| io_error(to, source))
}

fn retain_two(dir: &Utf8Path) -> Result<(), StateDbError> {
    let mut files = fs::read_dir(dir)
        .map_err(|source| io_error(dir, source))?
        .filter_map(Result::ok)
        .collect::<Vec<_>>();
    files.sort_by_key(std::fs::DirEntry::file_name);
    let remove = files.len().saturating_sub(2);
    for entry in files.into_iter().take(remove) {
        fs::remove_file(entry.path()).map_err(|source| StateDbError::Io(source.to_string()))?;
    }
    Ok(())
}

fn set_mode(path: &Utf8Path, mode: u32) -> Result<(), StateDbError> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|source| io_error(path, source))
}

fn sync_dir(path: &Utf8Path) -> Result<(), StateDbError> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error(path, source))
}

fn io_error(path: &Utf8Path, source: io::Error) -> StateDbError {
    StateDbError::Io(format!("{path}: {source}"))
}

fn db_error(error: impl std::fmt::Display) -> StateDbError {
    StateDbError::Database(error.to_string())
}

fn data_error(error: impl std::fmt::Display) -> StateDbError {
    StateDbError::Data(error.to_string())
}

#[derive(Debug, thiserror::Error)]
pub enum StateDbError {
    #[error("daemon state I/O failed: {0}")]
    Io(String),
    #[error("daemon state database failed: {0}")]
    Database(String),
    #[error("daemon state is invalid: {0}")]
    Data(String),
    #[error("daemon state schema {0} is newer than this binary")]
    NewerSchema(u64),
}

#[cfg(test)]
#[path = "state_db_tests.rs"]
mod tests;
