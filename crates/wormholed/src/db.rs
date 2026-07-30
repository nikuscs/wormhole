//! Typed redb schema, persistence accessors, and crash-safe migrations.

use std::{fs, io, os::unix::fs::PermissionsExt};

use camino::{Utf8Path, Utf8PathBuf};
use jiff::Timestamp;
use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Serialize, de::DeserializeOwned};
use uuid::Uuid;

use crate::buffer::BufferedRequest;

pub use crate::db_models::{
    AuthVerifier, AuthorizedKey, EnrollmentInvite, FailedWebhook, PersistedBind, PersistedBindSpec,
    PersistedEndpoint,
};

const CURRENT_SCHEMA: u64 = 2;
const META: TableDefinition<&str, u64> = TableDefinition::new("meta");
pub(crate) const BINDS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("binds");
pub(crate) const KEYS: TableDefinition<&str, &[u8]> = TableDefinition::new("keys");
pub(crate) const INVITES: TableDefinition<&str, &[u8]> = TableDefinition::new("invites");
pub(crate) const WEBHOOK_BUFFER: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("webhook_buffer");
pub(crate) const WEBHOOK_FAILED: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("webhook_failed");
pub(crate) const WEBHOOK_SEQUENCE: TableDefinition<&[u8], u64> =
    TableDefinition::new("webhook_sequence");
const SCHEMA_VERSION_KEY: &str = "schema_version";

/// Typed handle to relay persistence.
pub struct BufferQuotas {
    pub max_requests: u32,
    pub ttl_secs: u64,
    pub key_bytes: u64,
    pub total_bytes: u64,
}

pub struct RelayDb {
    pub(crate) database: Database,
    path: Utf8PathBuf,
}

impl RelayDb {
    /// Opens the relay database, migrating older schemas before use.
    pub fn open(data_dir: &Utf8Path) -> Result<Self, DbError> {
        fs::create_dir_all(data_dir)
            .map_err(|source| DbError::Io { path: data_dir.to_owned(), source })?;
        set_mode(data_dir, 0o700)?;
        let path = data_dir.join("state.redb");
        if !path.exists() {
            let database = Database::create(&path).map_err(redb_error)?;
            set_mode(&path, 0o600)?;
            initialize_schema(&database, CURRENT_SCHEMA)?;
            return Ok(Self { database, path });
        }
        set_mode(&path, 0o600)?;
        let database = Database::create(&path).map_err(redb_error)?;
        let schema = read_schema(&database)?;
        drop(database);
        if schema > CURRENT_SCHEMA {
            return Err(DbError::NewerSchema { found: schema, supported: CURRENT_SCHEMA });
        }
        if schema < CURRENT_SCHEMA {
            migrate(&path, data_dir, schema)?;
        }
        let database = Database::create(&path).map_err(redb_error)?;
        Ok(Self { database, path })
    }

    /// Returns the database file path.
    pub fn path(&self) -> &Utf8Path {
        &self.path
    }

    /// Inserts or replaces a persistent bind atomically.
    pub fn put_bind(&self, id: Uuid, bind: &PersistedBind) -> Result<(), DbError> {
        let encoded = encode(bind)?;
        let mut transaction = self.database.begin_write().map_err(redb_error)?;
        transaction.set_durability(Durability::Immediate).map_err(redb_error)?;
        {
            let mut table = transaction.open_table(BINDS).map_err(redb_error)?;
            table.insert(id.as_bytes().as_slice(), encoded.as_slice()).map_err(redb_error)?;
        }
        transaction.commit().map_err(redb_error)
    }

    /// Reads one persistent bind.
    pub fn get_bind(&self, id: Uuid) -> Result<Option<PersistedBind>, DbError> {
        let transaction = self.database.begin_read().map_err(redb_error)?;
        let table = transaction.open_table(BINDS).map_err(redb_error)?;
        decode_optional(table.get(id.as_bytes().as_slice()).map_err(redb_error)?)
    }

    /// Lists all persistent binds.
    pub fn list_binds(&self) -> Result<Vec<(Uuid, PersistedBind)>, DbError> {
        let transaction = self.database.begin_read().map_err(redb_error)?;
        let table = transaction.open_table(BINDS).map_err(redb_error)?;
        let mut binds = Vec::new();
        for entry in table.iter().map_err(redb_error)? {
            let (key, value) = entry.map_err(redb_error)?;
            let id =
                Uuid::from_slice(key.value()).map_err(|error| DbError::Data(error.to_string()))?;
            binds.push((id, decode(value.value())?));
        }
        Ok(binds)
    }

    /// Deletes a persistent bind.
    pub fn delete_bind(&self, id: Uuid) -> Result<bool, DbError> {
        let transaction = self.database.begin_write().map_err(redb_error)?;
        let removed = {
            let mut table = transaction.open_table(BINDS).map_err(redb_error)?;
            table.remove(id.as_bytes().as_slice()).map_err(redb_error)?.is_some()
        };
        transaction.commit().map_err(redb_error)?;
        Ok(removed)
    }

    /// Inserts or replaces an authorized-key record atomically.
    pub fn put_key(&self, fingerprint: &str, key: &AuthorizedKey) -> Result<(), DbError> {
        let encoded = encode(key)?;
        let mut transaction = self.database.begin_write().map_err(redb_error)?;
        transaction.set_durability(Durability::Immediate).map_err(redb_error)?;
        {
            let mut table = transaction.open_table(KEYS).map_err(redb_error)?;
            table.insert(fingerprint, encoded.as_slice()).map_err(redb_error)?;
        }
        transaction.commit().map_err(redb_error)
    }

    /// Reads one authorized-key record.
    pub fn get_key(&self, fingerprint: &str) -> Result<Option<AuthorizedKey>, DbError> {
        let transaction = self.database.begin_read().map_err(redb_error)?;
        let table = transaction.open_table(KEYS).map_err(redb_error)?;
        decode_optional(table.get(fingerprint).map_err(redb_error)?)
    }

    /// Lists all authorized-key records.
    pub fn list_keys(&self) -> Result<Vec<(String, AuthorizedKey)>, DbError> {
        let transaction = self.database.begin_read().map_err(redb_error)?;
        let table = transaction.open_table(KEYS).map_err(redb_error)?;
        let mut keys = Vec::new();
        for entry in table.iter().map_err(redb_error)? {
            let (key, value) = entry.map_err(redb_error)?;
            keys.push((key.value().to_owned(), decode(value.value())?));
        }
        Ok(keys)
    }

    /// Stores a buffered webhook payload.
    pub fn put_buffered(&self, bind: Uuid, seq: u64, request: &[u8]) -> Result<(), DbError> {
        self.put_raw(WEBHOOK_BUFFER, &buffer_key(bind, seq), request)
    }

    /// Reads a buffered webhook payload.
    pub fn get_buffered(&self, bind: Uuid, seq: u64) -> Result<Option<Vec<u8>>, DbError> {
        self.get_raw(WEBHOOK_BUFFER, &buffer_key(bind, seq))
    }

    /// Deletes a buffered webhook payload.
    pub fn delete_buffered(&self, bind: Uuid, seq: u64) -> Result<bool, DbError> {
        self.delete_raw(WEBHOOK_BUFFER, &buffer_key(bind, seq))
    }

    /// Stores a failed webhook record.
    pub fn put_failed(&self, bind: Uuid, seq: u64, failed: &FailedWebhook) -> Result<(), DbError> {
        self.put_raw(WEBHOOK_FAILED, &buffer_key(bind, seq), &encode(failed)?)
    }

    /// Reads a failed webhook record.
    pub fn get_failed(&self, bind: Uuid, seq: u64) -> Result<Option<FailedWebhook>, DbError> {
        self.get_raw(WEBHOOK_FAILED, &buffer_key(bind, seq))?
            .map(|value| decode(&value))
            .transpose()
    }

    /// Atomically reserves quotas, assigns a sequence, and commits one webhook.
    pub fn enqueue_buffered(
        &self,
        bind: Uuid,
        key_fpr: &str,
        mut request: BufferedRequest,
        quotas: BufferQuotas,
    ) -> Result<u64, DbError> {
        self.prune_expired(bind, quotas.ttl_secs)?;
        let mut transaction = self.database.begin_write().map_err(redb_error)?;
        transaction.set_durability(Durability::Immediate).map_err(redb_error)?;
        let owned_binds = {
            let table = transaction.open_table(BINDS).map_err(redb_error)?;
            let mut owned = std::collections::HashSet::new();
            for entry in table.iter().map_err(redb_error)? {
                let (stored_key, value) = entry.map_err(redb_error)?;
                let record: PersistedBind = decode(value.value())?;
                if record.key_fpr == key_fpr
                    && let Ok(bytes) = <[u8; 16]>::try_from(stored_key.value())
                {
                    owned.insert(Uuid::from_bytes(bytes));
                }
            }
            owned
        };
        let mut total_bytes = 0_u64;
        let mut key_bytes = 0_u64;
        let mut count = 0_u32;
        {
            let table = transaction.open_table(WEBHOOK_BUFFER).map_err(redb_error)?;
            for entry in table.iter().map_err(redb_error)? {
                let (stored_key, value) = entry.map_err(redb_error)?;
                let request: BufferedRequest = decode(value.value())?;
                let charged = buffered_charge(&request)?;
                total_bytes = total_bytes.saturating_add(charged);
                if let Some((stored_bind, _)) = parse_buffer_key(stored_key.value()) {
                    if stored_bind == bind {
                        count = count.saturating_add(1);
                    }
                    if owned_binds.contains(&stored_bind) {
                        key_bytes = key_bytes.saturating_add(charged);
                    }
                }
            }
        }
        {
            let table = transaction.open_table(WEBHOOK_FAILED).map_err(redb_error)?;
            for entry in table.iter().map_err(redb_error)? {
                let (stored_key, value) = entry.map_err(redb_error)?;
                total_bytes = total_bytes.saturating_add(value.value().len() as u64);
                if let Some((stored_bind, _)) = parse_buffer_key(stored_key.value())
                    && owned_binds.contains(&stored_bind)
                {
                    key_bytes = key_bytes.saturating_add(value.value().len() as u64);
                }
            }
        }
        if count >= quotas.max_requests {
            return Err(DbError::BufferQuota("endpoint request count reached".to_owned()));
        }
        let next_seq = {
            let mut sequences = transaction.open_table(WEBHOOK_SEQUENCE).map_err(redb_error)?;
            let previous = sequences
                .get(bind.as_bytes().as_slice())
                .map_err(redb_error)?
                .map_or(0, |value| value.value());
            let next = previous.checked_add(1).ok_or_else(|| {
                DbError::BufferQuota("endpoint sequence space exhausted".to_owned())
            })?;
            sequences.insert(bind.as_bytes().as_slice(), next).map_err(redb_error)?;
            next
        };
        request.seq = next_seq;
        let encoded = encode(&request)?;
        let added = buffered_charge(&request)?;
        if total_bytes.saturating_add(added) > quotas.total_bytes
            || key_bytes.saturating_add(added) > quotas.key_bytes
        {
            return Err(DbError::BufferQuota("byte quota reached".to_owned()));
        }
        {
            let mut table = transaction.open_table(WEBHOOK_BUFFER).map_err(redb_error)?;
            table
                .insert(buffer_key(bind, next_seq).as_slice(), encoded.as_slice())
                .map_err(redb_error)?;
        }
        transaction.commit().map_err(redb_error)?;
        Ok(next_seq)
    }

    /// Returns the oldest active buffered request for one bind.
    pub fn first_buffered(&self, bind: Uuid) -> Result<Option<BufferedRequest>, DbError> {
        let transaction = self.database.begin_read().map_err(redb_error)?;
        let table = transaction.open_table(WEBHOOK_BUFFER).map_err(redb_error)?;
        let mut first = None;
        for entry in table.iter().map_err(redb_error)? {
            let (key, value) = entry.map_err(redb_error)?;
            if parse_buffer_key(key.value()).is_some_and(|(stored, _)| stored == bind) {
                let request = decode::<BufferedRequest>(value.value())?;
                if first.as_ref().is_none_or(|current: &BufferedRequest| request.seq < current.seq)
                {
                    first = Some(request);
                }
            }
        }
        Ok(first)
    }

    /// Returns active and failed queue counts for one bind.
    pub fn buffered_counts(&self, bind: Uuid) -> Result<(u32, u32), DbError> {
        Ok((self.count_raw(WEBHOOK_BUFFER, bind)?, self.count_raw(WEBHOOK_FAILED, bind)?))
    }

    fn put_raw(
        &self,
        definition: TableDefinition<&[u8], &[u8]>,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), DbError> {
        let transaction = self.database.begin_write().map_err(redb_error)?;
        {
            let mut table = transaction.open_table(definition).map_err(redb_error)?;
            table.insert(key, value).map_err(redb_error)?;
        }
        transaction.commit().map_err(redb_error)
    }

    fn get_raw(
        &self,
        definition: TableDefinition<&[u8], &[u8]>,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, DbError> {
        let transaction = self.database.begin_read().map_err(redb_error)?;
        let table = transaction.open_table(definition).map_err(redb_error)?;
        Ok(table.get(key).map_err(redb_error)?.map(|value| value.value().to_vec()))
    }

    pub(crate) fn delete_raw(
        &self,
        definition: TableDefinition<&[u8], &[u8]>,
        key: &[u8],
    ) -> Result<bool, DbError> {
        let transaction = self.database.begin_write().map_err(redb_error)?;
        let removed = {
            let mut table = transaction.open_table(definition).map_err(redb_error)?;
            table.remove(key).map_err(redb_error)?.is_some()
        };
        transaction.commit().map_err(redb_error)?;
        Ok(removed)
    }
}

fn initialize_schema(database: &Database, version: u64) -> Result<(), DbError> {
    let mut transaction = database.begin_write().map_err(redb_error)?;
    transaction.set_durability(Durability::Immediate).map_err(redb_error)?;
    {
        transaction.open_table(BINDS).map_err(redb_error)?;
        transaction.open_table(KEYS).map_err(redb_error)?;
        transaction.open_table(INVITES).map_err(redb_error)?;
        transaction.open_table(WEBHOOK_BUFFER).map_err(redb_error)?;
        transaction.open_table(WEBHOOK_FAILED).map_err(redb_error)?;
        transaction.open_table(WEBHOOK_SEQUENCE).map_err(redb_error)?;
        let mut meta = transaction.open_table(META).map_err(redb_error)?;
        meta.insert(SCHEMA_VERSION_KEY, version).map_err(redb_error)?;
    }
    transaction.commit().map_err(redb_error)
}

fn read_schema(database: &Database) -> Result<u64, DbError> {
    let transaction = database.begin_read().map_err(redb_error)?;
    let table = match transaction.open_table(META) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
        Err(error) => return Err(redb_error(error)),
    };
    Ok(table.get(SCHEMA_VERSION_KEY).map_err(redb_error)?.map_or(0, |value| value.value()))
}

fn migrate(path: &Utf8Path, data_dir: &Utf8Path, old: u64) -> Result<(), DbError> {
    let backups = data_dir.join("backups");
    fs::create_dir_all(&backups).map_err(|source| DbError::Io { path: backups.clone(), source })?;
    let stamp = Timestamp::now().as_second();
    let backup = backups.join(format!("state-v{old}-{stamp}.redb"));
    copy_synced(path, &backup)?;
    retain_latest_backups(&backups)?;
    let temporary = data_dir.join(format!(".state-migrate-{stamp}.redb"));
    copy_synced(path, &temporary)?;
    let migrated = Database::create(&temporary).map_err(redb_error)?;
    initialize_schema(&migrated, CURRENT_SCHEMA)?;
    drop(migrated);
    fs::rename(&temporary, path).map_err(|source| DbError::Io { path: path.to_owned(), source })?;
    FileSync::directory(data_dir)?;
    Ok(())
}

fn retain_latest_backups(directory: &Utf8Path) -> Result<(), DbError> {
    let mut backups = fs::read_dir(directory)
        .map_err(|source| DbError::Io { path: directory.to_owned(), source })?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("state-v"))
        .collect::<Vec<_>>();
    backups.sort_by_key(|entry| entry.metadata().and_then(|metadata| metadata.modified()).ok());
    let remove_count = backups.len().saturating_sub(2);
    for entry in backups.into_iter().take(remove_count) {
        fs::remove_file(entry.path()).map_err(|source| DbError::Io {
            path: Utf8PathBuf::from_path_buf(entry.path())
                .unwrap_or_else(|path| Utf8PathBuf::from(path.to_string_lossy().as_ref())),
            source,
        })?;
    }
    Ok(())
}

fn copy_synced(source: &Utf8Path, destination: &Utf8Path) -> Result<(), DbError> {
    fs::copy(source, destination)
        .map_err(|error| DbError::Io { path: destination.to_owned(), source: error })?;
    fs::File::open(destination)
        .and_then(|file| file.sync_all())
        .map_err(|source| DbError::Io { path: destination.to_owned(), source })
}

struct FileSync;

impl FileSync {
    fn directory(path: &Utf8Path) -> Result<(), DbError> {
        fs::File::open(path)
            .and_then(|file| file.sync_all())
            .map_err(|source| DbError::Io { path: path.to_owned(), source })
    }
}

pub(crate) fn buffer_key(bind: Uuid, seq: u64) -> [u8; 24] {
    let mut key = [0_u8; 24];
    key[..16].copy_from_slice(bind.as_bytes());
    key[16..].copy_from_slice(&seq.to_be_bytes());
    key
}

pub(crate) fn parse_buffer_key(key: &[u8]) -> Option<(Uuid, u64)> {
    let bind = Uuid::from_slice(key.get(..16)?).ok()?;
    let sequence = u64::from_be_bytes(key.get(16..24)?.try_into().ok()?);
    Some((bind, sequence))
}

pub(crate) fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, DbError> {
    serde_json::to_vec(value).map_err(|error| DbError::Data(error.to_string()))
}

pub(crate) fn decode<T: DeserializeOwned>(value: &[u8]) -> Result<T, DbError> {
    serde_json::from_slice(value).map_err(|error| DbError::Data(error.to_string()))
}

fn decode_optional<T: DeserializeOwned>(
    value: Option<redb::AccessGuard<'_, &[u8]>>,
) -> Result<Option<T>, DbError> {
    value.map(|guard| decode(guard.value())).transpose()
}

fn set_mode(path: &Utf8Path, mode: u32) -> Result<(), DbError> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|source| DbError::Io { path: path.to_owned(), source })
}

fn buffered_charge(request: &BufferedRequest) -> Result<u64, DbError> {
    let active = encode(request)?.len();
    let failed = encode(&FailedWebhook {
        request: request.clone(),
        reason: "😀".repeat(512),
        failed_at: Timestamp::now(),
    })?
    .len();
    Ok(active.max(failed).try_into().unwrap_or(u64::MAX))
}

pub(crate) fn redb_error(error: impl std::fmt::Display) -> DbError {
    DbError::Redb(error.to_string())
}

/// Relay persistence failure.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    /// redb operation failed.
    #[error("redb operation failed: {0}")]
    Redb(String),
    /// Serialized data was invalid.
    #[error("invalid persisted data: {0}")]
    Data(String),
    /// Filesystem operation failed.
    #[error("database filesystem operation failed for {path}: {source}")]
    Io { path: Utf8PathBuf, source: io::Error },
    /// A durable buffer quota was exhausted.
    #[error("buffer quota exceeded: {0}")]
    BufferQuota(String),
    /// Database schema was created by a newer relay.
    #[error("database schema {found} is newer than supported schema {supported}")]
    NewerSchema { found: u64, supported: u64 },
}

#[cfg(test)]
#[path = "db_tests.rs"]
mod tests;
