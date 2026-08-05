use serde::{Deserialize, Serialize};
use worker::{Result, SqlStorage, SqlStorageValue};

pub const SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS invites (
  id TEXT PRIMARY KEY, secret_sha256 TEXT NOT NULL, name TEXT NOT NULL,
  created_at INTEGER NOT NULL, expires_at INTEGER, max_uses INTEGER,
  uses INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS keys (
  fingerprint TEXT PRIMARY KEY, public_key TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
  created_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, enrolled_invite TEXT
);
CREATE TRIGGER IF NOT EXISTS consume_invite AFTER INSERT ON keys
WHEN NEW.enrolled_invite IS NOT NULL BEGIN
  UPDATE invites SET uses = uses + 1 WHERE id = NEW.enrolled_invite;
END;
CREATE TABLE IF NOT EXISTS pending_auth (
  connection_id TEXT PRIMARY KEY, public_key TEXT NOT NULL, nonce TEXT NOT NULL,
  invite_id TEXT, invite_sha256 TEXT, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  connection_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, connected_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS binds (
  bind_id TEXT PRIMARY KEY, reservation TEXT UNIQUE, fingerprint TEXT NOT NULL,
  hostname TEXT NOT NULL UNIQUE, persistent INTEGER NOT NULL,
  connection_id TEXT, state TEXT NOT NULL, created_at INTEGER NOT NULL,
  last_active_at INTEGER NOT NULL DEFAULT 0,
  basic_hmac TEXT, bearer_hmac TEXT, link_hmac_key TEXT
);
CREATE INDEX IF NOT EXISTS binds_fingerprint ON binds(fingerprint);
CREATE INDEX IF NOT EXISTS binds_connection ON binds(connection_id);
CREATE INDEX IF NOT EXISTS binds_idle ON binds(state,last_active_at);
CREATE INDEX IF NOT EXISTS sessions_fingerprint ON sessions(fingerprint);
";

/// Columns added after the first release, applied to objects created before them.
///
/// `SQLite` cannot express `ADD COLUMN IF NOT EXISTS`, so each entry is checked against
/// `pragma_table_info` and added only when absent.
const ADDED_COLUMNS: [(&str, &str, &str); 1] =
    [("binds", "last_active_at", "INTEGER NOT NULL DEFAULT 0")];

#[derive(Debug, Deserialize)]
pub struct KeyRow {
    pub fingerprint: String,
    pub revoked: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthRow {
    pub public_key: String,
    pub nonce: String,
    pub invite_id: Option<String>,
    pub invite_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct BindRow {
    pub bind_id: String,
    pub reservation: Option<String>,
    pub fingerprint: String,
    pub hostname: String,
    pub persistent: i64,
    pub connection_id: Option<String>,
    pub state: String,
    pub basic_hmac: Option<String>,
    pub bearer_hmac: Option<String>,
    pub link_hmac_key: Option<String>,
}

impl BindRow {
    pub const fn has_auth(&self) -> bool {
        self.basic_hmac.is_some() || self.bearer_hmac.is_some() || self.link_hmac_key.is_some()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InviteRow {
    pub id: String,
    pub name: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub max_uses: Option<i64>,
    pub uses: i64,
    pub revoked: i64,
}

pub fn initialize(sql: &SqlStorage) -> Result<()> {
    let _cursor = sql.exec(SCHEMA, None)?;
    for (table, column, definition) in ADDED_COLUMNS {
        if column_exists(sql, table, column)? {
            continue;
        }
        let _added =
            sql.exec(&format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"), None)?;
        // Existing rows have no activity history, so treat their creation as their last activity
        // rather than sweeping them on the next connection.
        let _backfilled =
            sql.exec(&format!("UPDATE {table} SET {column}=created_at WHERE {column}=0"), None)?;
    }
    Ok(())
}

fn column_exists(sql: &SqlStorage, table: &str, column: &str) -> Result<bool> {
    #[derive(Deserialize)]
    struct Column {
        name: String,
    }
    // The table name is interpolated because a pragma function will not accept a bound parameter.
    // Both arguments come from `ADDED_COLUMNS`, never from a request.
    Ok(sql
        .exec(&format!("SELECT name FROM pragma_table_info('{table}')"), None)?
        .to_array::<Column>()?
        .iter()
        .any(|entry| entry.name == column))
}

/// Deletes persistent binds their owner has not used for `ttl_seconds`.
///
/// A reservation exists to keep one URL stable, not to hold a name forever. Only offline binds age
/// out, so a tunnel that is currently serving is never swept however old it is.
pub fn sweep_idle_binds(sql: &SqlStorage, fingerprint: &str, cutoff: i64) -> Result<()> {
    let _cursor = sql
        .exec(
            "DELETE FROM binds WHERE fingerprint=? AND persistent=1 AND state='offline' AND last_active_at<?",
        vec![fingerprint.into(), cutoff.into()],
    )?;
    Ok(())
}

pub fn key(sql: &SqlStorage, public_key: &str) -> Result<Option<KeyRow>> {
    one(sql, "SELECT fingerprint,revoked FROM keys WHERE public_key=?", vec![public_key.into()])
}

pub fn pending_auth(sql: &SqlStorage, connection: &str) -> Result<Option<AuthRow>> {
    one(
        sql,
        "SELECT public_key,nonce,invite_id,invite_sha256 FROM pending_auth WHERE connection_id=?",
        vec![connection.into()],
    )
}

pub fn bind_by_host(sql: &SqlStorage, hostname: &str) -> Result<Option<BindRow>> {
    one(
        sql,
        "SELECT bind_id,reservation,fingerprint,hostname,persistent,connection_id,state,basic_hmac,bearer_hmac,link_hmac_key FROM binds WHERE hostname=?",
        vec![hostname.into()],
    )
}

pub fn bind_by_id(sql: &SqlStorage, bind: &str) -> Result<Option<BindRow>> {
    one(
        sql,
        "SELECT bind_id,reservation,fingerprint,hostname,persistent,connection_id,state,basic_hmac,bearer_hmac,link_hmac_key FROM binds WHERE bind_id=?",
        vec![bind.into()],
    )
}

pub fn bind_by_reservation(sql: &SqlStorage, reservation: &str) -> Result<Option<BindRow>> {
    one(
        sql,
        "SELECT bind_id,reservation,fingerprint,hostname,persistent,connection_id,state,basic_hmac,bearer_hmac,link_hmac_key FROM binds WHERE reservation=?",
        vec![reservation.into()],
    )
}

pub fn invites(sql: &SqlStorage) -> Result<Vec<InviteRow>> {
    sql.exec(
        "SELECT id,name,created_at,expires_at,max_uses,uses,revoked FROM invites ORDER BY id",
        None,
    )?
    .to_array()
}

pub fn active_bind_count(sql: &SqlStorage, fingerprint: &str) -> Result<i64> {
    #[derive(Deserialize)]
    struct Count {
        count: i64,
    }
    Ok(sql
        .exec("SELECT COUNT(*) AS count FROM binds WHERE fingerprint=?", vec![fingerprint.into()])?
        .one::<Count>()?
        .count)
}

fn one<T: for<'de> Deserialize<'de>>(
    sql: &SqlStorage,
    query: &str,
    values: Vec<SqlStorageValue>,
) -> Result<Option<T>> {
    let rows = sql.exec(query, values)?.to_array::<T>()?;
    Ok(rows.into_iter().next())
}

#[cfg(test)]
#[path = "storage_tests.rs"]
mod tests;
