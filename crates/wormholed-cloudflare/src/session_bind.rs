//! Hostname ownership for binds: creation, adoption, and release.

use worker::{Result, SqlStorage, State};
use wormhole_proto::frames::Persistence;

use super::super::{connection_is_live, protocol_error, secure_uuid, valid_label};
use crate::{
    admin, edge_auth,
    storage::{self, BindRow},
};

const GENERATED_ATTEMPTS: usize = 64;

/// Identifies the client asking for a hostname.
pub(super) struct Owner<'a> {
    pub state: &'a State,
    pub sql: &'a SqlStorage,
    pub connection: &'a str,
    pub fingerprint: &'a str,
}

pub(super) fn create_bind(
    owner: &Owner<'_>,
    requested_host: (Option<&str>, bool),
    domain: &str,
    persist: Persistence,
    verifier: &edge_auth::Verifier,
) -> Result<Option<BindRow>> {
    let Owner { sql, connection, fingerprint, .. } = *owner;
    let (host, auto_host) = requested_host;
    if host.is_some_and(|host| !valid_label(host)) {
        return Err(protocol_error("invalid hostname label"));
    }
    if let Some(host) = host {
        let hostname = format!("{host}.{domain}");
        if let Some(row) = adopt(owner, &hostname, persist, verifier)? {
            return Ok(Some(row));
        }
    }
    let attempts = if host.is_some() && !auto_host { 1 } else { GENERATED_ATTEMPTS };
    for attempt in 0..attempts {
        let label = candidate_label(host, attempt)?;
        let hostname = format!("{label}.{domain}");
        let bind = secure_uuid()?.to_string();
        let reservation = (persist == Persistence::Persistent)
            .then(secure_uuid)
            .transpose()?
            .map(|id| id.to_string());
        let cursor = sql.exec(
            "INSERT OR IGNORE INTO binds(bind_id,reservation,fingerprint,hostname,persistent,connection_id,state,created_at,last_active_at,basic_hmac,bearer_hmac,link_hmac_key) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            vec![
                bind.as_str().into(),
                reservation.as_deref().into(),
                fingerprint.into(),
                hostname.as_str().into(),
                i64::from(persist == Persistence::Persistent).into(),
                connection.into(),
                "pending".into(),
                admin::now_seconds().into(),
                admin::now_seconds().into(),
                verifier.basic_hmac.as_deref().into(),
                verifier.bearer_hmac.as_deref().into(),
                verifier.link_hmac_key.as_deref().into(),
            ],
        )?;
        if cursor.rows_written() > 0 {
            return storage::bind_by_id(sql, &bind);
        }
    }
    Ok(None)
}

/// Whether `row` may be taken over by `fingerprint` on a new connection.
///
/// Ownership is the first gate: another client's hostname is never adoptable. Beyond that, a bind
/// only holds its hostname while it can still serve. A row left `online` by a connection that
/// vanished — an evicted object, a killed process — would otherwise own its label forever, with no
/// way to release it, which is precisely the state that breaks a stable URL.
pub(super) fn adoptable(row: &BindRow, fingerprint: &str, is_live: impl Fn(&str) -> bool) -> bool {
    if row.fingerprint != fingerprint {
        return false;
    }
    if row.state != "online" {
        return true;
    }
    row.connection_id.as_deref().is_none_or(|connection| !is_live(connection))
}

/// Drops the rows a departed connection left behind.
///
/// Temporary binds die with their connection; persistent ones keep their reservation but stop
/// claiming a live connection, so the hostname can be taken back.
pub(super) fn retire_session(sql: &SqlStorage, connection: &str) -> Result<()> {
    sql.exec("DELETE FROM sessions WHERE connection_id=?", vec![connection.into()])?;
    sql.exec("DELETE FROM binds WHERE connection_id=? AND persistent=0", vec![connection.into()])?;
    sql.exec(
        "UPDATE binds SET connection_id=NULL,state='offline',last_active_at=? WHERE connection_id=? AND persistent=1",
        vec![admin::now_seconds().into(), connection.into()],
    )?;
    Ok(())
}

/// Takes back a hostname this client already owns but is no longer serving.
///
/// A client that restarts asks for the same label again. Without this, its own dormant bind makes
/// the label look taken and the caller receives a suffixed one instead, which breaks every URL
/// configured elsewhere: OAuth redirects, webhooks, bookmarks. Only a bind with the same
/// fingerprint and no live connection is adoptable, so this cannot take another client's hostname.
fn adopt(
    owner: &Owner<'_>,
    hostname: &str,
    persist: Persistence,
    verifier: &edge_auth::Verifier,
) -> Result<Option<BindRow>> {
    let Owner { state, sql, connection, fingerprint } = *owner;
    let Some(row) = storage::bind_by_host(sql, hostname)? else {
        return Ok(None);
    };
    if !adoptable(&row, fingerprint, |connection| connection_is_live(state, connection)) {
        return Ok(None);
    }
    let persistent = persist == Persistence::Persistent;
    let reservation = match (persistent, row.reservation.as_deref()) {
        (true, Some(existing)) => Some(existing.to_owned()),
        (true, None) => Some(secure_uuid()?.to_string()),
        (false, _) => None,
    };
    sql.exec(
        "UPDATE binds SET connection_id=?,state='pending',last_active_at=?,reservation=?,persistent=?,basic_hmac=?,bearer_hmac=?,link_hmac_key=? WHERE bind_id=?",
        vec![
            connection.into(),
            admin::now_seconds().into(),
            reservation.as_deref().into(),
            i64::from(persistent).into(),
            verifier.basic_hmac.as_deref().into(),
            verifier.bearer_hmac.as_deref().into(),
            verifier.link_hmac_key.as_deref().into(),
            row.bind_id.as_str().into(),
        ],
    )?;
    storage::bind_by_id(sql, &row.bind_id)
}

pub(super) fn candidate_label(host: Option<&str>, attempt: usize) -> Result<String> {
    match (host, attempt) {
        (Some(host), 0) => Ok(host.to_owned()),
        (Some(host), _) => {
            let prefix = host.get(..56).unwrap_or(host).trim_end_matches('-');
            let suffix = &secure_uuid()?.simple().to_string()[..6];
            Ok(format!("{prefix}-{suffix}"))
        }
        (None, _) => Ok(format!("wh-{}", &secure_uuid()?.simple().to_string()[..12])),
    }
}

pub(super) fn reclaim(
    sql: &SqlStorage,
    connection: &str,
    fingerprint: &str,
    reservation: uuid::Uuid,
) -> Result<BindRow> {
    let reservation = reservation.to_string();
    let row = storage::bind_by_reservation(sql, &reservation)?
        .ok_or_else(|| protocol_error("unknown reservation"))?;
    if row.fingerprint != fingerprint || row.state == "online" {
        return Err(protocol_error("reservation is unavailable"));
    }
    sql.exec(
        "UPDATE binds SET connection_id=?,state='pending',last_active_at=? WHERE bind_id=?",
        vec![connection.into(), admin::now_seconds().into(), row.bind_id.as_str().into()],
    )?;
    storage::bind_by_id(sql, &row.bind_id)?.ok_or_else(|| protocol_error("reclaimed bind missing"))
}

/// Cutoff for a configured idle window, or `None` when a non-positive window disables ageing.
pub(super) const fn cutoff_from_ttl(ttl: i64, now: i64) -> Option<i64> {
    if ttl > 0 { Some(now.saturating_sub(ttl)) } else { None }
}

#[cfg(test)]
#[path = "session_control_tests.rs"]
mod tests;
