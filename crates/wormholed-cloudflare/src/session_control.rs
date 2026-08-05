use std::cell::RefCell;

use worker::{Env, Result, SqlStorage, State, WebSocket};
use wormhole_proto::frames::{
    BindSpec, ControlFrame, DenyReason, Limits, PROTO_VERSION, Persistence,
};
use wormhole_proto::{PublicKeyRef, verify_challenge};

use super::{
    MAX_BINDS, MAX_STREAMS, Runtime, SocketAttachment, bind_error, close_protocol,
    connection_is_live, control_domain, deny, invite_digest, parse_uuid, protocol_error,
    relay_domain, secure_uuid, send_control, session_connections, socket_attachment,
};
/// One day of inactivity, which spans an overnight gap without ageing out a live worktree.
const DEFAULT_IDLE_TTL_SECONDS: i64 = 24 * 60 * 60;

use crate::{
    admin, edge_auth,
    storage::{self, AuthRow},
};

pub fn handle_control(
    state: &State,
    env: &Env,
    runtime: &RefCell<Runtime>,
    ws: &WebSocket,
    connection: &str,
    frame: ControlFrame,
) -> Result<()> {
    let sql = state.storage().sql();
    match socket_attachment(&sql, ws, connection)? {
        SocketAttachment::Unauthenticated => match frame {
            ControlFrame::Hello { proto, pubkey, invite, .. } => {
                hello(env, ws, proto, &pubkey, invite.as_deref())
            }
            _ => close_protocol(ws, "expected client hello"),
        },
        SocketAttachment::Pending(auth) => match frame {
            ControlFrame::Auth { signature } => {
                authenticate(state, env, runtime, &sql, ws, (connection, &auth, &signature))
            }
            _ => close_protocol(ws, "expected authentication proof"),
        },
        SocketAttachment::Authenticated { fingerprint } => control_authenticated(
            &Control { state, env, runtime, sql: &sql },
            ws,
            connection,
            &fingerprint,
            frame,
        ),
        SocketAttachment::Retired => close_protocol(ws, "session was superseded"),
    }
}

fn hello(
    env: &Env,
    ws: &WebSocket,
    proto: u16,
    public_key: &str,
    invite: Option<&str>,
) -> Result<()> {
    if proto != PROTO_VERSION {
        return deny(ws, DenyReason::VersionMismatch { expected: PROTO_VERSION });
    }
    if PublicKeyRef::parse(public_key).is_err() {
        return deny(ws, DenyReason::UnknownKey);
    }
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).map_err(protocol_error)?;
    let (invite_id, invite_digest) = invite.and_then(invite_digest).unzip();
    let encoded_nonce = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce);
    ws.serialize_attachment(SocketAttachment::Pending(AuthRow {
        public_key: public_key.to_owned(),
        nonce: encoded_nonce.clone(),
        invite_id,
        invite_sha256: invite_digest,
    }))?;
    send_control(
        ws,
        &ControlFrame::Challenge { nonce: encoded_nonce, server: control_domain(env)? },
    )
}

fn authenticate(
    state: &State,
    env: &Env,
    runtime: &RefCell<Runtime>,
    sql: &SqlStorage,
    ws: &WebSocket,
    details: (&str, &AuthRow, &str),
) -> Result<()> {
    let (connection, auth, signature) = details;
    let nonce: [u8; 32] =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &auth.nonce)
            .map_err(protocol_error)?
            .try_into()
            .map_err(|_| protocol_error("invalid stored nonce"))?;
    if !verify_challenge(&auth.public_key, &nonce, &control_domain(env)?, PROTO_VERSION, signature)
    {
        return deny(ws, DenyReason::BadSignature);
    }
    let key_ref = PublicKeyRef::parse(&auth.public_key).map_err(protocol_error)?;
    let fingerprint = key_ref.fingerprint();
    match storage::key(sql, &auth.public_key)? {
        Some(key) if key.revoked != 0 => return deny(ws, DenyReason::KeyRevoked),
        Some(key) if key.fingerprint == fingerprint => {}
        Some(_) => return deny(ws, DenyReason::UnknownKey),
        None if !redeem(sql, auth, &fingerprint)? => return deny(ws, DenyReason::UnknownKey),
        None => {}
    }
    // One key runs many tunnels at once: parallel worktrees are the point of the tool. Retiring
    // sibling connections here would make them evict each other forever, so only connections that
    // have actually gone away are cleaned up.
    for previous in session_connections(sql, &fingerprint)? {
        if previous == connection || connection_is_live(state, &previous) {
            continue;
        }
        runtime.borrow_mut().invalidate_connection(&previous);
        retire_session(sql, &previous)?;
    }
    // Every connection pays for a small sweep, which keeps abandoned worktree reservations from
    // accumulating without a scheduled job or any extra Worker invocation.
    if let Some(cutoff) = idle_cutoff(env)? {
        storage::sweep_idle_binds(sql, &fingerprint, cutoff)?;
    }
    runtime.borrow_mut().invalidate_fingerprint(&fingerprint);
    sql.exec("DELETE FROM pending_auth WHERE connection_id=?", vec![connection.into()])?;
    sql.exec(
        "INSERT OR REPLACE INTO sessions(connection_id,fingerprint,connected_at) VALUES(?,?,?)",
        vec![connection.into(), fingerprint.as_str().into(), admin::now_seconds().into()],
    )?;
    ws.serialize_attachment(SocketAttachment::Authenticated { fingerprint })?;
    let session = secure_uuid()?;
    send_control(
        ws,
        &ControlFrame::Welcome {
            session,
            limits: Limits { max_binds: MAX_BINDS as u32, max_streams: MAX_STREAMS },
            motd: Some("Cloudflare Worker relay: HTTP/WebSocket transport only".to_owned()),
            domains: vec![relay_domain(env)?],
        },
    )
}

/// Timestamp before which an unused reservation is abandoned, or `None` when ageing is disabled.
///
/// `BIND_IDLE_TTL_SECONDS` is read per deployment so an operator can lengthen, shorten, or switch
/// the behaviour off with `0` without shipping new code.
fn idle_cutoff(env: &Env) -> Result<Option<i64>> {
    let ttl = env
        .var("BIND_IDLE_TTL_SECONDS")
        .ok()
        .map(|value| value.to_string())
        .map_or(Ok(DEFAULT_IDLE_TTL_SECONDS), |value| value.trim().parse::<i64>())
        .map_err(protocol_error)?;
    Ok(cutoff_from_ttl(ttl, admin::now_seconds()))
}

fn redeem(sql: &SqlStorage, auth: &AuthRow, fingerprint: &str) -> Result<bool> {
    let (Some(id), Some(digest)) = (&auth.invite_id, &auth.invite_sha256) else { return Ok(false) };
    let now = admin::now_seconds();
    let cursor = sql.exec(
        "INSERT INTO keys(fingerprint,public_key,name,created_at,revoked,enrolled_invite) SELECT ?,?,name,?,0,id FROM invites WHERE id=? AND secret_sha256=? AND revoked=0 AND (expires_at IS NULL OR expires_at>=?) AND (max_uses IS NULL OR uses<max_uses)",
        vec![fingerprint.into(), auth.public_key.as_str().into(), now.into(), id.as_str().into(), digest.as_str().into(), now.into()],
    )?;
    Ok(cursor.rows_written() > 0)
}

struct Control<'a> {
    state: &'a State,
    env: &'a Env,
    runtime: &'a RefCell<Runtime>,
    sql: &'a SqlStorage,
}

fn control_authenticated(
    control: &Control<'_>,
    ws: &WebSocket,
    connection: &str,
    fingerprint: &str,
    frame: ControlFrame,
) -> Result<()> {
    let Control { runtime, sql, .. } = *control;
    match frame {
        ControlFrame::Bind { request, spec, reservation } => {
            bind(control, ws, connection, fingerprint, (request, spec, reservation))
        }
        ControlFrame::BindReady { bind } => activate(runtime, sql, ws, connection, bind),
        ControlFrame::Unbind { bind, forget } => {
            unbind(runtime, sql, ws, fingerprint, bind, forget)
        }
        ControlFrame::ForgetReservation { reservation } => {
            forget(runtime, sql, ws, fingerprint, reservation)
        }
        ControlFrame::Ping { seq } => send_control(ws, &ControlFrame::Pong { seq }),
        _ => close_protocol(ws, "unexpected post-handshake control frame"),
    }
}

fn bind(
    control: &Control<'_>,
    ws: &WebSocket,
    connection: &str,
    fingerprint: &str,
    details: (uuid::Uuid, BindSpec, Option<uuid::Uuid>),
) -> Result<()> {
    let Control { state, env, runtime, sql } = *control;
    let (request, spec, reservation) = details;
    let BindSpec::Http { host, auto_host, domain, persist, buffer, auth } = spec else {
        return bind_error(ws, request, "raw TCP binds are unsupported by the Cloudflare relay");
    };
    if buffer.is_some() {
        return bind_error(ws, request, "offline buffering is unsupported by the Cloudflare relay");
    }
    let verifier = match edge_auth::build(env, auth.as_ref()) {
        Ok(verifier) => verifier,
        Err(error) => return bind_error(ws, request, &error),
    };
    let relay_domain = relay_domain(env)?;
    if domain.as_deref().is_some_and(|domain| domain != relay_domain) {
        return bind_error(ws, request, "requested domain is not served by this relay");
    }
    let row = if let Some(reservation) = reservation {
        reclaim(sql, connection, fingerprint, reservation)?
    } else {
        if storage::active_bind_count(sql, fingerprint)? >= MAX_BINDS {
            return bind_error(ws, request, "bind limit reached");
        }
        let Some(row) = create_bind(
            &Owner { state, sql, connection, fingerprint },
            (host.as_deref(), auto_host),
            &relay_domain,
            persist,
            &verifier,
        )?
        else {
            return bind_error(ws, request, "requested hostname is unavailable");
        };
        row
    };
    runtime.borrow_mut().invalidate_bind(&row.bind_id);
    send_control(
        ws,
        &ControlFrame::Bound {
            request,
            bind: parse_uuid(&row.bind_id)?,
            urls: vec![format!("https://{}", row.hostname)],
            persist: if row.persistent != 0 {
                Persistence::Persistent
            } else {
                Persistence::Temporary
            },
            reservation: row.reservation.as_deref().map(parse_uuid).transpose()?,
            pending_buffered: 0,
            failed_buffered: 0,
        },
    )
}

fn activate(
    runtime: &RefCell<Runtime>,
    sql: &SqlStorage,
    ws: &WebSocket,
    connection: &str,
    bind: uuid::Uuid,
) -> Result<()> {
    let cursor = sql.exec(
        "UPDATE binds SET state='online',last_active_at=? WHERE bind_id=? AND connection_id=? AND state='pending'",
        vec![admin::now_seconds().into(), bind.to_string().into(), connection.into()],
    )?;
    if cursor.rows_written() != 1 {
        return close_protocol(ws, "bind cannot be activated");
    }
    runtime.borrow_mut().invalidate_bind(&bind.to_string());
    send_control(ws, &ControlFrame::BindActive { bind })
}

fn unbind(
    runtime: &RefCell<Runtime>,
    sql: &SqlStorage,
    ws: &WebSocket,
    fingerprint: &str,
    bind: uuid::Uuid,
    forget: bool,
) -> Result<()> {
    let Some(row) = storage::bind_by_id(sql, &bind.to_string())? else {
        return close_protocol(ws, "unknown bind");
    };
    if row.fingerprint != fingerprint {
        return close_protocol(ws, "bind owner mismatch");
    }
    runtime.borrow_mut().invalidate_bind(&row.bind_id);
    if row.persistent != 0 && !forget {
        sql.exec(
            "UPDATE binds SET connection_id=NULL,state='offline',last_active_at=? WHERE bind_id=?",
            vec![admin::now_seconds().into(), bind.to_string().into()],
        )?;
    } else {
        sql.exec("DELETE FROM binds WHERE bind_id=?", vec![bind.to_string().into()])?;
    }
    send_control(ws, &ControlFrame::Unbound { bind })
}

fn forget(
    runtime: &RefCell<Runtime>,
    sql: &SqlStorage,
    ws: &WebSocket,
    fingerprint: &str,
    reservation: uuid::Uuid,
) -> Result<()> {
    let reservation_id = reservation.to_string();
    runtime.borrow_mut().invalidate_reservation(&reservation_id);
    sql.exec(
        "DELETE FROM binds WHERE reservation=? AND fingerprint=?",
        vec![reservation_id.into(), fingerprint.into()],
    )?;
    send_control(ws, &ControlFrame::ForgotReservation { reservation })
}

#[path = "session_bind.rs"]
mod bind_storage;
use bind_storage::{Owner, create_bind, cutoff_from_ttl, reclaim, retire_session};
