use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use worker::{Env, Method, Request, Response, Result, SqlStorage};

use crate::{api, storage};

const MAX_ADMIN_BODY: usize = 8 * 1024;

#[derive(Deserialize)]
struct CreateInvite {
    name: String,
    ttl_secs: Option<u64>,
    max_uses: Option<u32>,
}

#[derive(Serialize)]
struct CreatedInvite {
    id: String,
    token: String,
    name: String,
    created_at: i64,
    expires_at: Option<i64>,
    max_uses: Option<u32>,
}

pub async fn handle(mut request: Request, env: &Env, sql: &SqlStorage) -> Result<Response> {
    if !authorized(&request, env)? {
        return api::error(401, "admin_unauthorized", "valid administrator bearer token required");
    }
    let path = request.path();
    match (request.method(), path.as_str()) {
        (Method::Get, "/_wormhole/admin/invites") => list(sql),
        (Method::Post, "/_wormhole/admin/invites") => create(&mut request, sql).await,
        (Method::Delete, path) if path.starts_with("/_wormhole/admin/invites/") => {
            revoke(sql, path.trim_start_matches("/_wormhole/admin/invites/"))
        }
        _ => api::error(404, "not_found", "administration endpoint not found"),
    }
}

fn authorized(request: &Request, env: &Env) -> Result<bool> {
    let expected = env.secret("ADMIN_TOKEN")?.to_string();
    let Some(presented) = request.headers().get("authorization")? else {
        return Ok(false);
    };
    let Some(presented) = presented.strip_prefix("Bearer ") else {
        return Ok(false);
    };
    let left = Sha256::digest(presented.as_bytes());
    let right = Sha256::digest(expected.as_bytes());
    Ok(bool::from(left.as_slice().ct_eq(right.as_slice())))
}

async fn create(request: &mut Request, sql: &SqlStorage) -> Result<Response> {
    if request
        .headers()
        .get("content-length")?
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > MAX_ADMIN_BODY)
    {
        return api::error(413, "admin_body_too_large", "administration body exceeds 8 KiB");
    }
    let body = request.bytes().await?;
    if body.len() > MAX_ADMIN_BODY {
        return api::error(413, "admin_body_too_large", "administration body exceeds 8 KiB");
    }
    let input: CreateInvite = match serde_json::from_slice(&body) {
        Ok(input) => input,
        Err(_) => return api::error(400, "invalid_json", "invalid invite request"),
    };
    let name = input.name.trim();
    if name.is_empty() || name.len() > 128 || input.max_uses == Some(0) {
        return api::error(400, "invalid_invite", "invite name or usage constraint is invalid");
    }
    let now = now_seconds();
    let expires_at = match input.ttl_secs {
        Some(0) => return api::error(400, "invalid_invite", "invite TTL must be positive"),
        Some(ttl) => i64::try_from(ttl).ok().and_then(|ttl| now.checked_add(ttl)),
        None => None,
    };
    if input.ttl_secs.is_some() && expires_at.is_none() {
        return api::error(400, "invalid_invite", "invite TTL is too large");
    }
    let id = random_token(9)?;
    let secret = random_token(32)?;
    let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()));
    sql.exec(
        "INSERT INTO invites(id,secret_sha256,name,created_at,expires_at,max_uses) VALUES(?,?,?,?,?,?)",
        vec![id.as_str().into(), digest.into(), name.into(), now.into(), expires_at.into(), input.max_uses.map(i64::from).into()],
    )?;
    api::json(
        201,
        &CreatedInvite {
            id: id.clone(),
            token: format!("whi_{id}_{secret}"),
            name: name.to_owned(),
            created_at: now,
            expires_at,
            max_uses: input.max_uses,
        },
    )
}

fn list(sql: &SqlStorage) -> Result<Response> {
    api::json(200, &storage::invites(sql)?)
}

fn revoke(sql: &SqlStorage, id: &str) -> Result<Response> {
    if id.is_empty() || id.len() > 64 {
        return api::error(400, "invalid_invite", "invalid invite identifier");
    }
    let cursor = sql.exec("UPDATE invites SET revoked=1 WHERE id=?", vec![id.into()])?;
    if cursor.rows_written() == 0 {
        return api::error(404, "invite_not_found", "invite not found");
    }
    api::empty(204)
}

pub fn random_token(bytes: usize) -> Result<String> {
    let mut value = vec![0_u8; bytes];
    getrandom::fill(&mut value).map_err(|error| worker::Error::RustError(error.to_string()))?;
    Ok(URL_SAFE_NO_PAD.encode(value))
}

pub fn now_seconds() -> i64 {
    i64::try_from(worker::Date::now().as_millis() / 1000).unwrap_or(i64::MAX)
}
