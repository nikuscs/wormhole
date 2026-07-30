use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::admin::{AdminResponseError, AdminState, bad_request, internal};

#[utoipa::path(get, path = "/v1/invites", responses((status = 200, body = [InviteResponse])))]
pub async fn list(
    State(admin): State<AdminState>,
) -> Result<Json<Vec<InviteResponse>>, AdminResponseError> {
    let invites = admin
        .state
        .auth
        .list_invites()
        .map_err(internal)?
        .into_iter()
        .map(InviteResponse::from)
        .collect();
    Ok(Json(invites))
}

#[utoipa::path(post, path = "/v1/invites", request_body = CreateInviteRequest, responses((status = 201, body = CreatedInviteResponse), (status = 400)))]
pub async fn create(
    State(admin): State<AdminState>,
    Json(request): Json<CreateInviteRequest>,
) -> Result<(StatusCode, Json<CreatedInviteResponse>), AdminResponseError> {
    let created = admin
        .state
        .auth
        .create_invite(&request.name, request.ttl_secs, request.max_uses)
        .map_err(bad_request)?;
    Ok((StatusCode::CREATED, Json(CreatedInviteResponse::from(created))))
}

#[utoipa::path(delete, path = "/v1/invites/{id}", params(("id" = String, Path)), responses((status = 204), (status = 400)))]
pub async fn revoke(
    State(admin): State<AdminState>,
    Path(id): Path<String>,
) -> Result<StatusCode, AdminResponseError> {
    admin.state.auth.revoke_invite(&id).map_err(bad_request)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CreateInviteRequest {
    pub name: String,
    pub ttl_secs: Option<u64>,
    pub max_uses: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CreatedInviteResponse {
    pub id: String,
    pub token: String,
    pub name: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub max_uses: Option<u32>,
}

impl From<crate::authz::CreatedInvite> for CreatedInviteResponse {
    fn from(value: crate::authz::CreatedInvite) -> Self {
        Self {
            id: value.id,
            token: value.token,
            name: value.name,
            created_at: value.created_at,
            expires_at: value.expires_at,
            max_uses: value.max_uses,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct InviteResponse {
    pub id: String,
    pub name: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub max_uses: Option<u32>,
    pub uses: u32,
    pub revoked: bool,
}

impl From<crate::db::EnrollmentInvite> for InviteResponse {
    fn from(value: crate::db::EnrollmentInvite) -> Self {
        Self {
            id: value.id,
            name: value.name,
            created_at: value.created_at,
            expires_at: value.expires_at,
            max_uses: value.max_uses,
            uses: value.uses,
            revoked: value.revoked,
        }
    }
}
