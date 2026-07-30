//! Bearer authentication middleware for operational local API routes.

use axum::{
    Json,
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::Next,
    response::{IntoResponse as _, Response},
};
use subtle::ConstantTimeEq as _;
use utoipa::Modify;

use crate::api_types::{ApiErrorBody, ApiErrorDetail, ApiState};

pub struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        use utoipa::openapi::security::{
            Http, HttpAuthScheme, SecurityRequirement, SecurityScheme,
        };
        openapi.components.get_or_insert_default().add_security_scheme(
            "bearer_auth",
            SecurityScheme::Http(Http::new(HttpAuthScheme::Bearer)),
        );
        openapi.security =
            Some(vec![SecurityRequirement::new("bearer_auth", Vec::<String>::new())]);
    }
}

pub async fn authorize(State(state): State<ApiState>, request: Request, next: Next) -> Response {
    let supplied = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let accepted = supplied.is_some_and(|value| {
        value.len() == state.token.len() && value.as_bytes().ct_eq(state.token.as_bytes()).into()
    });
    if accepted {
        next.run(request).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(ApiErrorBody {
                error: ApiErrorDetail {
                    code: "unauthorized".to_owned(),
                    message: "missing or invalid bearer token".to_owned(),
                },
            }),
        )
            .into_response()
    }
}
