use std::sync::Arc;

use anyhow::{Context as _, Result};
use camino::Utf8Path;
use clap::{Args, Subcommand};
use http::Method;

use crate::output;

#[derive(Debug, Args)]
pub struct InviteArgs {
    #[command(subcommand)]
    command: InviteCommand,
}

#[derive(Debug, Subcommand)]
enum InviteCommand {
    /// Create an enrollment invite and print its token once.
    Create {
        /// Display name assigned to clients enrolled with this invite.
        #[arg(long)]
        name: String,
        /// Invite lifetime (default: 10m).
        #[arg(long, conflicts_with = "reusable")]
        ttl: Option<String>,
        /// Maximum successful enrollments (default: 1).
        #[arg(long, conflicts_with = "reusable")]
        uses: Option<u32>,
        /// Create an unlimited, non-expiring invite until explicitly revoked.
        #[arg(long)]
        reusable: bool,
        /// Emit structured JSON, including the one-time plaintext token.
        #[arg(long)]
        json: bool,
    },
    /// List invite metadata; plaintext tokens are never retained.
    Ls {
        #[arg(long)]
        json: bool,
    },
    /// Revoke an invite by its public identifier.
    Revoke { id: String },
}

pub async fn run(config_path: &Utf8Path, args: InviteArgs) -> Result<()> {
    let config = wormholed::config::WormholedConfig::load(config_path)
        .with_context(|| format!("loading relay config {config_path}"))?;
    config.validate().context("validating relay config")?;
    let request = request_for(&args)?;
    let socket = config.server.data_dir.join("admin.sock");
    match run_via_admin(socket.as_std_path(), &args, request.as_ref()).await {
        Ok(()) => return Ok(()),
        Err(wormholed::admin_client::AdminClientError::Connect(_)) => {}
        Err(error) => return Err(error.into()),
    }
    let database = Arc::new(wormholed::db::RelayDb::open(&config.server.data_dir)?);
    let store = wormholed::authz::AuthStore::new(
        database,
        wormholed::authz::KeyLimits::from(&config.limits),
    );
    match args.command {
        InviteCommand::Create { json, .. } => {
            let request = request.expect("create request");
            let created = store.create_invite(&request.name, request.ttl_secs, request.max_uses)?;
            render_created(wormholed::admin::CreatedInviteResponse::from(created), json)
        }
        InviteCommand::Ls { json } => {
            let invites = store
                .list_invites()?
                .into_iter()
                .map(wormholed::admin::InviteResponse::from)
                .collect::<Vec<_>>();
            render_list(&invites, json)
        }
        InviteCommand::Revoke { id } => {
            store.revoke_invite(&id)?;
            output::human(&format!("revoked invite {id}"));
            Ok(())
        }
    }
}

fn request_for(args: &InviteArgs) -> Result<Option<wormholed::admin::CreateInviteRequest>> {
    let InviteCommand::Create { name, ttl, uses, reusable, .. } = &args.command else {
        return Ok(None);
    };
    let (ttl_secs, max_uses) = if *reusable {
        (None, None)
    } else {
        let duration = humantime::parse_duration(ttl.as_deref().unwrap_or("10m"))?;
        let ttl_secs = duration.as_secs();
        if ttl_secs == 0 {
            anyhow::bail!("invite TTL must be at least one second");
        }
        (Some(ttl_secs), Some(uses.unwrap_or(1)))
    };
    Ok(Some(wormholed::admin::CreateInviteRequest { name: name.clone(), ttl_secs, max_uses }))
}

async fn run_via_admin(
    socket: &std::path::Path,
    args: &InviteArgs,
    create: Option<&wormholed::admin::CreateInviteRequest>,
) -> Result<(), wormholed::admin_client::AdminClientError> {
    let response = match &args.command {
        InviteCommand::Create { .. } => {
            wormholed::admin_client::request(socket, Method::POST, "/v1/invites", create).await?
        }
        InviteCommand::Ls { .. } => {
            wormholed::admin_client::request::<serde_json::Value>(
                socket,
                Method::GET,
                "/v1/invites",
                None,
            )
            .await?
        }
        InviteCommand::Revoke { id } => {
            let path = format!("/v1/invites/{}", wormholed::admin_client::encoded_path(id));
            wormholed::admin_client::request::<serde_json::Value>(
                socket,
                Method::DELETE,
                &path,
                None,
            )
            .await?
        }
    };
    if !response.status.is_success() {
        return Err(wormholed::admin_client::AdminClientError::Json(serde_json::Error::io(
            std::io::Error::other(String::from_utf8_lossy(&response.body).into_owned()),
        )));
    }
    match &args.command {
        InviteCommand::Create { json, .. } => {
            let created = serde_json::from_slice(&response.body)?;
            render_created(created, *json).map_err(json_error)?;
        }
        InviteCommand::Ls { json } => {
            let invites: Vec<wormholed::admin::InviteResponse> =
                serde_json::from_slice(&response.body)?;
            render_list(&invites, *json).map_err(json_error)?;
        }
        InviteCommand::Revoke { id } => output::human(&format!("revoked invite {id}")),
    }
    Ok(())
}

fn render_created(created: wormholed::admin::CreatedInviteResponse, json: bool) -> Result<()> {
    if json {
        return output::json(&created);
    }
    output::human(&format!(
        "Invite ID: {}\nToken: {}\nSave this token now; the server stores only its digest.",
        created.id, created.token
    ));
    Ok(())
}

fn render_list(invites: &[wormholed::admin::InviteResponse], json: bool) -> Result<()> {
    if json {
        return output::json(invites);
    }
    let rendered = invites
        .iter()
        .map(|invite| {
            let status = if invite.revoked {
                "revoked"
            } else if invite
                .expires_at
                .is_some_and(|expiry| expiry < jiff::Timestamp::now().as_second())
            {
                "expired"
            } else if invite.max_uses.is_some_and(|maximum| invite.uses >= maximum) {
                "exhausted"
            } else {
                "active"
            };
            let limit =
                invite.max_uses.map_or_else(|| "unlimited".to_owned(), |value| value.to_string());
            format!("{}\t{}\t{}/{}\t{status}", invite.id, invite.name, invite.uses, limit)
        })
        .collect::<Vec<_>>()
        .join("\n");
    output::human(if rendered.is_empty() { "No invites" } else { &rendered });
    Ok(())
}

fn json_error(error: anyhow::Error) -> wormholed::admin_client::AdminClientError {
    wormholed::admin_client::AdminClientError::Json(serde_json::Error::io(std::io::Error::other(
        error.to_string(),
    )))
}
