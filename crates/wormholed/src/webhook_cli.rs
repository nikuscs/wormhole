//! Relay failed-webhook administration commands.

use anyhow::Result;
use camino::Utf8Path;
use clap::{Args, Subcommand};
use http::Method;
use uuid::Uuid;

use crate::output;

#[derive(Debug, Args)]
pub struct WebhookArgs {
    #[command(subcommand)]
    command: WebhookCommand,
}

#[derive(Debug, Subcommand)]
enum WebhookCommand {
    Failed(FailedArgs),
}

#[derive(Debug, Args)]
struct FailedArgs {
    #[command(subcommand)]
    command: FailedCommand,
}

#[derive(Debug, Subcommand)]
enum FailedCommand {
    Ls {
        #[arg(long)]
        json: bool,
    },
    Retry {
        bind: Uuid,
        seq: u64,
    },
    Rm {
        bind: Uuid,
        seq: u64,
    },
}

pub async fn run(path: &Utf8Path, args: WebhookArgs) -> Result<()> {
    let config = wormholed::config::WormholedConfig::load(path)?;
    let socket = config.server.data_dir.join("admin.sock");
    match args.command {
        WebhookCommand::Failed(args) => match args.command {
            FailedCommand::Ls { json } => {
                let rows: Vec<wormholed::admin::FailedWebhookResponse> =
                    match wormholed::admin_client::request::<serde_json::Value>(
                        socket.as_std_path(),
                        Method::GET,
                        "/v1/webhooks/failed",
                        None,
                    )
                    .await
                    {
                        Ok(response) => {
                            let response = response.require_success()?;
                            serde_json::from_slice(&response.body)?
                        }
                        Err(wormholed::admin_client::AdminClientError::Connect(_)) => {
                            let database = wormholed::db::RelayDb::open(&config.server.data_dir)?;
                            database
                                .list_failed()?
                                .into_iter()
                                .map(|(bind, seq, failed)| {
                                    wormholed::admin::FailedWebhookResponse {
                                        bind,
                                        seq,
                                        reason: failed.reason,
                                        failed_at: failed.failed_at.to_string(),
                                    }
                                })
                                .collect()
                        }
                        Err(error) => return Err(error.into()),
                    };
                render(&rows, json)
            }
            FailedCommand::Retry { bind, seq } => {
                mutate(&config, Method::POST, bind, seq, true).await
            }
            FailedCommand::Rm { bind, seq } => {
                mutate(&config, Method::DELETE, bind, seq, false).await
            }
        },
    }
}

async fn mutate(
    config: &wormholed::config::WormholedConfig,
    method: Method,
    bind: Uuid,
    seq: u64,
    retry: bool,
) -> Result<()> {
    let suffix = if retry { "/retry" } else { "" };
    let socket = config.server.data_dir.join("admin.sock");
    match wormholed::admin_client::request::<serde_json::Value>(
        socket.as_std_path(),
        method,
        &format!("/v1/webhooks/failed/{bind}/{seq}{suffix}"),
        None,
    )
    .await
    {
        Ok(response) => {
            response.require_success()?;
        }
        Err(wormholed::admin_client::AdminClientError::Connect(_)) => {
            let database = wormholed::db::RelayDb::open(&config.server.data_dir)?;
            let found = if retry {
                database.retry_failed(bind, seq)?
            } else {
                database.delete_failed(bind, seq)?
            };
            if !found {
                anyhow::bail!("failed webhook not found: {bind}/{seq}");
            }
        }
        Err(error) => return Err(error.into()),
    }
    output::human(if retry { "queued for retry" } else { "removed" });
    Ok(())
}

fn render(rows: &[wormholed::admin::FailedWebhookResponse], json: bool) -> Result<()> {
    if json {
        output::json(rows)
    } else {
        let lines = rows
            .iter()
            .map(|row| format!("{}\t{}\t{}", row.bind, row.seq, row.reason))
            .collect::<Vec<_>>()
            .join("\n");
        output::human(if lines.is_empty() { "No failed webhooks" } else { &lines });
        Ok(())
    }
}
