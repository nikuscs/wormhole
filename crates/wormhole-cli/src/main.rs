//! Wormhole client CLI and headless per-user daemon.
//! Commands control tunnels through the daemon's local Unix-socket API.

mod api_expose;
mod api_status;
mod api_types;
mod capture_store;
mod cli;
pub mod client;
mod cloudflare_api;
mod cloudflare_bundle;
mod cloudflare_wrangler;
mod daemon;
mod daemon_commands;
mod endpoint_options;
mod error;
mod future_api;
mod local_api;
mod local_api_auth;
mod local_api_remotes;
mod local_commands;
mod local_notices;
mod local_proxy;
#[cfg(debug_assertions)]
mod mock_driver;
pub mod output;
mod project;
mod project_commands;
mod project_env;
mod project_name;
mod project_root;
mod relay_commands;
mod remote_onboarding;
mod run_command;
mod runtime;
mod share_api;
mod stable_identity;
mod state_db;
mod tunnel_commands;
mod utility_commands;

use clap::Parser as _;
use cli::{Cli, Command};
use error::CliError;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.quiet, cli.verbose);
    match execute(&cli).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            if error.should_render() {
                output::emit_error(&error, error.hint());
            }
            std::process::ExitCode::from(error.exit_code())
        }
    }
}

fn init_tracing(quiet: bool, verbose: u8) {
    let fallback = if quiet {
        "off"
    } else {
        match verbose {
            0 => "warn",
            1 => "info",
            2 => "debug",
            _ => "trace",
        }
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(fallback));
    let _installed =
        tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).try_init();
}

async fn execute(cli: &Cli) -> Result<(), CliError> {
    match &cli.command {
        Command::Daemon { command: cli::DaemonCommand::Run { detach } } => {
            daemon::run(cli.config.as_ref(), *detach).await?;
            Ok(())
        }
        Command::Status | Command::Daemon { command: cli::DaemonCommand::Status } => {
            let client = client::DaemonClient::ensure(cli.config.as_ref()).await?;
            output::emit(format(cli.json), &client.status().await?);
            Ok(())
        }
        Command::Daemon { command: cli::DaemonCommand::Stop } => {
            let client = client::DaemonClient::ensure(cli.config.as_ref()).await?;
            output::emit(format(cli.json), &client.shutdown().await?);
            Ok(())
        }
        Command::Daemon { command: cli::DaemonCommand::Logs { follow } } => {
            daemon_commands::logs(*follow).await
        }
        Command::Daemon { command: cli::DaemonCommand::Reload } => {
            let client = client::DaemonClient::ensure(cli.config.as_ref()).await?;
            output::emit(format(cli.json), &client.reload().await?);
            Ok(())
        }
        Command::Http(args) => {
            return tunnel_commands::expose(cli, args, wormhole_core::model::ServiceProto::Http)
                .await;
        }
        Command::Tcp(args) => {
            return tunnel_commands::expose(cli, args, wormhole_core::model::ServiceProto::Tcp)
                .await;
        }
        Command::Ls(args) => return tunnel_commands::list(cli, args.watch).await,
        Command::Down(args) => project_commands::down(cli, &args.targets, args.forget).await,
        Command::Up(args) => return project_commands::up(cli, &args.services).await,
        Command::Run(args) => return run_command::execute(cli, args).await,
        Command::Domains => return utility_commands::domains(cli).await,
        Command::Relay {
            command:
                cli::RelayCommand::Deploy { provider: cli::RelayDeployCommand::Cloudflare(args) },
        } => return relay_commands::deploy_cloudflare(cli, args).await,
        Command::Remote { command } => return utility_commands::remote(cli, command).await,
        Command::Key { command } => utility_commands::key(cli, command),
        Command::Interfaces => return utility_commands::interfaces(cli).await,
        Command::Doctor => utility_commands::doctor(cli).await,
        Command::Local { command } => local_commands::execute(cli, command).await,
        Command::Completions { shell } => utility_commands::completions(*shell),
        Command::Inspect { request_id } => {
            let id = request_id
                .parse()
                .map_err(|error| CliError::Invalid(format!("request id: {error}")))?;
            let client = client::DaemonClient::ensure(cli.config.as_ref()).await?;
            output::emit(format(cli.json), &client.capture(id).await?);
            Ok(())
        }
        Command::Requests(args) => return inspection(cli, args).await,
        Command::Replay { request_id } => {
            let id = request_id
                .parse()
                .map_err(|error| CliError::Invalid(format!("request id: {error}")))?;
            let client = client::DaemonClient::ensure(cli.config.as_ref()).await?;
            let response = client.replay(id).await?;
            output::emit(format(cli.json), &response);
            Ok(())
        }
        Command::Share(args) => {
            let client = client::DaemonClient::ensure(cli.config.as_ref()).await?;
            let response = client
                .share(&share_api::ShareRequest {
                    target: args.target.clone(),
                    expires: args.expires.clone(),
                    path: args.path.clone(),
                })
                .await?;
            output::emit(format(cli.json), &response);
            Ok(())
        }
    }
}

async fn inspection(cli: &Cli, args: &cli::RequestsArgs) -> Result<(), CliError> {
    let client = client::DaemonClient::ensure(cli.config.as_ref()).await?;
    if matches!(args.command, Some(cli::RequestCommand::Clear)) {
        output::emit(format(cli.json), &client.clear_captures().await?);
        return Ok(());
    }
    let captures = client.captures(args.endpoint.as_deref(), None).await?;
    let mut since = captures.iter().map(|capture| capture.captured_at).max();
    output::emit(format(cli.json), &captures);
    if args.follow {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            let captures = client.captures(args.endpoint.as_deref(), since).await?;
            if let Some(latest) = captures.iter().map(|capture| capture.captured_at).max() {
                since = Some(latest);
            }
            if !captures.is_empty() {
                output::emit(format(cli.json), &captures);
            }
        }
    }
    Ok(())
}

const fn format(json: bool) -> output::Format {
    if json { output::Format::Json } else { output::Format::Human }
}
