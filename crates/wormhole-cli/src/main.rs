//! Wormhole client CLI and headless per-user daemon.
//! Commands control tunnels through the daemon's local Unix-socket API.

mod api_expose;
mod api_status;
mod api_types;
mod cli;
pub mod client;
mod daemon;
mod daemon_commands;
mod error;
mod future_api;
mod local_api;
mod local_proxy;
#[cfg(debug_assertions)]
mod mock_driver;
pub mod output;
mod project;
mod project_commands;
mod project_name;
mod run_command;
mod runtime;
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
            return Ok(());
        }
        Command::Status | Command::Daemon { command: cli::DaemonCommand::Status } => {
            let client = client::DaemonClient::ensure(cli.config.as_ref()).await?;
            output::emit(format(cli.json), &client.status().await?);
            return Ok(());
        }
        Command::Daemon { command: cli::DaemonCommand::Stop } => {
            let client = client::DaemonClient::ensure(cli.config.as_ref()).await?;
            output::emit(format(cli.json), &client.shutdown().await?);
            return Ok(());
        }
        Command::Daemon { command: cli::DaemonCommand::Logs { follow } } => {
            return daemon_commands::logs(*follow).await;
        }
        Command::Daemon { command: cli::DaemonCommand::Reload } => {
            let client = client::DaemonClient::ensure(cli.config.as_ref()).await?;
            output::emit(format(cli.json), &client.reload().await?);
            return Ok(());
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
        Command::Down(args) => {
            return project_commands::down(cli, &args.targets, args.forget).await;
        }
        Command::Up(args) => return project_commands::up(cli, &args.services).await,
        Command::Run(args) => return run_command::execute(cli, args).await,
        Command::Remote { command } => return utility_commands::remote(cli, command).await,
        Command::Key { command } => return utility_commands::key(cli, command),
        Command::Interfaces => return utility_commands::interfaces(cli).await,
        Command::Doctor => return utility_commands::doctor(cli).await,
        Command::Completions { shell } => return utility_commands::completions(*shell),
        _ => {}
    }
    let command = match &cli.command {
        Command::Http(_) => "http",
        Command::Tcp(_) => "tcp",
        Command::Run(_) => "run",
        Command::Up(_) => "up",
        Command::Down(_) => "down",
        Command::Ls(_) => "ls",
        Command::Status => "status",
        Command::Inspect(_) => "inspect",
        Command::Replay { .. } => "replay",
        Command::Interfaces => "interfaces",
        Command::Remote { .. } => "remote",
        Command::Key { .. } => "key",
        Command::Doctor => "doctor",
        Command::Daemon { .. } => "daemon",
        Command::Completions { .. } => "completions",
        Command::Share(_) => "share",
    };
    Err(CliError::Unimplemented(command))
}

const fn format(json: bool) -> output::Format {
    if json { output::Format::Json } else { output::Format::Human }
}
