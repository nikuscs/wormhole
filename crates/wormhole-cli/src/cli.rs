//! Command-line grammar shared by execution and help tests.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Wormhole exposes local services through one or more secure tunnel providers.
#[derive(Debug, Parser)]
#[command(
    name = "wormhole",
    version,
    about = "Wormhole exposes local services through one or more secure tunnel providers",
    propagate_version = true
)]
pub struct Cli {
    /// Emit stable JSON instead of human-readable output.
    #[arg(long, global = true)]
    pub json: bool,
    /// Override the global configuration file.
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,
    /// Suppress nonessential diagnostics.
    #[arg(short = 'q', long, global = true, conflicts_with = "verbose")]
    pub quiet: bool,
    /// Increase diagnostic verbosity (repeat for trace logging).
    #[arg(short = 'v', long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Expose a local HTTP service.
    Http(TunnelArgs),
    /// Expose a local TCP service.
    Tcp(TunnelArgs),
    /// Run a command and expose its listening port.
    Run(RunArgs),
    /// Start services from wormhole.toml.
    Up(ProjectSelection),
    /// Stop project services or endpoint identifiers.
    Down(DownArgs),
    /// List active endpoints.
    Ls(ListArgs),
    /// Show daemon status.
    Status,
    /// Inspect one captured HTTP request.
    Inspect { request_id: String },
    /// List or manage captured HTTP requests.
    Requests(RequestsArgs),
    /// Replay one captured request.
    Replay { request_id: String },
    /// List discovered interface aliases.
    Interfaces,
    /// Manage named Wormhole remotes.
    Remote {
        #[command(subcommand)]
        command: RemoteCommand,
    },
    /// Manage the client identity key.
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
    /// Run structured health checks.
    Doctor,
    /// Manage the per-user daemon.
    Daemon {
        #[command(subcommand)]
        command: DaemonCommand,
    },
    /// Generate shell completions.
    Completions { shell: CompletionShell },
    /// Create an expiring share link.
    Share(ShareArgs),
}

#[derive(Debug, Args)]
pub struct TunnelArgs {
    /// Local target: PORT, HOST:PORT, or ALIAS:PORT.
    pub target: String,
    #[command(flatten)]
    pub options: TunnelOptions,
}

#[derive(Debug, Args, Default)]
pub struct TunnelOptions {
    /// Add a provider endpoint specification; repeat for multiple URLs.
    #[arg(long, value_name = "DRIVER[:QUALIFIER]")]
    pub endpoint: Vec<String>,
    /// Request a server-owned subdomain label.
    #[arg(long)]
    pub host: Option<String>,
    /// Request a provider-side public TCP port.
    #[arg(long, value_name = "PORT")]
    pub public_port: Option<u16>,
    /// Keep the endpoint and reclaim its reservation after restarts.
    #[arg(long)]
    pub persist: bool,
    #[command(flatten)]
    pub capture: CaptureOptions,
    /// Buffer up to this many offline requests.
    #[arg(long, value_name = "COUNT")]
    pub buffer: Option<u32>,
    /// Configure local delivery retries.
    #[arg(long, value_name = "SPEC")]
    pub retry: Option<String>,
    /// Configure relay-edge authentication.
    #[arg(long, value_name = "POLICY", env = "WORMHOLE_AUTH", action = clap::ArgAction::Append, conflicts_with = "auth_file")]
    pub auth: Vec<String>,
    /// Read relay-edge authentication from a file.
    #[arg(long, value_name = "PATH", conflicts_with = "auth")]
    pub auth_file: Option<PathBuf>,
    /// Select a named Wormhole remote.
    #[arg(long)]
    pub remote: Option<String>,
    /// Run the tunnel manager in this process.
    #[arg(long)]
    pub foreground: bool,
    /// Stable service name.
    #[arg(long)]
    pub name: Option<String>,
}

#[derive(Debug, Args)]
pub struct CaptureOptions {
    /// Disable request inspection.
    #[arg(long)]
    pub no_inspect: bool,
    /// Include static assets in request inspection.
    #[arg(long, requires = "endpoint")]
    pub include_assets: bool,
    /// Maximum complete request body retained for inspection.
    #[arg(long, default_value_t = 1024 * 1024)]
    pub capture_body_max: u64,
}

impl Default for CaptureOptions {
    fn default() -> Self {
        Self { no_inspect: false, include_assets: false, capture_body_max: 1024 * 1024 }
    }
}

#[derive(Debug, Args)]
pub struct RunArgs {
    /// Expected application port; skips automatic allocation.
    #[arg(long)]
    pub app_port: Option<u16>,
    #[command(flatten)]
    pub options: TunnelOptions,
    /// Command and arguments to run.
    #[arg(required = true, last = true)]
    pub command: Vec<String>,
}

#[derive(Debug, Args)]
pub struct ProjectSelection {
    /// Service names; omitted means every project service.
    pub services: Vec<String>,
}

#[derive(Debug, Args)]
pub struct DownArgs {
    /// Service names or endpoint identifiers.
    pub targets: Vec<String>,
    /// Also delete server-side persistent reservations.
    #[arg(long)]
    pub forget: bool,
}

#[derive(Debug, Args)]
pub struct ListArgs {
    /// Continuously wait for endpoint changes.
    #[arg(long)]
    pub watch: bool,
}

#[derive(Debug, Args)]
pub struct RequestsArgs {
    /// Restrict captures to one endpoint.
    #[arg(long)]
    pub endpoint: Option<String>,
    /// Follow newly captured requests.
    #[arg(long)]
    pub follow: bool,
    #[command(subcommand)]
    pub command: Option<RequestCommand>,
}

#[derive(Debug, Subcommand)]
pub enum RequestCommand {
    /// Delete all in-memory request captures.
    Clear,
}

#[derive(Debug, Subcommand)]
pub enum RemoteCommand {
    /// Add or replace a named remote.
    Add {
        name: String,
        addr: String,
        #[arg(long)]
        identity: Option<PathBuf>,
    },
    /// List configured remotes.
    Ls,
    /// Remove a named remote.
    Rm { name: String },
    /// Dial and authenticate to a named remote.
    Test { name: String },
}

#[derive(Debug, Subcommand)]
pub enum KeyCommand {
    /// Show the current public fingerprint.
    Show,
    /// Generate a new identity key.
    Rotate,
}

#[derive(Debug, Subcommand)]
pub enum DaemonCommand {
    /// Run the daemon.
    Run {
        /// Detach into a new session and log to the state directory.
        #[arg(long)]
        detach: bool,
    },
    /// Gracefully stop the daemon.
    Stop,
    /// Show daemon status.
    Status,
    /// Reload configuration without dropping live endpoints.
    Reload,
    /// Read daemon logs.
    Logs {
        /// Follow appended log lines.
        #[arg(short = 'f', long)]
        follow: bool,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CompletionShell {
    Bash,
    Fish,
    Zsh,
}

#[derive(Debug, Args)]
pub struct ShareArgs {
    /// Service name, project:service identity, or endpoint identifier.
    pub target: String,
    /// Share-link lifetime.
    #[arg(long, default_value = "24h")]
    pub expires: String,
    /// Landing path for the host-wide grant.
    #[arg(long, default_value = "/")]
    pub path: String,
}

#[cfg(test)]
#[path = "cli_tests.rs"]
mod tests;
