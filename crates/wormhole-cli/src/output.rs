//! All terminal output. The only module allowed to print.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::io::{IsTerminal as _, Write as _};

use indicatif::{ProgressBar, ProgressStyle};
use owo_colors::OwoColorize as _;
use serde::Serialize;

/// Selects human-readable or machine-readable command output.
pub enum Format {
    /// Render concise text for terminal users.
    Human,
    /// Render pretty-printed JSON for tools and agents.
    Json,
}

/// Emits a serializable value using the requested output format.
pub fn emit<T: Serialize + HumanRender>(format: Format, value: &T) {
    match format {
        Format::Json => {
            println!("{}", serde_json::to_string_pretty(value).expect("value must serialize"));
        }
        Format::Human => println!("{}", value.render_styled(styles_enabled_stdout())),
    }
}

/// Supplies the human-readable representation of command output.
pub trait HumanRender {
    /// Renders a value for terminal users.
    fn render(&self) -> String;

    /// Applies optional terminal styling without changing the plain contract.
    fn render_styled(&self, _styled: bool) -> String {
        self.render()
    }
}

impl HumanRender for wormhole_core::CapturedRequest {
    fn render(&self) -> String {
        format!(
            "{} {} {}\nstatus={} duration={}ms delivery={} request_bytes={} response_bytes={}",
            self.id,
            self.method,
            self.uri,
            self.response_status.map_or_else(|| "-".to_owned(), |status| status.to_string()),
            self.duration_ms,
            self.delivery,
            self.body.len(),
            self.response_body_prefix.len()
        )
    }
}

impl HumanRender for Vec<wormhole_core::CapturedRequest> {
    fn render(&self) -> String {
        self.iter()
            .map(|capture| {
                format!(
                    "{}\t{}\t{}\t{}",
                    capture.id,
                    capture.method,
                    capture.uri,
                    capture
                        .response_status
                        .map_or_else(|| "-".to_owned(), |status| status.to_string())
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl HumanRender for crate::future_api::ReplayResponse {
    fn render(&self) -> String {
        format!("status={} duration={}ms", self.status, self.duration_ms)
    }
}

impl HumanRender for crate::share_api::ShareResponse {
    fn render(&self) -> String {
        self.url.clone()
    }
}

impl HumanRender for crate::local_api::StatusResponse {
    fn render(&self) -> String {
        format!(
            "daemon {} pid={} uptime={}s services={} endpoints={}",
            self.version, self.pid, self.uptime_seconds, self.services, self.endpoints
        )
    }
}

impl HumanRender for Vec<wormhole_core::ActiveEndpoint> {
    fn render(&self) -> String {
        render_endpoints(self, false)
    }

    fn render_styled(&self, styled: bool) -> String {
        render_endpoints(self, styled)
    }
}

impl HumanRender for Vec<wormhole_core::ifaces::IfaceAlias> {
    fn render(&self) -> String {
        self.iter()
            .map(|alias| format!("{}\t{}\t{}", alias.alias, alias.iface, alias.ip))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl HumanRender for Vec<wormhole_core::model::DoctorCheck> {
    fn render(&self) -> String {
        self.iter()
            .map(|check| {
                format!(
                    "{}\t{}\t{}",
                    check.name,
                    if check.healthy { "ok" } else { "failed" },
                    check.detail
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl HumanRender for Vec<crate::api_types::RemoteView> {
    fn render(&self) -> String {
        self.iter()
            .map(|remote| format!("{}\t{}\t{}", remote.name, remote.addr, remote.server_name))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl HumanRender for crate::utility_commands::KeyView {
    fn render(&self) -> String {
        format!("{}\n{}", self.fingerprint, self.public_key)
    }
}

impl HumanRender for crate::utility_commands::RotationView {
    fn render(&self) -> String {
        format!("{} -> {}\n{}", self.old_fingerprint, self.new_fingerprint, self.reminder)
    }
}

impl HumanRender for crate::utility_commands::RemoteTestView {
    fn render(&self) -> String {
        format!("{}\t{}ms", self.name, self.latency_ms)
    }
}

impl HumanRender for Vec<crate::utility_commands::RemoteDomainsView> {
    fn render(&self) -> String {
        if self.is_empty() {
            return "no configured remotes".to_owned();
        }
        self.iter()
            .map(|remote| {
                remote.error.as_ref().map_or_else(
                    || {
                        format!(
                            "{}\t{}\t{}ms",
                            remote.remote,
                            remote.domains.join(","),
                            remote.latency_ms.unwrap_or_default()
                        )
                    },
                    |error| format!("{}\tfailed\t{error}", remote.remote),
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl HumanRender for crate::local_api::ClosedResponse {
    fn render(&self) -> String {
        if self.closed { "closed".to_owned() } else { "not found".to_owned() }
    }
}

/// Emits a command failure to stderr without contaminating stdout.
pub fn emit_error(error: &dyn std::fmt::Display, hint: Option<&str>) {
    if styles_enabled_stderr() {
        eprintln!("{} {error}", "error:".red().bold());
        if let Some(hint) = hint {
            eprintln!("{} {hint}", "hint:".bright_black());
        }
    } else {
        eprintln!("error: {error}");
        if let Some(hint) = hint {
            eprintln!("hint: {hint}");
        }
    }
}

/// Prints an exact consequential command to stderr before execution.
pub fn preview_command(command: &str) {
    eprintln!("command: {command}");
}

/// Writes an interactive prompt to stderr without contaminating stdout.
pub fn prompt(message: &str) -> Result<(), std::io::Error> {
    let mut stderr = std::io::stderr();
    write!(stderr, "{message}: ")?;
    stderr.flush()
}

/// Starts a stderr-only progress indicator when interactive styling is enabled.
pub fn spinner(message: &str, json: bool) -> Option<ProgressBar> {
    if json || !styles_enabled_stderr() {
        return None;
    }
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::with_template("{spinner:.cyan} {msg}")
            .expect("static spinner template is valid"),
    );
    spinner.set_message(message.to_owned());
    spinner.enable_steady_tick(std::time::Duration::from_millis(80));
    Some(spinner)
}

pub fn finish_spinner(spinner: Option<ProgressBar>) {
    if let Some(spinner) = spinner {
        spinner.finish_and_clear();
    }
}

fn render_endpoints(endpoints: &[wormhole_core::ActiveEndpoint], styled: bool) -> String {
    if endpoints.is_empty() {
        return "no endpoints".to_owned();
    }
    let mut lines = Vec::with_capacity(endpoints.len() + 1);
    if endpoints.iter().any(|endpoint| endpoint.driver == "wormhole") {
        lines.push(if styled {
            "🌀 wormhole".cyan().bold().to_string()
        } else {
            "🌀 wormhole".to_owned()
        });
    }
    lines.extend(endpoints.iter().map(|endpoint| endpoint_line(endpoint, styled)));
    lines.join("\n")
}

fn endpoint_line(endpoint: &wormhole_core::ActiveEndpoint, styled: bool) -> String {
    use wormhole_core::model::EndpointStatus;
    let (glyph, status) = match &endpoint.status {
        EndpointStatus::Online => ("✓", "online"),
        EndpointStatus::Reconnecting => ("↻", "reconnecting"),
        EndpointStatus::Offline => ("⏸", "offline"),
        EndpointStatus::Error(_) => ("✗", "error"),
    };
    let glyph = if styled {
        match endpoint.status {
            EndpointStatus::Online => glyph.green().bold().to_string(),
            EndpointStatus::Error(_) => glyph.red().bold().to_string(),
            EndpointStatus::Reconnecting => glyph.yellow().to_string(),
            EndpointStatus::Offline => glyph.bright_black().to_string(),
        }
    } else {
        glyph.to_owned()
    };
    let urls = if endpoint.urls.is_empty() {
        "-".to_owned()
    } else if styled {
        endpoint.urls.join(",").cyan().underline().to_string()
    } else {
        endpoint.urls.join(",")
    };
    let notices = endpoint
        .warnings
        .iter()
        .map(|warning| format!("\n  warning: {warning}"))
        .chain(endpoint.hints.iter().map(|hint| format!("\n  hint: {hint}")))
        .collect::<String>();
    let buffered = if endpoint.buffered_pending > 0 {
        format!(
            "\n  replaying {} buffered webhooks… delivered={} failed={}",
            endpoint.buffered_pending, endpoint.buffered_delivered, endpoint.buffered_failed
        )
    } else if endpoint.buffered_failed > 0 || endpoint.buffered_delivered > 0 {
        format!(
            "\tbuffered: delivered={} failed={}",
            endpoint.buffered_delivered, endpoint.buffered_failed
        )
    } else {
        String::new()
    };
    format!("{glyph} {}\t{status}\t{urls}{notices}{buffered}", endpoint.service)
}

fn styles_enabled_stdout() -> bool {
    styles_enabled(std::io::stdout().is_terminal())
}

fn styles_enabled_stderr() -> bool {
    styles_enabled(std::io::stderr().is_terminal())
}

fn styles_enabled(terminal: bool) -> bool {
    std::env::var_os("NO_COLOR").is_none()
        && (terminal
            || std::env::var_os("CLICOLOR_FORCE").as_deref() == Some(std::ffi::OsStr::new("1")))
}

/// Writes generated non-JSON command data to stdout.
pub fn emit_raw(bytes: &[u8]) -> Result<(), std::io::Error> {
    std::io::stdout().write_all(bytes)
}

#[cfg(test)]
#[path = "output_tests.rs"]
mod tests;
