use std::{fs, sync::Arc};

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use clap::{Args, Parser, Subcommand};

use crate::output;

#[derive(Debug, Parser)]
#[command(name = "wormholed", version, about = "Wormhole relay server")]
pub struct Cli {
    #[arg(long, global = true, default_value = "/etc/wormhole/wormholed.toml")]
    config: Utf8PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the relay or validate startup configuration.
    Serve(ServeArgs),
    /// Write a development-safe default configuration.
    Init,
    /// Manage authorized client keys.
    Key(KeyArgs),
    Invite(crate::invite_cli::InviteArgs),
    /// Show relay health and counters.
    Status(StatusArgs),
    /// List or remove public binds without exposing reservation secrets.
    Binds(BindsArgs),
    /// Manage durable webhook queues.
    Webhooks(crate::webhook_cli::WebhookArgs),
}

#[derive(Debug, Args)]
struct ServeArgs {
    /// Validate configuration and exit without binding sockets.
    #[arg(long)]
    check: bool,
}

#[derive(Debug, Args)]
struct JsonArgs {
    /// Emit stable machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct StatusArgs {
    #[arg(long)]
    json: bool,
    /// Fail instead of rendering the offline database state.
    #[arg(long)]
    require_online: bool,
}

#[derive(Debug, Args)]
struct BindsArgs {
    #[command(subcommand)]
    command: Option<BindsCommand>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Subcommand)]
enum BindsCommand {
    Ls(JsonArgs),
    Rm { id: uuid::Uuid },
}

#[derive(Debug, Args)]
struct KeyArgs {
    #[command(subcommand)]
    command: KeyCommand,
}

#[derive(Debug, Subcommand)]
enum KeyCommand {
    /// Add an authorized public key or public-key file.
    Authorize {
        /// Padded public key or path to a public-key file.
        pubkey_or_file: String,
        /// Human-readable key name.
        #[arg(long)]
        name: String,
    },
    /// List imported and managed keys.
    Ls(JsonArgs),
    /// Revoke a key by fingerprint.
    Revoke {
        /// Stable WH256 fingerprint.
        fingerprint: String,
    },
}

pub async fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve(args) => serve(&cli.config, args).await,
        Command::Init => initialize(&cli.config),
        Command::Key(args) => key(&cli.config, args).await,
        Command::Invite(args) => crate::invite_cli::run(&cli.config, args).await,
        Command::Status(args) => status(&cli.config, args).await,
        Command::Binds(args) => binds(&cli.config, args).await,
        Command::Webhooks(args) => crate::webhook_cli::run(&cli.config, args).await,
    }
}

async fn serve(path: &Utf8PathBuf, args: ServeArgs) -> Result<()> {
    let config = wormholed::config::WormholedConfig::load(path)
        .with_context(|| format!("loading relay config {path}"))?;
    config.validate().context("validating relay config")?;
    if args.check {
        output::human("configuration valid");
        return Ok(());
    }
    let certificates = Arc::new(
        wormholed::certs::CertManager::ready(&config)
            .await
            .context("preparing relay certificates")?,
    );
    let https_listener = tokio::net::TcpListener::bind(config.server.https_addr).await?;
    let bound_https_port = https_listener.local_addr()?.port();
    let database = Arc::new(wormholed::db::RelayDb::open(&config.server.data_dir)?);
    let auth = Arc::new(wormholed::authz::AuthStore::new(
        Arc::clone(&database),
        wormholed::authz::KeyLimits::from(&config.limits),
    ));
    auth.import_directory(&config.auth.authorized_keys)?;
    let registry = Arc::new(wormholed::registry::Registry::new(
        config.server.domains.clone(),
        config.server.public_https_port,
        bound_https_port,
        config.tcp.port_range,
    ));
    registry.preload(&database)?;
    let tcp_edges =
        Arc::new(wormholed::edge_tcp::TcpEdgeManager::new(config.server.https_addr.ip()));
    for (port, handle) in registry.tcp_routes() {
        tcp_edges.ensure_listener(port, handle).await?;
    }
    let state = Arc::new(wormholed::state::AppState::new(
        registry,
        database,
        tcp_edges,
        auth,
        config.limits.clone(),
    )?);
    wormholed::buffer::spawn_janitor(Arc::clone(&state));
    let https = wormholed::edge_https::HttpsEdge::from_listener(
        https_listener,
        Arc::clone(&state),
        wormholed::edge_https::HttpsEdge::tls_config(certificates.resolver()),
    );
    let public_https_port = config.server.public_https_port.unwrap_or(bound_https_port);
    let http = bind_http_redirect(&config, public_https_port).await?;
    let server = Arc::new(wormholed::quic::QuicServer::bind(
        config.server.quic_addr,
        Arc::clone(&state),
        &certificates,
        config.server.domains[0].clone(),
        config.limits.handshake_per_ip_per_min,
    )?);
    let admin = wormholed::admin::AdminServer::bind(
        &config.server.data_dir,
        Arc::clone(&state),
        Arc::clone(&certificates),
    )?;
    record_listener_addresses(&state, &server, &https, &http)?;
    wormholed::shutdown::spawn_certificate_reload(certificates);
    let result: Result<()> = tokio::select! {
        () = server.run() => Ok(()),
        result = https.run() => result.map_err(Into::into),
        result = http.run() => result.map_err(Into::into),
        result = admin.run() => result.map_err(Into::into),
        signal = wormholed::shutdown::wait_for_termination() => {
            signal.context("waiting for shutdown signal")
        },
    };
    wormholed::shutdown::drain(&state, &server).await;
    result
}

fn record_listener_addresses(
    state: &wormholed::state::AppState,
    server: &wormholed::quic::QuicServer,
    https: &wormholed::edge_https::HttpsEdge,
    http: &wormholed::edge_http::HttpRedirectEdge,
) -> Result<()> {
    let addresses = wormholed::state::ListenerAddresses {
        quic: server.local_addr()?,
        https: https.local_addr()?,
        http: http.local_addr()?,
    };
    state.set_listener_addresses(addresses);
    output::human(&format!(
        "QUIC {}, HTTPS {}, HTTP {}",
        addresses.quic, addresses.https, addresses.http
    ));
    Ok(())
}

async fn bind_http_redirect(
    config: &wormholed::config::WormholedConfig,
    public_https_port: u16,
) -> Result<wormholed::edge_http::HttpRedirectEdge, std::io::Error> {
    wormholed::edge_http::HttpRedirectEdge::bind(
        config.server.http_addr,
        public_https_port,
        config.server.domains.clone(),
    )
    .await
}

fn initialize(path: &Utf8PathBuf) -> Result<()> {
    wormholed::config::WormholedConfig::initialize(path)
        .with_context(|| format!("initializing relay config {path}"))?;
    output::human(&format!("created {path}"));
    Ok(())
}

async fn key(path: &Utf8Path, args: KeyArgs) -> Result<()> {
    let config = wormholed::config::WormholedConfig::load(path)
        .with_context(|| format!("loading relay config {path}"))?;
    config.validate().context("validating relay config")?;
    let socket = config.server.data_dir.join("admin.sock");
    match key_via_admin(socket.as_std_path(), &args).await {
        Ok(()) => return Ok(()),
        Err(wormholed::admin_client::AdminClientError::Connect(_)) => {}
        Err(error) => return Err(error.into()),
    }
    let database = Arc::new(wormholed::db::RelayDb::open(&config.server.data_dir)?);
    let store = wormholed::authz::AuthStore::new(
        database,
        wormholed::authz::KeyLimits::from(&config.limits),
    );
    store.import_directory(&config.auth.authorized_keys)?;
    match args.command {
        KeyCommand::Authorize { pubkey_or_file, name } => {
            let public_key = read_public_input(&pubkey_or_file)?;
            let fingerprint = store.authorize(&public_key, &name)?;
            output::human(&format!("authorized {fingerprint}"));
            Ok(())
        }
        KeyCommand::Ls(args) => {
            let keys = store.list()?;
            if args.json {
                let keys = keys
                    .into_iter()
                    .map(|(fingerprint, key)| wormholed::admin::KeyResponse {
                        fingerprint,
                        name: key.name,
                        created: key.created.to_string(),
                        revoked: key.revoked,
                    })
                    .collect::<Vec<_>>();
                output::json(&keys)
            } else {
                let rendered = keys
                    .iter()
                    .map(|(fingerprint, key)| {
                        let status = if key.revoked { "revoked" } else { "allowed" };
                        format!("{fingerprint}\t{}\t{status}", key.name)
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                output::human(if rendered.is_empty() { "No authorized keys" } else { &rendered });
                Ok(())
            }
        }
        KeyCommand::Revoke { fingerprint } => {
            store.revoke(&fingerprint)?;
            output::human(&format!("revoked {fingerprint}"));
            Ok(())
        }
    }
}

async fn key_via_admin(
    socket: &std::path::Path,
    args: &KeyArgs,
) -> Result<(), wormholed::admin_client::AdminClientError> {
    use http::Method;
    use wormholed::admin_client::request;

    let response = match &args.command {
        KeyCommand::Authorize { pubkey_or_file, name } => {
            let public_key = read_public_input(pubkey_or_file).map_err(|error| {
                wormholed::admin_client::AdminClientError::Json(serde_json::Error::io(
                    std::io::Error::other(error.to_string()),
                ))
            })?;
            request(
                socket,
                Method::POST,
                "/v1/keys",
                Some(&wormholed::admin::AuthorizeKeyRequest { public_key, name: name.clone() }),
            )
            .await?
        }
        KeyCommand::Ls(_) => {
            request::<serde_json::Value>(socket, Method::GET, "/v1/keys", None).await?
        }
        KeyCommand::Revoke { fingerprint } => {
            let path = format!("/v1/keys/{}", wormholed::admin_client::encoded_path(fingerprint));
            request::<serde_json::Value>(socket, Method::DELETE, &path, None).await?
        }
    };
    if !response.status.is_success() {
        return Err(wormholed::admin_client::AdminClientError::Json(serde_json::Error::io(
            std::io::Error::other(String::from_utf8_lossy(&response.body).into_owned()),
        )));
    }
    match &args.command {
        KeyCommand::Authorize { .. } => {
            let value: wormholed::admin::KeyFingerprint = serde_json::from_slice(&response.body)?;
            output::human(&format!("authorized {}", value.fingerprint));
        }
        KeyCommand::Ls(options) => {
            let keys: Vec<wormholed::admin::KeyResponse> = serde_json::from_slice(&response.body)?;
            if options.json {
                output::json(&keys).map_err(|error| {
                    wormholed::admin_client::AdminClientError::Json(serde_json::Error::io(
                        std::io::Error::other(error.to_string()),
                    ))
                })?;
            } else {
                let rendered = keys
                    .iter()
                    .map(|key| {
                        format!(
                            "{}\t{}\t{}",
                            key.fingerprint,
                            key.name,
                            if key.revoked { "revoked" } else { "allowed" }
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                output::human(if rendered.is_empty() { "No authorized keys" } else { &rendered });
            }
        }
        KeyCommand::Revoke { fingerprint } => output::human(&format!("revoked {fingerprint}")),
    }
    Ok(())
}

fn read_public_input(input: &str) -> Result<String> {
    let path = Utf8Path::new(input);
    if !path.is_file() {
        return Ok(input.to_owned());
    }
    let contents =
        fs::read_to_string(path).with_context(|| format!("reading public key {path}"))?;
    contents
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("public key file contains no key: {path}"))
}

async fn status(path: &Utf8Path, args: StatusArgs) -> Result<()> {
    use http::Method;
    let config = wormholed::config::WormholedConfig::load(path)?;
    let socket = config.server.data_dir.join("admin.sock");
    let response = match wormholed::admin_client::request::<serde_json::Value>(
        socket.as_std_path(),
        Method::GET,
        "/v1/status",
        None,
    )
    .await
    {
        Ok(response) => response,
        Err(wormholed::admin_client::AdminClientError::Connect(_)) => {
            if args.require_online {
                anyhow::bail!("relay is offline");
            }
            let database = wormholed::db::RelayDb::open(&config.server.data_dir)?;
            let offline = wormholed::admin::StatusResponse {
                uptime_seconds: 0,
                sessions: 0,
                binds: database.list_binds()?.len(),
                streams: 0,
                quic_addr: None,
                https_addr: None,
                http_addr: None,
                certificate_expiries: Vec::new(),
                certificate_error: None,
            };
            if args.json {
                return output::json(&offline);
            }
            output::human(&format!("Relay offline — 0 sessions, {} binds", offline.binds));
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    let value: wormholed::admin::StatusResponse = serde_json::from_slice(&response.body)?;
    if args.json {
        output::json(&value)
    } else {
        output::human(&format!(
            "Relay online — {} sessions, {} binds, {} streams",
            value.sessions, value.binds, value.streams
        ));
        Ok(())
    }
}

async fn binds(path: &Utf8Path, args: BindsArgs) -> Result<()> {
    use http::Method;
    if let Some(BindsCommand::Rm { id }) = &args.command {
        let id = *id;
        let config = wormholed::config::WormholedConfig::load(path)?;
        let socket = config.server.data_dir.join("admin.sock");
        match wormholed::admin_client::request::<serde_json::Value>(
            socket.as_std_path(),
            Method::DELETE,
            &format!("/v1/binds/{id}"),
            None,
        )
        .await
        {
            Ok(response) => {
                response.require_success()?;
                output::human(&format!("removed {id}"));
            }
            Err(wormholed::admin_client::AdminClientError::Connect(_)) => {
                let database = wormholed::db::RelayDb::open(&config.server.data_dir)?;
                if database.get_bind(id)?.is_none() {
                    anyhow::bail!("bind not found: {id}");
                }
                database.delete_bind_data(id)?;
                output::human(&format!("removed {id}"));
            }
            Err(error) => return Err(error.into()),
        }
        return Ok(());
    }
    let json = match args.command {
        Some(BindsCommand::Ls(list)) => list.json,
        Some(BindsCommand::Rm { .. }) => unreachable!(),
        None => args.json,
    };
    let config = wormholed::config::WormholedConfig::load(path)?;
    let socket = config.server.data_dir.join("admin.sock");
    let response = match wormholed::admin_client::request::<serde_json::Value>(
        socket.as_std_path(),
        Method::GET,
        "/v1/binds",
        None,
    )
    .await
    {
        Ok(response) => response,
        Err(wormholed::admin_client::AdminClientError::Connect(_)) => {
            let database = wormholed::db::RelayDb::open(&config.server.data_dir)?;
            let values = database
                .list_binds()?
                .into_iter()
                .map(|(id, bind)| wormholed::admin::BindResponse {
                    id,
                    endpoint: match bind.endpoint {
                        wormholed::db::PersistedEndpoint::Hostname(host) => host,
                        wormholed::db::PersistedEndpoint::TcpPort(port) => format!("tcp:{port}"),
                    },
                    state: "offline".to_owned(),
                    persistent: true,
                    key_fingerprint: bind.key_fpr,
                    authentication: bind.auth_verifier.is_some(),
                    buffering: matches!(
                        bind.spec,
                        wormholed::db::PersistedBindSpec::Http { buffer: Some(_), .. }
                    ),
                })
                .collect::<Vec<_>>();
            return render_binds(&values, json);
        }
        Err(error) => return Err(error.into()),
    };
    let values: Vec<wormholed::admin::BindResponse> = serde_json::from_slice(&response.body)?;
    render_binds(&values, json)
}

fn render_binds(values: &[wormholed::admin::BindResponse], json: bool) -> Result<()> {
    if json {
        output::json(values)
    } else {
        let rendered = values
            .iter()
            .map(|bind| format!("{}\t{}\t{}", bind.id, bind.endpoint, bind.state))
            .collect::<Vec<_>>()
            .join("\n");
        output::human(if rendered.is_empty() { "No binds" } else { &rendered });
        Ok(())
    }
}
