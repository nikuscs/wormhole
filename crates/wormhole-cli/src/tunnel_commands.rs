//! HTTP/TCP command parsing and daemon/foreground execution.

use std::{net::IpAddr, sync::Arc, time::Duration};

use wormhole_core::{
    ActiveEndpoint, ClientConfig, EndpointSpec, Service, Target, TunnelManager,
    driver::DriverRegistry,
    drivers::build_registry,
    keys_store::IdentityStore,
    model::{EndpointStatus, ServiceProto},
};
use wormhole_proto::frames::{BufferPolicy, Persistence};

use crate::{
    cli::{Cli, TunnelArgs, TunnelOptions},
    client::DaemonClient,
    error::CliError,
    local_api::CreateServiceRequest,
    output, project_env, project_name,
    runtime::{LOCAL_API_PORT, is_reserved_target},
    stable_identity,
};

pub async fn expose(cli: &Cli, args: &TunnelArgs, proto: ServiceProto) -> Result<(), CliError> {
    let config = load_command_config(cli)?;
    let target = resolve_target(parse_target(&args.target)?, &config).await?;
    let directory = std::env::current_dir()?;
    let generated_http_name = args.options.name.is_none() && proto == ServiceProto::Http;
    let name = args.options.name.clone().unwrap_or_else(|| {
        if generated_http_name {
            project_name::infer(None, &directory)
        } else {
            default_name(proto, &target)
        }
    });
    let slug = if generated_http_name {
        name.clone()
    } else {
        project_name::worktree_slug(None, &name, &directory)
    };
    let specs = build_specs(proto, &args.options, &config, Some(&slug)).await?;
    let managed_hosts = crate::local_notices::read_managed_hosts();
    let notices =
        crate::local_notices::detect(&specs, args.options.tld.as_deref(), &config, &managed_hosts);
    let service = Service { name, target, proto };
    let spinner = output::spinner("waiting for endpoints", cli.json);
    if args.options.foreground {
        let result = start_foreground(service, specs, config).await;
        output::finish_spinner(spinner);
        let (manager, mut endpoints) = result?;
        crate::local_notices::apply(&mut endpoints, &notices);
        output::emit(super::format(cli.json), &endpoints);
        let result = endpoint_result(&endpoints);
        if result.is_ok() {
            tokio::signal::ctrl_c().await.map_err(CliError::Io)?;
        }
        let cleanup = manager.shutdown_with_forget().await.map_err(CliError::from);
        result.and(cleanup)
    } else {
        let result = async {
            DaemonClient::ensure(cli.config.as_ref())
                .await?
                .create(&CreateServiceRequest {
                    project_id: None,
                    remotes: Some(config.remotes.clone()),
                    default_remote: config.default_remote.clone(),
                    service,
                    endpoints: specs,
                })
                .await
                .map_err(CliError::from)
        }
        .await;
        output::finish_spinner(spinner);
        let mut endpoints = result?;
        crate::local_notices::apply(&mut endpoints, &notices);
        output::emit(super::format(cli.json), &endpoints);
        endpoint_result(&endpoints)
    }
}

pub async fn list(cli: &Cli, watch: bool) -> Result<(), CliError> {
    let client = DaemonClient::ensure(cli.config.as_ref()).await?;
    let mut wait = false;
    loop {
        let services = client.services(wait).await?;
        let endpoints =
            services.into_iter().flat_map(|service| service.endpoints).collect::<Vec<_>>();
        output::emit(super::format(cli.json), &endpoints);
        if !watch {
            return Ok(());
        }
        wait = true;
    }
}

pub async fn down(cli: &Cli, targets: &[String], forget: bool) -> Result<(), CliError> {
    if targets.is_empty() {
        return Err(CliError::Invalid("down requires a service or endpoint id".to_owned()));
    }
    let client = DaemonClient::ensure(cli.config.as_ref()).await?;
    for target in targets {
        let closed = if let Ok(id) = target.parse() {
            client.delete_endpoint(id, forget).await?
        } else {
            client.delete_service(target, None, forget).await?
        };
        output::emit(super::format(cli.json), &closed);
    }
    Ok(())
}

pub async fn build_specs(
    proto: ServiceProto,
    options: &TunnelOptions,
    config: &ClientConfig,
    stable_slug: Option<&str>,
) -> Result<Vec<EndpointSpec>, CliError> {
    let drivers = if options.remote.is_some() {
        vec!["wormhole".to_owned()]
    } else if options.endpoint.is_empty() {
        config.defaults.drivers.clone()
    } else {
        options.endpoint.clone()
    };
    if drivers.is_empty() {
        return Err(CliError::Invalid("no endpoint drivers configured".to_owned()));
    }
    crate::endpoint_options::validate_tld(proto, options, &drivers)?;
    let auth = crate::endpoint_options::parse_auth(options).await?;
    let retry = options
        .retry
        .as_deref()
        .map(crate::endpoint_options::parse_retry)
        .transpose()?
        .or_else(|| config.defaults.retry.clone());
    let buffer = options.buffer.map(|max_requests| BufferPolicy {
        max_requests,
        max_body_bytes: 1024 * 1024,
        ttl_secs: 2 * 60 * 60,
    });
    drivers
        .into_iter()
        .map(|driver_spec| {
            let (driver, qualifier) = driver_spec
                .split_once(':')
                .map_or((driver_spec.as_str(), None), |(driver, value)| (driver, Some(value)));
            let remote = if driver == "wormhole" {
                options.remote.clone().or_else(|| qualifier.map(str::to_owned))
            } else {
                None
            };
            let mut spec = EndpointSpec {
                proto,
                driver: driver.to_owned(),
                qualifier: (driver != "wormhole").then(|| qualifier.map(str::to_owned)).flatten(),
                remote,
                host: options.host.clone(),
                auto_host: options.host.is_none(),
                domain: None,
                public_port: options.public_port,
                persist: if options.persist {
                    Persistence::Persistent
                } else {
                    Persistence::Temporary
                },
                buffer: buffer.clone(),
                auth: auth.clone(),
                retry: retry.clone(),
                inspect: proto == ServiceProto::Http
                    && !options.capture.no_inspect
                    && config.defaults.inspect,
                inspect_assets: proto == ServiceProto::Http && options.capture.include_assets,
                capture_body_max: options.capture.capture_body_max,
                reservation: None,
            };
            stable_identity::apply(&mut spec, stable_slug, config, options.tld.as_deref())?;
            Ok(spec)
        })
        .collect()
}

pub async fn resolve_target(target: Target, config: &ClientConfig) -> Result<Target, CliError> {
    let Target::Iface { alias, port } = target else {
        return Ok(target);
    };
    let resolver = wormhole_core::ifaces::IfaceResolver::new(config.aliases.clone());
    let ip = tokio::task::spawn_blocking(move || resolver.resolve(&alias))
        .await
        .map_err(|error| CliError::Invalid(error.to_string()))?
        .map_err(wormhole_core::ManagerError::from)?;
    Ok(Target::HostPort(ip.to_string(), port))
}

pub fn load_command_config(cli: &Cli) -> Result<ClientConfig, CliError> {
    let directory = std::env::current_dir()?;
    let project = project_env::config_path(&directory)?;
    let mut config =
        crate::daemon::load_config_with_project(cli.config.as_ref(), project.as_deref())?;
    if let Some(domain) = project_env::domain_override(&directory)? {
        config.defaults.domain = Some(domain);
    }
    config.validate()?;
    Ok(config)
}

pub fn parse_target(value: &str) -> Result<Target, CliError> {
    let target = if let Ok(port) = value.parse::<u16>() {
        Target::Port(nonzero_port(port)?)
    } else {
        let (host, port) = value
            .rsplit_once(':')
            .ok_or_else(|| CliError::Invalid("target must be PORT or HOST:PORT".to_owned()))?;
        let port = nonzero_port(
            port.parse::<u16>().map_err(|error| CliError::Invalid(error.to_string()))?,
        )?;
        if host == "localhost" || host.parse::<IpAddr>().is_ok() {
            Target::HostPort(host.to_owned(), port)
        } else {
            Target::Iface { alias: host.to_owned(), port }
        }
    };
    if is_reserved_target(&target) {
        return Err(CliError::Invalid(format!(
            "port {LOCAL_API_PORT} is reserved for the local Wormhole API"
        )));
    }
    Ok(target)
}

fn nonzero_port(port: u16) -> Result<u16, CliError> {
    if port == 0 {
        Err(CliError::Invalid("target port must be non-zero".to_owned()))
    } else {
        Ok(port)
    }
}

fn default_name(proto: ServiceProto, target: &Target) -> String {
    let port = match target {
        Target::Port(port) | Target::HostPort(_, port) | Target::Iface { port, .. } => port,
    };
    format!("{}-{port}", if proto == ServiceProto::Http { "http" } else { "tcp" })
}

pub async fn start_foreground(
    service: Service,
    specs: Vec<EndpointSpec>,
    config: ClientConfig,
) -> Result<(Arc<TunnelManager>, Vec<ActiveEndpoint>), CliError> {
    let identities = Arc::new(IdentityStore::from_environment()?);
    let registry = build_registry(&config, identities);
    #[cfg(debug_assertions)]
    if std::env::var_os("WORMHOLE_ENABLE_MOCK_DRIVER").as_deref() == Some(std::ffi::OsStr::new("1"))
    {
        registry.register(Arc::new(crate::mock_driver::MockDriver));
    }
    start_foreground_with_registry(service, specs, config, registry).await
}

async fn start_foreground_with_registry(
    service: Service,
    specs: Vec<EndpointSpec>,
    config: ClientConfig,
    registry: DriverRegistry,
) -> Result<(Arc<TunnelManager>, Vec<ActiveEndpoint>), CliError> {
    let manager = Arc::new(TunnelManager::new(Arc::new(registry), config));
    let mut driver_events = manager.take_driver_events().await.expect("new manager event stream");
    let handoff_manager = Arc::clone(&manager);
    tokio::spawn(async move {
        while let Some(event) = driver_events.recv().await {
            if let wormhole_core::DriverEvent::Handoff(barrier) = event.event {
                handoff_manager.confirm_handoff(event.endpoint);
                barrier.notify_one();
            }
        }
    });
    let ids = manager.expose(service, specs).await?;
    let endpoints = wait_manager(&manager, &ids).await;
    Ok((manager, endpoints))
}

async fn wait_manager(manager: &TunnelManager, ids: &[uuid::Uuid]) -> Vec<ActiveEndpoint> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let endpoints = manager
            .list()
            .into_iter()
            .filter(|endpoint| ids.contains(&endpoint.id))
            .collect::<Vec<_>>();
        if endpoints.len() == ids.len()
            && endpoints.iter().all(|endpoint| {
                matches!(endpoint.status, EndpointStatus::Online | EndpointStatus::Error(_))
            })
            || tokio::time::Instant::now() >= deadline
        {
            return endpoints;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

pub fn endpoint_result(endpoints: &[ActiveEndpoint]) -> Result<(), CliError> {
    if let Some(message) = endpoints.iter().find_map(|endpoint| match &endpoint.status {
        EndpointStatus::Error(message) if message.to_ascii_lowercase().contains("denied") => {
            Some(message.clone())
        }
        _ => None,
    }) {
        return Err(CliError::Denied(message));
    }
    let online =
        endpoints.iter().filter(|endpoint| endpoint.status == EndpointStatus::Online).count();
    if online == endpoints.len() {
        Ok(())
    } else if online == 0 {
        Err(CliError::EndpointFailed)
    } else {
        Err(CliError::Partial)
    }
}

#[cfg(test)]
#[path = "tunnel_commands_tests.rs"]
mod tests;
