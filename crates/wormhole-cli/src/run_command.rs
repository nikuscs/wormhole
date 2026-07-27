//! `wormhole run` child lifecycle and port discovery.

use std::{
    net::{Ipv4Addr, SocketAddr},
    process::Stdio,
    time::Duration,
};

use jiff::Timestamp;
use std::os::unix::process::CommandExt as _;
use tokio::process::Command;
use wormhole_core::{
    Service, Target,
    model::ServiceProto,
    ports::{detect_child_port, reserve_port, wait_for_listener},
};

use crate::{
    cli::{Cli, RunArgs},
    client::DaemonClient,
    error::CliError,
    local_api::CreateServiceRequest,
    local_proxy::LocalProxy,
    output, project_name,
    tunnel_commands::build_specs,
};

pub async fn execute(cli: &Cli, args: &RunArgs) -> Result<(), CliError> {
    let config = crate::tunnel_commands::load_command_config(cli)?;
    let (app_port, app_reservation) = reserve_app_port(args.app_port)?;
    let app_address = SocketAddr::from((Ipv4Addr::LOCALHOST, app_port));
    let proxy = LocalProxy::bind(app_address).await?;
    let name = project_name::infer(args.options.name.as_deref(), &std::env::current_dir()?);
    let specs = build_specs(ServiceProto::Http, &args.options, &config).await?;
    let service = Service {
        name: name.clone(),
        target: Target::Port(proxy.address().port()),
        proto: ServiceProto::Http,
    };
    let spinner = output::spinner("waiting for endpoints", cli.json);
    let exposure: Result<_, CliError> = if args.options.foreground {
        crate::tunnel_commands::start_foreground(service, specs, config)
            .await
            .map(|(manager, endpoints)| (None, Some(manager), endpoints))
    } else {
        async {
            let client = DaemonClient::ensure(cli.config.as_ref()).await?;
            let request = CreateServiceRequest {
                project_id: None,
                remotes: Some(config.remotes.clone()),
                default_remote: config.default_remote.clone(),
                service,
                endpoints: specs,
            };
            let endpoints = client.create(&request).await?;
            Ok((Some(client), None, endpoints))
        }
        .await
    };
    output::finish_spinner(spinner);
    let (client, manager, endpoints) = exposure?;
    output::emit(super::format(cli.json), &endpoints);
    if let Err(error) = crate::tunnel_commands::endpoint_result(&endpoints) {
        let cleanup = close_exposure(client.as_ref(), manager.as_ref(), &name).await;
        proxy.close().await;
        cleanup?;
        return Err(error);
    }
    let Some(url) = endpoints.iter().find_map(|endpoint| endpoint.urls.first()).cloned() else {
        let cleanup = close_exposure(client.as_ref(), manager.as_ref(), &name).await;
        proxy.close().await;
        cleanup?;
        return Err(CliError::EndpointFailed);
    };
    let mut command = prepared_command(&args.command, app_port)?;
    configure_child(&mut command, app_port, &url);
    let started = Timestamp::now();
    drop(app_reservation);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let cleanup = close_exposure(client.as_ref(), manager.as_ref(), &name).await;
            proxy.close().await;
            cleanup?;
            return Err(error.into());
        }
    };
    let pid = child.id().ok_or_else(|| CliError::Invalid("child has no process id".to_owned()))?;
    let (result, interrupted) =
        wait_or_interrupt(&mut child, &proxy, app_address, pid, started).await;
    terminate_process_group(&mut child, pid).await;
    let cleanup = close_exposure(client.as_ref(), manager.as_ref(), &name).await;
    proxy.close().await;
    cleanup?;
    if interrupted {
        return Err(CliError::ChildExit(130));
    }
    let status = result?;
    let code = child_exit_code(status);
    if code == 0 { Ok(()) } else { Err(CliError::ChildExit(code)) }
}

#[cfg(unix)]
fn child_exit_code(status: std::process::ExitStatus) -> u8 {
    use std::os::unix::process::ExitStatusExt as _;
    status.code().and_then(|code| code.try_into().ok()).unwrap_or_else(|| {
        status.signal().map_or(1, |signal| (128 + signal).try_into().unwrap_or(255))
    })
}

#[cfg(not(unix))]
fn child_exit_code(status: std::process::ExitStatus) -> u8 {
    status.code().and_then(|code| code.try_into().ok()).unwrap_or(1)
}

fn reserve_app_port(
    explicit: Option<u16>,
) -> Result<(u16, Option<std::net::TcpListener>), CliError> {
    explicit.map_or_else(
        || {
            reserve_port(4000..=4999)
                .map(|(port, listener)| (port, Some(listener)))
                .map_err(Into::into)
        },
        |port| Ok((port, None)),
    )
}

fn configure_child(command: &mut Command, app_port: u16, url: &str) {
    command
        .env("PORT", app_port.to_string())
        .env("HOST", Ipv4Addr::LOCALHOST.to_string())
        .env("WORMHOLE_URL", url)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    command.as_std_mut().process_group(0);
}

async fn wait_or_interrupt(
    child: &mut tokio::process::Child,
    proxy: &LocalProxy,
    expected: SocketAddr,
    pid: u32,
    started: Timestamp,
) -> (Result<std::process::ExitStatus, CliError>, bool) {
    let result = {
        let waiting = wait_for_child(child, proxy, expected, pid, started);
        tokio::pin!(waiting);
        tokio::select! {
            result = &mut waiting => Some(result),
            signal = tokio::signal::ctrl_c() => {
                if let Err(error) = signal {
                    return (Err(error.into()), false);
                }
                None
            }
        }
    };
    result.map_or_else(|| (Ok(failure_status()), true), |result| (result, false))
}

#[cfg(unix)]
fn failure_status() -> std::process::ExitStatus {
    use std::os::unix::process::ExitStatusExt as _;
    std::process::ExitStatus::from_raw(130 << 8)
}

#[cfg(not(unix))]
fn failure_status() -> std::process::ExitStatus {
    std::process::Command::new("false").status().expect("false command must run")
}

async fn terminate_process_group(child: &mut tokio::process::Child, pid: u32) {
    signal_process_group(pid, nix::sys::signal::Signal::SIGTERM);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while process_group_is_alive(pid) && tokio::time::Instant::now() < deadline {
        let _status = child.try_wait();
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    if process_group_is_alive(pid) {
        signal_process_group(pid, nix::sys::signal::Signal::SIGKILL);
    }
    let _waited = child.wait().await;
}

fn process_group_is_alive(pid: u32) -> bool {
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(-pid.cast_signed()), None).is_ok()
}

fn signal_process_group(pid: u32, signal: nix::sys::signal::Signal) {
    let _sent = nix::sys::signal::killpg(nix::unistd::Pid::from_raw(pid.cast_signed()), signal);
}

async fn close_exposure(
    client: Option<&DaemonClient>,
    manager: Option<&std::sync::Arc<wormhole_core::TunnelManager>>,
    name: &str,
) -> Result<(), CliError> {
    if let Some(client) = client {
        client.delete_service(name, None, false).await?;
    }
    if let Some(manager) = manager {
        manager.shutdown_with_forget().await?;
    }
    Ok(())
}

async fn wait_for_child(
    child: &mut tokio::process::Child,
    proxy: &LocalProxy,
    expected: SocketAddr,
    pid: u32,
    started: Timestamp,
) -> Result<std::process::ExitStatus, CliError> {
    let listener = wait_for_listener(expected, listener_timeout());
    tokio::pin!(listener);
    tokio::select! {
        status = child.wait() => return status.map_err(Into::into),
        result = &mut listener => {
            if result.is_err() {
                if let Some(port) = detect_for(pid, started).await {
                    proxy.retarget(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
                } else {
                    return Err(CliError::Invalid(
                        "child did not open a listening port".to_owned(),
                    ));
                }
            }
        }
    }
    child.wait().await.map_err(Into::into)
}

async fn detect_for(pid: u32, started: Timestamp) -> Option<u16> {
    let deadline = tokio::time::Instant::now() + detect_timeout();
    loop {
        let detected = tokio::task::spawn_blocking(move || detect_child_port(pid, started))
            .await
            .ok()
            .flatten();
        if detected.is_some() || tokio::time::Instant::now() >= deadline {
            return detected;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

fn prepared_command(arguments: &[String], port: u16) -> Result<Command, CliError> {
    let (program, args) = arguments
        .split_first()
        .ok_or_else(|| CliError::Invalid("run command is empty".to_owned()))?;
    let mut values = args.to_vec();
    let executable =
        std::path::Path::new(program).file_name().and_then(|name| name.to_str()).unwrap_or(program);
    let inject = matches!(executable, "vite" | "astro")
        || executable == "ng" && values.first().is_some_and(|value| value == "serve")
        || executable == "react-router" && values.first().is_some_and(|value| value == "dev");
    let has_port = values.iter().any(|value| value == "--port" || value.starts_with("--port="));
    if inject && !has_port {
        values.extend(["--port".to_owned(), port.to_string()]);
        if !values.iter().any(|value| value == "--host" || value.starts_with("--host=")) {
            values.extend(["--host".to_owned(), Ipv4Addr::LOCALHOST.to_string()]);
        }
    }
    let mut command = Command::new(program);
    command.args(values);
    Ok(command)
}

#[cfg(debug_assertions)]
fn listener_timeout() -> Duration {
    std::env::var("WORMHOLE_RUN_LISTEN_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.parse().ok())
        .map_or(Duration::from_mins(1), Duration::from_millis)
}

#[cfg(not(debug_assertions))]
const fn listener_timeout() -> Duration {
    Duration::from_mins(1)
}

#[cfg(debug_assertions)]
fn detect_timeout() -> Duration {
    std::env::var("WORMHOLE_RUN_DETECT_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.parse().ok())
        .map_or(Duration::from_secs(10), Duration::from_millis)
}

#[cfg(not(debug_assertions))]
const fn detect_timeout() -> Duration {
    Duration::from_secs(10)
}
