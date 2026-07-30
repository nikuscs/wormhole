//! Collision-free application port reservations for `wormhole run`.

use std::{
    collections::HashSet,
    fs::File,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    ops::RangeInclusive,
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
};

use crate::{error::CliError, runtime::LOCAL_API_PORT};

#[derive(Debug)]
pub(super) struct AppPortReservation {
    listeners: Vec<std::net::TcpListener>,
    _lock: nix::fcntl::Flock<File>,
}

impl AppPortReservation {
    pub(super) fn release_listener(&mut self) {
        self.listeners.clear();
    }
}

pub(super) fn reserve_app_port(
    explicit: Option<u16>,
) -> Result<(u16, Option<AppPortReservation>), CliError> {
    if explicit == Some(LOCAL_API_PORT) {
        return Err(CliError::Invalid(format!(
            "port {LOCAL_API_PORT} is reserved for the local Wormhole API"
        )));
    }
    explicit.map_or_else(reserve_generated_port, |port| Ok((port, None)))
}

fn reserve_generated_port() -> Result<(u16, Option<AppPortReservation>), CliError> {
    reserve_generated_port_in(4000..=4999)
}

pub(super) fn reserve_generated_port_in(
    range: RangeInclusive<u16>,
) -> Result<(u16, Option<AppPortReservation>), CliError> {
    let directory = port_lock_directory()?;
    let occupied = listening_ports();
    for port in range {
        if occupied.contains(&port) {
            continue;
        }
        let Some(lock) = try_port_lock(&directory, port)? else {
            continue;
        };
        if let Some(listeners) = reserve_all_families(port) {
            return Ok((port, Some(AppPortReservation { listeners, _lock: lock })));
        }
    }
    Err(wormhole_core::error::PortError::Exhausted.into())
}

fn listening_ports() -> HashSet<u16> {
    listeners::get_all().map_or_else(
        |_| HashSet::new(),
        |listeners| {
            listeners
                .into_iter()
                .filter(|listener| {
                    listener.protocol == listeners::Protocol::TCP
                        && listener.state == listeners::SocketState::Listen
                })
                .map(|listener| listener.socket.port())
                .collect()
        },
    )
}

pub(super) fn reserve_all_families(port: u16) -> Option<Vec<std::net::TcpListener>> {
    let ipv4 = std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)).ok()?;
    let mut listeners = vec![ipv4];
    match reserve_ipv6(port) {
        Ok(ipv6) => listeners.push(ipv6),
        Err(error) if ipv6_unavailable(&error) => {}
        Err(_) => return None,
    }
    Some(listeners)
}

pub(super) fn reserve_ipv6(port: u16) -> Result<std::net::TcpListener, std::io::Error> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.set_only_v6(true)?;
    socket.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())?;
    socket.listen(1)?;
    Ok(socket.into())
}

fn ipv6_unavailable(error: &std::io::Error) -> bool {
    matches!(error.kind(), std::io::ErrorKind::AddrNotAvailable | std::io::ErrorKind::Unsupported)
        || matches!(
            error.raw_os_error(),
            Some(nix::libc::EAFNOSUPPORT | nix::libc::EPROTONOSUPPORT)
        )
}

fn port_lock_directory() -> Result<std::path::PathBuf, CliError> {
    let path = std::env::temp_dir()
        .join(format!("wormhole-port-locks-{}", nix::unistd::geteuid().as_raw()));
    if let Err(error) = std::fs::create_dir(&path)
        && error.kind() != std::io::ErrorKind::AlreadyExists
    {
        return Err(error.into());
    }
    let metadata = std::fs::symlink_metadata(&path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
    {
        return Err(CliError::Invalid(format!(
            "unsafe Wormhole port lock directory: {}",
            path.display()
        )));
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
    Ok(path)
}

fn try_port_lock(
    directory: &std::path::Path,
    port: u16,
) -> Result<Option<nix::fcntl::Flock<File>>, CliError> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).read(true).write(true).mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);
    let file = options.open(directory.join(port.to_string()))?;
    match nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock) {
        Ok(lock) => Ok(Some(lock)),
        Err((_file, nix::errno::Errno::EWOULDBLOCK)) => Ok(None),
        Err((_file, error)) => Err(std::io::Error::from_raw_os_error(error as i32).into()),
    }
}
