//! `wormhole.toml` parsing and exact worktree project identity.

use std::{
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use wormhole_core::{
    EndpointSpec, Service,
    model::{RetryPolicy, ServiceProto},
};
use wormhole_proto::frames::{BufferPolicy, EdgeAuth, Persistence};

use crate::{error::CliError, project_name, project_root, tunnel_commands::parse_target};

#[derive(Debug, Deserialize)]
pub struct ProjectConfig {
    pub name: Option<String>,
    #[serde(default, rename = "service")]
    pub services: Vec<ProjectService>,
}

#[derive(Debug, Deserialize)]
pub struct ProjectService {
    pub name: String,
    pub target: String,
    pub proto: ServiceProto,
    #[serde(default, rename = "endpoint")]
    pub endpoints: Vec<ProjectEndpoint>,
}

#[derive(Debug, Deserialize)]
pub struct ProjectEndpoint {
    pub driver: String,
    pub remote: Option<String>,
    pub host: Option<String>,
    pub domain: Option<String>,
    pub public_port: Option<u16>,
    #[serde(default)]
    pub persist: bool,
    pub buffer: Option<ProjectBuffer>,
    pub auth: Option<ProjectAuth>,
    pub retry: Option<ProjectRetry>,
    pub inspect: Option<bool>,
    pub capture_assets: Option<bool>,
    pub capture_body_max: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ProjectBuffer {
    pub max_requests: u32,
    pub max_body: String,
    pub ttl: String,
}

#[derive(Debug, Deserialize)]
pub struct ProjectAuth {
    pub basic: Option<String>,
    pub bearer: Option<String>,
    #[serde(default)]
    pub links: bool,
}

#[derive(Debug, Deserialize)]
pub struct ProjectRetry {
    pub attempts: u32,
    pub backoff: String,
    pub max_backoff: Option<String>,
    #[serde(default)]
    pub on: Vec<String>,
    pub max_body: Option<String>,
    pub total_deadline: Option<String>,
}

impl ProjectConfig {
    pub fn load(directory: &Path) -> Result<Self, CliError> {
        let path = project_root::config_path(directory).ok_or_else(|| {
            CliError::Invalid("no wormhole.toml in this directory or repository".to_owned())
        })?;
        let content = fs::read_to_string(&path)?;
        toml::from_str(&content).map_err(|error| CliError::Invalid(error.to_string()))
    }

    pub fn selected(
        &self,
        names: &[String],
        directory: &Path,
        default_inspect: bool,
    ) -> Result<Vec<(Service, Vec<EndpointSpec>)>, CliError> {
        let mut selected = Vec::new();
        for service in &self.services {
            if !names.is_empty() && !names.contains(&service.name) {
                continue;
            }
            let target = parse_target(&service.target)?;
            let endpoints = service
                .endpoints
                .iter()
                .map(|endpoint| endpoint.build(service.proto, directory, default_inspect))
                .collect::<Result<Vec<_>, _>>()?;
            selected.push((
                Service { name: service.name.clone(), target, proto: service.proto },
                endpoints,
            ));
        }
        if selected.len() != if names.is_empty() { self.services.len() } else { names.len() } {
            return Err(CliError::Invalid("unknown or duplicate project service".to_owned()));
        }
        Ok(selected)
    }
}

impl ProjectEndpoint {
    fn build(
        &self,
        proto: ServiceProto,
        directory: &Path,
        default_inspect: bool,
    ) -> Result<EndpointSpec, CliError> {
        let (driver, qualifier) = self
            .driver
            .split_once(':')
            .map_or((self.driver.as_str(), None), |(driver, qualifier)| {
                (driver, Some(qualifier.to_owned()))
            });
        let buffer = self.buffer.as_ref().map(ProjectBuffer::build).transpose()?;
        let auth = self.auth.as_ref().map(ProjectAuth::build).transpose()?;
        let retry = self.retry.as_ref().map(ProjectRetry::build).transpose()?;
        Ok(EndpointSpec {
            proto,
            driver: driver.to_owned(),
            qualifier,
            remote: self.remote.clone(),
            host: self.host.as_deref().map(|host| {
                if driver == "wormhole" {
                    project_name::infer(Some(host), directory)
                } else {
                    host.to_owned()
                }
            }),
            auto_host: self.host.is_none(),
            domain: self.domain.clone(),
            public_port: self.public_port,
            persist: if self.persist { Persistence::Persistent } else { Persistence::Temporary },
            buffer,
            auth,
            retry,
            inspect: self.inspect.unwrap_or(default_inspect),
            inspect_assets: self.capture_assets.unwrap_or(false),
            capture_body_max: self
                .capture_body_max
                .as_deref()
                .map(parse_bytes)
                .transpose()?
                .unwrap_or(1024 * 1024),
            reservation: None,
        })
    }
}

impl ProjectBuffer {
    fn build(&self) -> Result<BufferPolicy, CliError> {
        Ok(BufferPolicy {
            max_requests: self.max_requests,
            max_body_bytes: parse_bytes(&self.max_body)?,
            ttl_secs: humantime::parse_duration(&self.ttl)
                .map_err(|error| CliError::Invalid(error.to_string()))?
                .as_secs(),
        })
    }
}

impl ProjectAuth {
    fn build(&self) -> Result<EdgeAuth, CliError> {
        if self.basic.as_ref().is_some_and(|value| value.split_once(':').is_none()) {
            return Err(CliError::Invalid("project basic auth must be user:password".to_owned()));
        }
        if self.bearer.as_ref().is_some_and(String::is_empty) {
            return Err(CliError::Invalid("project bearer auth must not be empty".to_owned()));
        }
        Ok(EdgeAuth {
            basic: self.basic.clone(),
            bearer: self.bearer.clone(),
            link_key: self.links.then(wormhole_core::share::generate_link_key),
        })
    }
}

impl ProjectRetry {
    fn build(&self) -> Result<RetryPolicy, CliError> {
        let delay = humantime::parse_duration(&self.backoff)
            .map_err(|error| CliError::Invalid(error.to_string()))?;
        let duration_ms = |value: &str| -> Result<u64, CliError> {
            humantime::parse_duration(value)
                .map_err(|error| CliError::Invalid(error.to_string()))?
                .as_millis()
                .try_into()
                .map_err(|error| CliError::Invalid(format!("retry duration: {error}")))
        };
        Ok(RetryPolicy {
            max_attempts: self.attempts,
            initial_delay_ms: delay
                .as_millis()
                .try_into()
                .map_err(|error| CliError::Invalid(format!("retry backoff: {error}")))?,
            max_delay_ms: self
                .max_backoff
                .as_deref()
                .map(duration_ms)
                .transpose()?
                .unwrap_or(30_000),
            retry_connect: self.on.is_empty() || self.on.iter().any(|item| item == "connect-error"),
            retry_5xx: self.on.iter().any(|item| item == "5xx"),
            max_body_bytes: self
                .max_body
                .as_deref()
                .map(parse_bytes)
                .transpose()?
                .unwrap_or(1024 * 1024),
            total_deadline_ms: self
                .total_deadline
                .as_deref()
                .map(duration_ms)
                .transpose()?
                .unwrap_or(60_000),
        })
    }
}

pub fn project_id(directory: &Path) -> Result<String, CliError> {
    let root = git_root(directory).unwrap_or_else(|| directory.to_owned());
    let canonical = root.canonicalize()?;
    let digest = Sha256::digest(canonical.as_os_str().as_encoded_bytes());
    let mut id = String::with_capacity(64);
    for byte in digest {
        write!(id, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(id)
}

fn git_root(directory: &Path) -> Option<PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(directory)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .output()
        .ok()?;
    output.status.success().then(|| PathBuf::from(String::from_utf8_lossy(&output.stdout).trim()))
}

pub fn parse_bytes(value: &str) -> Result<u64, CliError> {
    let split = value.find(|character: char| !character.is_ascii_digit()).unwrap_or(value.len());
    let (number, suffix) = value.split_at(split);
    let number = number
        .parse::<u64>()
        .map_err(|error| CliError::Invalid(format!("invalid byte size: {error}")))?;
    let multiplier = match suffix.to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "kib" => 1024,
        "mib" => 1024 * 1024,
        "gib" => 1024 * 1024 * 1024,
        "kb" => 1000,
        "mb" => 1000 * 1000,
        "gb" => 1000 * 1000 * 1000,
        _ => return Err(CliError::Invalid(format!("unknown byte-size suffix: {suffix}"))),
    };
    number
        .checked_mul(multiplier)
        .ok_or_else(|| CliError::Invalid("byte size overflows u64".to_owned()))
}

#[cfg(test)]
#[path = "project_tests.rs"]
mod tests;
