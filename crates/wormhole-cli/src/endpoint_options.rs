//! Validation and parsing for endpoint CLI policy overrides.

use wormhole_core::model::{RetryPolicy, ServiceProto};
use wormhole_proto::frames::EdgeAuth;

use crate::{cli::TunnelOptions, error::CliError};

pub fn validate_tld(
    proto: ServiceProto,
    options: &TunnelOptions,
    drivers: &[String],
) -> Result<(), CliError> {
    let Some(tld) = options.tld.as_deref() else {
        return Ok(());
    };
    if proto != ServiceProto::Http
        || !drivers.iter().any(|driver| driver.split(':').next() == Some("local"))
    {
        return Err(CliError::Invalid("--tld requires an HTTP local endpoint".to_owned()));
    }
    if !wormhole_core::config::valid_dns_suffix(tld) {
        return Err(CliError::Invalid("--tld must be a lowercase DNS suffix".to_owned()));
    }
    Ok(())
}

pub async fn parse_auth(options: &TunnelOptions) -> Result<Option<EdgeAuth>, CliError> {
    let values = if let Some(path) = &options.auth_file {
        vec![tokio::fs::read_to_string(path).await.map_err(CliError::Io)?.trim().to_owned()]
    } else {
        options.auth.clone()
    };
    let mut combined = EdgeAuth { basic: None, bearer: None, link_key: None };
    for value in values {
        let parsed = parse_auth_value(&value)?;
        if parsed.basic.is_some() && combined.basic.replace(parsed.basic.expect("basic")).is_some()
            || parsed.bearer.is_some()
                && combined.bearer.replace(parsed.bearer.expect("bearer")).is_some()
            || parsed.link_key.is_some()
                && combined.link_key.replace(parsed.link_key.expect("link key")).is_some()
        {
            return Err(CliError::Invalid("duplicate auth method".to_owned()));
        }
    }
    Ok((combined.basic.is_some() || combined.bearer.is_some() || combined.link_key.is_some())
        .then_some(combined))
}

fn parse_auth_value(value: &str) -> Result<EdgeAuth, CliError> {
    if let Some(credential) = value.strip_prefix("basic:")
        && credential.split_once(':').is_some()
    {
        return Ok(EdgeAuth { basic: Some(credential.to_owned()), bearer: None, link_key: None });
    }
    if value == "links" {
        return Ok(EdgeAuth {
            basic: None,
            bearer: None,
            link_key: Some(wormhole_core::share::generate_link_key()),
        });
    }
    if let Some(token) = value.strip_prefix("bearer:")
        && !token.is_empty()
    {
        return Ok(EdgeAuth { basic: None, bearer: Some(token.to_owned()), link_key: None });
    }
    Err(CliError::Invalid("auth must be basic:user:pass, bearer:secret, or links".to_owned()))
}

pub fn parse_retry(value: &str) -> Result<RetryPolicy, CliError> {
    let mut attempts = None;
    let mut delay = None;
    let mut max_delay = 30_000;
    let mut retry_connect = true;
    let mut retry_5xx = false;
    let mut max_body = 1024 * 1024;
    let mut deadline = 60_000;
    for item in value.split(',') {
        let (key, value) = item
            .split_once('=')
            .ok_or_else(|| CliError::Invalid(format!("invalid retry item: {item}")))?;
        match key {
            "attempts" => attempts = Some(value.parse::<u32>().map_err(invalid_retry)?),
            "backoff" => {
                let duration = humantime::parse_duration(value).map_err(invalid_retry)?;
                delay = Some(duration.as_millis().try_into().map_err(invalid_retry)?);
            }
            "max_backoff" => {
                max_delay = humantime::parse_duration(value)
                    .map_err(invalid_retry)?
                    .as_millis()
                    .try_into()
                    .map_err(invalid_retry)?;
            }
            "on" => {
                retry_connect = value.split('+').any(|item| item == "connect-error");
                retry_5xx = value.split('+').any(|item| item == "5xx");
            }
            "max_body" => max_body = crate::project::parse_bytes(value)?,
            "total_deadline" => {
                deadline = humantime::parse_duration(value)
                    .map_err(invalid_retry)?
                    .as_millis()
                    .try_into()
                    .map_err(invalid_retry)?;
            }
            _ => return Err(CliError::Invalid(format!("unknown retry key: {key}"))),
        }
    }
    Ok(RetryPolicy {
        max_attempts: attempts
            .ok_or_else(|| CliError::Invalid("retry attempts missing".to_owned()))?,
        initial_delay_ms: delay
            .ok_or_else(|| CliError::Invalid("retry backoff missing".to_owned()))?,
        max_delay_ms: max_delay,
        retry_connect,
        retry_5xx,
        max_body_bytes: max_body,
        total_deadline_ms: deadline,
    })
}

fn invalid_retry(error: impl std::fmt::Display) -> CliError {
    CliError::Invalid(format!("invalid retry policy: {error}"))
}
