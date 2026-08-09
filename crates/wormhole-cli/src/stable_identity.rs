//! Zero-configuration stable provider identities for worktrees.

use sha2::{Digest as _, Sha256};
use wormhole_core::{ClientConfig, EndpointSpec, model::ServiceProto};
use wormhole_proto::frames::Persistence;

use crate::error::CliError;

pub fn apply(
    spec: &mut EndpointSpec,
    stable_slug: Option<&str>,
    config: &ClientConfig,
    local_tld: Option<&str>,
) -> Result<(), CliError> {
    let Some(slug) = stable_slug.filter(|_| config.defaults.stable_worktree_urls) else {
        return Ok(());
    };
    if spec.proto != ServiceProto::Http {
        return Ok(());
    }
    match (spec.driver.as_str(), spec.qualifier.as_deref()) {
        ("wormhole", _) => {
            let generated = spec.host.is_none();
            if generated {
                spec.host = Some(slug.to_owned());
            }
            if spec.domain.is_none() {
                spec.domain.clone_from(&config.defaults.domain);
            }
            if generated {
                spec.persist = Persistence::Persistent;
            }
            Ok(())
        }
        ("local", _) => {
            if spec.host.is_none() {
                spec.host =
                    Some(format!("{slug}.{}", local_tld.unwrap_or(&config.defaults.local_tld)));
            }
            Ok(())
        }
        ("cloudflare", Some("named")) => apply_cloudflare(spec, slug, config),
        ("tailscale", qualifier) if spec.public_port.is_none() => {
            spec.public_port = Some(tailscale_port(slug, qualifier, config));
            Ok(())
        }
        _ => Ok(()),
    }
}

fn apply_cloudflare(
    spec: &mut EndpointSpec,
    slug: &str,
    config: &ClientConfig,
) -> Result<(), CliError> {
    if spec.host.is_some() && spec.domain.is_some() {
        return Err(CliError::Invalid(
            "cloudflare:named accepts an explicit host or a worktree domain, not both".to_owned(),
        ));
    }
    let generated = spec.host.is_none();
    if generated {
        let domain = spec
            .domain
            .take()
            .or_else(|| config.defaults.domain.clone())
            .or_else(|| config.defaults.cloudflare_domain.clone())
            .ok_or_else(|| {
                CliError::Invalid(
                    "stable cloudflare:named URLs require WORMHOLE_DOMAIN or defaults.domain"
                        .to_owned(),
                )
            })?;
        spec.host = Some(format!("{slug}.{domain}"));
    }
    if !spec.host.as_deref().is_some_and(valid_cloudflare_hostname) {
        return Err(CliError::Invalid(
            "cloudflare:named host must be a valid lowercase DNS hostname".to_owned(),
        ));
    }
    spec.domain = None;
    if generated {
        spec.persist = Persistence::Persistent;
    }
    Ok(())
}

fn valid_cloudflare_hostname(value: &str) -> bool {
    value.len() <= 253
        && value.contains('.')
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|character| {
                    character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
                })
        })
}

fn tailscale_port(slug: &str, qualifier: Option<&str>, config: &ClientConfig) -> u16 {
    let digest = Sha256::digest(slug.as_bytes());
    let hash = u64::from_be_bytes(digest[..8].try_into().expect("SHA-256 prefix"));
    if qualifier == Some("funnel") {
        const PORTS: [u16; 3] = [443, 8443, 10_000];
        return PORTS[usize::try_from(hash % 3).expect("funnel slot")];
    }
    let range = config.defaults.tailscale_https_port_range;
    let offset = u32::try_from(hash % u64::from(range.len())).expect("port offset");
    u16::try_from(u32::from(range.start) + offset).expect("configured port range")
}
