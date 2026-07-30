use std::{
    fmt::Write as _,
    io::{IsTerminal as _, Read as _, Write as _},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngExt as _;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::error::CliError;

const ADMIN_TOKEN_ENV: &str = "WORMHOLE_CLOUDFLARE_ADMIN_TOKEN";

pub(super) fn cloudflare_token() -> Result<Zeroizing<String>, CliError> {
    if let Ok(token) = std::env::var("CLOUDFLARE_API_TOKEN")
        && !token.trim().is_empty()
    {
        return Ok(Zeroizing::new(token));
    }
    if std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
        let token = rpassword::prompt_password("Cloudflare API token: ")?;
        if !token.trim().is_empty() {
            return Ok(Zeroizing::new(token));
        }
    }
    Err(CliError::Invalid(
        "set CLOUDFLARE_API_TOKEN with Zone DNS Edit, Zone Read, Workers Scripts Edit, and Workers Routes Edit"
            .to_owned(),
    ))
}

pub(super) fn existing_admin_token(worker: &str) -> Result<Zeroizing<String>, CliError> {
    if let Ok(token) = std::env::var(ADMIN_TOKEN_ENV)
        && !token.trim().is_empty()
    {
        return Ok(Zeroizing::new(token));
    }
    let path = admin_token_path(worker)?;
    if path.exists() {
        return read_admin_token(&path);
    }
    if std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
        let token = rpassword::prompt_password("Existing Wormhole relay ADMIN_TOKEN: ")?;
        if !token.trim().is_empty() {
            return Ok(Zeroizing::new(token));
        }
    }
    Err(CliError::Invalid(format!(
        "existing Worker requires {ADMIN_TOKEN_ENV} or its saved administrator token"
    )))
}

pub(super) fn save_admin_token(worker: &str, token: &str) -> Result<(), CliError> {
    let path = admin_token_path(worker)?;
    if let Some(parent) = path.parent() {
        prepare_private_directory(parent)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(true).write(true).mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);
    let mut file = options.open(path)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    file.write_all(token.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

pub(super) fn remove_admin_token(worker: &str) {
    if let Ok(path) = admin_token_path(worker) {
        let _removed = std::fs::remove_file(path);
    }
}

fn read_admin_token(path: &std::path::Path) -> Result<Zeroizing<String>, CliError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).custom_flags(nix::libc::O_NOFOLLOW);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if metadata.uid() != nix::unistd::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
        return Err(CliError::Invalid(format!(
            "saved Cloudflare administrator token has unsafe ownership or permissions: {}",
            path.display()
        )));
    }
    let mut token = String::new();
    file.take(4097).read_to_string(&mut token)?;
    if token.len() > 4096 || token.trim().is_empty() {
        return Err(CliError::Invalid(
            "saved Cloudflare administrator token is invalid".to_owned(),
        ));
    }
    Ok(Zeroizing::new(token.trim().to_owned()))
}

fn prepare_private_directory(path: &std::path::Path) -> Result<(), CliError> {
    if path.exists() {
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != nix::unistd::geteuid().as_raw()
        {
            return Err(CliError::Invalid(format!(
                "unsafe Cloudflare credential directory: {}",
                path.display()
            )));
        }
    } else {
        std::fs::create_dir_all(path)?;
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn admin_token_path(worker: &str) -> Result<std::path::PathBuf, CliError> {
    let base = directories::BaseDirs::new()
        .ok_or_else(|| CliError::Invalid("cannot locate the user config directory".to_owned()))?;
    Ok(base.config_dir().join("wormhole/cloudflare").join(format!("{worker}.admin-token")))
}

pub(super) fn random_secret() -> Zeroizing<String> {
    let bytes = rand::rng().random::<[u8; 32]>();
    Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes))
}

pub(super) fn worker_name(domain: &str) -> String {
    let label = domain
        .split('.')
        .next()
        .unwrap_or("relay")
        .chars()
        .map(|character| if character.is_ascii_alphanumeric() { character } else { '-' })
        .collect::<String>();
    let digest = Sha256::digest(domain.as_bytes());
    let mut suffix = String::with_capacity(8);
    for byte in &digest[..4] {
        write!(suffix, "{byte:02x}").expect("writing to a String cannot fail");
    }
    format!("wormhole-{}-{suffix}", label.trim_matches('-'))
}

pub(super) fn validate_domain(value: &str) -> Result<String, CliError> {
    let domain = value.trim().trim_end_matches('.').to_ascii_lowercase();
    let valid = domain.len() <= 253
        && domain.contains('.')
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|character| {
                    character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
                })
        });
    if valid {
        Ok(domain)
    } else {
        Err(CliError::Invalid("invalid Cloudflare relay domain".to_owned()))
    }
}

pub(super) fn validate_domain_layout(
    public_domain: &str,
    relay_domain: &str,
) -> Result<(), CliError> {
    if relay_domain != public_domain && relay_domain.ends_with(&format!(".{public_domain}")) {
        Ok(())
    } else {
        Err(CliError::Invalid("relay domain must be a subdomain of the public domain".to_owned()))
    }
}

pub(super) fn validate_worker_name(value: &str) -> Result<(), CliError> {
    if !value.is_empty()
        && value.len() <= 63
        && value.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
    {
        Ok(())
    } else {
        Err(CliError::Invalid("invalid Cloudflare Worker name".to_owned()))
    }
}

pub(super) fn validate_remote_name(value: &str) -> Result<(), CliError> {
    if !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        Ok(())
    } else {
        Err(CliError::Invalid("invalid remote name".to_owned()))
    }
}

pub(super) fn validate_bundle_version(version: &str) -> Result<(), CliError> {
    let current = env!("CARGO_PKG_VERSION");
    if current == "0.0.0" || version == current {
        Ok(())
    } else {
        Err(CliError::Invalid(format!(
            "Worker bundle version {version} does not match wormhole {current}"
        )))
    }
}
