//! ACME DNS-01 issuance, Cloudflare challenge records, cache, and renewal.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    sync::Arc,
    time::Duration,
};

use camino::{Utf8Path, Utf8PathBuf};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use parking_lot::RwLock;
use rustls::{pki_types::CertificateDer, pki_types::pem::PemObject, sign::CertifiedKey};
use serde::Serialize;
use x509_parser::parse_x509_certificate;

use crate::{
    acme_cloudflare::{CloudflareDns, DnsRecord},
    certs::{CertResolver, load_pem},
    config::{AcmeConfig, StaticCertificate, WormholedConfig},
};

const RENEW_BEFORE_SECONDS: i64 = 30 * 24 * 60 * 60;
const DAILY: Duration = Duration::from_hours(24);

/// Loads cached wildcard certificates or completes initial DNS-01 issuance.
pub async fn load_or_issue(
    config: &WormholedConfig,
) -> Result<Vec<(String, Arc<CertifiedKey>)>, AcmeError> {
    let acme = config
        .tls
        .acme
        .as_ref()
        .ok_or_else(|| AcmeError::Config("tls.acme is missing".to_owned()))?;
    let cert_dir = config.server.data_dir.join("certs");
    fs::create_dir_all(&cert_dir)
        .map_err(|source| AcmeError::Io { path: cert_dir.clone(), source })?;
    let account = load_account(&config.server.data_dir, acme).await?;
    let dns = CloudflareDns::new(acme)?;
    let mut ready = Vec::with_capacity(config.server.domains.len());
    for domain in &config.server.domains {
        if let Some(cached) = load_cached(&cert_dir, domain)? {
            ready.push((domain.clone(), cached));
            continue;
        }
        issue_domain(&account, &dns, &cert_dir, domain).await?;
        let mapping = cache_mapping(&cert_dir, domain);
        ready.push((
            domain.clone(),
            load_pem(&mapping).map_err(|error| AcmeError::Certificate(error.to_string()))?,
        ));
    }
    Ok(ready)
}

/// Starts the daily cache-expiry scan and hot-swap renewal loop.
pub fn spawn_renewal(
    config: WormholedConfig,
    resolver: Arc<CertResolver>,
    last_error: Arc<RwLock<Option<String>>>,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(DAILY);
        interval.tick().await;
        loop {
            interval.tick().await;
            match load_or_issue(&config).await {
                Ok(certificates) => {
                    for (domain, certificate) in certificates {
                        resolver.insert(domain, certificate);
                    }
                    *last_error.write() = None;
                }
                Err(error) => {
                    tracing::error!(%error, "ACME certificate renewal failed");
                    *last_error.write() = Some(error.to_string());
                }
            }
        }
    });
}

async fn load_account(data_dir: &Utf8Path, config: &AcmeConfig) -> Result<Account, AcmeError> {
    let account_dir = data_dir.join("acme");
    fs::create_dir_all(&account_dir)
        .map_err(|source| AcmeError::Io { path: account_dir.clone(), source })?;
    let credentials_path = account_dir.join("account.json");
    if credentials_path.is_file() {
        let encoded = fs::read(&credentials_path)
            .map_err(|source| AcmeError::Io { path: credentials_path.clone(), source })?;
        let credentials = serde_json::from_slice::<AccountCredentials>(&encoded)
            .map_err(|error| AcmeError::Account(error.to_string()))?;
        return Account::builder()
            .map_err(|error| AcmeError::Account(error.to_string()))?
            .from_credentials(credentials)
            .await
            .map_err(|error| AcmeError::Account(error.to_string()));
    }
    let contacts = [config.contact.as_str()];
    let (account, credentials) = Account::builder()
        .map_err(|error| AcmeError::Account(error.to_string()))?
        .create(
            &NewAccount {
                contact: &contacts,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            config.directory.clone(),
            None,
        )
        .await
        .map_err(|error| AcmeError::Account(error.to_string()))?;
    write_private_json(&credentials_path, &credentials)?;
    Ok(account)
}

async fn issue_domain(
    account: &Account,
    dns: &CloudflareDns,
    cert_dir: &Utf8Path,
    domain: &str,
) -> Result<(), AcmeError> {
    let identifiers = [Identifier::Dns(domain.to_owned()), Identifier::Dns(format!("*.{domain}"))];
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .map_err(|error| AcmeError::Order(error.to_string()))?;
    let mut records = Vec::new();
    if let Err(error) = provision_dns_challenges(&mut order, dns, domain, &mut records).await {
        cleanup_records(dns, &records).await;
        return Err(error);
    }
    let ready = order.poll_ready(&RetryPolicy::default()).await;
    cleanup_records(dns, &records).await;
    let status = ready.map_err(|error| AcmeError::Order(error.to_string()))?;
    if status != OrderStatus::Ready {
        return Err(AcmeError::Order(format!("unexpected order status: {status:?}")));
    }
    let private_key =
        order.finalize().await.map_err(|error| AcmeError::Order(error.to_string()))?;
    let certificate = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .map_err(|error| AcmeError::Order(error.to_string()))?;
    let mapping = cache_mapping(cert_dir, domain);
    write_private(&mapping.key, private_key.as_bytes())?;
    write_atomic(&mapping.cert, certificate.as_bytes(), 0o644)?;
    Ok(())
}

async fn provision_dns_challenges(
    order: &mut instant_acme::Order,
    dns: &CloudflareDns,
    domain: &str,
    records: &mut Vec<DnsRecord>,
) -> Result<(), AcmeError> {
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authorization = result.map_err(|error| AcmeError::Order(error.to_string()))?;
        match authorization.status {
            AuthorizationStatus::Valid => continue,
            AuthorizationStatus::Pending => {}
            status => {
                return Err(AcmeError::Order(format!("unexpected authorization: {status:?}")));
            }
        }
        let mut challenge = authorization
            .challenge(ChallengeType::Dns01)
            .ok_or_else(|| AcmeError::Order("DNS-01 challenge is missing".to_owned()))?;
        let identifier = challenge.identifier().to_string();
        let name = format!("_acme-challenge.{}", identifier.trim_start_matches("*."));
        let value = challenge.key_authorization().dns_value();
        records.push(dns.create_txt(domain, &name, &value).await?);
        tokio::time::sleep(Duration::from_secs(5)).await;
        challenge.set_ready().await.map_err(|error| AcmeError::Order(error.to_string()))?;
    }
    Ok(())
}

async fn cleanup_records(dns: &CloudflareDns, records: &[DnsRecord]) {
    for record in records {
        if let Err(error) = dns.delete(record).await {
            tracing::error!(%error, "failed to clean up ACME DNS record");
        }
    }
}

fn load_cached(cert_dir: &Utf8Path, domain: &str) -> Result<Option<Arc<CertifiedKey>>, AcmeError> {
    let mapping = cache_mapping(cert_dir, domain);
    if !mapping.cert.is_file() || !mapping.key.is_file() || expires_soon(&mapping.cert)? {
        return Ok(None);
    }
    Ok(Some(load_pem(&mapping).map_err(|error| AcmeError::Certificate(error.to_string()))?))
}

fn expires_soon(path: &Utf8Path) -> Result<bool, AcmeError> {
    let certificate = CertificateDer::pem_file_iter(path)
        .map_err(|error| AcmeError::Certificate(error.to_string()))?
        .next()
        .ok_or_else(|| AcmeError::Certificate("certificate chain is empty".to_owned()))?
        .map_err(|error| AcmeError::Certificate(error.to_string()))?;
    let (_, parsed) = parse_x509_certificate(certificate.as_ref())
        .map_err(|error| AcmeError::Certificate(error.to_string()))?;
    let renew_at = jiff::Timestamp::now().as_second() + RENEW_BEFORE_SECONDS;
    Ok(parsed.validity().not_after.timestamp() <= renew_at)
}

fn cache_mapping(cert_dir: &Utf8Path, domain: &str) -> StaticCertificate {
    StaticCertificate {
        domain: domain.to_owned(),
        cert: cert_dir.join(format!("{domain}.pem")),
        key: cert_dir.join(format!("{domain}.key.pem")),
    }
}

fn write_private_json<T: Serialize>(path: &Utf8Path, value: &T) -> Result<(), AcmeError> {
    let encoded =
        serde_json::to_vec_pretty(value).map_err(|error| AcmeError::Account(error.to_string()))?;
    write_private(path, &encoded)
}

fn write_private(path: &Utf8Path, value: &[u8]) -> Result<(), AcmeError> {
    write_atomic(path, value, 0o600)
}

fn write_atomic(path: &Utf8Path, value: &[u8], mode: u32) -> Result<(), AcmeError> {
    let temporary = path.with_extension(format!("{}.tmp", uuid::Uuid::now_v7()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&temporary)
        .map_err(|source| AcmeError::Io { path: temporary.clone(), source })?;
    file.write_all(value)
        .and_then(|()| file.sync_all())
        .map_err(|source| AcmeError::Io { path: temporary.clone(), source })?;
    fs::rename(&temporary, path)
        .map_err(|source| AcmeError::Io { path: path.to_owned(), source })?;
    Ok(())
}

/// ACME account, DNS challenge, issuance, cache, or renewal failure.
#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    /// Provisioning cannot proceed with the current settings.
    #[error("invalid ACME configuration: {0}")]
    Config(String),
    /// Account creation or restoration failed.
    #[error("ACME account failed: {0}")]
    Account(String),
    /// Order or challenge processing failed.
    #[error("ACME order failed: {0}")]
    Order(String),
    /// Cloudflare DNS API rejected a request.
    #[error("Cloudflare DNS failed: {0}")]
    Dns(String),
    /// Certificate cache or parsing failed.
    #[error("cached certificate failed: {0}")]
    Certificate(String),
    /// HTTP request failed.
    #[error("ACME HTTP failed: {0}")]
    Http(#[from] reqwest::Error),
    /// Filesystem operation failed.
    #[error("ACME filesystem operation failed for {path}: {source}")]
    Io { path: Utf8PathBuf, source: std::io::Error },
}

#[cfg(test)]
#[path = "acme_tests.rs"]
mod tests;
