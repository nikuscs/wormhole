//! Wildcard certificate loading and synchronous SNI resolution.

use std::{collections::HashMap, fmt, sync::Arc, time::Duration};

use parking_lot::RwLock;
use rustls::{
    crypto::aws_lc_rs::sign::any_supported_type,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};

use crate::{
    acme,
    config::{StaticCertificate, TlsMode, WormholedConfig},
};

/// Ready certificate set shared by QUIC and HTTPS listeners.
pub struct CertManager {
    resolver: Arc<CertResolver>,
    static_certs: Option<Vec<StaticCertificate>>,
    last_renewal_error: Arc<RwLock<Option<String>>>,
}

impl CertManager {
    /// Loads or issues every configured domain certificate before listeners bind.
    pub async fn ready(config: &WormholedConfig) -> Result<Self, CertError> {
        let _installed = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let resolver = Arc::new(CertResolver::new(config.server.domains.clone()));
        let static_certs = match config.tls.mode {
            TlsMode::Static => {
                let mappings = config
                    .tls
                    .static_config
                    .as_ref()
                    .ok_or_else(|| CertError::Config("tls.static is missing".to_owned()))?
                    .certs
                    .clone();
                load_static(&resolver, &mappings)?;
                Some(mappings)
            }
            TlsMode::SelfSigned => {
                load_self_signed(&resolver, &config.server.domains)?;
                None
            }
            TlsMode::AcmeDns01 => {
                let issued = acme::load_or_issue(config).await?;
                for (domain, certificate) in issued {
                    resolver.insert(domain, certificate);
                }
                None
            }
        };
        resolver.require_all()?;
        let last_renewal_error = Arc::new(RwLock::new(None));
        match config.tls.mode {
            TlsMode::Static => spawn_static_reload(
                static_certs.clone().expect("static mappings loaded"),
                Arc::clone(&resolver),
                Arc::clone(&last_renewal_error),
            ),
            TlsMode::AcmeDns01 => acme::spawn_renewal(
                config.clone(),
                Arc::clone(&resolver),
                Arc::clone(&last_renewal_error),
            ),
            TlsMode::SelfSigned => {}
        }
        Ok(Self { resolver, static_certs, last_renewal_error })
    }

    /// Returns the non-blocking SNI resolver shared by all TLS frontends.
    pub fn resolver(&self) -> Arc<CertResolver> {
        Arc::clone(&self.resolver)
    }

    /// Returns the latest background reload or renewal failure.
    pub fn last_renewal_error(&self) -> Option<String> {
        self.last_renewal_error.read().clone()
    }

    /// Returns certificate expiration times as Unix seconds for each configured domain.
    pub fn expiries(&self) -> Vec<(String, i64)> {
        self.resolver.expiries()
    }

    /// Reloads operator-managed PEM files atomically after all parse successfully.
    pub fn reload_static(&self) -> Result<(), CertError> {
        let mappings = self
            .static_certs
            .as_ref()
            .ok_or_else(|| CertError::Config("certificate mode is not static".to_owned()))?;
        let mut replacements = Vec::with_capacity(mappings.len());
        for mapping in mappings {
            replacements.push((mapping.domain.clone(), load_pem(mapping)?));
        }
        self.resolver.replace(replacements);
        Ok(())
    }
}

/// Pure-lookup rustls certificate resolver.
pub struct CertResolver {
    domains: Vec<String>,
    certificates: RwLock<HashMap<String, Arc<CertifiedKey>>>,
}

impl CertResolver {
    fn new(domains: Vec<String>) -> Self {
        Self { domains, certificates: RwLock::new(HashMap::new()) }
    }

    /// Looks up an apex or one-label wildcard hostname.
    pub fn resolve_name(&self, server_name: &str) -> Option<Arc<CertifiedKey>> {
        let domain = self.domains.iter().find(|domain| covers(domain, server_name))?;
        self.certificates.read().get(domain).cloned()
    }

    fn expiries(&self) -> Vec<(String, i64)> {
        let certificates = self.certificates.read();
        self.domains
            .iter()
            .filter_map(|domain| {
                let der = certificates.get(domain)?.cert.first()?;
                let (_, certificate) = x509_parser::parse_x509_certificate(der.as_ref()).ok()?;
                Some((domain.clone(), certificate.validity().not_after.timestamp()))
            })
            .collect()
    }

    pub(crate) fn insert(&self, domain: String, certificate: Arc<CertifiedKey>) {
        self.certificates.write().insert(domain, certificate);
    }

    fn replace(&self, replacements: Vec<(String, Arc<CertifiedKey>)>) {
        let mut certificates = self.certificates.write();
        for (domain, certificate) in replacements {
            certificates.insert(domain, certificate);
        }
    }

    fn require_all(&self) -> Result<(), CertError> {
        let certificates = self.certificates.read();
        for domain in &self.domains {
            if !certificates.contains_key(domain) {
                return Err(CertError::MissingDomain(domain.clone()));
            }
        }
        Ok(())
    }
}

impl fmt::Debug for CertResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CertResolver")
            .field("domains", &self.domains)
            .finish_non_exhaustive()
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.resolve_name(client_hello.server_name()?)
    }
}

fn spawn_static_reload(
    mappings: Vec<StaticCertificate>,
    resolver: Arc<CertResolver>,
    last_error: Arc<RwLock<Option<String>>>,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_hours(24));
        interval.tick().await;
        loop {
            interval.tick().await;
            let replacements = mappings
                .iter()
                .map(|mapping| load_pem(mapping).map(|key| (mapping.domain.clone(), key)))
                .collect::<Result<Vec<_>, _>>();
            match replacements {
                Ok(replacements) => {
                    resolver.replace(replacements);
                    *last_error.write() = None;
                }
                Err(error) => {
                    tracing::error!(%error, "static certificate reload failed");
                    *last_error.write() = Some(error.to_string());
                }
            }
        }
    });
}

fn load_static(resolver: &CertResolver, mappings: &[StaticCertificate]) -> Result<(), CertError> {
    for mapping in mappings {
        resolver.insert(mapping.domain.clone(), load_pem(mapping)?);
    }
    Ok(())
}

pub(crate) fn load_pem(mapping: &StaticCertificate) -> Result<Arc<CertifiedKey>, CertError> {
    let certificates = CertificateDer::pem_file_iter(&mapping.cert)
        .map_err(|error| CertError::Pem(mapping.cert.to_string(), error.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| CertError::Pem(mapping.cert.to_string(), error.to_string()))?;
    if certificates.is_empty() {
        return Err(CertError::Pem(
            mapping.cert.to_string(),
            "certificate chain is empty".to_owned(),
        ));
    }
    validate_certificate_names(&certificates[0], &mapping.domain)?;
    let private_key = PrivateKeyDer::from_pem_file(&mapping.key)
        .map_err(|error| CertError::Pem(mapping.key.to_string(), error.to_string()))?;
    certified_key(certificates, private_key)
}

fn validate_certificate_names(
    certificate: &CertificateDer<'_>,
    domain: &str,
) -> Result<(), CertError> {
    let (_, parsed) = x509_parser::parse_x509_certificate(certificate.as_ref())
        .map_err(|error| CertError::Pem(domain.to_owned(), error.to_string()))?;
    let alternative_names = parsed
        .subject_alternative_name()
        .map_err(|error| CertError::Pem(domain.to_owned(), error.to_string()))?
        .ok_or_else(|| CertError::Config(format!("certificate for {domain} has no SAN")))?;
    let wildcard = format!("*.{domain}");
    let mut apex_found = false;
    let mut wildcard_found = false;
    for name in &alternative_names.value.general_names {
        if let x509_parser::extensions::GeneralName::DNSName(name) = name {
            apex_found |= name.eq_ignore_ascii_case(domain);
            wildcard_found |= name.eq_ignore_ascii_case(&wildcard);
        }
    }
    if !apex_found || !wildcard_found {
        return Err(CertError::Config(format!("certificate must cover {domain} and {wildcard}")));
    }
    Ok(())
}

fn load_self_signed(resolver: &CertResolver, domains: &[String]) -> Result<(), CertError> {
    for domain in domains {
        let generated =
            rcgen::generate_simple_self_signed(vec![domain.clone(), format!("*.{domain}")])
                .map_err(|error| CertError::Generate(domain.clone(), error.to_string()))?;
        let certificates = vec![generated.cert.der().clone()];
        let private_key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der()));
        resolver.insert(domain.clone(), certified_key(certificates, private_key)?);
    }
    Ok(())
}

pub(crate) fn certified_key(
    certificates: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> Result<Arc<CertifiedKey>, CertError> {
    let signing_key = any_supported_type(&private_key)
        .map_err(|error| CertError::SigningKey(error.to_string()))?;
    let certified = CertifiedKey::new(certificates, signing_key);
    certified.keys_match().map_err(|error| CertError::SigningKey(error.to_string()))?;
    Ok(Arc::new(certified))
}

fn covers(domain: &str, server_name: &str) -> bool {
    if server_name == domain {
        return true;
    }
    server_name
        .strip_suffix(&format!(".{domain}"))
        .is_some_and(|label| !label.is_empty() && !label.contains('.'))
}

/// Certificate loading, issuance, or resolution failure.
#[derive(Debug, thiserror::Error)]
pub enum CertError {
    /// TLS configuration is incomplete.
    #[error("invalid certificate configuration: {0}")]
    Config(String),
    /// PEM parsing failed.
    #[error("failed to load PEM {0}: {1}")]
    Pem(String, String),
    /// Self-signed certificate generation failed.
    #[error("failed to generate certificate for {0}: {1}")]
    Generate(String, String),
    /// rustls rejected the private key.
    #[error("unsupported certificate signing key: {0}")]
    SigningKey(String),
    /// A configured domain has no ready certificate.
    #[error("no ready certificate for configured domain: {0}")]
    MissingDomain(String),
    /// ACME DNS-01 provisioning failed.
    #[error(transparent)]
    Acme(#[from] acme::AcmeError),
}

#[cfg(test)]
#[path = "certs_tests.rs"]
mod tests;
