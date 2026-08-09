//! Persisted local certificate authority and on-demand SNI certificates.

use std::{
    collections::HashMap, fmt, fs, io::Write as _, os::unix::fs::PermissionsExt as _, sync::Arc,
};

use camino::{Utf8Path, Utf8PathBuf};
use parking_lot::RwLock;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
};
use rustls::{
    crypto::aws_lc_rs::sign::any_supported_type,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject as _},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};

const CA_CERT_FILE: &str = "local-ca.pem";
const CA_KEY_FILE: &str = "local-ca-key.pem";

/// Local CA persistence or issuance failure.
#[derive(Debug, thiserror::Error)]
pub enum LocalCaError {
    #[error("local CA I/O failed for {path}: {source}")]
    Io { path: Utf8PathBuf, source: std::io::Error },
    #[error("local CA file must have owner-only permissions: {0}")]
    Permissions(Utf8PathBuf),
    #[error("local certificate generation failed: {0}")]
    Certificate(String),
    #[error("local certificate signing key failed: {0}")]
    Signing(String),
}

/// CA loaded from or generated in the Wormhole configuration directory.
pub struct LocalCertificateAuthority {
    issuer: Issuer<'static, KeyPair>,
    certificate: CertificateDer<'static>,
    certificate_path: Utf8PathBuf,
}

impl LocalCertificateAuthority {
    /// Loads the existing CA or generates it once with owner-only files.
    pub fn load_or_create(directory: &Utf8Path) -> Result<Self, LocalCaError> {
        let _installed = rustls::crypto::aws_lc_rs::default_provider().install_default();
        fs::create_dir_all(directory).map_err(|source| io_error(directory, source))?;
        let certificate_path = directory.join(CA_CERT_FILE);
        let key_path = directory.join(CA_KEY_FILE);
        if !certificate_path.exists() && !key_path.exists() {
            generate_ca(&certificate_path, &key_path)?;
        }
        ensure_private(&certificate_path)?;
        ensure_private(&key_path)?;
        let certificate_pem = read(&certificate_path)?;
        let key_pem = read(&key_path)?;
        let key = KeyPair::from_pem(&key_pem)
            .map_err(|error| LocalCaError::Certificate(error.to_string()))?;
        let issuer = Issuer::new(ca_params()?, key);
        let certificate = CertificateDer::from_pem_slice(certificate_pem.as_bytes())
            .map_err(|error| LocalCaError::Certificate(error.to_string()))?;
        Ok(Self { issuer, certificate, certificate_path })
    }

    /// CA certificate path used by trust-store commands.
    pub fn certificate_path(&self) -> &Utf8Path {
        &self.certificate_path
    }

    /// CA certificate in DER form.
    pub fn certificate_der(&self) -> CertificateDer<'static> {
        self.certificate.clone()
    }

    fn issue(&self, hostname: &str) -> Result<Arc<CertifiedKey>, LocalCaError> {
        let mut params = CertificateParams::new(vec![hostname.to_owned()])
            .map_err(|error| LocalCaError::Certificate(error.to_string()))?;
        params.extended_key_usages.push(ExtendedKeyUsagePurpose::ServerAuth);
        let key =
            KeyPair::generate().map_err(|error| LocalCaError::Certificate(error.to_string()))?;
        let certificate = params
            .signed_by(&key, &self.issuer)
            .map_err(|error| LocalCaError::Certificate(error.to_string()))?;
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let signing_key = any_supported_type(&private_key)
            .map_err(|error| LocalCaError::Signing(error.to_string()))?;
        Ok(Arc::new(CertifiedKey::new(
            vec![certificate.der().clone(), self.certificate.clone()],
            signing_key,
        )))
    }
}

/// SNI resolver that issues and caches one leaf certificate per hostname.
pub struct LocalCertResolver {
    authority: Arc<LocalCertificateAuthority>,
    certificates: RwLock<HashMap<String, Arc<CertifiedKey>>>,
}

impl LocalCertResolver {
    pub fn new(authority: Arc<LocalCertificateAuthority>) -> Self {
        Self { authority, certificates: RwLock::new(HashMap::new()) }
    }

    /// Resolves a hostname, issuing its leaf certificate on first use.
    pub fn resolve_name(&self, hostname: &str) -> Result<Arc<CertifiedKey>, LocalCaError> {
        let hostname = hostname.trim_end_matches('.').to_ascii_lowercase();
        if let Some(certificate) = self.certificates.read().get(&hostname) {
            return Ok(Arc::clone(certificate));
        }
        let certificate = self.authority.issue(&hostname)?;
        let mut certificates = self.certificates.write();
        Ok(Arc::clone(certificates.entry(hostname).or_insert(certificate)))
    }

    #[cfg(test)]
    pub(crate) fn cached_count(&self) -> usize {
        self.certificates.read().len()
    }
}

impl fmt::Debug for LocalCertResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("LocalCertResolver").finish_non_exhaustive()
    }
}

impl ResolvesServerCert for LocalCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.resolve_name(client_hello.server_name()?).ok()
    }
}

fn generate_ca(certificate_path: &Utf8Path, key_path: &Utf8Path) -> Result<(), LocalCaError> {
    let key = KeyPair::generate().map_err(|error| LocalCaError::Certificate(error.to_string()))?;
    let authority = CertifiedIssuer::self_signed(ca_params()?, key)
        .map_err(|error| LocalCaError::Certificate(error.to_string()))?;
    write_private(key_path, authority.key().serialize_pem().as_bytes())?;
    write_private(certificate_path, authority.pem().as_bytes())
}

fn ca_params() -> Result<CertificateParams, LocalCaError> {
    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|error| LocalCaError::Certificate(error.to_string()))?;
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "Wormhole Local CA");
    params.distinguished_name = distinguished_name;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    Ok(params)
}

fn write_private(path: &Utf8Path, contents: &[u8]) -> Result<(), LocalCaError> {
    let parent = path
        .parent()
        .ok_or_else(|| LocalCaError::Certificate("local CA path has no parent".to_owned()))?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).map_err(|source| io_error(path, source))?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|source| io_error(path, source))?;
    temporary.write_all(contents).map_err(|source| io_error(path, source))?;
    temporary.as_file().sync_all().map_err(|source| io_error(path, source))?;
    temporary.persist(path).map_err(|error| io_error(path, error.error))?;
    Ok(())
}

fn ensure_private(path: &Utf8Path) -> Result<(), LocalCaError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(LocalCaError::Permissions(path.to_owned()));
    }
    Ok(())
}

fn read(path: &Utf8Path) -> Result<String, LocalCaError> {
    fs::read_to_string(path).map_err(|source| io_error(path, source))
}

fn io_error(path: &Utf8Path, source: std::io::Error) -> LocalCaError {
    LocalCaError::Io { path: path.to_owned(), source }
}

#[cfg(test)]
#[path = "local_ca_tests.rs"]
mod tests;
