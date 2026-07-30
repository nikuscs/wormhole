use std::{fmt::Write as _, fs, io::Cursor, path::Path};

use camino::{Utf8Path, Utf8PathBuf};
use flate2::read::GzDecoder;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::error::CliError;

const ASSET: &str = "wormholed-cloudflare-worker.tar.gz";
const MAX_BUNDLE_BYTES: usize = 16 * 1024 * 1024;
const MANIFEST_SCHEMA: u8 = 1;

#[derive(Debug, Deserialize)]
pub struct BundleManifest {
    pub schema: u8,
    pub wormhole_version: String,
    pub wrangler_version: String,
}

pub struct WorkerBundle {
    pub config: Utf8PathBuf,
    pub manifest: BundleManifest,
}

pub async fn resolve(override_path: Option<&Path>) -> Result<WorkerBundle, CliError> {
    if let Some(path) = override_path {
        let directory = Utf8PathBuf::from_path_buf(path.to_path_buf())
            .map_err(|_| CliError::Invalid("Worker bundle path must be UTF-8".to_owned()))?;
        return validate(directory);
    }
    let version = env!("CARGO_PKG_VERSION");
    if version == "0.0.0" {
        return development_bundle().await;
    }
    let cache = cache_root()?.join(format!("v{version}"));
    if cache.exists() {
        return validate(cache);
    }
    download(version, &cache).await?;
    validate(cache)
}

async fn development_bundle() -> Result<WorkerBundle, CliError> {
    let crate_dir = Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../wormholed-cloudflare");
    let directory = crate_dir.join("deploy-bundle/wormholed-cloudflare-worker");
    let output = tokio::process::Command::new("npm")
        .args(["run", "bundle", "--prefix"])
        .arg(&crate_dir)
        .output()
        .await
        .map_err(|error| {
            CliError::Invalid(format!("cannot build development Worker bundle: {error}"))
        })?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        return Err(CliError::Invalid(format!(
            "development Worker bundle failed: {}",
            detail.trim().lines().last().unwrap_or("npm run bundle failed")
        )));
    }
    validate(directory)
}

fn validate(directory: Utf8PathBuf) -> Result<WorkerBundle, CliError> {
    if !directory.is_dir() {
        return Err(CliError::Invalid(format!("Worker bundle is not a directory: {directory}")));
    }
    let manifest_path = directory.join("manifest.json");
    let manifest: BundleManifest = serde_json::from_slice(&fs::read(&manifest_path)?)
        .map_err(|error| CliError::Invalid(format!("invalid Worker bundle manifest: {error}")))?;
    if manifest.schema != MANIFEST_SCHEMA {
        return Err(CliError::Invalid(format!(
            "unsupported Worker bundle schema: {}",
            manifest.schema
        )));
    }
    let config = directory.join("wrangler.jsonc");
    for path in [&config, &directory.join("build/index.js"), &directory.join("build/index_bg.wasm")]
    {
        if !path.is_file() {
            return Err(CliError::Invalid(format!("Worker bundle file is missing: {path}")));
        }
    }
    Ok(WorkerBundle { config, manifest })
}

async fn download(version: &str, destination: &Utf8Path) -> Result<(), CliError> {
    let base = release_base();
    let asset_url = format!("{base}/v{version}/{ASSET}");
    let checksum_url = format!("{asset_url}.sha256");
    let client = reqwest::Client::builder().build().map_err(download_error)?;
    let (archive, checksum) = tokio::try_join!(
        download_bytes(&client, &asset_url),
        download_bytes(&client, &checksum_url)
    )?;
    if archive.len() > MAX_BUNDLE_BYTES {
        return Err(CliError::Invalid("Worker bundle exceeds 16 MiB".to_owned()));
    }
    verify_checksum(&archive, &checksum)?;
    let parent = destination
        .parent()
        .ok_or_else(|| CliError::Invalid("Worker bundle cache path has no parent".to_owned()))?;
    fs::create_dir_all(parent)?;
    let temporary = tempfile::Builder::new().prefix("cloudflare-bundle-").tempdir_in(parent)?;
    let decoder = GzDecoder::new(Cursor::new(archive));
    let mut tar = tar::Archive::new(decoder);
    tar.unpack(temporary.path())
        .map_err(|error| CliError::Invalid(format!("cannot extract Worker bundle: {error}")))?;
    let unpacked = Utf8PathBuf::from_path_buf(temporary.keep())
        .map_err(|_| CliError::Invalid("bundle cache path must be UTF-8".to_owned()))?;
    validate(unpacked.clone())?;
    fs::rename(unpacked, destination)?;
    Ok(())
}

async fn download_bytes(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, CliError> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(download_error)?
        .error_for_status()
        .map_err(download_error)?;
    Ok(response.bytes().await.map_err(download_error)?.to_vec())
}

fn verify_checksum(archive: &[u8], checksum: &[u8]) -> Result<(), CliError> {
    let expected = std::str::from_utf8(checksum)
        .ok()
        .and_then(|value| value.split_whitespace().next())
        .filter(|value| value.len() == 64)
        .ok_or_else(|| CliError::Invalid("invalid Worker bundle checksum file".to_owned()))?;
    let actual = hex_digest(archive);
    if actual != expected {
        return Err(CliError::Invalid("Worker bundle checksum mismatch".to_owned()));
    }
    Ok(())
}

fn hex_digest(value: &[u8]) -> String {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(value) {
        write!(output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn cache_root() -> Result<Utf8PathBuf, CliError> {
    let base = directories::BaseDirs::new()
        .ok_or_else(|| CliError::Invalid("cannot locate the user cache directory".to_owned()))?;
    Utf8PathBuf::from_path_buf(base.cache_dir().join("wormhole/cloudflare"))
        .map_err(|_| CliError::Invalid("bundle cache path must be UTF-8".to_owned()))
}

fn release_base() -> String {
    #[cfg(debug_assertions)]
    if let Ok(value) = std::env::var("WORMHOLE_CLOUDFLARE_RELEASE_BASE") {
        return value.trim_end_matches('/').to_owned();
    }
    "https://github.com/nikuscs/wormhole/releases/download".to_owned()
}

fn download_error(error: reqwest::Error) -> CliError {
    CliError::Invalid(format!("cannot download Worker bundle: {error}"))
}

#[cfg(test)]
#[path = "cloudflare_bundle_tests.rs"]
mod tests;
