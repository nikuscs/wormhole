//! Identity generation and per-remote identity resolution.

use camino::{Utf8Path, Utf8PathBuf};
use wormhole_proto::Identity;

use crate::{error::IdentityError, remotes::Remote};

/// Filesystem-backed client identity store.
pub struct IdentityStore {
    home: Utf8PathBuf,
    default_path: Utf8PathBuf,
}

impl IdentityStore {
    /// Builds the standard `~/.config/wormhole/keys/identity.key` store.
    pub fn from_environment() -> Result<Self, IdentityError> {
        let base = directories::BaseDirs::new()
            .ok_or_else(|| IdentityError::Path("home directory is unavailable".to_owned()))?;
        let home = Utf8PathBuf::from_path_buf(base.home_dir().to_owned()).map_err(|path| {
            IdentityError::Path(format!("home path is not UTF-8: {}", path.display()))
        })?;
        Ok(Self::with_home(home))
    }

    /// Builds a store rooted at an injected home directory.
    pub fn with_home(home: Utf8PathBuf) -> Self {
        let default_path = home.join(".config/wormhole/keys/identity.key");
        Self { home, default_path }
    }

    /// Loads or generates the identity selected for a remote.
    pub fn resolve_identity(&self, remote: &Remote) -> Result<Identity, IdentityError> {
        Self::load_or_generate(&self.path_for_remote(remote))
    }

    /// Returns the expanded identity path selected for a remote.
    pub fn path_for_remote(&self, remote: &Remote) -> Utf8PathBuf {
        remote
            .identity
            .as_deref()
            .map_or_else(|| self.default_path.clone(), |path| self.expand_home(path))
    }

    /// Loads or creates the default identity.
    pub fn default_identity(&self) -> Result<Identity, IdentityError> {
        Self::load_or_generate(&self.default_path)
    }

    /// Replaces the default identity and returns the old and new fingerprints.
    pub fn rotate_default(&self) -> Result<(String, String), IdentityError> {
        let old = self.default_identity()?.fingerprint();
        let identity = Identity::generate();
        identity.save(&self.default_path)?;
        Ok((old, identity.fingerprint()))
    }

    /// Returns the default identity path.
    pub fn default_path(&self) -> &Utf8Path {
        &self.default_path
    }

    fn load_or_generate(path: &Utf8Path) -> Result<Identity, IdentityError> {
        if path.exists() {
            return Identity::load(path).map_err(Into::into);
        }
        let identity = Identity::generate();
        identity.save(path)?;
        tracing::info!(fingerprint = %identity.fingerprint(), "generated client identity");
        Ok(identity)
    }

    fn expand_home(&self, path: &Utf8Path) -> Utf8PathBuf {
        path.strip_prefix("~").map_or_else(|_| path.to_owned(), |suffix| self.home.join(suffix))
    }
}

#[cfg(test)]
#[path = "keys_store_tests.rs"]
mod tests;
