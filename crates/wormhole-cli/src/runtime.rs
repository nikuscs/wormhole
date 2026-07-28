//! Per-user runtime paths and Unix filesystem hygiene.

use std::{
    fs::{self, File, OpenOptions},
    io,
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
};

use camino::{Utf8Path, Utf8PathBuf};
use nix::libc::O_NOFOLLOW;

pub struct RuntimePaths {
    pub state_dir: Utf8PathBuf,
    pub socket: Utf8PathBuf,
    pub lock: Utf8PathBuf,
    pub token: Utf8PathBuf,
    pub log: Utf8PathBuf,
}

impl RuntimePaths {
    pub fn discover() -> Result<Self, RuntimeError> {
        let state_dir = if let Some(override_path) = std::env::var_os("WORMHOLE_STATE_DIR") {
            Utf8PathBuf::from_path_buf(override_path.into()).map_err(|_| RuntimeError::NonUtf8)?
        } else if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
            Utf8PathBuf::from_path_buf(runtime.into())
                .map_err(|_| RuntimeError::NonUtf8)?
                .join("wormhole")
        } else {
            fallback_state_dir()?
        };
        Ok(Self {
            socket: state_dir.join("daemon.sock"),
            lock: state_dir.join("daemon.lock"),
            token: state_dir.join("api-token"),
            log: state_dir.join("daemon.log"),
            state_dir,
        })
    }

    pub fn prepare(&self) -> Result<(), RuntimeError> {
        if self.state_dir.exists() {
            verify_directory(&self.state_dir)?;
        } else {
            fs::create_dir_all(&self.state_dir).map_err(RuntimeError::Io)?;
        }
        fs::set_permissions(&self.state_dir, fs::Permissions::from_mode(0o700))
            .map_err(RuntimeError::Io)?;
        verify_directory(&self.state_dir)
    }
}

pub fn open_private(path: &Utf8Path, truncate: bool) -> Result<File, RuntimeError> {
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(truncate)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(RuntimeError::Io)?;
    file.set_permissions(fs::Permissions::from_mode(0o600)).map_err(RuntimeError::Io)?;
    Ok(file)
}

fn verify_directory(path: &Utf8Path) -> Result<(), RuntimeError> {
    let metadata = fs::symlink_metadata(path).map_err(RuntimeError::Io)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(RuntimeError::UnsafeDirectory(path.to_owned()));
    }
    if metadata.uid() != current_uid() {
        return Err(RuntimeError::WrongOwner(path.to_owned()));
    }
    Ok(())
}

fn current_uid() -> u32 {
    nix::unistd::geteuid().as_raw()
}

#[cfg(target_os = "macos")]
fn fallback_state_dir() -> Result<Utf8PathBuf, RuntimeError> {
    let home = directories::BaseDirs::new().ok_or(RuntimeError::NoHome)?;
    Utf8PathBuf::from_path_buf(home.home_dir().join("Library/Application Support/wormhole"))
        .map_err(|_| RuntimeError::NonUtf8)
}

#[cfg(not(target_os = "macos"))]
fn fallback_state_dir() -> Result<Utf8PathBuf, RuntimeError> {
    let home = directories::BaseDirs::new().ok_or(RuntimeError::NoHome)?;
    Utf8PathBuf::from_path_buf(home.home_dir().join(".local/state/wormhole"))
        .map_err(|_| RuntimeError::NonUtf8)
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("runtime path is not valid UTF-8")]
    NonUtf8,
    #[error("cannot determine the home directory")]
    NoHome,
    #[error("unsafe runtime directory: {0}")]
    UnsafeDirectory(Utf8PathBuf),
    #[error("runtime directory is owned by another user: {0}")]
    WrongOwner(Utf8PathBuf),
    #[error("runtime filesystem error: {0}")]
    Io(#[from] io::Error),
}

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;
