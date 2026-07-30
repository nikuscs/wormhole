use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::OnceLock,
};

const BIN_DIR_ENV: &str = "WORMHOLE_E2E_BIN_DIR";

#[derive(Debug, Clone)]
pub struct Binaries {
    pub wormhole: PathBuf,
    pub wormholed: PathBuf,
}

pub fn binaries() -> Result<&'static Binaries, String> {
    static BINARIES: OnceLock<Result<Binaries, String>> = OnceLock::new();
    BINARIES.get_or_init(build_binaries).as_ref().map_err(Clone::clone)
}

fn build_binaries() -> Result<Binaries, String> {
    if let Some(directory) = std::env::var_os(BIN_DIR_ENV) {
        return binaries_in(Path::new(&directory));
    }
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = Command::new(&cargo)
        .args(["build", "-p", "wormhole-cli", "-p", "wormholed"])
        .status()
        .map_err(|error| error.to_string())?;
    if !status.success() {
        return Err("building e2e binaries failed".to_owned());
    }
    let output = Command::new(cargo)
        .args(["metadata", "--format-version=1", "--no-deps"])
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(format!("cargo metadata failed: {}", String::from_utf8_lossy(&output.stderr)));
    }
    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).map_err(|error| error.to_string())?;
    let target = metadata
        .get("target_directory")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "metadata has no target_directory".to_owned())?;
    binaries_in(&PathBuf::from(target).join("debug"))
}

fn binaries_in(directory: &Path) -> Result<Binaries, String> {
    let suffix = std::env::consts::EXE_SUFFIX;
    let binaries = Binaries {
        wormhole: directory.join(format!("wormhole{suffix}")),
        wormholed: directory.join(format!("wormholed{suffix}")),
    };
    for binary in [&binaries.wormhole, &binaries.wormholed] {
        if !binary.is_file() {
            return Err(format!("e2e binary does not exist: {}", binary.display()));
        }
    }
    Ok(binaries)
}

#[cfg(test)]
#[path = "binaries_tests.rs"]
mod tests;
