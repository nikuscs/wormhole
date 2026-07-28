use std::{path::PathBuf, process::Command, sync::OnceLock};

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
    let suffix = std::env::consts::EXE_SUFFIX;
    Ok(Binaries {
        wormhole: PathBuf::from(target).join("debug").join(format!("wormhole{suffix}")),
        wormholed: PathBuf::from(target).join("debug").join(format!("wormholed{suffix}")),
    })
}
