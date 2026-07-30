use crate::api_types::{RemoteAddRequest, RemoteView};
use wormhole_core::{ClientConfig, Remote};

pub struct PreparedRemote {
    pub name: String,
    pub remote: Remote,
    pub invite: Option<String>,
}

pub fn prepare(request: RemoteAddRequest) -> Result<PreparedRemote, String> {
    validate_name(&request.name)?;
    let server_name = request.server_name.map_or_else(|| authority_host(&request.addr), Ok)?;
    let identity = request.identity.map(camino::Utf8PathBuf::from);
    Ok(PreparedRemote {
        name: request.name,
        remote: Remote::new(request.addr, server_name, identity),
        invite: request.invite,
    })
}

pub fn apply_add(config: &mut ClientConfig, name: String, remote: Remote) {
    config.remotes.insert(name.clone(), remote);
    if config.default_remote.is_none() && config.remotes.len() == 1 {
        config.default_remote = Some(name);
    }
}

pub fn apply_remove(config: &mut ClientConfig, name: &str) -> Result<(), String> {
    if config.remotes.remove(name).is_none() {
        return Err(format!("unknown remote: {name}"));
    }
    if config.default_remote.as_deref() == Some(name) {
        config.default_remote = None;
    }
    Ok(())
}

pub fn views(config: &ClientConfig) -> Vec<RemoteView> {
    config
        .remotes
        .iter()
        .map(|(name, remote)| RemoteView::from_remote(name.clone(), remote))
        .collect()
}

pub fn authority_host(addr: &str) -> Result<String, String> {
    let (host, port) =
        addr.rsplit_once(':').ok_or_else(|| "remote address must be HOST:PORT".to_owned())?;
    port.parse::<u16>().map_err(|error| error.to_string())?;
    let host = host.trim_matches(['[', ']']);
    if host.is_empty() {
        return Err("remote address host cannot be empty".to_owned());
    }
    Ok(host.to_owned())
}

fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err(
            "remote name must contain 1-64 letters, digits, hyphens, or underscores".to_owned()
        );
    }
    Ok(())
}
