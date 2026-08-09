//! `wormhole up` and project-scoped `down` commands.

use crate::{
    cli::{Cli, TunnelOptions},
    client::DaemonClient,
    error::CliError,
    local_api::CreateServiceRequest,
    output,
    project::{ProjectConfig, project_id},
    project_name, stable_identity,
    tunnel_commands::{build_specs, endpoint_result, load_command_config, resolve_target},
};

pub async fn up(cli: &Cli, names: &[String]) -> Result<(), CliError> {
    let directory = std::env::current_dir()?;
    let project = ProjectConfig::load(&directory)?;
    let project_id = project_id(&directory)?;
    let config = load_command_config(cli)?;
    let client = DaemonClient::ensure(cli.config.as_ref()).await?;
    let project_name = project.name.clone();
    let mut active = Vec::new();
    for (mut service, mut endpoints) in
        project.selected(names, &directory, config.defaults.inspect)?
    {
        let slug = project_name::worktree_slug(project_name.as_deref(), &service.name, &directory);
        service.target = resolve_target(service.target, &config).await?;
        if endpoints.is_empty() {
            endpoints =
                build_specs(service.proto, &TunnelOptions::default(), &config, Some(&slug)).await?;
        } else {
            for endpoint in &mut endpoints {
                if endpoint.retry.is_none() {
                    endpoint.retry.clone_from(&config.defaults.retry);
                }
                stable_identity::apply(endpoint, Some(&slug), &config, None)?;
            }
        }
        active.extend(
            client
                .create(&CreateServiceRequest {
                    project_id: Some(project_id.clone()),
                    remotes: Some(config.remotes.clone()),
                    default_remote: config.default_remote.clone(),
                    service,
                    endpoints,
                })
                .await?,
        );
    }
    output::emit(super::format(cli.json), &active);
    endpoint_result(&active)
}

pub async fn down(cli: &Cli, targets: &[String], forget: bool) -> Result<(), CliError> {
    let cwd = std::env::current_dir()?;
    if targets.iter().any(|target| target.parse::<uuid::Uuid>().is_ok())
        || (!targets.is_empty() && crate::project_root::config_path(&cwd).is_none())
    {
        return crate::tunnel_commands::down(cli, targets, forget).await;
    }
    let directory = std::env::current_dir()?;
    let project = ProjectConfig::load(&directory)?;
    let selected_names = if forget && !targets.is_empty() {
        targets.to_vec()
    } else {
        project
            .selected(targets, &directory, false)?
            .into_iter()
            .map(|(service, _)| service.name)
            .collect::<Vec<_>>()
    };
    let id = project_id(&directory)?;
    let client = DaemonClient::ensure(cli.config.as_ref()).await?;
    for name in selected_names {
        output::emit(
            super::format(cli.json),
            &client.delete_service(&name, Some(&id), forget).await?,
        );
    }
    Ok(())
}
