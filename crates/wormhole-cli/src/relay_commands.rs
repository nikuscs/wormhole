use std::io::{BufRead as _, IsTerminal as _};

use serde::{Deserialize, Serialize};
use tokio::time::{Duration, sleep};
use wormhole_core::{Remote, enroll_remote, keys_store::IdentityStore, remotes::Transport};
use zeroize::Zeroizing;

use crate::{
    cli::{Cli, CloudflareDeployArgs},
    cloudflare_api::{CloudflareApi, CreatedDnsRecord, Zone},
    cloudflare_bundle,
    cloudflare_wrangler::Wrangler,
    error::CliError,
    output::{self, HumanRender},
    remote_onboarding::apply_add,
    utility_commands,
};

#[path = "relay_cloudflare_support.rs"]
mod support;
use support::{
    cloudflare_token, existing_admin_token, random_secret, remove_admin_token, save_admin_token,
    validate_bundle_version, validate_domain, validate_domain_layout, validate_remote_name,
    validate_worker_name, worker_name,
};

const HEALTH_ATTEMPTS: usize = 30;

#[derive(Serialize)]
pub struct CloudflareDeployView {
    status: &'static str,
    domain: String,
    relay_domain: String,
    worker: String,
    remote: Option<String>,
    dns_records_created: Vec<String>,
    logs_enabled: bool,
    waf_configured: bool,
}

impl HumanRender for CloudflareDeployView {
    fn render(&self) -> String {
        if self.status == "dry_run" {
            return format!(
                "Cloudflare deployment validated\nworker={} public=*.{} relay={}\nno Cloudflare resources changed",
                self.worker, self.domain, self.relay_domain
            );
        }
        format!(
            "Cloudflare relay deployed\nworker={} public=*.{} relay={}\nremote={}\nlogs=disabled waf=manual",
            self.worker,
            self.domain,
            self.relay_domain,
            self.remote.as_deref().unwrap_or("-")
        )
    }
}

pub async fn deploy_cloudflare(cli: &Cli, args: &CloudflareDeployArgs) -> Result<(), CliError> {
    let domain = validate_domain(&args.domain)?;
    let relay_domain = args
        .relay_domain
        .as_deref()
        .map_or_else(|| Ok(format!("relay.{domain}")), validate_domain)?;
    validate_domain_layout(&domain, &relay_domain)?;
    let worker = args.worker_name.clone().unwrap_or_else(|| worker_name(&domain));
    validate_worker_name(&worker)?;
    validate_remote_name(&args.remote_name)?;
    let bundle = cloudflare_bundle::resolve(args.bundle.as_deref()).await?;
    validate_bundle_version(&bundle.manifest.wormhole_version)?;
    let wrangler = Wrangler::new(&bundle.manifest.wrangler_version);
    let spinner = output::spinner("Validating Cloudflare Worker bundle", cli.json);
    let dry_run = wrangler.dry_run(&bundle, &worker, &domain, &relay_domain).await;
    output::finish_spinner(spinner);
    dry_run?;
    if args.dry_run {
        output::emit(
            super::format(cli.json),
            &CloudflareDeployView {
                status: "dry_run",
                domain,
                relay_domain,
                worker,
                remote: None,
                dns_records_created: Vec::new(),
                logs_enabled: false,
                waf_configured: false,
            },
        );
        return Ok(());
    }

    if args.manual_dns {
        deploy_manual(cli, args, domain, relay_domain, worker, bundle, wrangler).await
    } else {
        deploy_automated(cli, args, domain, relay_domain, worker, bundle, wrangler).await
    }
}

async fn deploy_automated(
    cli: &Cli,
    args: &CloudflareDeployArgs,
    domain: String,
    relay_domain: String,
    worker: String,
    bundle: cloudflare_bundle::WorkerBundle,
    wrangler: Wrangler,
) -> Result<(), CliError> {
    let api_token = cloudflare_token()?;
    wrangler.authenticated(Some(&api_token)).await?;
    let api = CloudflareApi::new(api_token)?;
    let zone = api.discover_zone(&domain).await?;
    let relay_ready = api.dns_ready(&zone, &relay_domain).await?;
    let wildcard = format!("*.{domain}");
    let wildcard_ready = api.dns_ready(&zone, &wildcard).await?;
    confirm(args, &worker, &domain, &relay_domain, &zone, relay_ready, wildcard_ready)?;
    let existed = wrangler.deployment_exists(&bundle, &worker, Some(api.token())).await?;
    let admin_token = if existed { existing_admin_token(&worker)? } else { random_secret() };
    let created_dns =
        prepare_dns(&api, &zone, &relay_domain, &wildcard, relay_ready, wildcard_ready).await?;
    if let Err(error) =
        wrangler.deploy(&bundle, &worker, &domain, &relay_domain, Some(api.token())).await
    {
        cleanup_dns(&api, &zone, &created_dns).await;
        return Err(error);
    }
    let result = finish_deploy(
        cli,
        args,
        &wrangler,
        &bundle,
        Some(api.token()),
        &worker,
        &domain,
        &relay_domain,
        existed,
        &admin_token,
    )
    .await;
    complete_or_rollback(cli, &wrangler, &api, &zone, &worker, existed, created_dns, result).await
}

async fn deploy_manual(
    cli: &Cli,
    args: &CloudflareDeployArgs,
    domain: String,
    relay_domain: String,
    worker: String,
    bundle: cloudflare_bundle::WorkerBundle,
    wrangler: Wrangler,
) -> Result<(), CliError> {
    wrangler.authenticated(None).await?;
    confirm_manual(args, &worker, &domain, &relay_domain)?;
    let existed = wrangler.deployment_exists(&bundle, &worker, None).await?;
    let admin_token = if existed { existing_admin_token(&worker)? } else { random_secret() };
    wrangler.deploy(&bundle, &worker, &domain, &relay_domain, None).await?;
    let result = finish_deploy(
        cli,
        args,
        &wrangler,
        &bundle,
        None,
        &worker,
        &domain,
        &relay_domain,
        existed,
        &admin_token,
    )
    .await;
    match result {
        Ok(view) => {
            output::emit(super::format(cli.json), &view);
            Ok(())
        }
        Err(error) => {
            let _rollback = wrangler.rollback(&worker, None, existed).await;
            Err(error)
        }
    }
}

async fn prepare_dns(
    api: &CloudflareApi,
    zone: &Zone,
    relay_domain: &str,
    wildcard: &str,
    relay_ready: bool,
    wildcard_ready: bool,
) -> Result<Vec<CreatedDnsRecord>, CliError> {
    let mut created = Vec::new();
    if !relay_ready {
        created.push(api.create_placeholder_dns(zone, relay_domain).await?);
    }
    if !wildcard_ready {
        match api.create_placeholder_dns(zone, wildcard).await {
            Ok(record) => created.push(record),
            Err(error) => {
                cleanup_dns(api, zone, &created).await;
                return Err(error);
            }
        }
    }
    Ok(created)
}

#[allow(clippy::too_many_arguments)]
async fn complete_or_rollback(
    cli: &Cli,
    wrangler: &Wrangler,
    api: &CloudflareApi,
    zone: &Zone,
    worker: &str,
    existed: bool,
    created_dns: Vec<CreatedDnsRecord>,
    result: Result<CloudflareDeployView, CliError>,
) -> Result<(), CliError> {
    match result {
        Ok(view) => {
            output::emit(
                super::format(cli.json),
                &CloudflareDeployView {
                    dns_records_created: created_dns
                        .iter()
                        .map(|record| record.name.clone())
                        .collect(),
                    ..view
                },
            );
            Ok(())
        }
        Err(error) => {
            let _rollback = wrangler.rollback(worker, Some(api.token()), existed).await;
            cleanup_dns(api, zone, &created_dns).await;
            Err(error)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn finish_deploy(
    cli: &Cli,
    args: &CloudflareDeployArgs,
    wrangler: &Wrangler,
    bundle: &cloudflare_bundle::WorkerBundle,
    provider_token: Option<&str>,
    worker: &str,
    domain: &str,
    relay_domain: &str,
    existed: bool,
    admin_token: &str,
) -> Result<CloudflareDeployView, CliError> {
    if !existed {
        let edge_key = random_secret();
        let secrets = Zeroizing::new(format!(
            "{{\"ADMIN_TOKEN\":\"{admin_token}\",\"EDGE_AUTH_KEY\":\"{}\"}}",
            *edge_key
        ));
        wrangler.set_secrets(bundle, worker, provider_token, secrets.as_bytes()).await?;
    }
    let spinner = output::spinner("Waiting for the relay health check", cli.json);
    let health = wait_for_health(relay_domain).await;
    output::finish_spinner(spinner);
    health?;
    let invite = create_invite(relay_domain, admin_token).await?;
    if !existed {
        save_admin_token(worker, admin_token)?;
    }
    if let Err(error) = enroll_and_save_remote(cli, args, relay_domain, &invite).await {
        if !existed {
            remove_admin_token(worker);
        }
        return Err(error);
    }
    Ok(CloudflareDeployView {
        status: "deployed",
        domain: domain.to_owned(),
        relay_domain: relay_domain.to_owned(),
        worker: worker.to_owned(),
        remote: Some(args.remote_name.clone()),
        dns_records_created: Vec::new(),
        logs_enabled: false,
        waf_configured: false,
    })
}

async fn enroll_and_save_remote(
    cli: &Cli,
    args: &CloudflareDeployArgs,
    domain: &str,
    invite: &str,
) -> Result<(), CliError> {
    let mut remote = Remote::new(format!("{domain}:443"), domain.to_owned(), None);
    remote.transport = Transport::Ws;
    remote.https_addr = Some(format!("{domain}:443"));
    let skip_enrollment = {
        #[cfg(debug_assertions)]
        {
            std::env::var_os("WORMHOLE_CLOUDFLARE_SKIP_ENROLL").is_some()
        }
        #[cfg(not(debug_assertions))]
        {
            false
        }
    };
    if !skip_enrollment {
        let identities = IdentityStore::from_environment()?;
        let identity = identities.resolve_identity(&remote)?;
        enroll_remote(&remote, &identity, invite).await?;
    }
    let mut config = utility_commands::load(cli.config.as_ref())?;
    apply_add(&mut config, args.remote_name.clone(), remote);
    utility_commands::save(cli.config.as_ref(), &config)
}

async fn wait_for_health(domain: &str) -> Result<(), CliError> {
    let client =
        reqwest::Client::builder().timeout(Duration::from_secs(5)).build().map_err(http_error)?;
    let url = format!("{}/health", relay_base(domain));
    for _ in 0..HEALTH_ATTEMPTS {
        if client.get(&url).send().await.is_ok_and(|response| response.status().is_success()) {
            return Ok(());
        }
        sleep(Duration::from_secs(2)).await;
    }
    Err(CliError::Invalid(format!("relay health check did not become ready: {url}")))
}

async fn create_invite(domain: &str, admin_token: &str) -> Result<Zeroizing<String>, CliError> {
    #[derive(Deserialize)]
    struct Invite {
        token: String,
    }
    let client =
        reqwest::Client::builder().timeout(Duration::from_secs(5)).build().map_err(http_error)?;
    let url = format!("{}/_wormhole/admin/invites", relay_base(domain));
    for _ in 0..HEALTH_ATTEMPTS {
        let response = client
            .post(&url)
            .bearer_auth(admin_token)
            .json(&serde_json::json!({"name":"initial-client","ttl_secs":600,"max_uses":1}))
            .send()
            .await;
        match response {
            Ok(response) if response.status().is_success() => {
                let invite: Invite = response.json().await.map_err(http_error)?;
                return Ok(Zeroizing::new(invite.token));
            }
            Ok(response) if !response.status().is_server_error() => {
                return Err(http_error(response.error_for_status().expect_err("non-success")));
            }
            Ok(_) | Err(_) => sleep(Duration::from_secs(2)).await,
        }
    }
    Err(CliError::Invalid(format!("relay invite endpoint did not become ready: {url}")))
}

fn confirm_manual(
    args: &CloudflareDeployArgs,
    worker: &str,
    domain: &str,
    relay_domain: &str,
) -> Result<(), CliError> {
    if args.yes {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return Err(CliError::Invalid(
            "Cloudflare deployment requires `--yes` outside an interactive terminal".to_owned(),
        ));
    }
    output::prompt(&format!(
        "Deploy Worker {worker} using existing DNS for relay {relay_domain} and public apps *.{domain}? [y/N]"
    ))?;
    confirm_answer()
}

fn confirm(
    args: &CloudflareDeployArgs,
    worker: &str,
    domain: &str,
    relay_domain: &str,
    zone: &Zone,
    relay_ready: bool,
    wildcard_ready: bool,
) -> Result<(), CliError> {
    if args.yes {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return Err(CliError::Invalid(
            "Cloudflare deployment requires `--yes` outside an interactive terminal".to_owned(),
        ));
    }
    let dns = match (relay_ready, wildcard_ready) {
        (true, true) => "reuse existing proxied DNS",
        (false, false) => "create relay and wildcard proxied DNS",
        (false, true) => "create relay proxied DNS",
        (true, false) => "create wildcard proxied DNS",
    };
    output::prompt(&format!(
        "Deploy Worker {worker} with relay {relay_domain} and public apps *.{domain} in zone {}; {dns}? [y/N]",
        zone.name
    ))?;
    confirm_answer()
}

fn confirm_answer() -> Result<(), CliError> {
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    if matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(())
    } else {
        Err(CliError::Invalid("Cloudflare deployment cancelled".to_owned()))
    }
}

async fn cleanup_dns(api: &CloudflareApi, zone: &Zone, records: &[CreatedDnsRecord]) {
    for record in records.iter().rev() {
        let _deleted = api.delete_dns(zone, record).await;
    }
}

fn relay_base(domain: &str) -> String {
    #[cfg(debug_assertions)]
    if let Ok(value) = std::env::var("WORMHOLE_CLOUDFLARE_RELAY_BASE") {
        return value.trim_end_matches('/').to_owned();
    }
    format!("https://{domain}")
}

fn http_error(error: reqwest::Error) -> CliError {
    CliError::Invalid(format!("Cloudflare relay request failed: {error}"))
}

#[cfg(test)]
#[path = "relay_commands_tests.rs"]
mod tests;
