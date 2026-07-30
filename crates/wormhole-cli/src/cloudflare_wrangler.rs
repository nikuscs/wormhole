use std::process::Stdio;

use tokio::{io::AsyncWriteExt as _, process::Command};

use crate::{cloudflare_bundle::WorkerBundle, error::CliError};

pub struct Wrangler {
    executable: String,
    prefix: Vec<String>,
    version: String,
}

impl Wrangler {
    pub fn new(version: &str) -> Self {
        #[cfg(debug_assertions)]
        if let Ok(executable) = std::env::var("WORMHOLE_CLOUDFLARE_WRANGLER") {
            return Self { executable, prefix: Vec::new(), version: version.to_owned() };
        }
        Self {
            executable: "npx".to_owned(),
            prefix: vec!["--yes".to_owned(), format!("wrangler@{version}")],
            version: version.to_owned(),
        }
    }

    pub async fn dry_run(
        &self,
        bundle: &WorkerBundle,
        name: &str,
        public_domain: &str,
        control_domain: &str,
    ) -> Result<(), CliError> {
        self.run(&deploy_args(bundle, name, public_domain, control_domain, true), None, None)
            .await
            .map(|_| ())
    }

    pub async fn authenticated(&self, token: Option<&str>) -> Result<(), CliError> {
        self.run(&["whoami".to_owned(), "--json".to_owned()], token, None).await.map(|_| ())
    }

    pub async fn deployment_exists(
        &self,
        bundle: &WorkerBundle,
        name: &str,
        token: Option<&str>,
    ) -> Result<bool, CliError> {
        let result = self
            .run(
                &[
                    "deployments".to_owned(),
                    "status".to_owned(),
                    "--config".to_owned(),
                    bundle.config.to_string(),
                    "--name".to_owned(),
                    name.to_owned(),
                    "--json".to_owned(),
                ],
                token,
                None,
            )
            .await;
        match result {
            Ok(_) => Ok(true),
            Err(error) if missing_worker(&error) => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub async fn deploy(
        &self,
        bundle: &WorkerBundle,
        name: &str,
        public_domain: &str,
        control_domain: &str,
        token: Option<&str>,
    ) -> Result<(), CliError> {
        self.run(&deploy_args(bundle, name, public_domain, control_domain, false), token, None)
            .await
            .map(|_| ())
    }

    pub async fn set_secrets(
        &self,
        bundle: &WorkerBundle,
        name: &str,
        token: Option<&str>,
        secrets: &[u8],
    ) -> Result<(), CliError> {
        self.run(
            &[
                "secret".to_owned(),
                "bulk".to_owned(),
                "--config".to_owned(),
                bundle.config.to_string(),
                "--name".to_owned(),
                name.to_owned(),
            ],
            token,
            Some(secrets),
        )
        .await
        .map(|_| ())
    }

    pub async fn rollback(
        &self,
        name: &str,
        token: Option<&str>,
        existed: bool,
    ) -> Result<(), CliError> {
        let args = if existed {
            vec![
                "rollback".to_owned(),
                "--name".to_owned(),
                name.to_owned(),
                "--message".to_owned(),
                "automatic rollback after failed Wormhole deployment".to_owned(),
                "--yes".to_owned(),
            ]
        } else {
            vec!["delete".to_owned(), name.to_owned(), "--force".to_owned()]
        };
        self.run(&args, token, None).await.map(|_| ())
    }

    async fn run(
        &self,
        arguments: &[String],
        token: Option<&str>,
        stdin: Option<&[u8]>,
    ) -> Result<Vec<u8>, CliError> {
        let mut command = Command::new(&self.executable);
        command.args(&self.prefix).args(arguments).stdout(Stdio::piped()).stderr(Stdio::piped());
        if let Some(token) = token {
            command.env("CLOUDFLARE_API_TOKEN", token);
        }
        command.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() });
        let mut child = command.spawn().map_err(|error| {
            CliError::Invalid(format!(
                "cannot run Wrangler {} using {}: {error}",
                self.version, self.executable
            ))
        })?;
        if let Some(input) = stdin
            && let Some(mut writer) = child.stdin.take()
        {
            writer.write_all(input).await?;
        }
        let output = child.wait_with_output().await?;
        if output.status.success() {
            return Ok(output.stdout);
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = wrangler_error_detail(&stderr);
        Err(CliError::Invalid(format!("Wrangler command failed: {detail}")))
    }
}

fn wrangler_error_detail(stderr: &str) -> &str {
    let lines = stderr.trim().lines();
    lines
        .clone()
        .rev()
        .find(|line| {
            let line = line.to_ascii_lowercase();
            line.contains("does not exist")
                || line.contains("not found")
                || line.contains("permission")
                || line.contains("failed")
        })
        .or_else(|| lines.last())
        .unwrap_or("Wrangler command failed")
}

fn missing_worker(error: &CliError) -> bool {
    let message = error.to_string().to_ascii_lowercase();
    message.contains("not found") || message.contains("does not exist")
}

fn deploy_args(
    bundle: &WorkerBundle,
    name: &str,
    public_domain: &str,
    control_domain: &str,
    dry_run: bool,
) -> Vec<String> {
    let mut args = vec![
        "deploy".to_owned(),
        "--config".to_owned(),
        bundle.config.to_string(),
        "--name".to_owned(),
        name.to_owned(),
        "--var".to_owned(),
        format!("RELAY_DOMAIN:{public_domain}"),
        "--var".to_owned(),
        format!("CONTROL_DOMAIN:{control_domain}"),
        "--route".to_owned(),
        format!("{control_domain}/*"),
        "--route".to_owned(),
        format!("*.{public_domain}/*"),
    ];
    if dry_run {
        args.push("--dry-run".to_owned());
    }
    args
}
