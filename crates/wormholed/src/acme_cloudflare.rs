//! Minimal Cloudflare DNS API client for ACME TXT challenges.

use std::fs;

use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::{acme::AcmeError, config::AcmeConfig};

const CLOUDFLARE_API: &str = "https://api.cloudflare.com/client/v4";

pub struct CloudflareDns {
    client: Client,
    token: String,
    base_url: String,
}

impl CloudflareDns {
    pub fn new(config: &AcmeConfig) -> Result<Self, AcmeError> {
        let token = fs::read_to_string(&config.cloudflare_token_file).map_err(|source| {
            AcmeError::Io { path: config.cloudflare_token_file.clone(), source }
        })?;
        if token.trim().is_empty() {
            return Err(AcmeError::Config("Cloudflare token is empty".to_owned()));
        }
        Ok(Self {
            client: Client::builder().build().map_err(AcmeError::Http)?,
            token: token.trim().to_owned(),
            base_url: CLOUDFLARE_API.to_owned(),
        })
    }

    pub async fn create_txt(
        &self,
        domain: &str,
        name: &str,
        content: &str,
    ) -> Result<DnsRecord, AcmeError> {
        let zone = self.zone_id(domain).await?;
        let response = self
            .client
            .post(format!("{}/zones/{zone}/dns_records", self.base_url))
            .bearer_auth(&self.token)
            .json(&CreateRecord { record_type: "TXT", name, content, ttl: 60 })
            .send()
            .await
            .map_err(AcmeError::Http)?
            .error_for_status()
            .map_err(AcmeError::Http)?
            .json::<ApiResponse<RecordResult>>()
            .await
            .map_err(AcmeError::Http)?;
        let result = response.result.ok_or_else(|| api_failure(response.errors))?;
        Ok(DnsRecord { zone, id: result.id })
    }

    pub async fn delete(&self, record: &DnsRecord) -> Result<(), AcmeError> {
        self.client
            .delete(format!("{}/zones/{}/dns_records/{}", self.base_url, record.zone, record.id))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(AcmeError::Http)?
            .error_for_status()
            .map_err(AcmeError::Http)?;
        Ok(())
    }

    async fn zone_id(&self, domain: &str) -> Result<String, AcmeError> {
        let mut errors = Vec::new();
        for candidate in zone_candidates(domain) {
            let response = self
                .client
                .get(format!("{}/zones", self.base_url))
                .bearer_auth(&self.token)
                .query(&[("name", candidate.as_str()), ("status", "active")])
                .send()
                .await
                .map_err(AcmeError::Http)?
                .error_for_status()
                .map_err(AcmeError::Http)?
                .json::<ApiResponse<Vec<ZoneResult>>>()
                .await
                .map_err(AcmeError::Http)?;
            if let Some(zone) = response.result.and_then(|zones| zones.into_iter().next()) {
                return Ok(zone.id);
            }
            errors.extend(response.errors);
        }
        Err(api_failure(errors))
    }
}

pub struct DnsRecord {
    zone: String,
    id: String,
}

#[derive(Serialize)]
struct CreateRecord<'a> {
    #[serde(rename = "type")]
    record_type: &'static str,
    name: &'a str,
    content: &'a str,
    ttl: u32,
}

#[derive(Deserialize)]
struct ApiResponse<T> {
    result: Option<T>,
    #[serde(default)]
    errors: Vec<ApiMessage>,
}

#[derive(Deserialize)]
struct ApiMessage {
    code: u64,
    message: String,
}

#[derive(Deserialize)]
struct ZoneResult {
    id: String,
}

#[derive(Deserialize)]
struct RecordResult {
    id: String,
}

fn zone_candidates(domain: &str) -> Vec<String> {
    let labels = domain.split('.').collect::<Vec<_>>();
    (0..labels.len().saturating_sub(1)).map(|index| labels[index..].join(".")).collect()
}

fn api_failure(errors: Vec<ApiMessage>) -> AcmeError {
    let message = errors
        .into_iter()
        .map(|error| format!("{}: {}", error.code, error.message))
        .collect::<Vec<_>>()
        .join(", ");
    AcmeError::Dns(if message.is_empty() {
        "empty Cloudflare response".to_owned()
    } else {
        message
    })
}

#[cfg(test)]
#[path = "acme_cloudflare_tests.rs"]
mod tests;
