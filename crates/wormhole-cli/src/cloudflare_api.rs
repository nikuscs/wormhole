use serde::{Deserialize, Serialize, de::DeserializeOwned};
use zeroize::Zeroizing;

use crate::error::CliError;

#[derive(Clone, Debug)]
pub struct Zone {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Debug)]
pub struct CreatedDnsRecord {
    pub id: String,
    pub name: String,
}

pub struct CloudflareApi {
    client: reqwest::Client,
    base: String,
    token: Zeroizing<String>,
}

impl CloudflareApi {
    pub fn new(token: Zeroizing<String>) -> Result<Self, CliError> {
        let client = reqwest::Client::builder().build().map_err(api_error)?;
        Ok(Self { client, base: api_base(), token })
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    pub async fn discover_zone(&self, domain: &str) -> Result<Zone, CliError> {
        let labels = domain.split('.').collect::<Vec<_>>();
        for offset in 0..labels.len().saturating_sub(1) {
            let candidate = labels[offset..].join(".");
            let path = format!("/zones?name={candidate}&status=active&per_page=1");
            let zones: Vec<ZoneResponse> = self.get(&path).await?;
            if let Some(zone) = zones.into_iter().next() {
                return Ok(Zone { id: zone.id, name: zone.name });
            }
        }
        Err(CliError::Invalid(format!("no active Cloudflare zone contains {domain}")))
    }

    pub async fn dns_ready(&self, zone: &Zone, name: &str) -> Result<bool, CliError> {
        let path = format!("/zones/{}/dns_records?name={name}&per_page=100", zone.id);
        let records: Vec<DnsRecord> = self.get(&path).await?;
        if records.is_empty() {
            return Ok(false);
        }
        if records.iter().any(|record| record.proxied == Some(true)) {
            return Ok(true);
        }
        Err(CliError::Invalid(format!("DNS record {name} exists but is not proxied by Cloudflare")))
    }

    pub async fn create_placeholder_dns(
        &self,
        zone: &Zone,
        name: &str,
    ) -> Result<CreatedDnsRecord, CliError> {
        let path = format!("/zones/{}/dns_records", zone.id);
        let record: DnsRecord = self
            .post(
                &path,
                &CreateDnsRecord {
                    record_type: "AAAA",
                    name,
                    content: "100::",
                    ttl: 1,
                    proxied: true,
                },
            )
            .await?;
        Ok(CreatedDnsRecord { id: record.id, name: record.name })
    }

    pub async fn delete_dns(&self, zone: &Zone, record: &CreatedDnsRecord) -> Result<(), CliError> {
        let url = format!("{}/zones/{}/dns_records/{}", self.base, zone.id, record.id);
        let response =
            self.client.delete(url).bearer_auth(&*self.token).send().await.map_err(api_error)?;
        decode::<serde_json::Value>(response).await.map(|_| ())
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, CliError> {
        let response = self
            .client
            .get(format!("{}{path}", self.base))
            .bearer_auth(&*self.token)
            .send()
            .await
            .map_err(api_error)?;
        decode(response).await
    }

    async fn post<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, CliError> {
        let response = self
            .client
            .post(format!("{}{path}", self.base))
            .bearer_auth(&*self.token)
            .json(body)
            .send()
            .await
            .map_err(api_error)?;
        decode(response).await
    }
}

#[derive(Deserialize)]
struct ApiResponse<T> {
    success: bool,
    result: Option<T>,
    #[serde(default)]
    errors: Vec<ApiMessage>,
}

#[derive(Deserialize)]
struct ApiMessage {
    message: String,
}

#[derive(Deserialize)]
struct ZoneResponse {
    id: String,
    name: String,
}

#[derive(Deserialize)]
struct DnsRecord {
    id: String,
    name: String,
    proxied: Option<bool>,
}

#[derive(Serialize)]
struct CreateDnsRecord<'a> {
    #[serde(rename = "type")]
    record_type: &'a str,
    name: &'a str,
    content: &'a str,
    ttl: u8,
    proxied: bool,
}

async fn decode<T: DeserializeOwned>(response: reqwest::Response) -> Result<T, CliError> {
    let status = response.status();
    let body: ApiResponse<T> = response.json().await.map_err(api_error)?;
    if status.is_success()
        && body.success
        && let Some(result) = body.result
    {
        return Ok(result);
    }
    let message = body.errors.into_iter().map(|error| error.message).collect::<Vec<_>>().join("; ");
    Err(CliError::Invalid(if message.is_empty() {
        format!("Cloudflare API returned {status}")
    } else {
        format!("Cloudflare API returned {status}: {message}")
    }))
}

fn api_base() -> String {
    #[cfg(debug_assertions)]
    if let Ok(value) = std::env::var("WORMHOLE_CLOUDFLARE_API_BASE") {
        return value.trim_end_matches('/').to_owned();
    }
    "https://api.cloudflare.com/client/v4".to_owned()
}

fn api_error(error: reqwest::Error) -> CliError {
    CliError::Invalid(format!("Cloudflare API request failed: {error}"))
}
