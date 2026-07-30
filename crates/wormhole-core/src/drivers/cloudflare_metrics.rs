//! cloudflared metrics and quick-URL discovery.

use std::time::Duration;

use serde_json::Value;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
    sync::mpsc,
};

use crate::{driver::DriverEvent, error::DriverError};

pub async fn discover_quick_url(
    metrics_port: u16,
    stderr: &mut Option<mpsc::Receiver<String>>,
    events: &mpsc::Sender<DriverEvent>,
) -> Result<String, DriverError> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut metric_url = None;
    let mut log_url = None;
    loop {
        if metric_url.is_none()
            && let Ok(body) = http_get_until(metrics_port, "/quicktunnel", deadline).await
        {
            metric_url = find_url(&body);
        }
        drain_logs(stderr, events, &mut log_url).await;
        match (&metric_url, &log_url) {
            (Some(metric), Some(log)) if metric != log => {
                return Err(DriverError::Protocol(format!(
                    "cloudflared quick URL sources disagree: metrics={metric}, log={log}"
                )));
            }
            (Some(url), Some(_)) => return Ok(url.clone()),
            _ => {}
        }
        if tokio::time::Instant::now() >= deadline {
            return metric_url.or(log_url).ok_or_else(|| {
                DriverError::Transport("cloudflared did not report a quick tunnel URL".to_owned())
            });
        }
        tokio::time::sleep_until(
            (tokio::time::Instant::now() + Duration::from_millis(100)).min(deadline),
        )
        .await;
    }
}

async fn drain_logs(
    stderr: &mut Option<mpsc::Receiver<String>>,
    events: &mpsc::Sender<DriverEvent>,
    log_url: &mut Option<String>,
) {
    if let Some(lines) = stderr.as_mut() {
        while let Ok(line) = lines.try_recv() {
            let _log = events.send(DriverEvent::Log(tracing::Level::DEBUG, line.clone())).await;
            *log_url = log_url.take().or_else(|| find_url(&line));
        }
    }
}

pub async fn ready(port: u16) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    http_get_until(port, "/ready", deadline).await.is_ok_and(|body| {
        let lowercase = body.to_ascii_lowercase();
        lowercase.contains("ready") || lowercase.contains("ok")
    })
}

async fn http_get_until(
    port: u16,
    path: &str,
    deadline: tokio::time::Instant,
) -> Result<String, DriverError> {
    let mut stream = tokio::time::timeout_at(deadline, TcpStream::connect(("127.0.0.1", port)))
        .await
        .map_err(|_| metrics_timeout())?
        .map_err(|error| DriverError::Transport(error.to_string()))?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    tokio::time::timeout_at(deadline, stream.write_all(request.as_bytes()))
        .await
        .map_err(|_| metrics_timeout())?
        .map_err(|error| DriverError::Transport(error.to_string()))?;
    let mut response = Vec::new();
    tokio::time::timeout_at(deadline, stream.read_to_end(&mut response))
        .await
        .map_err(|_| metrics_timeout())?
        .map_err(|error| DriverError::Transport(error.to_string()))?;
    let response = String::from_utf8_lossy(&response);
    let (headers, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| DriverError::Protocol("invalid cloudflared metrics response".to_owned()))?;
    if !headers.starts_with("HTTP/1.1 200") && !headers.starts_with("HTTP/1.0 200") {
        return Err(DriverError::Transport("cloudflared metrics returned non-200".to_owned()));
    }
    Ok(body.to_owned())
}

fn metrics_timeout() -> DriverError {
    DriverError::Transport("cloudflared metrics discovery deadline exceeded".to_owned())
}

fn find_url(input: &str) -> Option<String> {
    let value = serde_json::from_str::<Value>(input).ok();
    value.as_ref().and_then(find_url_value).or_else(|| input.split_whitespace().find_map(clean_url))
}

fn find_url_value(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => clean_url(value),
        Value::Array(values) => values.iter().find_map(find_url_value),
        Value::Object(values) => values.values().find_map(find_url_value),
        _ => None,
    }
}

fn clean_url(value: &str) -> Option<String> {
    let cleaned = value.trim_matches(|character: char| {
        matches!(character, '"' | '\'' | ',' | ')' | '(' | '\n' | '\r')
    });
    (cleaned.starts_with("https://") && cleaned.contains("trycloudflare.com"))
        .then(|| cleaned.to_owned())
}

#[cfg(test)]
#[path = "cloudflare_metrics_tests.rs"]
mod tests;
