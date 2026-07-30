use std::{fs, sync::Arc};

use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
    sync::Mutex,
};

use super::{CloudflareDns, DnsRecord, zone_candidates};
use crate::{acme::AcmeError, config::AcmeConfig};

#[test]
fn parent_zones_are_discovered_from_most_to_least_specific() {
    assert_eq!(
        zone_candidates("tun.eu.example.com"),
        ["tun.eu.example.com", "eu.example.com", "example.com"]
    );
    assert!(zone_candidates("localhost").is_empty());
}

#[test]
fn client_rejects_missing_and_empty_tokens() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = camino::Utf8Path::from_path(directory.path()).expect("UTF-8").join("token");
    let config = acme_config(path.clone());
    assert!(matches!(CloudflareDns::new(&config), Err(AcmeError::Io { .. })));
    fs::write(&path, "  \n").expect("write token");
    assert!(matches!(CloudflareDns::new(&config), Err(AcmeError::Config(_))));
    fs::write(&path, " secret\n").expect("write token");
    let client = CloudflareDns::new(&config).expect("client");
    assert_eq!(client.token, "secret");
}

#[tokio::test]
async fn txt_record_lifecycle_uses_discovered_parent_zone() {
    let responses = [
        json(200, r#"{"result":[],"errors":[]}"#),
        json(200, r#"{"result":[{"id":"zone-1"}],"errors":[]}"#),
        json(200, r#"{"result":{"id":"record-1"},"errors":[]}"#),
        json(204, ""),
    ];
    let (base_url, requests) = fake_server(&responses).await;
    let dns = client(base_url);
    let record = dns
        .create_txt("sub.example.com", "_acme-challenge.sub.example.com", "proof")
        .await
        .expect("create TXT");
    assert_eq!(record.zone, "zone-1");
    assert_eq!(record.id, "record-1");
    dns.delete(&record).await.expect("delete TXT");

    let requests = requests.lock().await;
    assert!(requests[0].contains("name=sub.example.com"));
    assert!(requests[1].contains("name=example.com"));
    assert!(requests[2].starts_with("POST /client/v4/zones/zone-1/dns_records"));
    assert!(requests[2].to_ascii_lowercase().contains("authorization: bearer token"));
    assert!(requests[2].contains(r#""type":"TXT""#));
    assert!(requests[2].contains(r#""content":"proof""#));
    assert!(requests[3].starts_with("DELETE /client/v4/zones/zone-1/dns_records/record-1"));
    drop(requests);
}

#[tokio::test]
async fn api_and_http_failures_are_reported() {
    let (base_url, _) = fake_server(&[
        json(200, r#"{"result":null,"errors":[{"code":100,"message":"bad zone"}]}"#),
        json(200, r#"{"result":null,"errors":[]}"#),
    ])
    .await;
    let Err(error) = client(base_url).create_txt("example.com", "name", "proof").await else {
        panic!("zone lookup must fail");
    };
    assert!(error.to_string().contains("100: bad zone"));

    let (base_url, _) = fake_server(&[
        json(200, r#"{"result":[{"id":"zone"}],"errors":[]}"#),
        json(500, "failure"),
    ])
    .await;
    assert!(matches!(
        client(base_url).create_txt("example.com", "name", "proof").await,
        Err(AcmeError::Http(_))
    ));

    let (base_url, _) = fake_server(&[json(500, "failure")]).await;
    assert!(matches!(
        client(base_url).delete(&DnsRecord { zone: "z".into(), id: "r".into() }).await,
        Err(AcmeError::Http(_))
    ));
}

fn client(base_url: String) -> CloudflareDns {
    CloudflareDns { client: reqwest::Client::new(), token: "token".to_owned(), base_url }
}

fn acme_config(cloudflare_token_file: camino::Utf8PathBuf) -> AcmeConfig {
    AcmeConfig {
        contact: "mailto:ops@example.com".to_owned(),
        directory: "http://localhost/directory".to_owned(),
        dns_provider: "cloudflare".to_owned(),
        cloudflare_token_file,
    }
}

fn json(status: u16, body: &str) -> (u16, String) {
    (status, body.to_owned())
}

async fn fake_server(responses: &[(u16, String)]) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind fake server");
    let address = listener.local_addr().expect("fake address");
    let responses = responses.to_vec();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&requests);
    tokio::spawn(async move {
        for (status, body) in responses {
            let (mut stream, _) = listener.accept().await.expect("accept request");
            let request = read_request(&mut stream).await;
            captured.lock().await.push(request);
            let reason = if status == 204 {
                "No Content"
            } else if status >= 400 {
                "Error"
            } else {
                "OK"
            };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.expect("write response");
        }
    });
    (format!("http://{address}/client/v4"), requests)
}

async fn read_request(stream: &mut tokio::net::TcpStream) -> String {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let count = stream.read(&mut buffer).await.expect("read request");
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..count]);
        let header_end = bytes.windows(4).position(|window| window == b"\r\n\r\n");
        if let Some(header_end) = header_end {
            let headers = String::from_utf8_lossy(&bytes[..header_end + 4]);
            let length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase().strip_prefix("content-length: ").map(str::to_owned)
                })
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            if bytes.len() >= header_end + 4 + length {
                break;
            }
        }
    }
    String::from_utf8(bytes).expect("UTF-8 request")
}
