use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http::{HeaderName, Request, StatusCode, Version};
use http_body_util::BodyExt as _;
use rustls::pki_types::ServerName;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
    sync::mpsc,
};
use tokio_rustls::TlsConnector;
use wormhole_proto::frames::{
    BindSpec, BufferPolicy, EdgeAuth, HeaderField, HttpResponseHead, Persistence,
};

use super::{
    HttpsEdge, buffered_response, connection_tokens, control_response, hostname_from_authority,
    is_hop_header, is_upgrade_request, link_redirect, offline_response, request_head,
    response_connection_tokens, response_from_tunnel, static_response, valid_websocket_request,
    version_string,
};
use crate::{
    authz::{AuthStore, KeyLimits},
    certs::CertManager,
    config::{
        AuthConfig, LimitsConfig, PortRange, ServerConfig, TcpConfig, TlsConfig, TlsMode,
        WormholedConfig,
    },
    db::RelayDb,
    edge_tcp::TcpEdgeManager,
    edge_types::{forwarded_node, is_forwarding_header},
    registry::{AllocationRequest, HttpTunnelResponse, Registry, SessionCommand},
    state::AppState,
};

#[test]
fn authority_strips_public_port_and_trailing_dot() {
    assert_eq!(hostname_from_authority("demo.tun.example.com:8443"), Some("demo.tun.example.com"));
    assert_eq!(hostname_from_authority("demo.tun.example.com."), Some("demo.tun.example.com"));
    assert_eq!(hostname_from_authority(""), None);
}

#[test]
fn edge_removes_hop_and_untrusted_forwarding_headers() {
    for name in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        assert!(is_hop_header(&HeaderName::from_bytes(name.as_bytes()).expect("header")));
    }
    for name in ["forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto"] {
        assert!(is_forwarding_header(name));
    }
    assert!(!is_hop_header(&HeaderName::from_static("content-type")));
    assert_eq!(
        connection_tokens(["keep-alive, X-Private", " , Upgrade"].into_iter()),
        ["keep-alive", "x-private", "upgrade"]
    );
}

#[test]
fn request_head_sanitizes_headers_and_appends_trusted_forwarding() {
    let request = Request::builder()
        .method("POST")
        .uri("/path?q=1")
        .version(Version::HTTP_10)
        .header("host", "demo.example.com")
        .header("connection", "keep-alive, x-private")
        .header("keep-alive", "timeout=5")
        .header("x-private", "secret")
        .header("x-forwarded-for", "attacker")
        .header("x-forwarded-host", "attacker.example")
        .header("content-type", "text/plain")
        .body(())
        .expect("request");
    let (parts, ()) = request.into_parts();
    let head =
        request_head(parts, "192.0.2.10:1234".parse().expect("peer"), "demo.example.com", false);
    assert_eq!(head.method, "POST");
    assert_eq!(head.uri, "/path?q=1");
    assert_eq!(head.version, "HTTP/1.0");
    let names = head.headers.iter().map(|field| field.name.as_str()).collect::<Vec<_>>();
    assert!(names.contains(&"host"));
    assert!(names.contains(&"content-type"));
    assert!(!names.contains(&"connection"));
    assert!(!names.contains(&"keep-alive"));
    assert!(!names.contains(&"x-private"));
    assert_eq!(decoded_values(&head.headers, "x-forwarded-for"), ["192.0.2.10"]);
    assert_eq!(decoded_values(&head.headers, "x-forwarded-host"), ["demo.example.com"]);
    assert_eq!(
        decoded_values(&head.headers, "forwarded"),
        ["for=192.0.2.10;proto=https;host=demo.example.com"]
    );
}

#[test]
fn upgrade_request_preserves_only_upgrade_headers() {
    let request = Request::builder()
        .uri("/")
        .header("connection", "upgrade, x-drop")
        .header("upgrade", "websocket")
        .header("x-drop", "secret")
        .body(())
        .expect("request");
    assert!(is_upgrade_request(&request));
    let (parts, ()) = request.into_parts();
    let head = request_head(parts, "[2001:db8::1]:9".parse().expect("peer"), "host", true);
    let names = head.headers.iter().map(|field| field.name.as_str()).collect::<Vec<_>>();
    assert!(names.contains(&"connection"));
    assert!(names.contains(&"upgrade"));
    assert!(!names.contains(&"x-drop"));
    assert_eq!(decoded_values(&head.headers, "x-forwarded-for"), ["2001:db8::1"]);
    assert!(!is_upgrade_request(&Request::new(())));
}

#[tokio::test]
async fn tunneled_response_filters_hop_headers_and_streams_body() {
    let (body_tx, body_rx) = mpsc::channel(4);
    body_tx.send(Ok(Bytes::from_static(b"hello"))).await.expect("body");
    body_tx.send(Ok(Bytes::from_static(b" world"))).await.expect("body");
    drop(body_tx);
    let tunneled = HttpTunnelResponse {
        head: HttpResponseHead {
            status: 201,
            version: "HTTP/1.1".to_owned(),
            headers: vec![
                field("connection", "x-secret"),
                field("x-secret", "remove"),
                field("content-type", "text/plain"),
            ],
        },
        body: body_rx,
        upgrade: None,
    };
    let response = response_from_tunnel(tunneled, None).expect("response");
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers()["content-type"], "text/plain");
    assert!(!response.headers().contains_key("x-secret"));
    let body = response.into_body().collect().await.expect("collect").to_bytes();
    assert_eq!(body, "hello world");
}

#[test]
fn tunneled_response_rejects_invalid_metadata_and_missing_upgrades() {
    let invalid_name =
        tunnel(200, vec![HeaderField { name: "bad header".to_owned(), value_b64: String::new() }]);
    assert!(response_from_tunnel(invalid_name, None).is_err());
    let invalid_value =
        tunnel(200, vec![HeaderField { name: "x-test".to_owned(), value_b64: "!".to_owned() }]);
    assert!(response_from_tunnel(invalid_value, None).is_err());
    assert!(response_from_tunnel(tunnel(101, vec![]), None).is_err());
    assert!(
        response_connection_tokens(&[
            field("connection", "Keep-Alive, X-Test"),
            HeaderField { name: "connection".to_owned(), value_b64: "!".to_owned() },
        ])
        .contains(&"x-test".to_owned())
    );
}

#[tokio::test]
async fn static_edge_responses_have_contract_headers_and_bodies() {
    assert_response(
        static_response(StatusCode::BAD_GATEWAY, "Bad Gateway"),
        StatusCode::BAD_GATEWAY,
        "Bad Gateway",
    )
    .await;
    assert_response(control_response(&request_at("/health")), StatusCode::OK, "ok").await;
    assert_response(control_response(&request_at("/missing")), StatusCode::NOT_FOUND, "Not Found")
        .await;

    let response = offline_response();
    assert_eq!(response.headers()[http::header::RETRY_AFTER], "30");
    assert_response(response, StatusCode::SERVICE_UNAVAILABLE, "Tunnel Offline").await;
    let response = buffered_response();
    assert_eq!(response.headers()["wormhole-buffered"], "true");
    assert_response(response, StatusCode::ACCEPTED, "Accepted").await;

    let redirect = link_redirect("/clean", "wormhole_auth=token");
    assert_eq!(redirect.headers()[http::header::LOCATION], "/clean");
    assert_eq!(redirect.headers()[http::header::SET_COOKIE], "wormhole_auth=token");
    assert_eq!(redirect.headers()[http::header::CACHE_CONTROL], "no-store");
    assert_eq!(redirect.headers()[http::header::REFERRER_POLICY], "no-referrer");
}

#[test]
fn websocket_validation_rejects_each_invalid_shape() {
    assert!(valid_websocket_request(&websocket_request("wormhole.test", None), "wormhole.test"));
    assert!(valid_websocket_request(
        &websocket_request("wormhole.test", Some("https://wormhole.test")),
        "wormhole.test"
    ));
    for request in [
        websocket_request("wormhole.test", Some("https://attacker.test")),
        websocket_request("demo.wormhole.test", None),
        Request::builder().method("POST").uri("/_wormhole/ws").body(()).expect("request"),
        Request::builder().uri("/_wormhole/ws?query=1").body(()).expect("request"),
    ] {
        assert!(!valid_websocket_request(&request, "wormhole.test"));
    }
    let duplicate_origin = Request::builder()
        .uri("/_wormhole/ws")
        .header("host", "wormhole.test")
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "key")
        .header("origin", "https://wormhole.test")
        .header("origin", "https://wormhole.test")
        .body(())
        .expect("request");
    assert!(!valid_websocket_request(&duplicate_origin, "wormhole.test"));
}

#[test]
fn forwarded_nodes_and_http_versions_have_stable_wire_names() {
    assert_eq!(forwarded_node("192.0.2.1".parse().expect("IPv4")), "192.0.2.1");
    assert_eq!(forwarded_node("2001:db8::1".parse().expect("IPv6")), "\"[2001:db8::1]\"");
    assert_eq!(version_string(Version::HTTP_09), "HTTP/0.9");
    assert_eq!(version_string(Version::HTTP_10), "HTTP/1.0");
    assert_eq!(version_string(Version::HTTP_11), "HTTP/1.1");
    assert_eq!(version_string(Version::HTTP_2), "HTTP/2");
    assert_eq!(version_string(Version::HTTP_3), "HTTP/3");
}

#[tokio::test]
async fn tls_edge_routes_control_tunnels_auth_and_websocket_startup() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let data = camino::Utf8Path::from_path(directory.path()).expect("UTF-8 path").to_owned();
    let config = edge_config(data.clone());
    let certificates = CertManager::ready(&config).await.expect("certificates");
    let certificate =
        certificates.resolver().resolve_name("tun.example.com").expect("certificate").cert[0]
            .clone();
    let state = edge_state(&config, &data);
    allocate_http(&state.registry, "demo", None);
    let buffered = allocate_buffered(&state.registry);
    let online_task = allocate_online(&state.registry);
    allocate_http(
        &state.registry,
        "private",
        Some(EdgeAuth { basic: Some("agent:secret".to_owned()), bearer: None, link_key: None }),
    );
    allocate_http(
        &state.registry,
        "shared",
        Some(EdgeAuth { basic: None, bearer: None, link_key: Some(STANDARD.encode([5_u8; 32])) }),
    );
    let edge = Arc::new(
        HttpsEdge::bind(
            "127.0.0.1:0".parse().expect("address"),
            Arc::clone(&state),
            certificates.resolver(),
        )
        .await
        .expect("bind HTTPS edge"),
    );
    let address = edge.local_addr().expect("edge address");
    let task = tokio::spawn({
        let edge = Arc::clone(&edge);
        async move { edge.run().await }
    });
    assert_basic_tls_routes(address, &certificate).await;
    assert_buffered_routes(address, &certificate, &state, buffered).await;
    assert_auth_and_websocket_routes(address, certificate).await;
    online_task.await.expect("online responder");
    task.abort();
}

async fn assert_basic_tls_routes(
    address: std::net::SocketAddr,
    certificate: &rustls::pki_types::CertificateDer<'static>,
) {
    for (sni, host, path, status) in [
        ("tun.example.com", "tun.example.com", "/health", 200),
        ("tun.example.com", "tun.example.com", "/missing", 404),
        ("missing.tun.example.com", "missing.tun.example.com", "/", 404),
        ("demo.tun.example.com", "other.tun.example.com", "/", 421),
        ("demo.tun.example.com", "demo.tun.example.com", "/", 503),
    ] {
        assert_status(
            tls_exchange(address, certificate.clone(), sni, host, path, "").await,
            status,
        );
    }
    let proxied = tls_exchange(
        address,
        certificate.clone(),
        "online.tun.example.com",
        "online.tun.example.com",
        "/target?q=1",
        "X-Test: public\r\n",
    )
    .await;
    assert_status(proxied.clone(), 202);
    assert!(
        proxied
            .to_ascii_lowercase()
            .contains("x-robots-tag: noindex, nofollow, noarchive, nosnippet")
    );
    assert!(proxied.ends_with("proxied"));
    let persistent = tls_exchange(
        address,
        certificate.clone(),
        "demo.tun.example.com",
        "demo.tun.example.com",
        "/",
        "",
    )
    .await;
    assert!(!persistent.to_ascii_lowercase().contains("x-robots-tag"));
}

async fn assert_auth_and_websocket_routes(
    address: std::net::SocketAddr,
    certificate: rustls::pki_types::CertificateDer<'static>,
) {
    let unauthorized = tls_exchange(
        address,
        certificate.clone(),
        "private.tun.example.com",
        "private.tun.example.com",
        "/",
        "",
    )
    .await;
    assert_status(unauthorized.clone(), 401);
    assert!(unauthorized.to_ascii_lowercase().contains("www-authenticate: basic"));
    for (sni, headers, status) in [
        ("private.tun.example.com", "Authorization: Basic YWdlbnQ6c2VjcmV0\r\n", 503),
        ("shared.tun.example.com", "", 403),
        ("tun.example.com", "", 400),
    ] {
        let path = if sni == "tun.example.com" { "/_wormhole/ws" } else { "/" };
        assert_status(
            tls_exchange(address, certificate.clone(), sni, sni, path, headers).await,
            status,
        );
    }
    let websocket = tls_exchange(
        address,
        certificate,
        "tun.example.com",
        "tun.example.com",
        "/_wormhole/ws",
        "Connection: upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
    )
    .await;
    assert_status(websocket, 101);
}

fn websocket_request(host: &str, origin: Option<&str>) -> Request<()> {
    let mut request = Request::builder()
        .method("GET")
        .uri("/_wormhole/ws")
        .header("host", host)
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");
    if let Some(origin) = origin {
        request = request.header("origin", origin);
    }
    request.body(()).expect("request")
}

fn edge_config(data: camino::Utf8PathBuf) -> WormholedConfig {
    WormholedConfig {
        server: ServerConfig {
            domains: vec!["tun.example.com".to_owned()],
            public_https_port: None,
            quic_addr: "127.0.0.1:0".parse().expect("address"),
            https_addr: "127.0.0.1:0".parse().expect("address"),
            http_addr: "127.0.0.1:0".parse().expect("address"),
            data_dir: data.clone(),
        },
        tls: TlsConfig { mode: TlsMode::SelfSigned, static_config: None, acme: None },
        tcp: TcpConfig { port_range: PortRange { start: 10_000, end: 10_010 } },
        limits: LimitsConfig::default(),
        auth: AuthConfig { authorized_keys: data.join("keys") },
    }
}

fn edge_state(config: &WormholedConfig, data: &camino::Utf8Path) -> Arc<AppState> {
    let database = Arc::new(RelayDb::open(data).expect("database"));
    let auth = Arc::new(AuthStore::new(Arc::clone(&database), KeyLimits::from(&config.limits)));
    let registry =
        Arc::new(Registry::new(config.server.domains.clone(), None, 443, config.tcp.port_range));
    Arc::new(
        AppState::new(
            registry,
            database,
            Arc::new(TcpEdgeManager::new("127.0.0.1".parse().expect("IP"))),
            auth,
            config.limits.clone(),
        )
        .expect("state"),
    )
}

fn allocate_buffered(registry: &Registry) -> uuid::Uuid {
    let (session_tx, _session_rx) = mpsc::channel(1);
    registry
        .allocate(AllocationRequest {
            key_fpr: "owner".to_owned(),
            spec: BindSpec::Http {
                host: Some("buffered".to_owned()),
                auto_host: false,
                domain: Some("tun.example.com".to_owned()),
                persist: Persistence::Persistent,
                buffer: Some(BufferPolicy { max_requests: 2, max_body_bytes: 4, ttl_secs: 60 }),
                auth: None,
            },
            reservation: None,
            session_tx,
        })
        .expect("allocate buffered route")
        .bind
}

fn allocate_online(registry: &Registry) -> tokio::task::JoinHandle<()> {
    let (session_tx, mut session_rx) = mpsc::channel(1);
    let allocation = registry
        .allocate(AllocationRequest {
            key_fpr: "owner".to_owned(),
            spec: BindSpec::Http {
                host: Some("online".to_owned()),
                auto_host: false,
                domain: Some("tun.example.com".to_owned()),
                persist: Persistence::Temporary,
                buffer: None,
                auth: None,
            },
            reservation: None,
            session_tx: session_tx.clone(),
        })
        .expect("allocate online route");
    registry.activate(allocation.bind, &session_tx).expect("activate route");
    tokio::spawn(async move {
        let Some(SessionCommand::OpenHttp { header, body, upgrade, reply }) =
            session_rx.recv().await
        else {
            panic!("expected HTTP command");
        };
        assert!(!upgrade);
        assert_eq!(body.capacity(), 16);
        let wormhole_proto::frames::StreamHeader::Http { request, .. } = header else {
            panic!("expected HTTP header");
        };
        assert_eq!(request.uri, "/target?q=1");
        let (body_tx, body_rx) = mpsc::channel(1);
        body_tx.send(Ok(Bytes::from_static(b"proxied"))).await.expect("response body");
        drop(body_tx);
        reply
            .send(Ok(HttpTunnelResponse {
                head: HttpResponseHead {
                    status: 202,
                    version: "HTTP/1.1".to_owned(),
                    headers: vec![field("content-length", "7")],
                },
                body: body_rx,
                upgrade: None,
            }))
            .expect("reply edge");
    })
}

fn allocate_http(registry: &Registry, host: &str, auth: Option<EdgeAuth>) {
    let (session_tx, _session_rx) = mpsc::channel(1);
    registry
        .allocate(AllocationRequest {
            key_fpr: "owner".to_owned(),
            spec: BindSpec::Http {
                host: Some(host.to_owned()),
                auto_host: false,
                domain: Some("tun.example.com".to_owned()),
                persist: Persistence::Persistent,
                buffer: None,
                auth,
            },
            reservation: None,
            session_tx,
        })
        .expect("allocate route");
}

async fn assert_buffered_routes(
    address: std::net::SocketAddr,
    certificate: &rustls::pki_types::CertificateDer<'static>,
    state: &AppState,
    bind: uuid::Uuid,
) {
    let accepted = tls_exchange_request(
        address,
        certificate.clone(),
        "buffered.tun.example.com",
        "buffered.tun.example.com",
        "POST",
        "/hook?wh_token=secret&event=push",
        "Authorization: Bearer client\r\nCookie: theme=dark; wormhole_auth=secret\r\n",
        b"yes",
    )
    .await;
    assert_status(accepted, 202);
    let request = state.database.first_buffered(bind).expect("buffer lookup").expect("request");
    assert_eq!(request.uri, "/hook?event=push");
    assert_eq!(request.body, b"yes");
    assert!(request.headers.iter().any(|field| field.name == "authorization"));
    assert!(request.headers.iter().any(|field| field.name == "cookie"));

    let oversized = tls_exchange_request(
        address,
        certificate.clone(),
        "buffered.tun.example.com",
        "buffered.tun.example.com",
        "POST",
        "/hook",
        "",
        b"large",
    )
    .await;
    assert_status(oversized, 413);
    assert_eq!(state.database.buffered_counts(bind).expect("counts"), (1, 0));
}

async fn tls_exchange(
    address: std::net::SocketAddr,
    certificate: rustls::pki_types::CertificateDer<'static>,
    sni: &str,
    host: &str,
    path: &str,
    extra_headers: &str,
) -> String {
    tls_exchange_request(address, certificate, sni, host, "GET", path, extra_headers, b"").await
}

#[allow(clippy::too_many_arguments)]
async fn tls_exchange_request(
    address: std::net::SocketAddr,
    certificate: rustls::pki_types::CertificateDer<'static>,
    sni: &str,
    host: &str,
    method: &str,
    path: &str,
    extra_headers: &str,
    body: &[u8],
) -> String {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate).expect("add test root");
    let mut config =
        rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(address).await.expect("connect HTTPS edge");
    let name = ServerName::try_from(sni.to_owned()).expect("server name");
    let mut tls = connector.connect(name, stream).await.expect("TLS handshake");
    let connection = if extra_headers.to_ascii_lowercase().contains("connection:") {
        ""
    } else {
        "Connection: close\r\n"
    };
    let content_length =
        if body.is_empty() { String::new() } else { format!("Content-Length: {}\r\n", body.len()) };
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\n{connection}{content_length}{extra_headers}\r\n"
    );
    tls.write_all(head.as_bytes()).await.expect("write request head");
    tls.write_all(body).await.expect("write request body");
    let mut response = Vec::new();
    let mut buffer = [0_u8; 2048];
    loop {
        let count = tls.read(&mut buffer).await.expect("read response");
        if count == 0 {
            break;
        }
        response.extend_from_slice(&buffer[..count]);
        if response.starts_with(b"HTTP/1.1 101")
            && response.windows(4).any(|window| window == b"\r\n\r\n")
        {
            break;
        }
    }
    String::from_utf8(response).expect("UTF-8 response")
}

fn assert_status(response: String, status: u16) {
    assert!(
        response.starts_with(&format!("HTTP/1.1 {status} ")),
        "unexpected response: {response}"
    );
}

fn request_at(uri: &str) -> Request<()> {
    Request::builder().uri(uri).body(()).expect("request")
}

fn field(name: &str, value: &str) -> HeaderField {
    HeaderField { name: name.to_owned(), value_b64: STANDARD.encode(value) }
}

fn decoded_values(fields: &[HeaderField], name: &str) -> Vec<String> {
    fields
        .iter()
        .filter(|field| field.name == name)
        .map(|field| {
            String::from_utf8(STANDARD.decode(&field.value_b64).expect("base64")).expect("UTF-8")
        })
        .collect()
}

fn tunnel(status: u16, headers: Vec<HeaderField>) -> HttpTunnelResponse {
    let (_body_tx, body) = mpsc::channel(1);
    HttpTunnelResponse {
        head: HttpResponseHead { status, version: "HTTP/1.1".to_owned(), headers },
        body,
        upgrade: None,
    }
}

async fn assert_response(
    response: super::Response<super::EdgeBody>,
    status: StatusCode,
    body: &str,
) {
    assert_eq!(response.status(), status);
    assert_eq!(response.into_body().collect().await.expect("body").to_bytes(), body);
}

#[test]
fn authority_strips_public_port() {
    assert_eq!(hostname_from_authority("demo.tun.example.com:8443"), Some("demo.tun.example.com"));
    assert_eq!(hostname_from_authority(""), None);
}

#[test]
fn first_wave_removes_hop_and_untrusted_forwarding_headers() {
    assert!(is_hop_header(&HeaderName::from_static("connection")));
    assert!(is_hop_header(&HeaderName::from_static("transfer-encoding")));
    assert!(is_forwarding_header("forwarded"));
    assert!(!is_hop_header(&HeaderName::from_static("content-type")));
    assert_eq!(
        connection_tokens(["keep-alive, X-Private"].into_iter()),
        ["keep-alive", "x-private"]
    );
}

#[test]
fn forwarded_nodes_quote_bracketed_ipv6() {
    assert_eq!(forwarded_node("192.0.2.1".parse().expect("IPv4")), "192.0.2.1");
    assert_eq!(forwarded_node("2001:db8::1".parse().expect("IPv6")), "\"[2001:db8::1]\"");
}

#[test]
fn websocket_upgrade_rejects_wrong_origin_and_non_apex_host() {
    assert!(valid_websocket_request(&websocket_request("wormhole.test", None), "wormhole.test"));
    assert!(valid_websocket_request(
        &websocket_request("wormhole.test", Some("https://wormhole.test")),
        "wormhole.test"
    ));
    assert!(!valid_websocket_request(
        &websocket_request("wormhole.test", Some("https://attacker.test")),
        "wormhole.test"
    ));
    assert!(!valid_websocket_request(
        &websocket_request("demo.wormhole.test", None),
        "wormhole.test"
    ));
}

#[test]
fn http_versions_have_stable_wire_names() {
    assert_eq!(version_string(Version::HTTP_09), "HTTP/0.9");
    assert_eq!(version_string(Version::HTTP_10), "HTTP/1.0");
    assert_eq!(version_string(Version::HTTP_11), "HTTP/1.1");
    assert_eq!(version_string(Version::HTTP_2), "HTTP/2");
    assert_eq!(version_string(Version::HTTP_3), "HTTP/3");
}

#[test]
fn request_head_removes_spoofed_forwarding_and_connection_nominated_headers() {
    let (parts, ()) = Request::builder()
        .method("POST")
        .uri("/hook?event=push")
        .header("content-type", "application/json")
        .header("connection", "keep-alive, x-private")
        .header("x-private", "secret")
        .header("forwarded", "for=attacker")
        .header("x-forwarded-for", "attacker")
        .body(())
        .expect("request")
        .into_parts();
    let head =
        request_head(parts, "192.0.2.7:1234".parse().expect("peer"), "hook.example.com", false);

    assert_eq!(head.method, "POST");
    assert_eq!(head.uri, "/hook?event=push");
    assert_eq!(head.version, "HTTP/1.1");
    assert!(head.headers.iter().any(|field| field.name == "content-type"));
    assert!(!head.headers.iter().any(|field| field.name == "x-private"));
    let forwarded = head
        .headers
        .iter()
        .find(|field| field.name == "forwarded")
        .expect("trusted Forwarded header");
    assert_eq!(
        STANDARD.decode(&forwarded.value_b64).expect("header"),
        b"for=192.0.2.7;proto=https;host=hook.example.com"
    );
}

#[tokio::test]
async fn first_wave_tunneled_response_filters_hop_headers_and_streams_body() {
    let (body_tx, body_rx) = mpsc::channel(1);
    body_tx.send(Ok(Bytes::from_static(b"response"))).await.expect("body");
    drop(body_tx);
    let response = response_from_tunnel(
        HttpTunnelResponse {
            head: HttpResponseHead {
                status: 201,
                version: "HTTP/1.1".to_owned(),
                headers: vec![
                    HeaderField {
                        name: "content-type".to_owned(),
                        value_b64: STANDARD.encode("text/plain"),
                    },
                    HeaderField {
                        name: "connection".to_owned(),
                        value_b64: STANDARD.encode("x-private"),
                    },
                    HeaderField {
                        name: "x-private".to_owned(),
                        value_b64: STANDARD.encode("secret"),
                    },
                ],
            },
            body: body_rx,
            upgrade: None,
        },
        None,
    )
    .expect("response");
    assert_eq!(response.status(), 201);
    assert_eq!(response.headers().get("content-type").expect("content type"), "text/plain");
    assert!(!response.headers().contains_key("connection"));
    assert!(!response.headers().contains_key("x-private"));
    assert_eq!(response.into_body().collect().await.expect("body").to_bytes(), b"response"[..]);
}

#[tokio::test]
async fn apex_control_paths_expose_only_health() {
    let health = Request::builder().uri("/health").body(()).expect("health request");
    let response = control_response(&health);
    assert_eq!(response.status(), 200);
    assert_eq!(response.into_body().collect().await.expect("body").to_bytes(), b"ok"[..]);

    let other = Request::builder().uri("/").body(()).expect("other request");
    assert_eq!(control_response(&other).status(), 404);
}
