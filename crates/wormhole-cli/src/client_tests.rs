use std::{convert::Infallible, sync::Arc};

use bytes::Bytes;
use http::{Method, StatusCode};
use http_body_util::Full;
use hyper::{Response, service::service_fn};
use hyper_util::rt::TokioIo;
use tokio::{
    net::UnixListener,
    sync::{Mutex, oneshot},
};

use super::{ClientError, DaemonClient};
use crate::runtime::RuntimePaths;

#[tokio::test]
async fn typed_client_methods_encode_routes_and_queries() {
    let (client, request) = mock_client(StatusCode::OK, b"[]");
    assert!(client.services(true).await.expect("services").is_empty());
    assert_request(request, Method::GET, "/v1/services?watch=1").await;

    let (client, request) = mock_client(StatusCode::OK, br#"{"closed":true}"#);
    assert!(
        client
            .delete_service("name/with space", Some("project"), true)
            .await
            .expect("delete service")
            .closed
    );
    assert_request(
        request,
        Method::DELETE,
        "/v1/services/name%2Fwith%20space?forget=1&project_id=project",
    )
    .await;

    let (client, request) = mock_client(StatusCode::OK, b"[]");
    assert!(client.remotes().await.expect("remotes").is_empty());
    assert_request(request, Method::GET, "/v1/remotes").await;

    let (client, request) = mock_client(StatusCode::OK, br#"{"closed":true}"#);
    assert!(client.remove_remote("edge/name").await.expect("remove remote").closed);
    assert_request(request, Method::DELETE, "/v1/remotes/edge%2Fname").await;

    let endpoint = uuid::Uuid::now_v7();
    let (client, request) = mock_client(StatusCode::OK, br#"{"closed":false}"#);
    assert!(!client.delete_endpoint(endpoint, false).await.expect("delete endpoint").closed);
    assert_request(request, Method::DELETE, &format!("/v1/endpoints/{endpoint}?forget=0")).await;

    let since: jiff::Timestamp = "2026-01-01T00:00:00Z".parse().expect("timestamp");
    let (client, request) = mock_client(StatusCode::OK, b"[]");
    assert!(
        client
            .captures(Some(&endpoint.to_string()), Some(since))
            .await
            .expect("captures")
            .is_empty()
    );
    assert_request(
        request,
        Method::GET,
        &format!("/v1/requests?endpoint={endpoint}&since=2026-01-01T00:00:00Z"),
    )
    .await;
}

#[tokio::test]
async fn typed_client_surfaces_structured_and_plain_api_errors() {
    let id = uuid::Uuid::now_v7();
    let (client, request) = mock_client(
        StatusCode::NOT_FOUND,
        br#"{"error":{"code":"not_found","message":"capture missing"}}"#,
    );
    let error = client.capture(id).await.expect_err("API error");
    assert!(
        matches!(error, ClientError::Api { status: StatusCode::NOT_FOUND, ref message } if message == "capture missing")
    );
    assert_request(request, Method::GET, &format!("/v1/requests/{id}")).await;

    let (client, request) = mock_client(StatusCode::BAD_GATEWAY, b"plain failure");
    let error = client.clear_captures().await.expect_err("plain API error");
    assert!(
        matches!(error, ClientError::Api { status: StatusCode::BAD_GATEWAY, ref message } if message == "plain failure")
    );
    assert_request(request, Method::DELETE, "/v1/requests").await;
}

#[tokio::test]
async fn creating_a_service_supersedes_a_registration_that_outlived_its_command() {
    let conflict = (
        StatusCode::CONFLICT,
        br#"{"error":{"code":"conflict","message":"service already exists: web"}}"#.as_slice(),
    );
    let (client, requests) = scripted_client(vec![
        conflict,
        (StatusCode::OK, br#"{"closed":true}"#.as_slice()),
        (StatusCode::OK, b"[]".as_slice()),
    ]);

    assert!(client.create_replacing(&create_request()).await.expect("replace").is_empty());

    let seen = requests.lock().await.clone();
    assert_eq!(
        seen,
        vec![
            (Method::POST, "/v1/services".to_owned()),
            // Forgetting is deliberately off, so the handover keeps the public URL.
            (Method::DELETE, "/v1/services/web?forget=0&project_id=project".to_owned()),
            (Method::POST, "/v1/services".to_owned()),
        ]
    );
}

#[tokio::test]
async fn creating_a_service_reports_an_unrelated_conflict_unchanged() {
    let (client, requests) = scripted_client(vec![(
        StatusCode::CONFLICT,
        br#"{"error":{"code":"conflict","message":"port already bound"}}"#.as_slice(),
    )]);

    let error = client.create_replacing(&create_request()).await.expect_err("conflict");

    assert!(matches!(error, ClientError::Api { status: StatusCode::CONFLICT, .. }));
    assert_eq!(requests.lock().await.len(), 1);
}

fn create_request() -> crate::local_api::CreateServiceRequest {
    crate::local_api::CreateServiceRequest {
        project_id: Some("project".to_owned()),
        remotes: None,
        default_remote: None,
        service: wormhole_core::Service {
            name: "web".to_owned(),
            target: wormhole_core::model::Target::Port(3000),
            proto: wormhole_core::model::ServiceProto::Http,
        },
        endpoints: Vec::new(),
    }
}

type RecordedRequests = Arc<Mutex<Vec<(Method, String)>>>;

fn scripted_client(
    responses: Vec<(StatusCode, &'static [u8])>,
) -> (DaemonClient, RecordedRequests) {
    let directory = tempfile::tempdir().expect("tempdir").keep();
    let state_dir = camino::Utf8PathBuf::from_path_buf(directory).expect("UTF-8 path");
    let paths = RuntimePaths {
        socket: state_dir.join("daemon.sock"),
        lock: state_dir.join("daemon.lock"),
        token: state_dir.join("api-token"),
        log: state_dir.join("daemon.log"),
        state_dir,
    };
    let listener = UnixListener::bind(&paths.socket).expect("listener");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    let remaining =
        Arc::new(Mutex::new(responses.into_iter().collect::<std::collections::VecDeque<_>>()));
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let recorded = Arc::clone(&recorded);
            let remaining = Arc::clone(&remaining);
            let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                let recorded = Arc::clone(&recorded);
                let remaining = Arc::clone(&remaining);
                async move {
                    recorded
                        .lock()
                        .await
                        .push((request.method().clone(), request.uri().to_string()));
                    let (status, body) =
                        remaining.lock().await.pop_front().expect("scripted response");
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(status)
                            .body(Full::new(Bytes::from_static(body)))
                            .expect("response"),
                    )
                }
            });
            let _served = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        }
    });
    (DaemonClient { paths, token: "test-token".to_owned() }, seen)
}

fn mock_client(
    status: StatusCode,
    body: &'static [u8],
) -> (DaemonClient, oneshot::Receiver<(Method, String, String)>) {
    let directory = tempfile::tempdir().expect("tempdir").keep();
    let state_dir = camino::Utf8PathBuf::from_path_buf(directory).expect("UTF-8 path");
    let paths = RuntimePaths {
        socket: state_dir.join("daemon.sock"),
        lock: state_dir.join("daemon.lock"),
        token: state_dir.join("api-token"),
        log: state_dir.join("daemon.log"),
        state_dir,
    };
    let listener = UnixListener::bind(&paths.socket).expect("listener");
    let (sent, received) = oneshot::channel();
    let sent = Arc::new(Mutex::new(Some(sent)));
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
            let sent = Arc::clone(&sent);
            async move {
                let authorization = request
                    .headers()
                    .get(http::header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_owned();
                let sender = sent.lock().await.take();
                if let Some(sent) = sender {
                    let _ignored = sent.send((
                        request.method().clone(),
                        request.uri().to_string(),
                        authorization,
                    ));
                }
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(status)
                        .body(Full::new(Bytes::from_static(body)))
                        .expect("response"),
                )
            }
        });
        hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await
            .expect("serve connection");
    });
    (DaemonClient { paths, token: "test-token".to_owned() }, received)
}

async fn assert_request(
    request: oneshot::Receiver<(Method, String, String)>,
    method: Method,
    path: &str,
) {
    let (actual_method, actual_path, authorization) = request.await.expect("request");
    assert_eq!(actual_method, method);
    assert_eq!(actual_path, path);
    assert_eq!(authorization, "Bearer test-token");
}
