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
