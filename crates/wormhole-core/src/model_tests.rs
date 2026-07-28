use super::{CapturedRequest, EndpointSpec, RetryPolicy};

#[test]
fn byte_fields_round_trip_as_canonical_base64() {
    let capture = CapturedRequest {
        id: uuid::Uuid::nil(),
        endpoint_id: None,
        bind_id: uuid::Uuid::max(),
        method: "POST".to_owned(),
        uri: "/".to_owned(),
        headers: Vec::new(),
        body: vec![0, 255],
        body_truncated: false,
        response_status: Some(200),
        response_headers: Vec::new(),
        response_body_prefix: vec![1, 2, 3],
        response_body_truncated: false,
        duration_ms: 1,
        delivery: "live".to_owned(),
        captured_at: jiff::Timestamp::now(),
    };
    let json = serde_json::to_string(&capture).expect("serialize");
    assert!(json.contains("AP8="));
    let decoded: CapturedRequest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded, capture);
}

#[test]
fn retry_and_endpoint_defaults_are_applied_during_deserialization() {
    let retry: RetryPolicy =
        serde_json::from_str(r#"{"max_attempts":2,"initial_delay_ms":5}"#).expect("retry");
    assert_eq!(retry.max_delay_ms, 30_000);
    assert!(retry.retry_connect);
    assert_eq!(retry.max_body_bytes, 1024 * 1024);
    assert_eq!(retry.total_deadline_ms, 60_000);

    let endpoint: EndpointSpec = serde_json::from_str(
        r#"{"proto":"http","driver":"mock","persist":"temporary","inspect":false}"#,
    )
    .expect("endpoint");
    assert_eq!(endpoint.capture_body_max, 1024 * 1024);
}
