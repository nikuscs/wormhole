#[test]
fn signed_url_contains_expiry_and_requested_path() {
    let key = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [7_u8; 32]);
    let url = super::mint_share_url("https://demo.example.com", "/landing", &key, 2_000_000_000)
        .expect("share URL");
    assert!(url.starts_with("https://demo.example.com/landing?wh_token="));
}
