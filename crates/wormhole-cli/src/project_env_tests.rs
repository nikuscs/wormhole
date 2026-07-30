use super::parse_domain;

#[test]
fn domain_parsing_is_scoped_and_quote_aware() {
    let contents = r#"
# unrelated
OTHER=value
export WORMHOLE_DOMAIN="preview.example.com"
WORMHOLE_DOMAIN=ignored.example.com
"#;
    assert_eq!(parse_domain(contents).as_deref(), Some("preview.example.com"));
    assert_eq!(parse_domain("OTHER=value"), None);
}
