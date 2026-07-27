use std::fs;

use utoipa::OpenApi as _;

use super::LocalApi;

#[test]
fn committed_openapi_is_current() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/local-api.openapi.json");
    let generated = serde_json::to_string_pretty(&LocalApi::openapi()).expect("serialize");
    if std::env::var_os("UPDATE_LOCAL_API_OPENAPI").is_some() {
        fs::write(&path, format!("{generated}\n")).expect("write OpenAPI");
    }
    let committed = fs::read_to_string(path).expect("committed OpenAPI");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&committed).expect("committed JSON"),
        serde_json::from_str::<serde_json::Value>(&generated).expect("generated JSON")
    );
}
