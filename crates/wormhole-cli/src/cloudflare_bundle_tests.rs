use std::fs;

use super::{hex_digest, validate, verify_checksum};

#[test]
fn local_bundle_requires_manifest_config_and_worker_files() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = camino::Utf8PathBuf::from_path_buf(directory.path().to_path_buf()).expect("utf8");
    fs::create_dir(root.join("build")).expect("build");
    fs::write(
        root.join("manifest.json"),
        format!(
            r#"{{"schema":1,"wormhole_version":"{}","wrangler_version":"4.115.0"}}"#,
            env!("CARGO_PKG_VERSION")
        ),
    )
    .expect("manifest");
    fs::write(root.join("wrangler.jsonc"), "{}").expect("config");
    fs::write(root.join("build/index.js"), "export default {};").expect("js");
    fs::write(root.join("build/index_bg.wasm"), b"wasm").expect("wasm");

    let bundle = validate(root).expect("valid bundle");
    assert_eq!(bundle.manifest.schema, 1);
    assert_eq!(bundle.manifest.wrangler_version, "4.115.0");
}

#[test]
fn bundle_checksum_must_match() {
    let archive = b"worker bundle";
    let checksum = format!("{}  bundle.tar.gz\n", hex_digest(archive));
    verify_checksum(archive, checksum.as_bytes()).expect("matching checksum");
    assert!(
        verify_checksum(
            archive,
            b"0000000000000000000000000000000000000000000000000000000000000000"
        )
        .is_err()
    );
}
