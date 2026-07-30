use std::fs;

use super::binaries_in;

#[test]
fn configured_binary_directory_requires_both_programs() {
    let directory = tempfile::tempdir().expect("tempdir");
    let suffix = std::env::consts::EXE_SUFFIX;
    let wormhole = directory.path().join(format!("wormhole{suffix}"));
    fs::write(&wormhole, []).expect("write wormhole");

    let error = binaries_in(directory.path()).expect_err("wormholed must be required");
    assert!(error.contains("wormholed"));

    let wormholed = directory.path().join(format!("wormholed{suffix}"));
    fs::write(&wormholed, []).expect("write wormholed");
    let binaries = binaries_in(directory.path()).expect("both binaries exist");
    assert_eq!(binaries.wormhole, wormhole);
    assert_eq!(binaries.wormholed, wormholed);
}
