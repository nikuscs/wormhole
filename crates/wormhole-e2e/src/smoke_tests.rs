#[test]
#[ignore = "e2e"]
fn binary_harness_builds_and_discovers_both_programs() {
    let binaries = super::harness::binaries().expect("binaries");
    super::harness::run_help(&binaries.wormhole).expect("wormhole help");
    super::harness::run_help(&binaries.wormholed).expect("wormholed help");
}
