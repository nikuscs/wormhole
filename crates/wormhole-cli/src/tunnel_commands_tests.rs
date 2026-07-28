use super::parse_target;

#[test]
fn zero_ports_have_a_useful_diagnostic() {
    for target in ["0", "localhost:0"] {
        let error = parse_target(target).expect_err("zero port rejected");
        assert!(error.to_string().contains("port must be non-zero"));
    }
}
