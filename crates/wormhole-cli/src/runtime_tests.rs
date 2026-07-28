use super::current_uid;

#[test]
fn runtime_owner_uses_effective_uid() {
    assert_eq!(current_uid(), nix::unistd::geteuid().as_raw());
}
