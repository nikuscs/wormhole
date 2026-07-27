use uuid::Uuid;

use super::{should_forget_bind, should_forget_cancelled};

#[test]
fn cancelled_reclaim_preserves_existing_reservation() {
    assert!(should_forget_cancelled(None));
    assert!(!should_forget_cancelled(Some(Uuid::now_v7())));
    assert!(should_forget_bind(false, true));
    assert!(should_forget_bind(true, false));
    assert!(!should_forget_bind(false, false));
}
