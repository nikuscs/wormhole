use uuid::Uuid;

use super::should_forget_cancelled;

#[test]
fn cancelled_reclaim_preserves_existing_reservation() {
    assert!(should_forget_cancelled(None));
    assert!(!should_forget_cancelled(Some(Uuid::now_v7())));
}
