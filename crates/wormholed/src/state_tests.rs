use std::sync::atomic::{AtomicU32, Ordering};

use super::{decrement, try_increment};

#[test]
fn atomic_limit_never_exceeds_maximum() {
    let counter = AtomicU32::new(0);

    assert!(try_increment(&counter, 2));
    assert!(try_increment(&counter, 2));
    assert!(!try_increment(&counter, 2));
    assert_eq!(counter.load(Ordering::Acquire), 2);
}

#[test]
fn decrement_saturates_at_zero() {
    let counter = AtomicU32::new(1);

    decrement(&counter);
    decrement(&counter);

    assert_eq!(counter.load(Ordering::Acquire), 0);
}
