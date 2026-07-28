use std::sync::atomic::{AtomicU32, Ordering};

use super::{BufferMemoryReservation, decrement, try_increment};

#[test]
fn atomic_limit_never_exceeds_maximum() {
    let counter = AtomicU32::new(0);

    assert!(try_increment(&counter, 2));
    assert!(try_increment(&counter, 2));
    assert!(!try_increment(&counter, 2));
    assert_eq!(counter.load(Ordering::Acquire), 2);
}

#[test]
fn aggregate_buffer_memory_is_bounded_and_released() {
    let counter = std::sync::atomic::AtomicU64::new(0);
    let mut first = BufferMemoryReservation { counter: &counter, reserved: 0 };
    let mut second = BufferMemoryReservation { counter: &counter, reserved: 0 };

    assert!(first.reserve(6, 10));
    assert!(!second.reserve(5, 10));
    assert!(second.reserve(4, 10));
    drop(first);
    assert_eq!(counter.load(Ordering::Acquire), 4);
    drop(second);
    assert_eq!(counter.load(Ordering::Acquire), 0);
}

#[test]
fn decrement_saturates_at_zero() {
    let counter = AtomicU32::new(1);

    decrement(&counter);
    decrement(&counter);

    assert_eq!(counter.load(Ordering::Acquire), 0);
}
