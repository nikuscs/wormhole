use std::cell::RefCell;

use futures::channel::mpsc;

use super::{MAX_STREAMS, PendingHttp, Runtime, allocate_channel};

fn pending() -> PendingHttp {
    let (body, _body_rx) = mpsc::channel(1);
    let (credit, _credit_rx) = mpsc::unbounded();
    PendingHttp {
        head: None,
        body,
        buffer: Vec::new(),
        head_received: false,
        credit,
        upgrade: false,
    }
}

#[test]
fn saturated_session_rejects_one_request_without_invalidating_other_connections() {
    let runtime = RefCell::new(Runtime::default());
    for index in 0..MAX_STREAMS {
        let channel = allocate_channel(&runtime, "busy").expect("allocation").expect("stream slot");
        runtime.borrow_mut().pending.insert(("busy".to_owned(), channel), pending());
        assert_eq!(channel, 2 + index * 2);
    }

    assert_eq!(allocate_channel(&runtime, "busy").expect("saturation result"), None);
    assert_eq!(allocate_channel(&runtime, "other").expect("other connection"), Some(2));
    assert_eq!(runtime.borrow().pending.len(), MAX_STREAMS as usize);
}
