use super::{Direction, MuxError, MuxState, WsMessage};

#[test]
fn message_round_trip_and_limits() {
    let message = WsMessage { channel: 7, payload: b"hello".to_vec() };
    assert_eq!(WsMessage::decode(&message.encode().expect("encode")).expect("decode"), message);
    assert!(matches!(
        WsMessage { channel: 1, payload: vec![0; super::MAX_PAYLOAD + 1] }.encode(),
        Err(MuxError::PayloadTooLarge)
    ));
    let control = WsMessage { channel: 0, payload: vec![0; super::MAX_PAYLOAD + 1] };
    assert_eq!(
        WsMessage::decode(&control.encode().expect("control envelope")).expect("decode control"),
        control
    );
    assert!(matches!(
        WsMessage { channel: 0, payload: vec![0; super::MAX_CONTROL_PAYLOAD + 1] }.encode(),
        Err(MuxError::PayloadTooLarge)
    ));
}

#[test]
fn open_ack_fin_reset_sequence_is_enforced() {
    let mut mux = MuxState::default();
    mux.open(1).expect("open");
    assert!(mux.enqueue(1, b"early".to_vec()).is_err());
    mux.acknowledge(1).expect("ack");
    mux.enqueue(1, b"data".to_vec()).expect("enqueue");
    assert_eq!(mux.next_message().expect("message").payload, b"data");
    mux.finish(1, Direction::Send).expect("finish");
    assert!(mux.enqueue(1, b"late".to_vec()).is_err());
    mux.reset(1);
    assert!(mux.acknowledge(1).is_err());
}

#[test]
fn per_channel_message_queue_is_bounded() {
    let mut mux = MuxState::default();
    mux.open(1).expect("open");
    mux.acknowledge(1).expect("ack");
    for _ in 0..super::MAX_QUEUED_MESSAGES_PER_CHANNEL {
        mux.enqueue(1, vec![0]).expect("within queue limit");
    }
    assert_eq!(mux.enqueue(1, vec![0]), Err(MuxError::QueueFull));
    assert_eq!(mux.acknowledge(1), Err(MuxError::UnknownChannel));
}

#[test]
fn stalled_channel_does_not_starve_ready_channel() {
    let mut mux = MuxState::default();
    for channel in [1, 3] {
        mux.open(channel).expect("open");
        mux.acknowledge(channel).expect("ack");
    }
    for _ in 0..super::INITIAL_WINDOW as usize / super::MAX_PAYLOAD {
        mux.enqueue(1, vec![0; super::MAX_PAYLOAD]).expect("window payload");
        mux.next_message().expect("consume window");
    }
    mux.enqueue(1, b"stalled".to_vec()).expect("stalled queue");
    mux.enqueue(3, b"ready".to_vec()).expect("ready queue");
    assert_eq!(mux.next_message().expect("ready message").channel, 3);
    mux.close();
    assert!(mux.next_message().is_none());
}
