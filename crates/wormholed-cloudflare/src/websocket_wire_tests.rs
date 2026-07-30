use super::{Action, Decoder, binary, close, text};

fn server_frame(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![(if fin { 0x80 } else { 0 }) | opcode];
    match payload.len() {
        0..=125 => frame.push(payload.len() as u8),
        126..=65_535 => {
            frame.push(126);
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        _ => {
            frame.push(127);
            frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
    }
    frame.extend_from_slice(payload);
    frame
}

fn unmask(frame: &[u8]) -> (u8, Vec<u8>) {
    let opcode = frame[0] & 0x0f;
    let short = frame[1] & 0x7f;
    let (length, mask_at) = match short {
        0..=125 => (short as usize, 2),
        126 => (u16::from_be_bytes([frame[2], frame[3]]) as usize, 4),
        _ => (u64::from_be_bytes(frame[2..10].try_into().expect("length")) as usize, 10),
    };
    assert_ne!(frame[1] & 0x80, 0);
    let mask: [u8; 4] = frame[mask_at..mask_at + 4].try_into().expect("mask");
    let payload = frame[mask_at + 4..mask_at + 4 + length]
        .iter()
        .enumerate()
        .map(|(index, byte)| byte ^ mask[index % 4])
        .collect();
    (opcode, payload)
}

#[test]
fn client_frames_are_masked_and_preserve_message_types() {
    assert_eq!(unmask(&text("hello").expect("text")), (1, b"hello".to_vec()));
    assert_eq!(unmask(&binary(&[0, 1, 2]).expect("binary")), (2, vec![0, 1, 2]));
    assert_eq!(
        unmask(&close(1000, "done").expect("close")),
        (8, [1000_u16.to_be_bytes().as_slice(), b"done"].concat())
    );
}

#[test]
fn decoder_handles_partial_fragmented_and_control_frames() {
    let mut decoder = Decoder::default();
    let first = server_frame(false, 1, b"hel");
    assert!(decoder.push(&first[..1]).expect("partial").is_empty());
    assert!(decoder.push(&first[1..]).expect("first fragment").is_empty());
    let mut rest = server_frame(true, 0, b"lo");
    rest.extend(server_frame(true, 9, b"ping"));
    rest.extend(server_frame(true, 8, &[3, 232, b'o', b'k']));
    assert_eq!(
        decoder.push(&rest).expect("remaining frames"),
        [
            Action::Text("hello".to_owned()),
            Action::Pong(b"ping".to_vec()),
            Action::Close { code: Some(1000), reason: "ok".to_owned() },
        ]
    );
}

#[test]
fn decoder_rejects_masked_server_and_extension_frames() {
    let mut decoder = Decoder::default();
    assert!(decoder.push(&[0x81, 0x80, 0, 0, 0, 0]).is_err());
    let mut decoder = Decoder::default();
    assert!(decoder.push(&[0xc1, 0]).is_err());
}
