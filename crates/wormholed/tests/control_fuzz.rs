use proptest::prelude::*;
use tokio::io::AsyncWriteExt as _;
use wormhole_proto::codec::ControlChannel;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]
    #[test]
    fn arbitrary_control_bytes_never_panic(input in proptest::collection::vec(any::<u8>(), 0..128 * 1024)) {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
        runtime.block_on(async move {
            let (mut writer, reader) = tokio::io::duplex(input.len().saturating_add(16).max(16));
            let task = tokio::spawn(async move {
                let _written = writer.write_all(&input).await;
            });
            let mut channel = ControlChannel::new(reader);
            let _result = tokio::time::timeout(std::time::Duration::from_secs(1), channel.recv()).await;
            task.await.expect("writer");
        });
    }
}
