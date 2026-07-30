use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
};

use super::SemanticsServer;

#[test]
fn large_response_survives_chunked_empty_request_body() {
    let server = SemanticsServer::start().expect("server");
    let mut stream = TcpStream::connect(("127.0.0.1", server.port())).expect("connect");
    stream
        .write_all(
            b"GET /large HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n",
        )
        .expect("request");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).expect("response");
    let split =
        response.windows(4).position(|window| window == b"\r\n\r\n").expect("response head");

    assert_eq!(response.len() - split - 4, 2 * 1024 * 1024);
}
