use flate2::{Compression, write::GzEncoder};
use std::{
    io::{Read as _, Write as _},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

pub struct SemanticsServer {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    deliveries: Arc<AtomicUsize>,
    task: Option<thread::JoinHandle<()>>,
}

impl SemanticsServer {
    pub fn start() -> std::io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let deliveries = Arc::new(AtomicUsize::new(0));
        let worker_deliveries = Arc::clone(&deliveries);
        let task = thread::spawn(move || {
            while !worker_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if stream.set_nonblocking(false).is_err() {
                            continue;
                        }
                        let deliveries = Arc::clone(&worker_deliveries);
                        thread::spawn(move || serve(stream, &deliveries));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => return,
                }
            }
        });
        Ok(Self { address, stop, deliveries, task: Some(task) })
    }

    pub const fn port(&self) -> u16 {
        self.address.port()
    }

    pub fn deliveries(&self) -> usize {
        self.deliveries.load(Ordering::Acquire)
    }
}

impl Drop for SemanticsServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _wake = TcpStream::connect(self.address);
        if let Some(task) = self.task.take() {
            let _joined = task.join();
        }
    }
}

fn serve(mut stream: TcpStream, deliveries: &AtomicUsize) {
    let Ok(request) = read_head(&mut stream) else {
        return;
    };
    let Ok(request_body) = read_request_body(&mut stream, &request) else {
        return;
    };
    let request_line = request.lines().next().unwrap_or("GET / HTTP/1.1");
    let method = request_line.split_whitespace().next().unwrap_or("GET");
    let path = request_line.split_whitespace().nth(1).unwrap_or("/");
    match path {
        "/cookies" => {
            let _written = stream.write_all(
                b"HTTP/1.1 200 OK\r\nSet-Cookie: first=1\r\nSet-Cookie: second=2\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
            );
        }
        "/gzip" => serve_gzip(&mut stream),
        "/head" => serve_head(&mut stream, method),
        "/sse" => serve_sse(&mut stream),
        "/range" => serve_range(&mut stream),
        "/large" => serve_large(&mut stream),
        "/upload" => serve_upload(&mut stream, request_body.len()),
        "/disconnect" => {
            let _written = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nshort",
            );
        }
        "/status/204" => write_empty_status(&mut stream, 204, "No Content"),
        "/status/205" => write_empty_status(&mut stream, 205, "Reset Content"),
        "/status/304" => write_empty_status(&mut stream, 304, "Not Modified"),
        "/headers" => serve_headers(&mut stream, &request),
        "/webhook" => {
            let delivery = deliveries.fetch_add(1, Ordering::AcqRel);
            if delivery > 0 {
                let _written = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
            }
        }
        "/slow" => {
            thread::sleep(Duration::from_secs(2));
            let _written = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nslow",
            );
        }
        "/upgrade" => serve_upgrade(&mut stream, &request),
        _ => {
            let _written = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    }
}

fn serve_gzip(stream: &mut TcpStream) {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    let _written = encoder.write_all(b"compressed hello");
    let body = encoder.finish().unwrap_or_default();
    let _written = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _written = stream.write_all(&body);
}

fn serve_head(stream: &mut TcpStream, method: &str) {
    let _written = stream.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 7\r\nConnection: close\r\n\r\n",
    );
    if method != "HEAD" {
        let _written = stream.write_all(b"content");
    }
}

fn serve_sse(stream: &mut TcpStream) {
    let _written = stream.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\nD\r\ndata: first\n\n\r\n",
    );
    let _flushed = stream.flush();
    thread::sleep(Duration::from_millis(25));
    let _written = stream.write_all(b"E\r\ndata: second\n\n\r\n0\r\n\r\n");
}

fn serve_range(stream: &mut TcpStream) {
    let _written = stream.write_all(
        b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 2-5/10\r\nContent-Length: 4\r\nConnection: close\r\n\r\n2345",
    );
}

fn serve_large(stream: &mut TcpStream) {
    const LENGTH: usize = 2 * 1024 * 1024;
    let _written = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {LENGTH}\r\nConnection: close\r\n\r\n"
    );
    let chunk = vec![b'x'; 16 * 1024];
    for _ in 0..LENGTH / chunk.len() {
        if stream.write_all(&chunk).is_err() {
            break;
        }
    }
}

fn serve_upload(stream: &mut TcpStream, length: usize) {
    let response = length.to_string();
    let _written = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
        response.len()
    );
}

fn serve_headers(stream: &mut TcpStream, request: &str) {
    let body = request
        .lines()
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            lower.starts_with("x-forwarded-") || lower.starts_with("x-client:")
        })
        .collect::<Vec<_>>()
        .join("\n");
    let _written = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
}

fn serve_upgrade(stream: &mut TcpStream, request: &str) {
    let key = request
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("sec-websocket-key"))
        .map_or("", |(_, value)| value.trim());
    let accept = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
    let _written = write!(
        stream,
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {accept}\r\n\r\n",
    );
    echo_websocket_frame(stream);
}

fn read_request_body(stream: &mut TcpStream, request: &str) -> std::io::Result<Vec<u8>> {
    if let Some(length) = content_length(request) {
        let mut body = vec![0_u8; length];
        stream.read_exact(&mut body)?;
        return Ok(body);
    }
    let chunked = request.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
        })
    });
    if !chunked {
        return Ok(Vec::new());
    }
    read_chunked_body(stream)
}

fn read_chunked_body(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let line = read_crlf_line(stream)?;
        let length = usize::from_str_radix(line.split(';').next().unwrap_or("0"), 16)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        if length == 0 {
            while !read_crlf_line(stream)?.is_empty() {}
            return Ok(body);
        }
        let start = body.len();
        body.resize(start + length, 0);
        stream.read_exact(&mut body[start..])?;
        let mut crlf = [0_u8; 2];
        stream.read_exact(&mut crlf)?;
        if crlf != *b"\r\n" {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "chunk terminator"));
        }
    }
}

fn read_crlf_line(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut line = Vec::new();
    while !line.ends_with(b"\r\n") {
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte)?;
        line.push(byte[0]);
        if line.len() > 1024 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "chunk line"));
        }
    }
    line.truncate(line.len() - 2);
    String::from_utf8(line)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

fn content_length(request: &str) -> Option<usize> {
    request.lines().filter_map(|line| line.split_once(':')).find_map(|(name, value)| {
        name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse().ok()).flatten()
    })
}

fn write_empty_status(stream: &mut TcpStream, status: u16, reason: &str) {
    let _written = write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
}

fn echo_websocket_frame(stream: &mut TcpStream) {
    let mut head = [0_u8; 2];
    if stream.read_exact(&mut head).is_err() || head[1] & 0x80 == 0 {
        return;
    }
    let length = usize::from(head[1] & 0x7f);
    if length > 125 {
        return;
    }
    let mut mask = [0_u8; 4];
    let mut payload = vec![0_u8; length];
    if stream.read_exact(&mut mask).is_err() || stream.read_exact(&mut payload).is_err() {
        return;
    }
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % mask.len()];
    }
    let _written = stream.write_all(&[head[0], length as u8]);
    let _written = stream.write_all(&payload);
    let _flushed = stream.flush();
    thread::sleep(Duration::from_millis(100));
}

fn read_head(stream: &mut TcpStream) -> std::io::Result<String> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") && request.len() < 64 * 1024 {
        let mut byte = [0_u8; 1];
        if stream.read(&mut byte)? == 0 {
            break;
        }
        request.push(byte[0]);
    }
    String::from_utf8(request)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

#[cfg(test)]
#[path = "semantics_server_tests.rs"]
mod tests;
