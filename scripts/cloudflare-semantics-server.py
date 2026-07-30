#!/usr/bin/env python3
"""Local origin used by the live Cloudflare Worker semantics gate."""

from __future__ import annotations

import base64
import gzip
import hashlib
import struct
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LARGE_BODY = b"x" * (2 * 1024 * 1024)


class SemanticsServer(ThreadingHTTPServer):
    request_queue_size = 128


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_HEAD(self) -> None:  # noqa: N802
        if self.path == "/head":
            self._headers(200, 7, "text/plain")
            return
        self._headers(404, 0)

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/upload":
            self._headers(404, 0)
            return
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length)
        response = str(len(body)).encode()
        self._headers(200, len(response), "text/plain")
        self.wfile.write(response)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/websocket" and self.headers.get("upgrade", "").lower() == "websocket":
            self._websocket()
        elif self.path == "/":
            self._body(b"<!doctype html><title>Wormhole semantics</title>", "text/html")
        elif self.path == "/gzip":
            body = gzip.compress(b"compressed hello")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/sse":
            body = b"data: first\n\ndata: second\n\n"
            self._headers(200, len(body), "text/event-stream")
            self.wfile.write(body[:13])
            self.wfile.flush()
            time.sleep(0.05)
            self.wfile.write(body[13:])
        elif self.path == "/range":
            body = b"2345"
            self.send_response(206)
            self.send_header("Content-Range", "bytes 2-5/10")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/cookies":
            body = b"cookies"
            self.send_response(200)
            self.send_header("Set-Cookie", "first=1; Path=/")
            self.send_header("Set-Cookie", "second=2; Path=/")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/large":
            self._headers(200, len(LARGE_BODY), "application/octet-stream")
            self.wfile.write(LARGE_BODY)
        elif self.path.startswith("/slow/"):
            time.sleep(0.25)
            self._body(self.path.removeprefix("/slow/").encode(), "text/plain")
        elif self.path == "/disconnect":
            self._headers(200, 100, "application/octet-stream")
            self.wfile.write(b"short")
            self.wfile.flush()
            self.close_connection = True
        elif self.path in {"/status/204", "/status/205", "/status/304"}:
            status = int(self.path.rsplit("/", 1)[1])
            self._headers(status, 0)
        else:
            self._headers(404, 0)

    def _websocket(self) -> None:
        key = self.headers.get("sec-websocket-key")
        if key is None:
            self._headers(400, 0)
            return
        accept = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        ).decode()
        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        while True:
            frame = self._read_websocket_frame()
            if frame is None:
                return
            opcode, payload = frame
            if opcode == 8:
                self._write_websocket_frame(8, payload)
                return
            self._write_websocket_frame(10 if opcode == 9 else opcode, payload)

    def _read_websocket_frame(self) -> tuple[int, bytes] | None:
        header = self.rfile.read(2)
        if len(header) != 2:
            return None
        opcode = header[0] & 0x0F
        length = header[1] & 0x7F
        if length == 126:
            length = struct.unpack("!H", self.rfile.read(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self.rfile.read(8))[0]
        mask = self.rfile.read(4) if header[1] & 0x80 else b""
        payload = self.rfile.read(length)
        if mask:
            payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        return opcode, payload

    def _write_websocket_frame(self, opcode: int, payload: bytes) -> None:
        self.wfile.write(bytes([0x80 | opcode]))
        if len(payload) <= 125:
            self.wfile.write(bytes([len(payload)]))
        elif len(payload) <= 65_535:
            self.wfile.write(bytes([126]) + struct.pack("!H", len(payload)))
        else:
            self.wfile.write(bytes([127]) + struct.pack("!Q", len(payload)))
        self.wfile.write(payload)
        self.wfile.flush()

    def _body(self, body: bytes, content_type: str) -> None:
        self._headers(200, len(body), content_type)
        self.wfile.write(body)

    def _headers(self, status: int, length: int, content_type: str | None = None) -> None:
        self.send_response(status)
        if content_type is not None:
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.end_headers()

    def log_message(self, _format: str, *_args: object) -> None:
        return


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    server = SemanticsServer(("127.0.0.1", port), Handler)
    print(server.server_port, flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
