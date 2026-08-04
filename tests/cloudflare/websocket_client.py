#!/usr/bin/env python3
"""Minimal dependency-free WSS echo probe for the live Cloudflare semantics gate."""

from __future__ import annotations

import base64
import hashlib
import os
import socket
import ssl
import struct
import sys
from urllib.parse import urlsplit

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def frame(opcode: int, payload: bytes) -> bytes:
    mask = os.urandom(4)
    header = bytearray([0x80 | opcode])
    if len(payload) <= 125:
        header.append(0x80 | len(payload))
    elif len(payload) <= 65_535:
        header.append(0x80 | 126)
        header.extend(struct.pack("!H", len(payload)))
    else:
        header.append(0x80 | 127)
        header.extend(struct.pack("!Q", len(payload)))
    header.extend(mask)
    header.extend(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    return bytes(header)


def read_exact(stream: ssl.SSLSocket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        chunk = stream.recv(length - len(chunks))
        if not chunk:
            raise RuntimeError("WebSocket closed before frame completed")
        chunks.extend(chunk)
    return bytes(chunks)


def read_frame(stream: ssl.SSLSocket) -> tuple[int, bytes]:
    header = read_exact(stream, 2)
    opcode = header[0] & 0x0F
    length = header[1] & 0x7F
    if length == 126:
        length = struct.unpack("!H", read_exact(stream, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", read_exact(stream, 8))[0]
    if header[1] & 0x80:
        raise RuntimeError("server WebSocket frame must not be masked")
    return opcode, read_exact(stream, length)


def main() -> None:
    parsed = urlsplit(sys.argv[1])
    if parsed.scheme != "wss" or parsed.hostname is None:
        raise RuntimeError("expected a wss:// URL")
    port = parsed.port or 443
    path = parsed.path or "/"
    key = base64.b64encode(os.urandom(16)).decode()
    expected = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
    raw = socket.create_connection((parsed.hostname, port), timeout=20)
    with ssl.create_default_context().wrap_socket(raw, server_hostname=parsed.hostname) as stream:
        stream.settimeout(20)
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {parsed.hostname}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Origin: https://{parsed.hostname}\r\n\r\n"
        )
        stream.sendall(request.encode())
        response = bytearray()
        while b"\r\n\r\n" not in response:
            response.extend(read_exact(stream, 1))
        head = response.decode("latin-1")
        if not head.startswith("HTTP/1.1 101") or f"sec-websocket-accept: {expected}".lower() not in head.lower():
            raise RuntimeError(f"WebSocket handshake failed: {head.splitlines()[0]}")
        payload = b"wormhole websocket"
        stream.sendall(frame(1, payload))
        opcode, echoed = read_frame(stream)
        if opcode != 1 or echoed != payload:
            raise RuntimeError("WebSocket echo mismatch")
        stream.sendall(frame(8, struct.pack("!H", 1000)))
        opcode, _close = read_frame(stream)
        if opcode != 8:
            raise RuntimeError("WebSocket close response missing")
    print("WebSocket semantics passed")


if __name__ == "__main__":
    main()
