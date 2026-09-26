#!/usr/bin/env python3
"""
tg_ws_relay — WebSocket -> TCP relay for TG WS Proxy (Android).

Speaks the same protocol as the Cloudflare Worker from the desktop project
(docs/CfWorker.md): the client opens

    GET /apiws?dst=<Telegram DC IP>&dc=<n>[&key=<secret>]   (WebSocket upgrade)

and every binary frame is the raw, already MTProto-encrypted TCP stream to
<dst>:443. The relay never sees Telegram content.

The point of hosting it yourself: under mobile "whitelist" filtering only
servers on the operator's allowed list are reachable. Put this on such a
server (typically hosting inside the country) and add it to the app.

Only the Python 3.8+ standard library is used.

    python3 tg_ws_relay.py --port 8080 --key SECRET
    python3 tg_ws_relay.py --port 443 --cert fullchain.pem --keyfile privkey.pem --key SECRET
"""

import argparse
import asyncio
import base64
import hashlib
import hmac
import ipaddress
import logging
import os
import signal
import ssl
import struct
import sys
from urllib.parse import parse_qs, urlsplit

__version__ = "1.0.0"

WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# Telegram's announced address space (AS62041, AS59930, AS44907, AS211157).
# Anything else is refused so the relay cannot be used as an open proxy.
TELEGRAM_NETS = [ipaddress.ip_network(n) for n in (
    "91.105.192.0/23",
    "91.108.4.0/22",
    "91.108.8.0/22",
    "91.108.12.0/22",
    "91.108.16.0/22",
    "91.108.20.0/22",
    "91.108.56.0/22",
    "95.161.64.0/20",
    "149.154.160.0/20",
    "185.76.151.0/24",
)]

MAX_FRAME = 16 * 1024 * 1024
READ_CHUNK = 64 * 1024

log = logging.getLogger("tg-ws-relay")


class Config:
    path = "/apiws"
    key = ""
    allow_any_dst = False
    dst_port = 443
    connect_timeout = 10.0
    idle_timeout = 600.0
    max_conns = 1024


cfg = Config()
active = 0


def dst_allowed(dst: str) -> bool:
    try:
        ip = ipaddress.ip_address(dst)
    except ValueError:
        return False
    if cfg.allow_any_dst:
        return True
    return any(ip in n for n in TELEGRAM_NETS)


async def http_error(writer, code: int, text: str):
    body = text.encode()
    writer.write(
        f"HTTP/1.1 {code} {text}\r\n"
        f"Content-Type: text/plain\r\nContent-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n".encode() + body
    )
    try:
        await writer.drain()
    except Exception:
        pass
    writer.close()


def ws_frame(opcode: int, payload: bytes) -> bytes:
    n = len(payload)
    head = bytes([0x80 | opcode])
    if n < 126:
        head += bytes([n])
    elif n < 65536:
        head += bytes([126]) + struct.pack(">H", n)
    else:
        head += bytes([127]) + struct.pack(">Q", n)
    return head + payload


def unmask(data: bytes, mask: bytes) -> bytes:
    if not data:
        return data
    # XOR through big ints: fast enough without numpy.
    m = (mask * (len(data) // 4 + 1))[:len(data)]
    return (int.from_bytes(data, "big") ^ int.from_bytes(m, "big")).to_bytes(len(data), "big")


async def read_frame(reader):
    h = await reader.readexactly(2)
    fin = h[0] & 0x80
    opcode = h[0] & 0x0F
    masked = h[1] & 0x80
    n = h[1] & 0x7F
    if n == 126:
        n = struct.unpack(">H", await reader.readexactly(2))[0]
    elif n == 127:
        n = struct.unpack(">Q", await reader.readexactly(8))[0]
    if n > MAX_FRAME:
        raise ValueError("frame too large")
    mask = await reader.readexactly(4) if masked else None
    payload = await reader.readexactly(n)
    if mask:
        payload = unmask(payload, mask)
    return fin, opcode, payload


async def pump_ws_to_tcp(ws_reader, ws_writer, tcp_writer, stats):
    while True:
        _, opcode, payload = await asyncio.wait_for(read_frame(ws_reader), cfg.idle_timeout)
        if opcode in (0x0, 0x1, 0x2):
            if payload:
                tcp_writer.write(payload)
                stats[0] += len(payload)
                await tcp_writer.drain()
        elif opcode == 0x8:  # close: echo and stop
            ws_writer.write(ws_frame(0x8, payload[:2]))
            return
        elif opcode == 0x9:  # ping
            ws_writer.write(ws_frame(0xA, payload))
            await ws_writer.drain()


async def pump_tcp_to_ws(tcp_reader, ws_writer, stats):
    while True:
        data = await asyncio.wait_for(tcp_reader.read(READ_CHUNK), cfg.idle_timeout)
        if not data:
            ws_writer.write(ws_frame(0x8, struct.pack(">H", 1000)))
            return
        ws_writer.write(ws_frame(0x2, data))
        stats[1] += len(data)
        await ws_writer.drain()


async def handle(reader, writer):
    global active
    peer = writer.get_extra_info("peername")
    sock = writer.get_extra_info("socket")
    if sock is not None:
        try:
            import socket
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 15)
    except Exception:
        writer.close()
        return

    try:
        lines = head.decode("latin-1").split("\r\n")
        method, target, _ = lines[0].split(" ", 2)
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
    except ValueError:
        return await http_error(writer, 400, "Bad Request")

    url = urlsplit(target)
    if method != "GET":
        return await http_error(writer, 405, "Method Not Allowed")
    if url.path == "/healthz":
        return await http_error(writer, 200, "OK")
    if url.path != cfg.path:
        return await http_error(writer, 404, "Not Found")
    if headers.get("upgrade", "").lower() != "websocket" or "sec-websocket-key" not in headers:
        return await http_error(writer, 426, "Upgrade Required")

    q = parse_qs(url.query)
    if cfg.key and not hmac.compare_digest(q.get("key", [""])[0].encode(), cfg.key.encode()):
        return await http_error(writer, 403, "Forbidden")
    dst = q.get("dst", [""])[0]
    if not dst_allowed(dst):
        return await http_error(writer, 400, "Bad Destination")
    if active >= cfg.max_conns:
        return await http_error(writer, 503, "Busy")

    try:
        tcp_reader, tcp_writer = await asyncio.wait_for(
            asyncio.open_connection(dst, cfg.dst_port), cfg.connect_timeout)
    except Exception as exc:
        log.info("connect to %s failed: %r", dst, exc)
        return await http_error(writer, 502, "Bad Gateway")
    tsock = tcp_writer.get_extra_info("socket")
    if tsock is not None:
        try:
            import socket
            tsock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

    accept = base64.b64encode(hashlib.sha1(headers["sec-websocket-key"].encode() + WS_GUID).digest())
    resp = (b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
            b"Sec-WebSocket-Accept: " + accept + b"\r\n")
    if "binary" in headers.get("sec-websocket-protocol", ""):
        resp += b"Sec-WebSocket-Protocol: binary\r\n"
    writer.write(resp + b"\r\n")
    await writer.drain()

    active += 1
    stats = [0, 0]
    log.debug("open %s -> %s (dc=%s)", peer, dst, q.get("dc", ["?"])[0])
    tasks = [
        asyncio.ensure_future(pump_ws_to_tcp(reader, writer, tcp_writer, stats)),
        asyncio.ensure_future(pump_tcp_to_ws(tcp_reader, writer, stats)),
    ]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in tasks:
            t.cancel()
        for t in tasks:
            try:
                await t
            except BaseException:
                pass
        for w in (tcp_writer, writer):
            try:
                w.close()
            except Exception:
                pass
        active -= 1
        log.debug("close %s: up=%d down=%d", dst, stats[0], stats[1])


async def main_async(args):
    ctx = None
    if args.cert:
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(args.cert, args.keyfile)
    server = await asyncio.start_server(handle, args.host, args.port, ssl=ctx, backlog=512)
    scheme = "wss" if ctx else "ws"
    log.info("tg_ws_relay %s listening on %s://%s:%d%s%s", __version__, scheme, args.host,
             args.port, cfg.path, " (key required)" if cfg.key else " (NO KEY — anyone can use it)")
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError):
            pass
    async with server:
        await stop.wait()


def main():
    ap = argparse.ArgumentParser(description="WebSocket->TCP relay for TG WS Proxy")
    ap.add_argument("--host", default=os.environ.get("RELAY_HOST", "0.0.0.0"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("RELAY_PORT", "8080")))
    ap.add_argument("--path", default=os.environ.get("RELAY_PATH", "/apiws"))
    ap.add_argument("--key", default=os.environ.get("RELAY_KEY", ""),
                    help="shared secret; clients add ?key=... (strongly recommended)")
    ap.add_argument("--cert", default=os.environ.get("RELAY_CERT"), help="TLS certificate chain (PEM)")
    ap.add_argument("--keyfile", default=os.environ.get("RELAY_KEYFILE"), help="TLS private key (PEM)")
    ap.add_argument("--max-conns", type=int, default=1024)
    ap.add_argument("--allow-any-dst", action="store_true",
                    help="do not restrict destinations to Telegram networks (testing only)")
    ap.add_argument("--dst-port", type=int, default=443, help=argparse.SUPPRESS)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    cfg.path = args.path
    cfg.key = args.key
    cfg.allow_any_dst = args.allow_any_dst
    cfg.max_conns = args.max_conns
    cfg.dst_port = args.dst_port
    if args.cert and not args.keyfile:
        ap.error("--cert needs --keyfile")
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    sys.exit(main())
