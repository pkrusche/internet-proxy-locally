#!/usr/bin/env python3
"""DNS rebinding fixture and connection trap for `ipl-lab check`."""

from __future__ import annotations

import ipaddress
import os
import signal
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import threading
import time

# Mounted fixture settings are required; defaults could silently invalidate probes.
FIXTURE_ENV = "/fixture/fixture.env"


def _fixture_env() -> dict[str, str]:
    """`KEY=value` lines from the mounted file; `#` and blanks ignored."""
    try:
        with open(FIXTURE_ENV) as handle:
            text = handle.read()
    except OSError as exc:
        raise SystemExit(
            f"cannot read {FIXTURE_ENV} ({exc}) — it is bind-mounted by "
            "`ipl-lab up`, which renders it from config.toml."
        ) from exc
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip()
    return values


ENV = _fixture_env()


def _required(name: str) -> str:
    value = ENV.get(name, "").strip()
    if not value:
        raise SystemExit(
            f"{name} is missing from {FIXTURE_ENV}. "
            "Restart with `ipl-lab up` to regenerate fixture settings."
        )
    return value


REBIND_ZONE = _required("REBIND_ZONE")
# The public half of every first answer, and of the mixed-answer records.
PUBLIC_ANSWER = _required("PUBLIC_ANSWER")
# Public-numbered address assigned on the internal Docker lab network.
ORIGIN_ADDRESS = os.environ.get("IPL_ORIGIN_ADDRESS", "")

# A public IP claims an allowlisted PTR to isolate hostname-policy enforcement.
PTR_ADDRESS = _required("PTR_ADDRESS")
PTR_CLAIMS = _required("PTR_CLAIMS")
TRAP_PORT = 443
RESPONDER_PORT = 5353

DNSMASQ = [
    "/usr/sbin/dnsmasq",
    "--no-daemon",
    # This container's own /etc/hosts must not leak into answers; the
    # fixture records are the only local source.
    "--no-hosts",
    "--log-queries",
    "--addn-hosts=/tmp/fixture-hosts",
    # Delegate the rebinding zone to the responder below.
    f"--server=/{REBIND_ZONE}/127.0.0.1#{RESPONDER_PORT}",
    # A cache would defeat the whole fixture: the second lookup has to
    # reach the responder to be answered differently from the first.
    "--cache-size=0",
    # PTR_ADDRESS claims to be an allowlisted host. `1.0.0.1` reversed is
    # itself, which is why this literal looks odd but is correct.
    f"--ptr-record={'.'.join(reversed(PTR_ADDRESS.split('.')))}.in-addr.arpa,{PTR_CLAIMS}",
]


def log(message: str) -> None:
    print(f"IPL-FIXTURE {message}", flush=True)


def own_address() -> str:
    """This container's address on the backend network — the trap address,
    and the private half of every rebound answer.

    Uses a connected UDP socket purely to pick the outbound interface; no
    packet is sent, so this works with no network at all. The address is
    TEST-NET-1 (RFC 5737), which is never routed anywhere — it only has to
    be off-link for the kernel to choose the default route. Deliberately
    not the fixture's own public answer: nothing here is talking to it,
    and a shared literal would read as though something were.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.0.2.1", 53))
        return sock.getsockname()[0]
    finally:
        sock.close()


TYPE_A = 1
TYPE_AAAA = 28


def parse_question(packet: bytes) -> tuple[str, int] | None:
    """Return (name, qtype) for a single-question query, or None."""
    if len(packet) < 12:
        return None
    qdcount = struct.unpack("!H", packet[4:6])[0]
    if qdcount != 1:
        return None
    labels: list[str] = []
    offset = 12
    while offset < len(packet):
        length = packet[offset]
        if length == 0:
            offset += 1
            break
        # Compression pointers never appear in a question section.
        if length & 0xC0:
            return None
        offset += 1
        labels.append(packet[offset : offset + length].decode("ascii", "replace"))
        offset += length
    if offset + 4 > len(packet):
        return None
    qtype = struct.unpack("!H", packet[offset : offset + 2])[0]
    return ".".join(labels).lower(), qtype


def build_response(query: bytes, address: str | None) -> bytes:
    """Answer `query` with one A record, or with an empty NOERROR answer
    when `address` is None.

    An empty answer matters: replying NXDOMAIN to the AAAA query that
    resolvers send alongside the A query would mark the whole name as
    nonexistent on some stacks.
    """
    ident = query[:2]
    question_end = 12
    while question_end < len(query) and query[question_end] != 0:
        question_end += 1 + query[question_end]
    question_end += 5  # terminating zero byte + qtype + qclass
    question = query[12:question_end]

    flags = 0x8180  # response, recursion desired + available, NOERROR
    answer_count = 0 if address is None else 1
    header = ident + struct.pack("!HHHHH", flags, 1, answer_count, 0, 0)
    if address is None:
        return header + question
    answer = (
        b"\xc0\x0c"  # pointer to the question's name
        + struct.pack("!HHIH", TYPE_A, 1, 0, 4)  # A, IN, TTL 0, 4 bytes
        + socket.inet_aton(address)
    )
    return header + question + answer


class Responder:
    """Answers the rebinding zone, one counter per name."""

    def __init__(self, trap_address: str):
        self.trap_address = trap_address
        self._seen: dict[str, int] = {}
        self._lock = threading.Lock()

    def answer_for(self, name: str) -> str:
        with self._lock:
            count = self._seen.get(name, 0) + 1
            self._seen[name] = count
        # First lookup looks legitimate; every later one rebinds.
        address = PUBLIC_ANSWER if count == 1 else self.trap_address
        log(f"dns name={name} query={count} answer={address}")
        return address

    def serve(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", RESPONDER_PORT))
        log(f"responder listening on 127.0.0.1:{RESPONDER_PORT} zone={REBIND_ZONE}")
        while True:
            try:
                packet, peer = sock.recvfrom(4096)
            except OSError:
                continue
            question = parse_question(packet)
            if question is None:
                continue
            name, qtype = question
            if qtype == TYPE_A and name.endswith(REBIND_ZONE):
                reply = build_response(packet, self.answer_for(name))
            else:
                # AAAA, or anything else in the zone: exists, no address.
                reply = build_response(packet, None)
            try:
                sock.sendto(reply, peer)
            except OSError:
                pass


def serve_trap(address: str, ready: threading.Event | None = None) -> None:
    """Accept and log connections that should never arrive."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((address, TRAP_PORT))
    sock.listen(16)
    log(f"trap listening on {address}:{TRAP_PORT}")
    if ready is not None:
        ready.set()
    while True:
        try:
            conn, peer = sock.accept()
        except OSError:
            continue
        log(f"trap connect from={peer[0]}:{peer[1]}")
        try:
            conn.close()
        except OSError:
            pass


def local_hosts(source: str, nominal: str, actual: str, trap: str) -> str:
    """Replace public/private roles with the local origin/trap, retaining order."""
    rows = []
    for line in source.splitlines():
        fields = line.split()
        if fields and not fields[0].startswith("#"):
            address = actual if fields[0] == nominal else trap
            if fields[0] != nominal and not ipaddress.ip_address(fields[0]).is_private:
                raise RuntimeError(
                    "fixture public records must all use the configured control"
                )
            line = " ".join([address, *fields[1:]])
        rows.append(line)
    return "\n".join(rows) + "\n"


class Origin(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: str, cert: str, key: str, port: int = 443):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, key)
        super().__init__((address, port), OriginHandler)


class OriginHandler(socketserver.BaseRequestHandler):
    server: Origin

    def handle(self) -> None:
        try:
            self.request.settimeout(5)
            with self.server.context.wrap_socket(self.request, server_side=True) as tls:
                data = b""
                while b"\r\n\r\n" not in data and len(data) < 16384:
                    chunk = tls.recv(4096)
                    if not chunk:
                        return
                    data += chunk
                if b"\r\n\r\n" not in data:
                    return
                headers = data.decode("latin-1").split("\r\n")
                host = next(
                    (
                        line.split(":", 1)[1].strip()
                        for line in headers
                        if line.lower().startswith("host:")
                    ),
                    "unknown",
                )
                log(f"origin request host={host} from={self.client_address[0]}")
                body = b"IPL fixture origin\n"
                tls.sendall(
                    f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                    + body
                )
        except (OSError, ssl.SSLError):
            return


def main() -> int:
    global PUBLIC_ANSWER
    trap_address = own_address()
    actual = ORIGIN_ADDRESS
    if not actual or not ipaddress.ip_address(actual).is_global:
        raise RuntimeError(
            "IPL_ORIGIN_ADDRESS must be the lab's public-numbered IPv4 address"
        )
    if not ipaddress.ip_address(trap_address).is_private or trap_address == actual:
        raise RuntimeError(
            "fixture requires separate private trap and public origin interfaces"
        )
    with open("/fixture/hosts") as source:
        hosts = local_hosts(source.read(), PUBLIC_ANSWER, actual, trap_address)
    with open("/tmp/fixture-hosts", "w") as target:
        target.write(hosts)
    PUBLIC_ANSWER = actual
    origin = Origin(actual, "/fixture/origin.pem", "/fixture/origin-key.pem")
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    log(f"starting address={trap_address} public={PUBLIC_ANSWER}")
    log(f"origin listening on {actual}:443")

    responder = Responder(trap_address)
    threading.Thread(target=responder.serve, daemon=True).start()
    trap_ready = threading.Event()
    threading.Thread(
        target=serve_trap, args=(trap_address, trap_ready), daemon=True
    ).start()
    if not trap_ready.wait(5):
        raise RuntimeError("private trap failed to listen")

    dnsmasq = subprocess.Popen(DNSMASQ)
    # Probe a static control through dnsmasq itself before advertising readiness.
    control = next(
        line.split()[1] for line in hosts.splitlines() if line.startswith(actual + " ")
    )
    question = (
        b"".join(bytes([len(label)]) + label.encode() for label in control.split("."))
        + b"\0"
    )
    packet = (
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        + question
        + struct.pack("!HH", TYPE_A, 1)
    )
    deadline = time.monotonic() + 5
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.settimeout(0.2)
        while time.monotonic() < deadline and dnsmasq.poll() is None:
            probe.sendto(packet, ("127.0.0.1", 53))
            try:
                response, _ = probe.recvfrom(4096)
                if response[:2] == packet[:2] and socket.inet_aton(actual) in response:
                    log("ready")
                    break
            except OSError:
                pass
        else:
            dnsmasq.terminate()
            dnsmasq.wait(timeout=5)
            raise RuntimeError("fixture DNS control did not become ready")

    def forward(signum, _frame):
        dnsmasq.send_signal(signum)

    signal.signal(signal.SIGTERM, forward)
    signal.signal(signal.SIGINT, forward)

    # dnsmasq is the fixture's reason to exist; if it dies, so does the
    # container, rather than leaving a half-working resolver behind.
    code = dnsmasq.wait()
    log(f"dnsmasq exited status={code}")
    return code


if __name__ == "__main__":
    sys.exit(main())
