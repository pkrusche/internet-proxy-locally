#!/usr/bin/env python3
"""DNS rebinding fixture and connection trap for `ipl-lab check`.

Runs as PID 1 in the DNS-fixture container and does three things:

1. supervises dnsmasq, which serves the static mixed-answer records and
   forwards everything else upstream (data/images/dnsfixture/Dockerfile);
2. answers the `rebind.fixture.test` zone, which dnsmasq delegates here.
   The *first* A query for a given name is answered with a public address;
   every later query for that same name is answered with this container's
   own — private — address, with TTL 0 so nothing may cache it. That is a
   DNS rebind: an engine that validates the first answer and then resolves
   again before connecting ends up pointed at a private address;
3. listens on TCP 443 as a trap. Nothing should ever connect: the only way
   to arrive is to have followed the rebound answer. Every connection is
   logged, which is what makes `dns-rebinding` gradable — "did the engine
   reach a private address" stops being an inference and becomes an
   observation.

Both the answers and the trap hits are logged as single `IPL-FIXTURE`
lines, which checks/egress.py parses out of the container's log stream.

Stdlib only; the parsing here is deliberately minimal because dnsmasq
fronts it — this responder only ever sees queries for one zone, already
normalized, and never has to speak to a real client.
"""

from __future__ import annotations

import signal
import socket
import struct
import subprocess
import sys
import threading

# Every fact about what this fixture serves comes from lab/fixtures.toml,
# rendered into lab/config/fixture.env and bind-mounted read-only at the
# path below (lab/render.py `_render_fixture_env()`). It used to be a third
# copy of those values, with a "keep in sync" comment and nothing enforcing
# it — and this copy is the one nothing could check, because it only
# existed inside the image.
#
# Mounted rather than baked in as build args: an image is built once and
# `[fixture]` is edited more often than that, so values compiled into it go
# stale silently. Read at start, they cannot.
#
# There is no fallback on purpose: a fixture serving something other than
# what the checker probes for produces denials that look like enforcement
# and are really NXDOMAIN, so a missing value has to stop the container
# rather than quietly change what is measured.
FIXTURE_ENV = "/fixture/fixture.env"


def _fixture_env() -> dict[str, str]:
    """`KEY=value` lines from the mounted file; `#` and blanks ignored."""
    try:
        with open(FIXTURE_ENV) as handle:
            text = handle.read()
    except OSError as exc:
        raise SystemExit(
            f"cannot read {FIXTURE_ENV} ({exc}) — it is bind-mounted by "
            "`ipl-lab up`, which renders it from lab/fixtures.toml."
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
            "Regenerate it with `ipl-lab policy`."
        )
    return value


REBIND_ZONE = _required("REBIND_ZONE")
# The public half of every first answer, and of the mixed-answer records.
PUBLIC_ANSWER = _required("PUBLIC_ANSWER")

# Reverse-DNS claim for the `ptr-allowlist` check: this address asserts a
# PTR of an allowlisted hostname. An engine that resolves a bare-IP
# destination backwards and matches the answer against its hostname
# allowlist will let it through — which is exactly what Squid used to do
# (docs/findings.md). The address is public, so the SSRF floors do not fire
# and the allowlist is genuinely the rule under test; it is deliberately
# none of the addresses any other check connects to.
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
    "--addn-hosts=/fixture/hosts",
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


# ---------------------------------------------------------------------------
# Minimal DNS
# ---------------------------------------------------------------------------

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


def serve_trap(address: str) -> None:
    """Accept and log connections that should never arrive."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", TRAP_PORT))
    sock.listen(16)
    log(f"trap listening on {address}:{TRAP_PORT}")
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


def main() -> int:
    trap_address = own_address()
    log(f"starting address={trap_address} public={PUBLIC_ANSWER}")

    responder = Responder(trap_address)
    threading.Thread(target=responder.serve, daemon=True).start()
    threading.Thread(target=serve_trap, args=(trap_address,), daemon=True).start()

    dnsmasq = subprocess.Popen(DNSMASQ)

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
