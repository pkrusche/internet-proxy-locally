# The local DNS fixture for `ipl-lab check`: dnsmasq plus a small stdlib
# responder. Built by `ipl-lab setup`, started only by `ipl-lab up`, never
# part of normal operation.
#
# It serves two fixtures that public DNS cannot provide:
#
#   * mixed answers — one name resolving to a public *and* a private
#     address, from lab/config/dns-fixture.hosts via dnsmasq's `--addn-hosts`.
#     A hosts file mounted at /etc/hosts cannot do this: duplicate names
#     collapse to one address (musl keeps the first, Squid's parser the
#     last), and `--host-record=name,v4,v4` keeps only one because the
#     second slot is for IPv6.
#   * rebinding — the `rebind.fixture.test` zone, which dnsmasq delegates
#     to rebind.py. dnsmasq has no way to vary an answer per query, and
#     this also needs a connection trap, so that part is ours.
#
# dnsmasq still fronts everything: it speaks the client protocol (UDP,
# TCP, EDNS) and forwards non-fixture names upstream, so the engine under
# test can still reach pypi.org and the nip.io/sslip.io fixtures. rebind.py
# only ever answers one delegated zone over UDP from localhost, which is
# why its DNS handling can be as small as it is.
#
# Every pin this image depends on is a literal in this file — the base
# image and both apk versions — and the unit suite asserts they stay pinned
# and stay in step with `DNSFIXTURE_IMAGE` in images.py, whose tag is the
# dnsmasq version with an optional -buildN suffix for build-context changes.
#
# Upgrading: edit the versions below, bump `DNSFIXTURE_IMAGE` to match,
# commit, then `ipl-lab setup`.

FROM alpine:3.22.1

RUN apk add --no-cache "dnsmasq=2.91-r1" "python3=3.12.14-r0"

COPY rebind.py /usr/local/bin/rebind.py

LABEL org.opencontainers.image.licenses="GPL-2.0-or-later"
LABEL org.opencontainers.image.source="https://thekelleys.org.uk/dnsmasq/"

# 53: DNS. 443: HTTPS origin on the lab public interface, trap on the private one.
# Neither is published to the host — the fixture is reachable only from the
# container network, by the engine under test.
EXPOSE 53/udp 53/tcp 443/tcp

# rebind.py is PID 1 and starts dnsmasq itself. Nothing about what this
# fixture serves is in the image: the records are bind-mounted read-only at
# /fixture/hosts and the rebinding zone, public answer and PTR claim at
# /fixture/fixture.env, both rendered from config.toml.
ENTRYPOINT ["/usr/bin/python3", "-u", "/usr/local/bin/rebind.py"]
