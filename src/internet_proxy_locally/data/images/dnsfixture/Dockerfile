# The local DNS fixture for `check --full`: dnsmasq plus a small stdlib
# responder. Built by `./run.py setup`, started only by
# `./run.py up --test-policy`, never part of normal operation.
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
# Both packages are pinned in services/dnsfixture.toml and refused by
# run.py when unpinned.

ARG BASE_IMAGE=alpine:3.22.1

FROM ${BASE_IMAGE}

ARG DNSMASQ_VERSION
ARG PYTHON3_VERSION

RUN for pin in "dnsmasq=${DNSMASQ_VERSION}" "python3=${PYTHON3_VERSION}"; do \
        echo "${pin}" | grep -Eq '^[a-z0-9]+=[0-9]+(\.[0-9]+)+-r[0-9]+$' \
        || { echo "package pins must look like name=1.2.3-r0 (got '${pin}'; see services/dnsfixture.toml, run ./run.py pin dnsfixture)" >&2; exit 1; }; \
    done

RUN apk add --no-cache "dnsmasq=${DNSMASQ_VERSION}" "python3=${PYTHON3_VERSION}"

COPY rebind.py /usr/local/bin/rebind.py

LABEL org.opencontainers.image.licenses="GPL-2.0-or-later"
LABEL org.opencontainers.image.source="https://thekelleys.org.uk/dnsmasq/"

# 53: DNS, served by dnsmasq. 443: the rebinding trap, served by rebind.py.
# Neither is published to the host — the fixture is reachable only from the
# container network, by the engine under test.
EXPOSE 53/udp 53/tcp 443/tcp

# rebind.py is PID 1 and starts dnsmasq itself. Nothing about what this
# fixture serves is in the image: the records are bind-mounted read-only at
# /fixture/hosts and the rebinding zone, public answer and PTR claim at
# /fixture/fixture.env, both rendered from data/lab/fixtures.toml.
ENTRYPOINT ["/usr/bin/python3", "-u", "/usr/local/bin/rebind.py"]
