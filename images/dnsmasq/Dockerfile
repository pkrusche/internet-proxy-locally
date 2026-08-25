# Minimal dnsmasq image: the local DNS fixture for `check --full`'s
# dns-mixed-answers row. Built by `./run.py setup`, started only by
# `./run.py up --test-policy`, and never part of normal operation.
#
# Why a DNS server rather than a hosts file: a mixed answer set is a single
# name resolving to several addresses, and /etc/hosts cannot express that.
# Both resolvers involved collapse duplicate names to one address — musl
# keeps the first, Squid's own hosts parser keeps the last — so a hosts
# file measures which record survived, not how the engine treats a
# multi-address answer. dnsmasq's `--addn-hosts` does aggregate them
# (docs/security.md).
#
# Pinned the same way as the Squid image: an apk version recorded in
# services/dnsmasq.toml, refused by run.py when unpinned.

ARG BASE_IMAGE=alpine:3.22.1

FROM ${BASE_IMAGE}

ARG DNSMASQ_VERSION

RUN test -n "${DNSMASQ_VERSION}" \
    && echo "${DNSMASQ_VERSION}" | grep -Eq '^[0-9]+(\.[0-9]+)+-r[0-9]+$' \
    || { echo "DNSMASQ_VERSION must be a pinned apk version such as 2.91-r1 (see services/dnsmasq.toml; run ./run.py pin dnsmasq)" >&2; exit 1; }

RUN apk add --no-cache "dnsmasq=${DNSMASQ_VERSION}"

LABEL org.opencontainers.image.licenses="GPL-2.0-or-later"
LABEL org.opencontainers.image.source="https://thekelleys.org.uk/dnsmasq/"

EXPOSE 53/udp 53/tcp

# The fixture records are bind-mounted read-only at /fixture/hosts. Names
# not in that file are forwarded to whatever upstream resolver the backend
# put in this container's /etc/resolv.conf, so the engine under test can
# still reach pypi.org, nip.io and the rest.
#
# --no-hosts       ignore this container's own /etc/hosts, so the fixture
#                  file is the only local source of answers
# --no-daemon      stay in the foreground; logs go to the container stream
# --log-queries    every lookup the engine makes is visible in `run.py logs`
ENTRYPOINT ["/usr/sbin/dnsmasq", "--no-daemon", "--no-hosts", "--log-queries", \
            "--addn-hosts=/fixture/hosts"]
