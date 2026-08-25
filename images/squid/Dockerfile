# Minimal image for Squid, built by `./run.py --engine squid setup` through
# Docker or Apple `container`; no Compose.
#
# Upstream Squid publishes no official OCI image, so this installs the
# distribution package at a pinned apk version. That version is recorded in
# services/squid.toml — builds with an unpinned version are refused by
# run.py, and the Dockerfile itself rejects a non-pinned value as a second
# line of defense.
#
# Base image: keep the default here in sync with [build] in
# services/squid.toml. Alpine is multi-arch (amd64/arm64).

ARG BASE_IMAGE=alpine:3.22.1

FROM ${BASE_IMAGE}

ARG SQUID_VERSION

RUN test -n "${SQUID_VERSION}" \
    && echo "${SQUID_VERSION}" | grep -Eq '^[0-9]+(\.[0-9]+)+-r[0-9]+$' \
    || { echo "SQUID_VERSION must be a pinned apk version such as 6.12-r0 (see services/squid.toml; run ./run.py pin squid)" >&2; exit 1; }

RUN apk add --no-cache ca-certificates "squid=${SQUID_VERSION}"

# The packaged default config is never used — run.py bind-mounts the real
# policy over /etc/squid/squid.conf — but removing it means a mount failure
# cannot silently fall back to a permissive stock configuration.
RUN rm -f /etc/squid/squid.conf

# Cause-specific denial pages referenced by `deny_info` in config/squid.conf.
COPY errors/ /usr/share/squid/errors/en/

# License notice for redistribution. Unlike the Smokescreen image — which
# builds from a clone and can copy the upstream LICENSE.txt — the Alpine
# squid package ships no license text (there is no /usr/share/licenses
# entry; /usr/share/squid/errors/COPYRIGHT covers only the error templates),
# so the SPDX identifier apk records for the package is declared here.
# Squid is GPL-2.0-or-later; the full text is at
# https://github.com/squid-cache/squid/blob/master/COPYING
LABEL org.opencontainers.image.licenses="GPL-2.0-or-later"
LABEL org.opencontainers.image.source="https://github.com/squid-cache/squid"

USER squid
EXPOSE 3128

# -N runs in the foreground (no daemon); the config sends both logs to the
# container's stdout/stderr.
ENTRYPOINT ["/usr/sbin/squid", "-N", "-f", "/etc/squid/squid.conf"]
