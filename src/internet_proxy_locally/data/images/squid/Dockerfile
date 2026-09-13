# Minimal image for Squid, built by `ipl --engine squid setup` through
# Docker or Apple `container`; no Compose.
#
# Upstream Squid publishes no official OCI image, so this installs the
# distribution package at a pinned apk version. Every pin this image
# depends on is a literal in this file — the base image and the squid
# version — and the unit suite asserts they stay pinned and stay in step
# with `SQUID_IMAGE` in images.py.
#
# Upgrading: edit the versions below, bump `SQUID_IMAGE` to match, commit,
# then `ipl --engine squid setup`. Alpine keeps one squid version per
# release branch, so a pin is stable until the base image moves; if a bump
# ever removes the pinned version from the repository, the build fails at
# `apk add` rather than silently installing something else.
#
# `SQUID_IMAGE`'s tag carries a `-buildN` suffix after the apk version
# (currently `-build2`, adding non-root Squid with tmpfs CA staging): a local
# build revision, not a new upstream apk release, bumped whenever this
# Dockerfile's build context changes without the apk pin itself moving —
# `prepare_image()` skips a build when the tag is already present, so
# reusing the old tag after such a change would leave a stale image
# silently missing whatever the edit added.
#
# Alpine is multi-arch (amd64/arm64), and its squid is built
# `--with-openssl`.

FROM alpine:3.22.1

RUN apk add --no-cache ca-certificates "squid=6.12-r0" "su-exec=0.2-r3"

# The packaged default config is never used — ipl bind-mounts the real
# policy over /etc/squid/squid.conf — but removing it means a mount failure
# cannot silently fall back to a permissive stock configuration.
RUN rm -f /etc/squid/squid.conf

# The ssl_bump cert-DB, needed only when `--tls-interception` is on
# (docs/tls-interception.md). Unconditional and cheap: it lets this one
# image serve both tls_interception states, so there is no tag fork for
# that reason. `security_file_certgen`'s path (`/usr/lib/squid/`) was
# confirmed against this Alpine package's `apk info -L squid`.
RUN /usr/lib/squid/security_file_certgen -c -s /var/lib/ssl_db -M 4MB \
    && chown -R squid:squid /var/lib/ssl_db

# Cause-specific denial pages referenced by `deny_info` in config/squid.conf.
COPY errors/ /usr/share/squid/errors/en/

# Host CA mounts are accessible only to the short-lived root bootstrap, not
# Squid. The bootstrap stages a private copy in tmpfs before dropping root.
RUN mkdir -m 0700 /run/ipl-ca
COPY entrypoint.sh /usr/local/bin/ipl-squid-entrypoint
RUN chmod 0755 /usr/local/bin/ipl-squid-entrypoint

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
# container's stdout/stderr. The policy arrives entirely through the read-only
# bind mount over /etc/squid/squid.conf. Only TLS startup overrides USER to root;
# the entrypoint permanently drops privileges before executing this command.
ENTRYPOINT ["/usr/local/bin/ipl-squid-entrypoint"]
CMD ["/usr/sbin/squid", "-N", "-f", "/etc/squid/squid.conf"]
