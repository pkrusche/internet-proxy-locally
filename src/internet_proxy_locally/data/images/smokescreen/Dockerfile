# Minimal multi-stage image for stripe/smokescreen, built by `ipl setup`
# (or `ipl --engine smokescreen setup`) through Docker or Apple
# `container`; no Compose.
#
# Upstream publishes no OCI images and no regular version tags, so this
# builds from a pinned source commit. Every pin this image depends on is a
# literal in this file — both base images and the 40-character commit SHA —
# and the unit suite asserts they stay pinned and stay in step with
# `SMOKESCREEN_IMAGE` in images.py, whose tag is the first 12 characters of
# that SHA plus a -buildN suffix for changes to the image itself.
#
# Upgrading: resolve the new commit on a networked machine
# (`git ls-remote https://github.com/stripe/smokescreen HEAD`), put the full
# SHA in the checkout below, bump `SMOKESCREEN_IMAGE` to its first 12
# characters, commit, then `ipl --engine smokescreen setup`. Bump the
# -buildN suffix when changing this Dockerfile without changing the SHA,
# so setup does not reuse an older image with different launch defaults.
#
# Both stages are multi-arch (amd64/arm64).

FROM golang:1.24.6-alpine3.22 AS build

RUN apk add --no-cache git ca-certificates

RUN git clone --filter=blob:none https://github.com/stripe/smokescreen /src \
    && git -C /src checkout --detach 131fba29ce1e3c2b9d78f359a2fb633703d5013d

WORKDIR /src
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=131fba29ce1e3c2b9d78f359a2fb633703d5013d" \
      -o /out/smokescreen .

FROM alpine:3.22.1

RUN apk add --no-cache ca-certificates \
    && addgroup -S smokescreen \
    && adduser -S -G smokescreen -H -s /sbin/nologin smokescreen

COPY --from=build /out/smokescreen /usr/local/bin/smokescreen
# Required license notice for redistribution of the built binary.
# Upstream names it LICENSE.txt; re-check after a ref bump.
COPY --from=build /src/LICENSE.txt /licenses/smokescreen.LICENSE

USER smokescreen

# The ACL is bind-mounted read-only at /etc/smokescreen/acl.yaml and the
# daemon config at /etc/smokescreen/config.yaml. The latter exists only
# because `allow_missing_role` is a config-file key with no CLI equivalent.
EXPOSE 4750
ENTRYPOINT ["/usr/local/bin/smokescreen"]
CMD ["--config-file", "/etc/smokescreen/config.yaml", \
     "--listen-ip", "0.0.0.0", \
     "--listen-port", "4750", \
     "--egress-acl-file", "/etc/smokescreen/acl.yaml"]
