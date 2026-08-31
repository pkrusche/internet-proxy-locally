# Minimal multi-stage image for stripe/smokescreen.
#
# Built by `./run.py setup` (or `./run.py --engine smokescreen setup`)
# through Docker or Apple `container`; no Compose. The source revision is
# pinned in services/smokescreen.toml and passed in as SMOKESCREEN_REF —
# builds with an unpinned ref are refused by run.py, and the Dockerfile
# itself rejects a non-SHA ref as a second line of defense.
#
# Base images: keep the defaults here in sync with [build] in
# services/smokescreen.toml. Both stages are multi-arch (amd64/arm64).

ARG GO_IMAGE=golang:1.24.6-alpine3.22
ARG RUNTIME_IMAGE=alpine:3.22.1

FROM ${GO_IMAGE} AS build

ARG SMOKESCREEN_REPO=https://github.com/stripe/smokescreen
ARG SMOKESCREEN_REF

RUN test -n "${SMOKESCREEN_REF}" \
    && echo "${SMOKESCREEN_REF}" | grep -Eq '^[0-9a-f]{40}$' \
    || { echo "SMOKESCREEN_REF must be a full commit SHA (see services/smokescreen.toml; run ./run.py pin smokescreen)" >&2; exit 1; }

RUN apk add --no-cache git ca-certificates

RUN git clone --filter=blob:none "${SMOKESCREEN_REPO}" /src \
    && git -C /src checkout --detach "${SMOKESCREEN_REF}"

WORKDIR /src
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${SMOKESCREEN_REF}" \
      -o /out/smokescreen .

FROM ${RUNTIME_IMAGE}

RUN apk add --no-cache ca-certificates \
    && addgroup -S smokescreen \
    && adduser -S -G smokescreen -H -s /sbin/nologin smokescreen

COPY --from=build /out/smokescreen /usr/local/bin/smokescreen
# Required license notice for redistribution of the built binary.
# Upstream names it LICENSE.txt; re-check after a ref bump.
COPY --from=build /src/LICENSE.txt /licenses/smokescreen.LICENSE

USER smokescreen

# ACL is bind-mounted read-only at /etc/smokescreen/acl.yaml by run.py.
EXPOSE 4750
ENTRYPOINT ["/usr/local/bin/smokescreen"]
