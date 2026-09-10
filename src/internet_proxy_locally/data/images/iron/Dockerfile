# iron-proxy 0.49.0, built from its release commit for amd64 and arm64.
# Update the source SHA and version together, then bump IRON_IMAGE in images.py.
# A build-only change also needs a new -buildN tag so setup rebuilds the image.
FROM golang:1.26.1-alpine3.23 AS build

RUN apk add --no-cache git ca-certificates
RUN git clone --filter=blob:none https://github.com/ironsh/iron-proxy /src \
    && git -C /src checkout --detach c8724937fbe109b7fbc6ddb21490e15902b187c0

WORKDIR /src
ENV GOTOOLCHAIN=local
RUN CGO_ENABLED=0 go build -mod=readonly -trimpath \
    -ldflags "-s -w -X github.com/ironsh/iron-proxy/internal/version.Version=0.49.0" \
    -o /out/iron-proxy ./cmd/iron-proxy

FROM alpine:3.22.1

RUN apk add --no-cache ca-certificates
COPY --from=build /out/iron-proxy /usr/local/bin/iron-proxy
COPY --from=build /src/LICENSE /licenses/iron-proxy.LICENSE

# The explicit proxy listener handles both absolute-form HTTP and CONNECT.
# Config and opt-in CA material are mounted read-only by ServiceSpec.
EXPOSE 1080
ENTRYPOINT ["/usr/local/bin/iron-proxy"]
CMD ["-config", "/config/iron.yaml"]
