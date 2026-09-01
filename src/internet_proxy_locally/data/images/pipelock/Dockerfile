# Pipelock, the one engine with a usable upstream OCI image.
#
# Upstream publishes to GHCR, so there is nothing to build — this file
# exists so that *every* image this repository runs is named by a
# Dockerfile, and every pin is a literal somebody reviewed in a diff.
# The digest below is what `up` actually runs; the tag it is built into is
# `PIPELOCK_IMAGE` in images.py.
#
# Upgrading: resolve the new release's digest on a networked machine
# (`docker buildx imagetools inspect ghcr.io/luckypipewrench/pipelock:<v>`),
# put it in the FROM line, bump the version in this comment and in
# `PIPELOCK_IMAGE`, commit, then `ipl setup`.
#
# Note: git tags upstream are `vX.Y.Z`, but the published GHCR image tags
# are unprefixed (`3.3.0`, plus `3.3.0-amd64` / `3.3.0-arm64` and `latest`).
# Only recent versions stay published; older tags are not retained — which
# is the reason a digest, not a tag, is what gets pinned here.

# pipelock 3.3.0
FROM ghcr.io/luckypipewrench/pipelock@sha256:42b58a428defca8f57d74b005e865898deb9568c9d742e46b32c80b0d2b011f7

# The upstream ENTRYPOINT is inherited; this is what run.py used to pass as
# `container.args`. The policy arrives through the read-only bind mount at
# /config/pipelock.yaml.
CMD ["run", "--config", "/config/pipelock.yaml", "--listen", "0.0.0.0:8888"]
