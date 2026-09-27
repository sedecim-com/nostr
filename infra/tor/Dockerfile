# syntax=docker/dockerfile:1.27.0@sha256:bde3983e9c939224420ddaf6b784cc30e09b035a4dea01f581230c50809f372e
# NFR010-03: base pinned by digest and every package apk installs pinned to an exact version (tor, su-exec
# and the libraries tor links that the base lacks). Alpine keeps only the latest build of each package in
# a branch: when one of these gets an update the build fails instead of changing silently, and the pins
# must be bumped (docs/building.md, "Imagen tor").
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
# The tor package's pre-install adduser writes the current day into /etc/shadow; the account is locked,
# so clear that field to keep the layer identical across build days.
RUN apk add --no-cache \
      tor=0.4.9.13-r0 \
      su-exec=0.3-r0 \
      libevent=2.1.13-r0 \
      libcap2=2.78-r0 \
      libseccomp=2.6.0-r2 \
      xz-libs=5.8.4-r0 \
      zstd-libs=1.5.7-r2 \
  && sed -i -E 's/^(tor:[^:]*):[0-9]*:/\1::/' /etc/shadow \
  && mkdir -p /var/lib/tor && chown -R tor /var/lib/tor
COPY --chmod=644 torrc /etc/tor/torrc
COPY --chmod=755 entrypoint.sh /entrypoint.sh
EXPOSE 9050
ENTRYPOINT ["/entrypoint.sh"]
