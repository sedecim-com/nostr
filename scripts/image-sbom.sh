#!/bin/sh
# NFR010-04: the SBOM of one image as it is, made by syft from the image itself (CycloneDX JSON). release.yml
# attests it for each image it publishes, and for the pinned Buzz image; reproducible-images.yml makes it on
# every change to the images. scripts/image-sbom-check.mjs then checks that no devDependency is in the runtime.
#   sh scripts/image-sbom.sh oci-archive:image.tar sbom.cdx.json     (an image built by scripts/build-image.sh)
#   sh scripts/image-sbom.sh registry:ghcr.io/block/buzz@sha256:… sbom-buzz.cdx.json
# syft is downloaded at the pinned version and checked against its published checksum (OPS-13), unless SYFT
# points to a syft binary of that version.
set -eu

SYFT_VERSION=1.52.0
# sha256 of syft_1.52.0_linux_amd64.tar.gz (syft_1.52.0_checksums.txt of the release)
SYFT_SHA256=caeedb81fb0491615f1ebd1761e4145d41ee86dd2cc7bf80669f9f5ad9d6133d

src=${1:-}
out=${2:-}
case "$src" in
  oci-archive:?* | docker-archive:?* | registry:?*@sha256:*) ;;
  *) echo "uso: sh scripts/image-sbom.sh <oci-archive:img.tar | registry:imagen@sha256:…> <salida.cdx.json>" >&2; exit 2 ;;
esac
[ -n "$out" ] || { echo "falta el archivo de salida" >&2; exit 2; }

syft=${SYFT:-}
if [ -z "$syft" ]; then
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  curl -sSfL -o "$tmp/syft.tgz" "https://github.com/anchore/syft/releases/download/v$SYFT_VERSION/syft_${SYFT_VERSION}_linux_amd64.tar.gz"
  echo "$SYFT_SHA256  $tmp/syft.tgz" | sha256sum -c - >/dev/null || { echo "syft $SYFT_VERSION: checksum incorrecto" >&2; exit 1; }
  tar -xzf "$tmp/syft.tgz" -C "$tmp" syft
  syft="$tmp/syft"
fi
"$syft" version | grep -q "^Version: *$SYFT_VERSION\$" || { echo "se esperaba syft $SYFT_VERSION" >&2; exit 1; }

SYFT_CHECK_FOR_APP_UPDATE=false "$syft" scan "$src" -o "cyclonedx-json=$out" -q
echo "$out: SBOM de $src (syft $SYFT_VERSION)"
