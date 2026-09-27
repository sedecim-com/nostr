#!/bin/sh
# NFR010-03: builds one release image reproducibly as an OCI archive and prints its manifest digest on the
# last line of stdout. release.yml (images), reproducible-images.yml and scripts/rebuild-image.sh all use
# this exact invocation, so the digest in a release's images.txt can be rebuilt from the tag.
#   sh scripts/build-image.sh <service> <out.tar>        (run from the repository root; needs docker buildx, jq, git)
# Env:
#   SOURCE_DATE_EPOCH  timestamp for files and image metadata (default: committer time of HEAD)
#   IMAGE_VERSION      org.opencontainers.image.version label (default: exact v* tag of HEAD, else "dev")
#   IMAGE_REVISION     org.opencontainers.image.revision label (default: HEAD)
#   IMAGE_SOURCE       org.opencontainers.image.source label (default: https://github.com/sedecim-com/nostr)
#   IMAGE_NAME         name:tag recorded in the OCI index (optional; does not change the manifest digest)
#   BUILDER            existing buildx builder (default: a fresh docker-container builder running the
#                      pinned BuildKit, removed afterwards, so nothing is cached between builds)
#   DRY_RUN=1          print the build arguments, one per line, and exit
set -eu

# Layer compression and image metadata depend on the BuildKit version: pinned by digest.
BUILDKIT_IMAGE=moby/buildkit:v0.32.2@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8
PLATFORM=linux/amd64
SERVICES="indexer identity-service policy-engine blob-store managed-signer notification-gateway web tor"

usage() {
  echo "uso: sh scripts/build-image.sh <servicio> <salida.tar>   (servicio: $SERVICES)" >&2
  exit 2
}

service=${1:-}
out=${2:-}
if [ -z "$service" ] || [ -z "$out" ]; then usage; fi

# Same context / target / SERVICE as docker-compose.yml.
case "$service" in
  indexer | identity-service | policy-engine | blob-store | managed-signer | notification-gateway)
    context=. target=service arg="SERVICE=$service" ;;
  web) context=. target=web arg='' ;;
  tor) context=infra/tor target='' arg='' ;;
  *) usage ;;
esac

SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
export SOURCE_DATE_EPOCH
revision=${IMAGE_REVISION:-$(git rev-parse HEAD)}
version=${IMAGE_VERSION:-$(git describe --tags --exact-match --match 'v*' 2>/dev/null || echo dev)}
source=${IMAGE_SOURCE:-https://github.com/sedecim-com/nostr}

# Attestations (provenance, SBOM) are added by release.yml publish-images, never embedded by buildx:
# they carry the build time and would change the digest.
set -- --platform "$PLATFORM" --no-cache --pull --provenance=false --sbom=false \
  --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
  --label "org.opencontainers.image.source=$source" \
  --label "org.opencontainers.image.revision=$revision" \
  --label "org.opencontainers.image.version=$version" \
  --label "org.opencontainers.image.licenses=Apache-2.0" \
  --output "type=oci,dest=$out,rewrite-timestamp=true${IMAGE_NAME:+,name=$IMAGE_NAME}"
[ -z "$target" ] || set -- "$@" --target "$target"
[ -z "$arg" ] || set -- "$@" --build-arg "$arg"
set -- "$@" "$context"

if [ "${DRY_RUN:-0}" = 1 ]; then
  printf '%s\n' "$@"
  exit 0
fi

command -v jq >/dev/null 2>&1 || { echo "falta jq en el PATH" >&2; exit 2; }
builder=${BUILDER:-}
if [ -z "$builder" ]; then
  builder="repro-$service-$$"
  docker buildx create --name "$builder" --driver docker-container --driver-opt "image=$BUILDKIT_IMAGE" >/dev/null
  trap 'docker buildx rm "$builder" >/dev/null 2>&1 || true' EXIT
fi

docker buildx build --builder "$builder" "$@" >&2
tar -xOf "$out" index.json | jq -r '.manifests | if length == 1 then .[0].digest else error("expected one manifest") end'
