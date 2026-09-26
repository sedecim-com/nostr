#!/bin/sh
# BUZZ-05 (ADR 0003): compares the current upstream Buzz image with the pin and applies a new pin.
#
#   sh scripts/buzz-upstream.sh check
#       Resolves ghcr.io/block/buzz:main anonymously and prints key=value lines (for $GITHUB_OUTPUT):
#       image, pinned, changed (true|false), revision and date (best effort, from the OCI labels).
#   sh scripts/buzz-upstream.sh apply IMAGE [REVISION] [DATE]
#       Writes IMAGE (pinned by digest) to infra/buzz/PIN, the default of docker-compose.yml and the
#       Kubernetes base (deploy/k8s/base/kustomization.yaml, `images` entry `buzz`).
#
# Needs curl and jq. BUZZ_REPO / BUZZ_TAG override block/buzz and main.
set -eu
REPO=${BUZZ_REPO:-block/buzz}
TAG=${BUZZ_TAG:-main}
REGISTRY=https://ghcr.io
PIN=infra/buzz/PIN
COMPOSE=docker-compose.yml
KUSTOMIZATION=deploy/k8s/base/kustomization.yaml
ACCEPT='application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'

pinned_image() { sed -n 's/^BUZZ_IMAGE=//p' "$PIN"; }

check() {
  token=$(curl -fsSL "$REGISTRY/token?scope=repository:$REPO:pull&service=ghcr.io" | jq -r .token)
  auth="Authorization: Bearer $token"
  # The digest of what the tag points to (an OCI index for multi-arch images), not of one platform.
  digest=$(curl -fsSI -H "$auth" -H "Accept: $ACCEPT" "$REGISTRY/v2/$REPO/manifests/$TAG" | tr -d '\r' | awk -F': ' 'tolower($1) == "docker-content-digest" { print $2 }')
  printf '%s' "$digest" | grep -Eq '^sha256:[0-9a-f]{64}$' || { echo "could not resolve ghcr.io/$REPO:$TAG" >&2; exit 1; }
  image="ghcr.io/$REPO@$digest"
  pinned=$(pinned_image)

  # Best effort: upstream commit and build date from the linux/amd64 image config labels.
  revision='' date=''
  manifest=$(curl -fsSL -H "$auth" -H "Accept: $ACCEPT" "$REGISTRY/v2/$REPO/manifests/$digest" || true)
  amd64=$(printf '%s' "$manifest" | jq -r '(.manifests // [])[] | select(.platform.os == "linux" and .platform.architecture == "amd64") | .digest' 2>/dev/null | head -n 1 || true)
  [ -n "$amd64" ] && manifest=$(curl -fsSL -H "$auth" -H "Accept: $ACCEPT" "$REGISTRY/v2/$REPO/manifests/$amd64" || true)
  config=$(printf '%s' "$manifest" | jq -r '.config.digest // empty' 2>/dev/null || true)
  if [ -n "$config" ] && blob=$(curl -fsSL -H "$auth" "$REGISTRY/v2/$REPO/blobs/$config" 2>/dev/null); then
    revision=$(printf '%s' "$blob" | jq -r '.config.Labels["org.opencontainers.image.revision"] // empty' 2>/dev/null || true)
    date=$(printf '%s' "$blob" | jq -r '.created // empty' 2>/dev/null | cut -c1-10 || true)
  fi

  # Labels come from the registry: keep only well-formed values (they end up in $GITHUB_OUTPUT and sed).
  printf '%s' "$revision" | grep -Eq '^[0-9a-f]{7,40}$' || revision=''
  printf '%s' "$date" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' || date=''
  echo "image=$image"
  echo "pinned=$pinned"
  if [ "$image" = "$pinned" ]; then echo "changed=false"; else echo "changed=true"; fi
  echo "revision=$revision"
  echo "date=$date"
}

# Replaces KEY=... in the pin file (values are hex, dates or image references: safe for sed).
set_pin() {
  tmp=$(mktemp)
  sed "s|^$1=.*|$1=$2|" "$PIN" > "$tmp" && cat "$tmp" > "$PIN"
  rm -f "$tmp"
}

apply() {
  image=$1 revision=${2:-} date=${3:-}
  printf '%s' "$image" | grep -Eq '^ghcr\.io/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$' || { echo "IMAGE must be pinned by digest (ghcr.io/...@sha256:...)" >&2; exit 1; }
  printf '%s' "$revision" | grep -Eq '^([0-9a-f]{7,40})?$' || { echo "invalid REVISION" >&2; exit 1; }
  printf '%s' "$date" | grep -Eq '^([0-9]{4}-[0-9]{2}-[0-9]{2})?$' || { echo "invalid DATE" >&2; exit 1; }
  old=$(pinned_image)
  grep -q "$old" "$COMPOSE" || { echo "$COMPOSE does not default to the pinned image $old" >&2; exit 1; }
  grep -q "digest: ${old#*@}" "$KUSTOMIZATION" || { echo "$KUSTOMIZATION does not pin the digest of $old" >&2; exit 1; }
  set_pin BUZZ_IMAGE "$image"
  [ -z "$revision" ] || set_pin BUZZ_COMMIT "$revision"
  [ -z "$date" ] || set_pin BUZZ_COMMIT_DATE "$date"
  tmp=$(mktemp)
  sed "s|$old|$image|g" "$COMPOSE" > "$tmp" && cat "$tmp" > "$COMPOSE"
  sed -e "s|newName: ${old%@*}\$|newName: ${image%@*}|" -e "s|digest: ${old#*@}|digest: ${image#*@}|" "$KUSTOMIZATION" > "$tmp" && cat "$tmp" > "$KUSTOMIZATION"
  rm -f "$tmp"
}

case "${1:-}" in
  check) check ;;
  apply) shift; [ $# -ge 1 ] || { echo "usage: $0 apply IMAGE [REVISION] [DATE]" >&2; exit 2; }; apply "$@" ;;
  *) echo "usage: $0 check | apply IMAGE [REVISION] [DATE]" >&2; exit 2 ;;
esac
