#!/bin/sh
# NFR010-03: rebuilds a released image from its tag, in a fresh clone and a fresh BuildKit builder, and
# compares the digest with the one published in the release's images.txt.
#   sh scripts/rebuild-image.sh <tag> <service> [images.txt]
# Without images.txt it is downloaded with gh (verify it first with scripts/verify-release.sh).
# Needs git, docker buildx, jq (and gh when images.txt is not given).
set -eu

REPO=${REPO:-sedecim-com/nostr}

tag=${1:-}
service=${2:-}
images=${3:-}
case "$tag" in
  v*) ;;
  *) echo "uso: sh scripts/rebuild-image.sh vX.Y.Z <servicio> [images.txt]" >&2; exit 2 ;;
esac
[ -n "$service" ] || { echo "uso: sh scripts/rebuild-image.sh vX.Y.Z <servicio> [images.txt]" >&2; exit 2; }

work=$(mktemp -d)
echo "== Directorio de trabajo: $work"

if [ -z "$images" ]; then
  command -v gh >/dev/null 2>&1 || { echo "falta gh (o pasa images.txt como tercer argumento)" >&2; exit 2; }
  gh release download "$tag" --repo "$REPO" --pattern images.txt --dir "$work"
  images="$work/images.txt"
fi
ref=$(grep "/nostr-$service@sha256:" "$images" || true)
[ -n "$ref" ] || { echo "FALLO: $service no aparece en $images" >&2; exit 1; }
expected=${ref#*@}

# The checkout's file modes end up in the image: clone with the umask the release runner uses.
umask 022
git clone --quiet --depth 1 --branch "$tag" "https://github.com/$REPO.git" "$work/src"
[ -f "$work/src/scripts/build-image.sh" ] || { echo "FALLO: $tag es anterior a las imágenes reproducibles (NFR010-03)" >&2; exit 1; }

echo "== Construyendo $service desde $tag (puede tardar varios minutos)"
built=$(cd "$work/src" && IMAGE_VERSION="$tag" IMAGE_SOURCE="https://github.com/$REPO" \
  sh scripts/build-image.sh "$service" "$work/$service.tar" | tail -n 1)

echo "publicado:   $expected"
echo "reconstruido: $built"
if [ "$built" != "$expected" ]; then
  echo "FALLO: el digest no coincide. Para ver la diferencia:" >&2
  echo "  skopeo copy docker://$ref oci-archive:$work/publicado.tar" >&2
  echo "  sh scripts/image-diff.sh $work/publicado.tar $work/$service.tar" >&2
  exit 1
fi
echo "OK: $ref se reconstruye bit a bit desde $tag"
