#!/bin/sh
# NFR010-03: shows where two OCI archives of the same image differ (after scripts/build-image.sh produced
# different digests): the image config and, for each layer whose digest differs, the file listing
# (mode, owner, size, mtime) and the files whose content differs. For a deeper, semantic comparison
# use diffoci (https://github.com/reproducible-containers/diffoci).
#   sh scripts/image-diff.sh a.tar b.tar                 (needs jq and GNU tar)
set -eu

a=${1:-}
b=${2:-}
[ -f "$a" ] && [ -f "$b" ] || { echo "uso: sh scripts/image-diff.sh a.tar b.tar" >&2; exit 2; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/a" "$tmp/b"
tar -xf "$a" -C "$tmp/a"
tar -xf "$b" -C "$tmp/b"

blob() { echo "$tmp/$1/blobs/sha256/${2#sha256:}"; }
manifest() { blob "$1" "$(jq -r '.manifests[0].digest' "$tmp/$1/index.json")"; }

ma=$(manifest a)
mb=$(manifest b)
echo "== manifest: $(basename "$ma") vs $(basename "$mb")"

echo "== config (diff -u)"
jq -S . "$(blob a "$(jq -r .config.digest "$ma")")" > "$tmp/config-a.json"
jq -S . "$(blob b "$(jq -r .config.digest "$mb")")" > "$tmp/config-b.json"
diff -u "$tmp/config-a.json" "$tmp/config-b.json" || true

jq -r '.layers[].digest' "$ma" > "$tmp/layers-a"
jq -r '.layers[].digest' "$mb" > "$tmp/layers-b"
if [ "$(wc -l < "$tmp/layers-a")" != "$(wc -l < "$tmp/layers-b")" ]; then
  echo "== distinto número de capas: $(wc -l < "$tmp/layers-a") vs $(wc -l < "$tmp/layers-b")"
fi

i=0
paste -d ' ' "$tmp/layers-a" "$tmp/layers-b" | while read -r la lb; do
  i=$((i + 1))
  [ "$la" != "$lb" ] || continue
  echo "== capa $i: $la vs $lb"
  if [ -z "$la" ] || [ -z "$lb" ]; then continue; fi
  tar -tvf "$(blob a "$la")" --full-time | sort -k6 > "$tmp/list-a"
  tar -tvf "$(blob b "$lb")" --full-time | sort -k6 > "$tmp/list-b"
  diff -u "$tmp/list-a" "$tmp/list-b" | head -n 200 || true
  mkdir -p "$tmp/x$i/a" "$tmp/x$i/b"
  tar -xf "$(blob a "$la")" -C "$tmp/x$i/a" 2>/dev/null || true
  tar -xf "$(blob b "$lb")" -C "$tmp/x$i/b" 2>/dev/null || true
  diff -rq --no-dereference "$tmp/x$i/a" "$tmp/x$i/b" | head -n 100 || true
done
