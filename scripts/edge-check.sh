#!/usr/bin/env bash
# SEC-12: the public relay host of the edge proxy (deploy/k8s/base/files) forwards only what clients use: the
# WebSocket and NIP-11 at "/" and Blossom media under "/media/". The other routes of Buzz (operator API, git,
# invites, HTTP bridge, moderation, workflows, admin; docs/security/buzz-attack-surface.md) answer the edge's own
# 404 and never reach the relay. This runs the real config in the pinned nginx image in front of a stub upstream
# that answers UPSTREAM-HIT to any path, so a route that gets through is seen as a hit.
#   bash scripts/edge-check.sh     (needs docker)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

conf=deploy/k8s/base/files
image=$(awk '/- name: nginx$/{f=1} f&&/newName:/{n=$2} f&&/digest:/{print n"@"$2; exit}' deploy/k8s/base/kustomization.yaml)
[[ -n "$image" ]] || { echo "edge-check: no nginx image in deploy/k8s/base/kustomization.yaml" >&2; exit 1; }

net="edge-check-$$"
work=$(mktemp -d)
cleanup() {
  docker rm -f "${net}-edge" "${net}-stub" >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

# Every upstream the config names: its host becomes an alias of the stub and its port a listener.
mapfile -t upstreams < <(grep -ho 'proxy_pass http://[a-z0-9-]*:[0-9]*' "$conf/edge-nginx.conf" "$conf/core-server.conf" | sed 's#proxy_pass http://##' | sort -u)
[[ ${#upstreams[@]} -gt 0 ]] || { echo "edge-check: no upstreams found in $conf" >&2; exit 1; }
aliases=()
while read -r host; do aliases+=(--network-alias "$host"); done < <(printf '%s\n' "${upstreams[@]}" | cut -d: -f1 | sort -u)
{
  echo 'events {}'
  echo 'http {'
  while read -r port; do
    printf '  server { listen %s; location / { default_type text/plain; return 200 "UPSTREAM-HIT\\n"; } }\n' "$port"
  done < <(printf '%s\n' "${upstreams[@]}" | cut -d: -f2 | sort -u)
  echo '}'
} >"$work/stub.conf"

docker network create "$net" >/dev/null
docker run -d --name "${net}-stub" --network "$net" "${aliases[@]}" -v "$work/stub.conf:/etc/nginx/nginx.conf:ro" "$image" >/dev/null
docker run -d --name "${net}-edge" --network "$net" -p 127.0.0.1::8080 \
  -v "$PWD/$conf/edge-nginx.conf:/etc/nginx/edge/nginx.conf:ro" \
  -v "$PWD/$conf/core-server.conf:/etc/nginx/edge/core-server.conf:ro" \
  "$image" nginx -c /etc/nginx/edge/nginx.conf -g 'daemon off;' >/dev/null
port=$(docker port "${net}-edge" 8080/tcp | head -1 | sed 's/.*://')

ready=0
for _ in $(seq 1 30); do
  if curl -fsS -o /dev/null --max-time 2 "http://127.0.0.1:$port/_edge_health" 2>/dev/null; then ready=1; break; fi
  sleep 1
done
if [[ $ready -ne 1 ]]; then
  echo "edge-check: the edge did not start" >&2
  docker logs "${net}-edge" >&2 || true
  exit 1
fi

relay=nostr-stage-relay.example.org
failures=0
# check <allow|deny> <method> <host> <path>
check() {
  local want=$1 method=$2 host=$3 path=$4 code body verb=(-X "$2")
  body="$work/body"
  : >"$body"
  [[ $method == HEAD ]] && verb=(--head)
  code=$(curl -sS --path-as-is "${verb[@]}" -o "$body" -w '%{http_code}' --max-time 10 -H "Host: $host" "http://127.0.0.1:$port$path" 2>/dev/null) || code=000
  if [[ $want == allow ]]; then
    # A HEAD answer has no body: the status alone says it reached the upstream.
    if [[ $code == 200 ]] && { [[ $method == HEAD ]] || grep -q UPSTREAM-HIT "$body"; }; then return 0; fi
    echo "FAIL  $method $host$path: should reach the upstream, got $code" >&2
  else
    if [[ $code == 404 ]] && [[ "$(tr -d '\r\n' <"$body")" == "not found" ]]; then return 0; fi
    echo "FAIL  $method $host$path: should get the edge's 404, got $code $(head -c 40 "$body" | tr -d '\r\n')" >&2
  fi
  failures=$((failures + 1))
}

# What clients use.
check allow GET "$relay" /
check allow GET "$relay" /media/0a1b2c.png
check allow HEAD "$relay" /media/0a1b2c.png
check allow PUT "$relay" /media/upload
# The other hosts keep their routes.
check allow GET nostr-stage-secure.example.org /
check allow GET nostr-stage.example.org /

# What Buzz serves and clients do not use (docs/security/buzz-attack-surface.md).
for path in /info /health /_liveness /_readiness /_status /_mesh /.well-known/nostr.json /upload /media; do
  check deny GET "$relay" "$path"
done
for route in "POST /events" "POST /query" "POST /count" "POST /gifs/search" "POST /gifs/share" "POST /hooks/x" \
  "GET /workflows/x/runs" "GET /workflows/x/runs/y/approvals" \
  "GET /operator/communities" "POST /operator/communities" "POST /operator/listener/pubkeys" "DELETE /operator/listener/pubkeys" \
  "POST /operator/communities/archive" "POST /operator/communities/unarchive" "POST /operator/communities/delete" \
  "GET /operator/communities/availability" "POST /operator/communities/transfer" \
  "POST /api/invites" "GET /api/join-policy" "GET /api/join-policy/terms" "GET /api/join-policy/privacy" \
  "POST /api/invites/accept-policy" "POST /api/invites/claim" \
  "GET /moderation/reports" "GET /moderation/audit" "GET /moderation/restricted" \
  "POST /_mesh/demo/echo" "GET /huddle/x/audio" "PUT /upload" \
  "GET /git/o/r/info/refs?service=git-upload-pack" "POST /git/o/r/git-upload-pack" "POST /git/o/r/git-receive-pack" \
  "POST /internal/git/policy" "GET /api/admin/v1/communities"; do
  check deny "${route%% *}" "$relay" "${route#* }"
done
# A path that only looks like an allowed one must not get through: the edge matches the path nginx normalizes.
for path in /media/../operator/communities /media/%2e%2e/operator/communities /media/..%2foperator/communities \
  //operator/communities /./operator/communities /%6fperator/communities /operator%2fcommunities /MEDIA/x /Media/upload /media/.%2e/events; do
  check deny GET "$relay" "$path"
done

if [[ $failures -gt 0 ]]; then
  echo "edge-check: $failures check(s) failed" >&2
  exit 1
fi
echo "edge-check ok: relay host allows / and /media/ only; every other Buzz route gets the edge's 404"
