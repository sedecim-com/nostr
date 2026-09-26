#!/bin/sh
# Waits until the self-hosted stack answers on its public ports (used by CI and after `docker compose up`).
set -eu
TIMEOUT="${WAIT_TIMEOUT:-600}"
wait_for() {
  name="$1"; shift
  start=$(date +%s)
  until "$@" >/dev/null 2>&1; do
    if [ $(( $(date +%s) - start )) -gt "$TIMEOUT" ]; then echo "timeout waiting for $name"; exit 1; fi
    sleep 3
  done
  echo "ready: $name"
}
nip11() { curl -fsS -H 'Accept: application/nostr+json' "$1" | grep -q '"name"'; }
wait_for "relay (Buzz) :3000" nip11 http://localhost:3000/
wait_for "secure-relay :7000" nip11 http://localhost:7000/
wait_for "indexer :8081" curl -fsS http://localhost:8081/health
wait_for "identity-service :8082" curl -fsS http://localhost:8082/health
wait_for "policy-engine :8083" curl -fsS http://localhost:8083/health
wait_for "blob-store :8085" curl -fsS http://localhost:8085/health
wait_for "web :8080" curl -fsS http://localhost:8080/flags.json
