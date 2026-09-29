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
wait_for "continuity-vault :8088" curl -fsS http://localhost:8088/health
wait_for "web :8080" curl -fsS http://localhost:8080/flags.json

# Optional profiles, when on (COMPOSE_PROFILES in the environment or in .env; NFR006-04 runs them all in CI).
profiles=${COMPOSE_PROFILES:-$(sed -n 's/^COMPOSE_PROFILES=//p' .env 2>/dev/null | tail -n 1)}
has() { case ",$profiles," in *",$1,"*) return 0 ;; esac; return 1; }
if has managed; then wait_for "managed-signer :8084" curl -fsS http://localhost:8084/health; fi
if has push; then wait_for "notification-gateway :8086" curl -fsS http://localhost:8086/health; fi
# relay-allowlist has no host port: its health says whether its first sync with the policy-engine went through.
if has institutional; then wait_for "relay-allowlist (first sync)" sh -c 'docker compose exec -T relay-allowlist wget -qO- http://127.0.0.1:8087/health | grep -q "\"ok\":true"'; fi
# Tor only has to be running here: reaching the network through it is what the tor-profile job checks.
if has tor; then wait_for "tor" sh -c 'docker compose logs tor | grep -q "Tor .* running"'; fi
