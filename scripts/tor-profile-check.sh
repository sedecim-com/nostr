#!/usr/bin/env bash
# FR021-02: validates the compose `tor` profile end to end. Starts the relays and the Tor container,
# waits for the onion service hostnames (tor-data volume), for Tor to bootstrap and for each onion to
# answer NIP-11 through the compose SOCKS port, then uses the real sovereign CLI in the Tor profile:
#   - secure-relay .onion: channel message published and read back (NIP-29 kind 9);
#   - relay (Buzz) .onion: NIP-17 DM between two Tor personas, read back by the recipient (NIP-42 AUTH
#     through the onion service). Buzz binds each connection to the community of its Host header, so the
#     onion host gets its own community first (scripts/buzz-provision-community.ts, operator NIP-98).
#
# Usage: bash scripts/tor-profile-check.sh              (starts relay, secure-relay and tor with --build)
#        TOR_CHECK_SKIP_UP=1 bash scripts/tor-profile-check.sh   (stack already running)
#        TOR_CHECK_TIMEOUT=600 ...                      (seconds for bootstrap + onion reachability)
#        BUZZ_OPERATOR_SECRET=<hex>                     (key in the relay RELAY_OPERATOR_PUBKEYS; without it a
#                                                        throwaway operator key is generated for the relay started here)
# Results (CLI output, tor log) in ./tor-profile-results or TOR_CHECK_OUT.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
OUT=${TOR_CHECK_OUT:-$ROOT/tor-profile-results}
TIMEOUT=${TOR_CHECK_TIMEOUT:-420}
TSX="$ROOT/node_modules/.bin/tsx"
SOCKS="127.0.0.1:${TOR_SOCKS_PORT:-9050}"
COMPOSE=(docker compose --profile tor)
rm -rf "$OUT"
mkdir -p "$OUT"
DATA=$(mktemp -d)
trap 'rm -rf "$DATA"' EXIT

for bin in docker curl node; do
  command -v "$bin" > /dev/null || { echo "tor-profile-check: missing $bin" >&2; exit 2; }
done
[ -x "$TSX" ] || { echo "tor-profile-check: run npm ci first" >&2; exit 2; }

fail() {
  echo "FAIL (FR021-02): $*" >&2
  "${COMPOSE[@]}" logs --no-color --tail 200 tor > "$OUT/tor.log" 2>&1 || true
  echo "--- last lines of the tor container (full log in $OUT/tor.log):" >&2
  tail -n 40 "$OUT/tor.log" >&2 || true
  exit 1
}

# wait_until DESCRIPTION SECONDS CMD... : polls CMD every 3 s
wait_until() {
  local what=$1 limit=$2 start
  shift 2
  start=$(date +%s)
  until "$@" > /dev/null 2>&1; do
    if [ $(($(date +%s) - start)) -gt "$limit" ]; then fail "timeout after ${limit}s waiting for $what"; fi
    sleep 3
  done
  echo "ready: $what ($(($(date +%s) - start))s)"
}

if [ -z "${BUZZ_OPERATOR_SECRET:-}" ]; then
  [ "${TOR_CHECK_SKIP_UP:-0}" != 1 ] || { echo "tor-profile-check: with TOR_CHECK_SKIP_UP=1 set BUZZ_OPERATOR_SECRET (a key in the relay RELAY_OPERATOR_PUBKEYS)" >&2; exit 2; }
  # Throwaway operator key, only for the relay this script starts (never written to .env).
  keys=$("$TSX" apps/key-generator/src/cli.ts service-key --i-understand)
  BUZZ_OPERATOR_SECRET=$(printf '%s\n' "$keys" | sed -n 's/^secret_hex=//p')
  RELAY_OPERATOR_PUBKEYS=$(printf '%s\n' "$keys" | sed -n 's/^pubkey_hex=//p')
  export BUZZ_OPERATOR_SECRET RELAY_OPERATOR_PUBKEYS
fi

if [ "${TOR_CHECK_SKIP_UP:-0}" != 1 ]; then
  [ -f .env ] || sh scripts/init-env.sh
  "${COMPOSE[@]}" up -d --build relay secure-relay tor
fi

nip11() { curl -fsS --max-time 20 -H 'Accept: application/nostr+json' "$@" | grep -q '"name"'; }
wait_until "relay (Buzz) NIP-11 on :3000" 600 nip11 http://localhost:3000/
wait_until "secure-relay NIP-11 on :7000" 300 nip11 http://localhost:7000/

hostname_of() { "${COMPOSE[@]}" exec -T tor cat "/var/lib/tor/$1/hostname"; }
hostnames_ready() { "${COMPOSE[@]}" exec -T tor test -s /var/lib/tor/relay/hostname -a -s /var/lib/tor/secure-relay/hostname; }
wait_until "onion hostnames in the tor-data volume" 120 hostnames_ready
RELAY_ONION=$(hostname_of relay | tr -d '\r\n')
SECURE_ONION=$(hostname_of secure-relay | tr -d '\r\n')
case "$RELAY_ONION$SECURE_ONION" in
  *[!a-z2-7.]* | "") fail "unexpected onion hostnames: '$RELAY_ONION' '$SECURE_ONION'" ;;
esac
echo "relay onion:        ws://$RELAY_ONION"
echo "secure-relay onion: ws://$SECURE_ONION"

# Buzz maps each Host to one community and rejects unmapped hosts: give the onion host its own.
BUZZ_HTTP_URL=http://localhost:${RELAY_PORT:-3000} "$TSX" scripts/buzz-provision-community.ts "$RELAY_ONION" > "$OUT/buzz.provision.log" 2>&1 ||
  fail "could not provision the Buzz community for $RELAY_ONION (see $OUT/buzz.provision.log; RELAY_OPERATOR_PUBKEYS must hold the operator key)"
cat "$OUT/buzz.provision.log"

bootstrapped() { "${COMPOSE[@]}" logs --no-color tor | grep -q 'Bootstrapped 100%'; }
wait_until "Tor bootstrap (Bootstrapped 100%)" "$TIMEOUT" bootstrapped
# Descriptors are published after bootstrap; the first circuits to a fresh onion often fail.
wait_until "secure-relay onion answering NIP-11 through the compose SOCKS port" "$TIMEOUT" nip11 --socks5-hostname "$SOCKS" "http://$SECURE_ONION/"
wait_until "relay onion answering NIP-11 through the compose SOCKS port" "$TIMEOUT" nip11 --socks5-hostname "$SOCKS" "http://$RELAY_ONION/"

cli() { # cli DATA_SUBDIR ARGS...
  local dir=$1
  shift
  SOVEREIGN_DATA_DIR="$DATA/$dir" SOVEREIGN_PASSPHRASE=tor-profile-check TOR_SOCKS="$SOCKS" timeout 180 "$TSX" apps/sovereign-client/src/cli.ts "$@"
}
persona_id() { sed -n 's/^ *"id": "\([^"]*\)".*/\1/p' "$1" | head -n 1; }
pubkey_of() { sed -n 's/^ *"pubkey": "\([0-9a-f]\{64\}\)".*/\1/p' "$1" | head -n 1; }

# send_with_retry LOG DIR PERSONA CMD... : one submit, then `resume` (same event id) until REPLICATED
send_with_retry() {
  local log=$1 dir=$2 persona=$3
  shift 3
  cli "$dir" "$@" | tee "$log" || true
  for _ in 1 2 3 4 5; do
    if grep -q REPLICATED "$log"; then return 0; fi
    sleep 10
    cli "$dir" resume --persona "$persona" | tee -a "$log" || true
  done
  grep -q REPLICATED "$log"
}

# --- secure-relay .onion: channel message published and read back
cli secure persona create --label tor-secure --relay "ws://$SECURE_ONION" --tor --high-risk > "$OUT/secure.persona.json" || fail "persona create (secure-relay onion)"
S=$(persona_id "$OUT/secure.persona.json")
TEXT="tor profile check $(date +%s)"
send_with_retry "$OUT/secure.send.log" secure "$S" channel send --persona "$S" --group tor-check "$TEXT" ||
  fail "channel message to the secure-relay .onion was not accepted (see $OUT/secure.send.log)"
cli secure channel read --persona "$S" --group tor-check | tee "$OUT/secure.read.log" || true
grep -qF "$TEXT" "$OUT/secure.read.log" || fail "the message published to the secure-relay .onion was not read back through Tor"
echo "ok - secure-relay .onion: published and read back through the compose Tor SOCKS port"

# --- relay (Buzz) .onion: NIP-17 DM from Tor persona A to Tor persona B, read back by B
cli buzz-a persona create --label tor-buzz-a --relay "ws://$RELAY_ONION" --tor --high-risk > "$OUT/buzz-a.persona.json" || fail "persona create A (relay onion)"
cli buzz-b persona create --label tor-buzz-b --relay "ws://$RELAY_ONION" --tor --high-risk > "$OUT/buzz-b.persona.json" || fail "persona create B (relay onion)"
A=$(persona_id "$OUT/buzz-a.persona.json")
B=$(persona_id "$OUT/buzz-b.persona.json")
B_PUB=$(pubkey_of "$OUT/buzz-b.persona.json")
[ -n "$B_PUB" ] || fail "could not read the pubkey of persona B"
DM="dm por onion $(date +%s)"
send_with_retry "$OUT/buzz.send.log" buzz-a "$A" dm send --persona "$A" --to "$B_PUB" "$DM" ||
  fail "NIP-17 DM to the relay (Buzz) .onion was not accepted; if the log shows auth errors, Buzz rejected the NIP-42 AUTH signed for ws://$RELAY_ONION (see $OUT/buzz.send.log)"
found=0
for _ in 1 2 3 4 5 6; do
  cli buzz-b dm inbox --persona "$B" > "$OUT/buzz.inbox.log" 2>&1 || true
  if grep -qF "$DM" "$OUT/buzz.inbox.log"; then found=1; break; fi
  sleep 5
done
cat "$OUT/buzz.inbox.log"
[ "$found" = 1 ] || fail "the DM was not read back from the relay (Buzz) .onion by its recipient (NIP-42 AUTH over the onion service; see $OUT/buzz.inbox.log)"
echo "ok - relay (Buzz) .onion: DM published and read back by the recipient through Tor"

"${COMPOSE[@]}" logs --no-color --tail 200 tor > "$OUT/tor.log" 2>&1 || true
echo "FR021-02: tor profile OK (relay and secure-relay onion services reachable and usable by the sovereign CLI)"
