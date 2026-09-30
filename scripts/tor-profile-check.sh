#!/usr/bin/env bash
# FR021-02: validates the compose `tor` profile end to end. Starts the relays and the Tor container,
# waits for the onion service hostnames (tor-data volume), for Tor to bootstrap and for each onion to
# answer NIP-11 through the compose SOCKS port, then uses the real sovereign CLI in the Tor profile:
#   - secure-relay .onion: channel message published and read back (NIP-29 kind 9), and a NIP-17 DM read back
#     by its recipient (FR025-11: the onion instance's relay_url is the onion, so NIP-42 over it is accepted,
#     and the client authenticates before asking for gift wraps);
#   - relay (Buzz) .onion: NIP-17 DM between two Tor personas, read back by the recipient (NIP-42 AUTH
#     through the onion service). Buzz binds each connection to the community of its Host header, so the
#     onion host gets its own community first (scripts/buzz-provision-community.ts, operator NIP-98). Buzz
#     does not take DM relay lists (kind 10050), so this DM goes to the sender's relays, the same onion.
#
# Usage: bash scripts/tor-profile-check.sh              (starts relay, secure-relay, secure-relay-onion and tor with --build)
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
BOOTSTRAP_TIMEOUT=${TOR_CHECK_BOOTSTRAP_TIMEOUT:-600}
BOOTSTRAP_STALL=${TOR_CHECK_BOOTSTRAP_STALL:-180}
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
# The operator endpoint checks the NIP-98 `u` against this origin: the URL this script calls.
BUZZ_HTTP_URL=http://localhost:${RELAY_PORT:-3000}
export RELAY_OPERATOR_API_ORIGIN=${RELAY_OPERATOR_API_ORIGIN:-$BUZZ_HTTP_URL}

if [ "${TOR_CHECK_SKIP_UP:-0}" != 1 ]; then
  [ -f .env ] || sh scripts/init-env.sh
  "${COMPOSE[@]}" up -d --build relay secure-relay secure-relay-onion tor
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
BUZZ_HTTP_URL=$BUZZ_HTTP_URL "$TSX" scripts/buzz-provision-community.ts "$RELAY_ONION" > "$OUT/buzz.provision.log" 2>&1 ||
  fail "could not provision the Buzz community for $RELAY_ONION: $(cat "$OUT/buzz.provision.log") (RELAY_OPERATOR_PUBKEYS must hold the operator key and RELAY_OPERATOR_API_ORIGIN the URL called)"
cat "$OUT/buzz.provision.log"

# OPS-21: Tor can stall while loading relay descriptors (a slow directory mirror or guard): in one CI run it sat at
# 69% for five minutes. If the bootstrap makes no progress for BOOTSTRAP_STALL seconds, tor is restarted once; a new
# bootstrap picks other mirrors and guards. The onion keys are in the tor-data volume, so the addresses stay the same.
bootstrap_progress() { "${COMPOSE[@]}" logs --no-color tor 2> /dev/null | sed -n 's/.*Bootstrapped \([0-9]*\)%.*/\1/p' | tail -n 1; }
wait_bootstrap() {
  local start=$SECONDS since=$SECONDS last=-1 p restarted=0
  while :; do
    p=$(bootstrap_progress)
    p=${p:-0}
    if [ "$p" -ge 100 ]; then
      echo "ready: Tor bootstrap (Bootstrapped 100%) ($((SECONDS - start))s)"
      return 0
    fi
    if [ "$p" != "$last" ]; then
      last=$p
      since=$SECONDS
    elif [ "$restarted" = 0 ] && [ $((SECONDS - since)) -gt "$BOOTSTRAP_STALL" ]; then
      echo "  Tor bootstrap stalled at $p% for $((SECONDS - since))s: restarting tor once"
      "${COMPOSE[@]}" logs --no-color tor > "$OUT/tor.before-restart.log" 2>&1 || true
      "${COMPOSE[@]}" restart tor > /dev/null 2>&1 || fail "could not restart tor after the bootstrap stalled at $p%"
      restarted=1
      last=-1
      since=$SECONDS
    fi
    if [ $((SECONDS - start)) -gt "$BOOTSTRAP_TIMEOUT" ]; then
      fail "timeout after ${BOOTSTRAP_TIMEOUT}s waiting for Tor bootstrap (Bootstrapped 100%), last at $p%"
    fi
    sleep 3
  done
}
wait_bootstrap
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

# OPS-21: a DM goes to the DM relays its recipient published (kind 10050, FR017-06). Over a slow circuit that
# publish can stay QUEUED, and the DM would then go to the sender's relays instead. So the recipient's list is
# republished while it is QUEUED, before anyone writes to it. FAILED is the relay's answer, which the CLI prints:
# the secure relay must take the list. Buzz does not take kind 10050 (pass rejected-ok): there the DM goes to the
# sender's relays, which in this check are the same onion.
# dm_relays_ready LOG DIR PERSONA [rejected-ok]
dm_relays_ready() {
  local log=$1 dir=$2 persona=$3 rejected_ok=${4:-} start=$SECONDS rejected
  for i in 1 2 3 4 5 6; do
    if grep -q 'relays de DM (kind 10050): REPLICATED' "$log"; then
      echo "ok - $dir: DM relays (kind 10050) accepted by the relay after $((SECONDS - start))s (attempt $i)"
      return 0
    fi
    rejected=$(grep -m 1 'relays de DM (kind 10050): FAILED' "$log" || true)
    if [ -n "$rejected" ]; then
      [ -n "$rejected_ok" ] || return 1
      echo "ok - $dir: the relay does not take DM relay lists (FAILED${rejected#*FAILED}); the DM goes to the sender's relays, the same onion here"
      return 0
    fi
    sleep 10
    cli "$dir" dm relays --persona "$persona" >> "$log" 2>&1 || true
  done
  grep -q 'relays de DM (kind 10050): REPLICATED' "$log"
}

# read_until LOG DIR TEXT WHAT CMD...: runs the read command CMD until TEXT shows up. Each attempt keeps its output
# (LOG.N) and says how long it took, so a failure shows where the time went. OPS-21: over Tor a single read can end
# before the relay has answered with the event, even after the publish was accepted.
read_until() {
  local log=$1 dir=$2 text=$3 what=$4 start=$SECONDS t
  shift 4
  for i in 1 2 3 4 5 6 7 8; do
    t=$SECONDS
    cli "$dir" "$@" > "$log.$i" 2>&1 || true
    cp "$log.$i" "$log"
    if grep -qF "$text" "$log"; then
      echo "ok - $dir: $what read on attempt $i, $((SECONDS - start))s after the first"
      return 0
    fi
    echo "  $dir: attempt $i did not show the $what ($((SECONDS - t))s): $(tail -n 1 "$log")"
    sleep $((i * 5))
  done
  return 1
}

# read_dm LOG DIR PERSONA TEXT: reads the persona's DM inbox until TEXT shows up.
read_dm() { read_until "$1" "$2" "$4" DM dm inbox --persona "$3"; }

# --- secure-relay .onion: channel message published and read back
cli secure persona create --label tor-secure --relay "ws://$SECURE_ONION" --tor --high-risk > "$OUT/secure.persona.json" || fail "persona create (secure-relay onion)"
S=$(persona_id "$OUT/secure.persona.json")
TEXT="tor profile check $(date +%s)"
send_with_retry "$OUT/secure.send.log" secure "$S" channel send --persona "$S" --group tor-check "$TEXT" ||
  fail "channel message to the secure-relay .onion was not accepted (see $OUT/secure.send.log)"
read_until "$OUT/secure.read.log" secure "$TEXT" "channel message" channel read --persona "$S" --group tor-check ||
  fail "the message published to the secure-relay .onion was not read back through Tor (see $OUT/secure.read.log.*)"
cat "$OUT/secure.read.log"
echo "ok - secure-relay .onion: published and read back through the compose Tor SOCKS port"

# --- secure-relay .onion: NIP-17 DM from the Tor persona above to a second one, read back by the recipient
cli secure-b persona create --label tor-secure-b --relay "ws://$SECURE_ONION" --tor --high-risk > "$OUT/secure-b.persona.json" 2> "$OUT/secure-b.relays.log" || fail "persona create B (secure-relay onion)"
cat "$OUT/secure-b.relays.log"
SB=$(persona_id "$OUT/secure-b.persona.json")
SB_PUB=$(pubkey_of "$OUT/secure-b.persona.json")
[ -n "$SB_PUB" ] || fail "could not read the pubkey of persona B (secure-relay onion)"
dm_relays_ready "$OUT/secure-b.relays.log" secure-b "$SB" || fail "persona B could not publish its DM relays (kind 10050) to the secure-relay .onion (see $OUT/secure-b.relays.log)"
SDM="dm por el onion del secure relay $(date +%s)"
send_with_retry "$OUT/secure.dm.send.log" secure "$S" dm send --persona "$S" --to "$SB_PUB" "$SDM" ||
  fail "NIP-17 DM to the secure-relay .onion was not accepted (see $OUT/secure.dm.send.log)"
read_dm "$OUT/secure.inbox.log" secure-b "$SB" "$SDM" ||
  fail "the DM was not read back from the secure-relay .onion by its recipient: nostr-rs-relay only serves gift wraps after a NIP-42 AUTH for the host of its relay_url, which must be the onion (see $OUT/secure.inbox.log.* and the secure-relay-onion log)"
cat "$OUT/secure.inbox.log"
echo "ok - secure-relay .onion: DM read back by its recipient (NIP-42 through the onion service)"

# --- relay (Buzz) .onion: NIP-17 DM from Tor persona A to Tor persona B, read back by B
cli buzz-a persona create --label tor-buzz-a --relay "ws://$RELAY_ONION" --tor --high-risk > "$OUT/buzz-a.persona.json" || fail "persona create A (relay onion)"
cli buzz-b persona create --label tor-buzz-b --relay "ws://$RELAY_ONION" --tor --high-risk > "$OUT/buzz-b.persona.json" 2> "$OUT/buzz-b.relays.log" || fail "persona create B (relay onion)"
cat "$OUT/buzz-b.relays.log"
A=$(persona_id "$OUT/buzz-a.persona.json")
B=$(persona_id "$OUT/buzz-b.persona.json")
B_PUB=$(pubkey_of "$OUT/buzz-b.persona.json")
[ -n "$B_PUB" ] || fail "could not read the pubkey of persona B"
dm_relays_ready "$OUT/buzz-b.relays.log" buzz-b "$B" rejected-ok || fail "persona B's DM relays (kind 10050) got no answer from the relay (Buzz) .onion (see $OUT/buzz-b.relays.log)"
DM="dm por onion $(date +%s)"
send_with_retry "$OUT/buzz.send.log" buzz-a "$A" dm send --persona "$A" --to "$B_PUB" "$DM" ||
  fail "NIP-17 DM to the relay (Buzz) .onion was not accepted; if the log shows auth errors, Buzz rejected the NIP-42 AUTH signed for ws://$RELAY_ONION (see $OUT/buzz.send.log)"
read_dm "$OUT/buzz.inbox.log" buzz-b "$B" "$DM" ||
  fail "the DM was not read back from the relay (Buzz) .onion by its recipient (NIP-42 AUTH over the onion service; see $OUT/buzz.inbox.log.*)"
cat "$OUT/buzz.inbox.log"
echo "ok - relay (Buzz) .onion: DM published and read back by the recipient through Tor"

"${COMPOSE[@]}" logs --no-color --tail 200 tor > "$OUT/tor.log" 2>&1 || true
echo "FR021-02: tor profile OK (relay and secure-relay onion services reachable and usable by the sovereign CLI)"
