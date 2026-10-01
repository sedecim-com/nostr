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
# FR020-06: then the same CLI as the compose service `sovereign`, run as docs/sovereign-tor.md says
# (`docker compose run --rm sovereign …`, TOR_SOCKS=tor:9050 on the internal network tor-socks, the passphrase and the
# backup password as secret files):
#   - what Docker applied to its container and what the container sees from inside (scripts/sovereign-sandbox.mjs):
#     no published port, non-root, no capabilities, read-only root filesystem, one internal network, no DNS or route
#     out, no secret in a variable or in the image, and an image with the CLI's production closure only;
#   - a channel message to the secure-relay .onion through tor:9050, read back;
#   - an encrypted backup taken out of the container and restored from a file;
#   - with tor stopped, a send that waits in the outbox with «No enviado: red de privacidad no disponible».
#
# Usage: bash scripts/tor-profile-check.sh              (starts relay, secure-relay, secure-relay-onion and tor with --build)
#        TOR_CHECK_SKIP_UP=1 bash scripts/tor-profile-check.sh   (stack already running)
#        TOR_CHECK_TIMEOUT=600 ...                      (seconds for bootstrap + onion reachability)
#        BUZZ_OPERATOR_SECRET=<hex>                     (key in the relay RELAY_OPERATOR_PUBKEYS; without it a
#                                                        throwaway operator key is generated for the relay started here)
# Results (CLI output, tor log; on failure also the logs of the relays behind the onions) in ./tor-profile-results or
# TOR_CHECK_OUT.
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
PROBE=
cleanup() {
  rm -rf "$DATA"
  if [ -n "$PROBE" ]; then docker rm -f "$PROBE" > /dev/null 2>&1 || true; fi
}
trap cleanup EXIT
# The task a failure belongs to: FR021-02 (the tor profile), then FR020-06 (the CLI as a compose service).
TASK=FR021-02

for bin in docker curl node; do
  command -v "$bin" > /dev/null || { echo "tor-profile-check: missing $bin" >&2; exit 2; }
done
[ -x "$TSX" ] || { echo "tor-profile-check: run npm ci first" >&2; exit 2; }

fail() {
  echo "FAIL ($TASK): $*" >&2
  # The relays behind the onions too: an event that stays QUEUED shows whether it ever reached them.
  local s
  for s in tor secure-relay-onion relay; do
    "${COMPOSE[@]}" logs --no-color --tail 200 "$s" > "$OUT/$s.log" 2>&1 || true
  done
  echo "--- last lines of the tor container (full log in $OUT/tor.log):" >&2
  tail -n 40 "$OUT/tor.log" >&2 || true
  echo "--- last lines of secure-relay-onion (full log in $OUT/secure-relay-onion.log; Buzz in $OUT/relay.log):" >&2
  tail -n 40 "$OUT/secure-relay-onion.log" >&2 || true
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

# --- FR020-06: the CLI as the compose service `sovereign`, run as the docs say: `docker compose run --rm sovereign …`
# with no --profile flag (running the service turns its profile on). Its stores go to the sovereign-data volume, sealed
# with the passphrase of a secret file; the backup password is another. Both are readable by the container user (not
# the runner): mode 644 inside $DATA, which only the runner can enter (mktemp -d), as docs/sovereign-tor.md suggests.
TASK=FR020-06
SOV_PASS="$DATA/sovereign-passphrase"
SOV_BACKUP_PASS="$DATA/sovereign-backup-password"
printf 'tor-profile-check %s\n' "$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')" > "$SOV_PASS"
printf 'backup %s\n' "$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')" > "$SOV_BACKUP_PASS"
chmod 644 "$SOV_PASS" "$SOV_BACKUP_PASS"
# sov_compose ARGS...: docker compose with the two secret files; svc [RUN OPTIONS] sovereign ARGS...: one command in it.
sov_compose() { SOVEREIGN_PASSPHRASE_FILE="$SOV_PASS" SOVEREIGN_BACKUP_PASSWORD_FILE="$SOV_BACKUP_PASS" timeout 180 docker compose "$@"; }
svc() { sov_compose run --rm -T "$@"; }
"${COMPOSE[@]}" build sovereign > "$OUT/sovereign.build.log" 2>&1 || fail "could not build the sovereign image (see $OUT/sovereign.build.log)"

# What Docker applied: a container of the service (sleeping), its image and its network, inspected from the host.
PROBE="sedecim-sovereign-probe-$$"
sov_compose run -d --name "$PROBE" --entrypoint sleep sovereign 300 > /dev/null 2> "$OUT/sovereign.probe.log" ||
  fail "could not start a container of the sovereign service (see $OUT/sovereign.probe.log)"
docker inspect "$PROBE" > "$OUT/sovereign.container.json"
docker image inspect "$(docker inspect -f '{{.Image}}' "$PROBE")" > "$OUT/sovereign.image.json"
SOV_NET=$(node -e 'console.log(Object.keys(JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"))[0].NetworkSettings.Networks)[0] || "none")' "$OUT/sovereign.container.json")
docker network inspect "$SOV_NET" > "$OUT/sovereign.network.json" 2>&1 || echo '[{}]' > "$OUT/sovereign.network.json"
docker rm -f "$PROBE" > /dev/null
PROBE=
node scripts/sovereign-sandbox.mjs inspect "$OUT/sovereign.container.json" "$OUT/sovereign.image.json" "$OUT/sovereign.network.json" "$SOV_PASS" | tee "$OUT/sovereign.sandbox.log" ||
  fail "the sovereign container is not configured as docker-compose.yml says: the 'not ok' lines above (inspect output in $OUT/sovereign.*.json)"
# What it sees from inside: the same checks as the CLI would run into (this script's checker mounted read-only).
svc -v "$ROOT/scripts/sovereign-sandbox.mjs:/sandbox-check.mjs:ro" --entrypoint node sovereign /sandbox-check.mjs inside > "$OUT/sovereign.inside.log" 2>&1 ||
  { cat "$OUT/sovereign.inside.log"; fail "from inside, the sovereign container is not what docker-compose.yml and the Dockerfile promise: the 'not ok' lines above"; }
cat "$OUT/sovereign.inside.log"
echo "ok - sovereign service: sandbox as configured (inspect) and as seen from inside"

# The CLI through tor:9050: a channel message to the secure-relay .onion, read back.
svc sovereign persona create --label tor-compose --relay "ws://$SECURE_ONION" --tor --high-risk > "$OUT/sovereign.persona.json" 2> "$OUT/sovereign.persona.log" ||
  fail "persona create in the sovereign service (see $OUT/sovereign.persona.log)"
C=$(persona_id "$OUT/sovereign.persona.json")
[ -n "$C" ] || fail "no persona id from the sovereign service (see $OUT/sovereign.persona.json)"
CTEXT="sovereign service $(date +%s)"
svc sovereign channel send --persona "$C" --group tor-check "$CTEXT" > "$OUT/sovereign.send.log" 2>&1 || true
for _ in 1 2 3 4 5; do
  if grep -q REPLICATED "$OUT/sovereign.send.log"; then break; fi
  sleep 10
  svc sovereign resume --persona "$C" >> "$OUT/sovereign.send.log" 2>&1 || true
done
grep -q REPLICATED "$OUT/sovereign.send.log" || fail "the sovereign service could not publish to the secure-relay .onion through tor:9050 (see $OUT/sovereign.send.log)"
for i in 1 2 3 4 5 6; do
  svc sovereign channel read --persona "$C" --group tor-check > "$OUT/sovereign.read.log" 2>&1 || true
  if grep -qF "$CTEXT" "$OUT/sovereign.read.log"; then break; fi
  sleep $((i * 5))
done
grep -qF "$CTEXT" "$OUT/sovereign.read.log" || fail "the message of the sovereign service was not read back through tor:9050 (see $OUT/sovereign.read.log)"
echo "ok - sovereign service: published to the secure-relay .onion and read back through tor:9050"

# scripts/backup.sh leaves sovereign-data out: the backup of a persona is the CLI's own, encrypted with the backup
# password. Written to the volume, taken out with cat (so the host file is the runner's), restored from a mounted file
# into another data directory. The copy stays in $DATA: it is not uploaded with the results.
svc --entrypoint rm sovereign -rf /data/tor-check-backup.json /data/tor-check-restore > /dev/null 2>&1 || true
svc sovereign backup export --persona "$C" --out /data/tor-check-backup.json --password-file /run/secrets/sovereign_backup_password > "$OUT/sovereign.backup.log" 2>&1 ||
  fail "backup export in the sovereign service (see $OUT/sovereign.backup.log)"
svc --entrypoint cat sovereign /data/tor-check-backup.json > "$DATA/sovereign-backup.json" 2>> "$OUT/sovereign.backup.log" ||
  fail "could not take the backup out of the sovereign-data volume (see $OUT/sovereign.backup.log)"
chmod 644 "$DATA/sovereign-backup.json"
{ grep -q '"format": "sedecim-identity-backup"' "$DATA/sovereign-backup.json" && grep -q '"ncryptsec": "ncryptsec1' "$DATA/sovereign-backup.json"; } ||
  fail "what came out of the container is not an encrypted identity backup (see $OUT/sovereign.backup.log)"
svc -e SOVEREIGN_DATA_DIR=/data/tor-check-restore -v "$DATA/sovereign-backup.json:/restore/backup.json:ro" sovereign backup restore /restore/backup.json --password-file /run/secrets/sovereign_backup_password > "$OUT/sovereign.restore.json" 2>> "$OUT/sovereign.backup.log" ||
  fail "backup restore in the sovereign service (see $OUT/sovereign.backup.log)"
[ "$(persona_id "$OUT/sovereign.restore.json")" = "$C" ] || fail "the restored backup is not persona $C (see $OUT/sovereign.restore.json)"
svc --entrypoint rm sovereign -rf /data/tor-check-backup.json /data/tor-check-restore > /dev/null 2>&1 || true
echo "ok - sovereign service: encrypted backup taken out of the container and restored from a file, passwords from secret files"

# Without tor the service has no way out (tor-socks is internal): the message waits in the outbox.
"${COMPOSE[@]}" stop tor > /dev/null 2>&1 || fail "could not stop tor"
svc --no-deps sovereign channel send --persona "$C" --group tor-check "sin tor" > "$OUT/sovereign.no-tor.log" 2>&1 || true
grep -q 'QUEUED — No enviado: red de privacidad no disponible' "$OUT/sovereign.no-tor.log" ||
  fail "with tor stopped the sovereign service did not hold the message as «No enviado: red de privacidad no disponible» (see $OUT/sovereign.no-tor.log)"
echo "ok - sovereign service with tor stopped: nothing sent, the message waits (No enviado: red de privacidad no disponible)"

"${COMPOSE[@]}" logs --no-color --tail 200 tor > "$OUT/tor.log" 2>&1 || true
echo "FR021-02, FR020-06: tor profile OK (relay and secure-relay onion services reachable and usable by the sovereign CLI, also as the compose service)"
