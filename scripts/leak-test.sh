#!/usr/bin/env bash
# Leak tests with a real network capture (FR020-03) and egress allowlist per profile (FR022-02).
#
# Runs the real sovereign CLI inside a Linux network namespace whose only link is a veth pair to the
# host, captures every frame on that link with tcpdump, and checks the pcap (tests/leak/check.ts):
#   - Tor profile (sovereign-tor): zero DNS, zero IPv6, zero packets to anything but the SOCKS proxy;
#     every SOCKS CONNECT names an allowlisted relay by name (socks5h).
#   - Direct profile (sovereign): every connection goes to the persona's relays (its allowlist).
#   - Groups over Tor (FR020-05): two Tor personas, each with its own data dir, work together through the proxy
#     only: MLS group (key package, invitation, messages), encrypted group media on a Blossom onion, a NIP-17 DM,
#     and the rotation worker removing a revoked member for a policy-engine behind its own onion.
#   - Negative controls: deliberately leaky commands (DNS, DoH, direct TCP, IPv6, a destination outside
#     the allowlist) that the harness MUST detect, so the suite can actually fail.
#
# The "Tor" side is a local SOCKS5 stub (tests/leak/stub.ts) that maps .onion names to an in-memory relay, a
# Blossom server and a policy-engine: deterministic, no Tor bootstrap. The property under test is that the client emits nothing
# except to the proxy; what sits behind the proxy is irrelevant to it (docs/sovereign-tor.md).
#
# Requirements: Linux, root (re-executes itself with sudo), iproute2, tcpdump, curl, node + npm ci.
# Usage: bash scripts/leak-test.sh            (results in ./leak-results, or LEAK_OUT)
#        LEAK_REQUIRE_IPV6=1 bash scripts/leak-test.sh   (fail if the kernel has no IPv6: CI)
set -euo pipefail

if [ "$(id -u)" != 0 ]; then
  exec sudo env "PATH=$PATH" "LEAK_OUT=${LEAK_OUT:-}" "LEAK_REQUIRE_IPV6=${LEAK_REQUIRE_IPV6:-}" bash "$0" "$@"
fi

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
OUT=${LEAK_OUT:-$ROOT/leak-results}
TSX="$ROOT/node_modules/.bin/tsx"
NS=acceso-leak
VH=aleak-host
VN=aleak-ns
HOST_IP=10.200.0.1
NS_IP=10.200.0.2
HOST_IP6=fd00:acce:55::1
NS_IP6=fd00:acce:55::2
RELAY_PORT=7777
SOCKS_PORT=9050
ONION=accesoleaktestrelayaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion
BLOB_ONION=accesoleaktestblobbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion
POLICY_ONION=accesoleaktestpolicycccccccccccccccccccccccccccccccccccc.onion
# Host side only (127.0.0.1, outside the namespace): sets the stub's policy-engine up for the rotation worker.
CONTROL_PORT=7780
CMD_TIMEOUT=${LEAK_CMD_TIMEOUT:-120}

for bin in ip tcpdump node timeout curl; do
  command -v "$bin" > /dev/null || { echo "leak-test: missing $bin" >&2; exit 2; }
done
[ -x "$TSX" ] || { echo "leak-test: run npm ci first ($TSX missing)" >&2; exit 2; }

rm -rf "$OUT"
mkdir -p "$OUT"
chmod 755 "$OUT"
DATA=$(mktemp -d /tmp/acceso-leak-data.XXXXXX)
STUB_PID=""
CAP_PID=""
HAVE_IPV6=0
FAILS=0
SUMMARY="$OUT/summary.txt"
: > "$SUMMARY"

cleanup() {
  set +e
  [ -n "$CAP_PID" ] && kill -INT "$CAP_PID" 2> /dev/null
  [ -n "$STUB_PID" ] && kill "$STUB_PID" 2> /dev/null
  ip netns del "$NS" 2> /dev/null
  ip link del "$VH" 2> /dev/null
  rm -rf "/etc/netns/$NS" "$DATA"
  if command -v iptables > /dev/null; then iptables -D FORWARD -i "$VH" -j DROP 2> /dev/null; fi
  if command -v ip6tables > /dev/null; then ip6tables -D FORWARD -i "$VH" -j DROP 2> /dev/null; fi
}
trap cleanup EXIT

record() { # record PASS|FAIL NAME
  echo "$1 $2" | tee -a "$SUMMARY"
  if [ "$1" = FAIL ]; then FAILS=$((FAILS + 1)); fi
}

# --- namespace: one veth to the host, default route through it so that any leak becomes a packet on
# the captured link (the host never forwards it: FORWARD is dropped for this interface).
cleanup
trap cleanup EXIT
ip netns add "$NS"
ip link add "$VH" type veth peer name "$VN"
ip link set "$VN" netns "$NS"
ip addr add "$HOST_IP/30" dev "$VH"
ip link set "$VH" up
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip addr add "$NS_IP/30" dev "$VN"
ip netns exec "$NS" ip link set "$VN" up
ip netns exec "$NS" ip route add default via "$HOST_IP"
if command -v iptables > /dev/null; then iptables -I FORWARD -i "$VH" -j DROP; fi
# `ip netns exec` bind-mounts /etc/netns/$NS/resolv.conf: a DNS attempt goes to the host side, captured.
mkdir -p "/etc/netns/$NS"
echo "nameserver $HOST_IP" > "/etc/netns/$NS/resolv.conf"
# Name lookups must hit the wire: without this, glibc's nss-resolve / nss-mdns would ask the HOST's
# systemd-resolved / avahi over a unix socket and a DNS leak would never appear in the capture.
printf 'passwd: files\ngroup: files\nshadow: files\nhosts: files dns\n' > "/etc/netns/$NS/nsswitch.conf"

if [ -d /proc/sys/net/ipv6 ]; then
  HAVE_IPV6=1
  # Explicitly enabled on both ends (some hosts ship disable_ipv6=1 as the default for new links).
  sysctl -qw "net.ipv6.conf.$VH.disable_ipv6=0" || true
  for conf in all default "$VN"; do
    ip netns exec "$NS" sysctl -qw "net.ipv6.conf.$conf.disable_ipv6=0" "net.ipv6.conf.$conf.accept_ra=0" "net.ipv6.conf.$conf.router_solicitations=0" || true
  done
  ip -6 addr add "$HOST_IP6/64" dev "$VH" nodad
  ip netns exec "$NS" ip -6 addr add "$NS_IP6/64" dev "$VN" nodad
  ip netns exec "$NS" ip -6 route add default via "$HOST_IP6"
  if command -v ip6tables > /dev/null; then ip6tables -I FORWARD -i "$VH" -j DROP; fi
elif [ "${LEAK_REQUIRE_IPV6:-}" = 1 ]; then
  echo "leak-test: this kernel has no IPv6 and LEAK_REQUIRE_IPV6=1" >&2
  exit 2
else
  echo "leak-test: kernel without IPv6: the IPv6 negative control is skipped (IPv6 leaks are impossible here)"
fi
CLIENTS=$NS_IP
if [ "$HAVE_IPV6" = 1 ]; then CLIENTS="$NS_IP,$NS_IP6"; fi
sleep 1 # let the kernel's own link chatter (MLD/ND after link up) settle before capturing

# --- host side: relay + SOCKS stub standing in for Tor
SOCKS_LOG="$OUT/socks.jsonl"
: > "$SOCKS_LOG"
"$TSX" tests/leak/stub.ts --host "$HOST_IP" --relay-port "$RELAY_PORT" --socks-port "$SOCKS_PORT" --socks-log "$SOCKS_LOG" \
  --control-port "$CONTROL_PORT" > "$OUT/stub.log" 2>&1 &
STUB_PID=$!
for _ in $(seq 1 100); do
  if grep -q 'leak stub ready' "$OUT/stub.log"; then break; fi
  sleep 0.2
done
grep -q 'leak stub ready' "$OUT/stub.log" || { cat "$OUT/stub.log"; echo "leak-test: stub did not start" >&2; exit 1; }

capture_start() { # capture_start NAME
  ip netns exec "$NS" tcpdump -i "$VN" -n -U -Z root -s 160 -w "$OUT/$1.pcap" 2> "$OUT/$1.tcpdump.log" &
  CAP_PID=$!
  for _ in $(seq 1 50); do
    if grep -q 'listening on' "$OUT/$1.tcpdump.log"; then return 0; fi
    sleep 0.2
  done
  cat "$OUT/$1.tcpdump.log" >&2
  echo "leak-test: tcpdump did not start" >&2
  exit 1
}

capture_stop() {
  sleep 1 # trailing FIN/RST and late retransmissions
  kill -INT "$CAP_PID"
  wait "$CAP_PID" || true
  CAP_PID=""
}

in_ns() { # in_ns CMD... : run inside the namespace, time-bounded
  ip netns exec "$NS" timeout "$CMD_TIMEOUT" "$@"
}

cli() { # cli PROFILE ARGS... : the real sovereign CLI inside the namespace
  local profile=$1
  shift
  in_ns env SOVEREIGN_DATA_DIR="$DATA/$profile" SOVEREIGN_PASSPHRASE=leak-test-passphrase \
    TOR_SOCKS="$HOST_IP:$SOCKS_PORT" SOVEREIGN_FLAGS=/nonexistent "$TSX" apps/sovereign-client/src/cli.ts "$@"
}

check() { # check NAME ARGS... : verdict of tests/leak/check.ts
  local name=$1
  shift
  if "$TSX" tests/leak/check.ts --label "$name" --client "$CLIENTS" --report "$OUT/$name.report.json" "$@" 2>&1 | tee "$OUT/$name.check.log"; then
    record PASS "$name"
  else
    record FAIL "$name"
  fi
}

json_field() { # json_field FIELD FILE : a top-level string field of the CLI's persona JSON
  sed -n "s/^  \"$1\": \"\([^\"]*\)\".*/\1/p" "$2" | head -n 1
}

# profile_work NAME RELAY_URL TEXT [--tor --high-risk] : real work with the CLI (create, send, read, sync)
profile_work() {
  local name=$1 relay=$2 text=$3 id
  shift 3
  cli "$name" persona create --label "leak-$name" --relay "$relay" "$@" > "$OUT/$name.persona.json" || return 1
  cat "$OUT/$name.persona.json"
  id=$(json_field id "$OUT/$name.persona.json")
  [ -n "$id" ] || return 1
  cli "$name" channel send --persona "$id" --group leaktest "$text" || return 1
  cli "$name" channel read --persona "$id" --group leaktest || return 1
  cli "$name" history sync --persona "$id" || return 1
  cli "$name" persona list > "$OUT/$name.personas.txt" || return 1
}

# run_profile NAME RELAY_URL [--tor --high-risk] : profile_work while capturing the namespace link
run_profile() {
  local name=$1 relay=$2
  shift 2
  local log="$OUT/$name.cli.log" text
  text="leak test $name $(date +%s) https://leak-canary.example/preview.png"
  : > "$SOCKS_LOG"
  capture_start "$name"
  local ok=1
  profile_work "$name" "$relay" "$text" "$@" > "$log" 2>&1 || ok=0
  capture_stop
  cp "$SOCKS_LOG" "$OUT/$name.socks.jsonl"
  cat "$log"
  if [ "$ok" = 1 ] && grep -q 'REPLICATED' "$log" && grep -qF "$text" "$log"; then record PASS "$name-cli-real-work"; else record FAIL "$name-cli-real-work"; fi
}

# groups_work GROUP_TEXT DM_TEXT : two Tor personas (two users, each with its own data dir) through the proxy only
groups_work() {
  local group_text=$1 dm_text=$2 relay="ws://$ONION" a b pa pb gid sha
  cli tor-a persona create --label leak-tor-a --relay "$relay" --tor --high-risk > "$OUT/tor-a.persona.json" || return 1
  cli tor-b persona create --label leak-tor-b --relay "$relay" --tor --high-risk > "$OUT/tor-b.persona.json" || return 1
  a=$(json_field id "$OUT/tor-a.persona.json")
  pa=$(json_field pubkey "$OUT/tor-a.persona.json")
  b=$(json_field id "$OUT/tor-b.persona.json")
  pb=$(json_field pubkey "$OUT/tor-b.persona.json")
  [ -n "$a" ] && [ -n "$pa" ] && [ -n "$b" ] && [ -n "$pb" ] || return 1
  echo "persona A $a ($pa), persona B $b ($pb)"
  # MLS over Tor: key package, group, invitation (Welcome), messages
  cli tor-b group keypackage --persona "$b" || return 1
  cli tor-a group create --persona "$a" --name leak-group > "$OUT/tor-groups.create.txt" || return 1
  cat "$OUT/tor-groups.create.txt"
  gid=$(awk 'NR == 1 { print $1 }' "$OUT/tor-groups.create.txt")
  [ -n "$gid" ] || return 1
  cli tor-a group invite --persona "$a" --group "$gid" --to "$pb" || return 1
  cli tor-b group accept --persona "$b" || return 1
  cli tor-a group send --persona "$a" --group "$gid" "$group_text" || return 1
  # Group media (MIP-04): encrypted by A, uploaded to the Blossom onion; downloaded and decrypted by B
  printf 'leak test file %s\n' "$group_text" > "$DATA/leak-file.txt"
  cli tor-a group send-file --persona "$a" --group "$gid" --file "$DATA/leak-file.txt" --server "http://$BLOB_ONION" "adjunto" || return 1
  cli tor-b group read --persona "$b" --group "$gid" | tee "$OUT/tor-groups.read.txt" || return 1
  sha=$(sed -n 's/.*--sha \([0-9a-f]\{64\}\).*/\1/p' "$OUT/tor-groups.read.txt" | head -n 1)
  [ -n "$sha" ] || return 1
  cli tor-b group fetch-file --persona "$b" --group "$gid" --sha "$sha" --out "$DATA/leak-file.out" || return 1
  if cmp "$DATA/leak-file.txt" "$DATA/leak-file.out"; then echo "FILE-ROUNDTRIP-OK"; else return 1; fi
  # NIP-17 DM from A to B's DM relays (kind 10050, published by persona create)
  cli tor-a dm send --persona "$a" --to "$pb" "$dm_text" || return 1
  cli tor-b dm inbox --persona "$b" || return 1
  # Rotation worker: the organisation revokes a device of B (policy-engine behind its onion, set up from the host);
  # A, group admin and policy admin (NIP-98), removes B with an MLS commit and marks the rotation done
  curl -fsS -X POST --data "{\"pubkey\":\"$pa\"}" "http://127.0.0.1:$CONTROL_PORT/admin" || return 1
  curl -fsS -X POST --data "{\"groupId\":\"$gid\",\"member\":\"$pb\"}" "http://127.0.0.1:$CONTROL_PORT/revoke" || return 1
  echo
  cli tor-a group rotation-worker --persona "$a" --policy "http://$POLICY_ONION" --once | tee "$OUT/tor-groups.rotation.txt" || return 1
  { cli tor-a persona list && cli tor-b persona list; } > "$OUT/tor-groups.personas.txt" || return 1
  echo "$a" > "$OUT/tor-groups.ids.txt"
  echo "$b" >> "$OUT/tor-groups.ids.txt"
}

# run_groups : groups_work while capturing the namespace link
run_groups() {
  local log="$OUT/tor-groups.cli.log" stamp group_text dm_text ok=1 onion id covered=1
  stamp=$(date +%s)
  group_text="leak test group $stamp"
  dm_text="leak test dm $stamp"
  : > "$SOCKS_LOG"
  capture_start tor-groups
  groups_work "$group_text" "$dm_text" > "$log" 2>&1 || ok=0
  capture_stop
  cp "$SOCKS_LOG" "$OUT/tor-groups.socks.jsonl"
  cat "$log"
  if [ "$ok" = 1 ] && grep -qF ": $group_text" "$OUT/tor-groups.read.txt" && grep -q 'FILE-ROUNDTRIP-OK' "$log" \
    && grep -qF ": $dm_text" "$log" && grep -Eq '^[0-9a-f]+  removed  epoch=' "$OUT/tor-groups.rotation.txt"; then
    record PASS tor-groups-cli-real-work
  else
    record FAIL tor-groups-cli-real-work
  fi
  # What the phase is about went through the proxy: the three onions, and each persona under its own credentials.
  for onion in "$ONION" "$BLOB_ONION" "$POLICY_ONION"; do
    grep -qF "\"host\":\"$onion\"" "$OUT/tor-groups.socks.jsonl" || { echo "no SOCKS CONNECT to $onion"; covered=0; }
  done
  while read -r id; do
    grep -qF "\"username\":\"$id\"" "$OUT/tor-groups.socks.jsonl" || { echo "no SOCKS CONNECT by persona $id"; covered=0; }
  done < <(cat "$OUT/tor-groups.ids.txt" 2> /dev/null || true)
  if [ "$ok" = 1 ] && [ "$covered" = 1 ]; then record PASS tor-groups-socks-coverage; else record FAIL tor-groups-socks-coverage; fi
}

# --- FR020-03: Tor profile, zero traffic outside the proxy
run_profile tor "ws://$ONION" --tor --high-risk
check tor --pcap "$OUT/tor.pcap" --socks "$HOST_IP:$SOCKS_PORT" --personas "$OUT/tor.personas.txt" --socks-log "$OUT/tor.socks.jsonl" --min-outbound 10

# --- FR020-05: groups, media, DM and rotation worker over Tor, two personas in one capture
run_groups
check tor-groups --pcap "$OUT/tor-groups.pcap" --socks "$HOST_IP:$SOCKS_PORT" --personas "$OUT/tor-groups.personas.txt" --all-personas \
  --socks-log "$OUT/tor-groups.socks.jsonl" --socks-allow "$BLOB_ONION:80" --socks-allow "$POLICY_ONION:80" --min-outbound 20

# --- FR022-02: direct profile (sovereign), every destination inside the persona allowlist
run_profile direct "ws://$HOST_IP:$RELAY_PORT"
check direct --pcap "$OUT/direct.pcap" --socks "$HOST_IP:$SOCKS_PORT" --personas "$OUT/direct.personas.txt" --socks-log "$OUT/direct.socks.jsonl" --min-outbound 10

# --- negative controls: the harness must see each of these leaks
TOR_ALLOW="tcp/$HOST_IP:$SOCKS_PORT"
negative() { # negative NAME EXPECT CHECK_ARGS -- LEAKY_ARGS...
  local name=$1 expect=$2 allow=$3
  shift 3
  capture_start "$name"
  in_ns "$TSX" tests/leak/leaky.ts "$@" > "$OUT/$name.cli.log" 2>&1 || true
  capture_stop
  if [ "$allow" = personas-direct ]; then
    check "$name" --pcap "$OUT/$name.pcap" --socks "$HOST_IP:$SOCKS_PORT" --personas "$OUT/direct.personas.txt" --expect "$expect"
  else
    check "$name" --pcap "$OUT/$name.pcap" --allow "$allow" --expect "$expect"
  fi
}
negative neg-dns-libc dns "$TOR_ALLOW" dns-libc
negative neg-dns-cares dns "$TOR_ALLOW" dns-cares
negative neg-doh doh "$TOR_ALLOW" doh
negative neg-direct direct "$TOR_ALLOW" direct "$HOST_IP:$RELAY_PORT"
negative neg-egress direct personas-direct direct "$HOST_IP:8443"
if [ "$HAVE_IPV6" = 1 ]; then
  negative neg-ipv6 ipv6 "$TOR_ALLOW" ipv6 "[$HOST_IP6]:443"
fi
# The real client's direct-profile traffic judged by the Tor policy must be flagged (bypassing the proxy).
check neg-cli-bypass --pcap "$OUT/direct.pcap" --allow "$TOR_ALLOW" --expect direct

echo "--- leak tests: $FAILS failure(s)"
cat "$SUMMARY"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  { echo "### Leak tests (FR020-03 / FR020-05 / FR022-02)"; echo '```'; cat "$SUMMARY"; echo '```'; } >> "$GITHUB_STEP_SUMMARY"
fi
chmod -R a+rX "$OUT"
[ "$FAILS" = 0 ]
