#!/usr/bin/env bash
# Leak tests with a real network capture (FR020-03) and egress allowlist per profile (FR022-02).
#
# Runs the real sovereign CLI inside a Linux network namespace whose only link is a veth pair to the
# host, captures every frame on that link with tcpdump, and checks the pcap (tests/leak/check.ts):
#   - Tor profile (sovereign-tor): zero DNS, zero IPv6, zero packets to anything but the SOCKS proxy;
#     every SOCKS CONNECT names an allowlisted relay by name (socks5h).
#   - Direct profile (sovereign): every connection goes to the persona's relays (its allowlist).
#   - Negative controls: deliberately leaky commands (DNS, DoH, direct TCP, IPv6, a destination outside
#     the allowlist) that the harness MUST detect, so the suite can actually fail.
#
# The "Tor" side is a local SOCKS5 stub (tests/leak/stub.ts) that maps a .onion name to an in-memory
# relay: deterministic, no Tor bootstrap. The property under test is that the client emits nothing
# except to the proxy; what sits behind the proxy is irrelevant to it (docs/sovereign-tor.md).
#
# Requirements: Linux, root (re-executes itself with sudo), iproute2, tcpdump, node + npm ci.
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
CMD_TIMEOUT=${LEAK_CMD_TIMEOUT:-120}

for bin in ip tcpdump node timeout; do
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
"$TSX" tests/leak/stub.ts --host "$HOST_IP" --relay-port "$RELAY_PORT" --socks-port "$SOCKS_PORT" --socks-log "$SOCKS_LOG" > "$OUT/stub.log" 2>&1 &
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

# profile_work NAME RELAY_URL TEXT [--tor --high-risk] : real work with the CLI (create, send, read, sync)
profile_work() {
  local name=$1 relay=$2 text=$3 id
  shift 3
  cli "$name" persona create --label "leak-$name" --relay "$relay" "$@" > "$OUT/$name.persona.json" || return 1
  cat "$OUT/$name.persona.json"
  id=$(sed -n 's/^ *"id": "\([^"]*\)".*/\1/p' "$OUT/$name.persona.json" | head -n 1)
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

# --- FR020-03: Tor profile, zero traffic outside the proxy
run_profile tor "ws://$ONION" --tor --high-risk
check tor --pcap "$OUT/tor.pcap" --socks "$HOST_IP:$SOCKS_PORT" --personas "$OUT/tor.personas.txt" --socks-log "$OUT/tor.socks.jsonl" --min-outbound 10

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
  { echo "### Leak tests (FR020-03 / FR022-02)"; echo '```'; cat "$SUMMARY"; echo '```'; } >> "$GITHUB_STEP_SUMMARY"
fi
chmod -R a+rX "$OUT"
[ "$FAILS" = 0 ]
