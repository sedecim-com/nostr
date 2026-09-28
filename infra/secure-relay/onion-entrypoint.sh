#!/bin/sh
# Sovereign Tor Mode (compose profile `tor`): the secure relay behind its onion service (FR025-11).
# nostr-rs-relay accepts a NIP-42 AUTH only when the host of its `relay` tag is the host of relay_url, and a
# client that dials the onion signs for the onion. So relay_url must be the onion address, which exists only
# once Tor has created the service: the tor container publishes the hostname (never the key) in
# /var/lib/onion-names, and this renders the config from it before starting the relay.
set -eu
name=/var/lib/onion-names/secure-relay
i=0
until [ -s "$name" ]; do
  i=$((i + 1))
  [ "$i" -le 300 ] || { echo "secure-relay-onion: no onion hostname in $name after 300 s" >&2; exit 1; }
  sleep 1
done
host=$(tr -d ' \r\n' < "$name")
case "$host" in
  *[!a-z2-7.]* | *.*.* ) echo "secure-relay-onion: unexpected onion hostname '$host'" >&2; exit 1 ;;
  ????????????????????????????????????????????????????????.onion) ;;
  *) echo "secure-relay-onion: unexpected onion hostname '$host'" >&2; exit 1 ;;
esac
sed "s|^relay_url = .*|relay_url = \"ws://$host/\"|" /etc/secure-relay/config.toml > /tmp/config.toml
grep -qx "relay_url = \"ws://$host/\"" /tmp/config.toml || { echo "secure-relay-onion: relay_url not found in the config" >&2; exit 1; }
echo "secure-relay-onion: relay_url = ws://$host/"
exec ./nostr-rs-relay --db "${APP_DATA:-/usr/src/app/db}" --config /tmp/config.toml
