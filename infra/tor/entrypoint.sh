#!/bin/sh
set -eu
chown -R tor /var/lib/tor
chmod 700 /var/lib/tor
( for i in $(seq 1 60); do
    if [ -f /var/lib/tor/relay/hostname ] && [ -f /var/lib/tor/secure-relay/hostname ]; then
      echo "onion relay (Buzz): ws://$(cat /var/lib/tor/relay/hostname)"
      echo "onion secure relay (Marmot/Tor): ws://$(cat /var/lib/tor/secure-relay/hostname)"
      break
    fi; sleep 2
  done ) &
exec su-exec tor tor -f /etc/tor/torrc
