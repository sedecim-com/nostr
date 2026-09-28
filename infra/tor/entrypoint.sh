#!/bin/sh
set -eu
chown -R tor /var/lib/tor
chmod 700 /var/lib/tor
( for i in $(seq 1 60); do
    if [ -f /var/lib/tor/relay/hostname ] && [ -f /var/lib/tor/secure-relay/hostname ]; then
      # Hostnames only, never the keys, for the services that must know their own onion (secure-relay-onion).
      if [ -d /var/lib/onion-names ]; then
        for s in relay secure-relay; do cp /var/lib/tor/$s/hostname /var/lib/onion-names/$s; chmod 644 /var/lib/onion-names/$s; done
      fi
      echo "onion relay (Buzz): ws://$(cat /var/lib/tor/relay/hostname)"
      echo "onion secure relay (Marmot/Tor): ws://$(cat /var/lib/tor/secure-relay/hostname)"
      break
    fi; sleep 2
  done ) &
exec su-exec tor tor -f /etc/tor/torrc
