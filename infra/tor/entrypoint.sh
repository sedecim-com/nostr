#!/bin/sh
set -eu
chown -R tor /var/lib/tor
chmod 700 /var/lib/tor
( for i in $(seq 1 60); do
    if [ -f /var/lib/tor/relay/hostname ]; then echo "onion relay: ws://$(cat /var/lib/tor/relay/hostname)"; break; fi; sleep 2
  done ) &
exec su-exec tor tor -f /etc/tor/torrc
