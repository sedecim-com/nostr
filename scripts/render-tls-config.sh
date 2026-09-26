#!/bin/sh
# Renders per-domain config that cannot come from env vars (nostr-rs-relay reads relay_url from its file).
set -eu
: "${DOMAIN:?set DOMAIN}"
sed "s#^relay_url = .*#relay_url = \"wss://secure.${DOMAIN}/\"#" infra/secure-relay/config.toml > infra/secure-relay/config.tls.toml
echo "infra/secure-relay/config.tls.toml -> wss://secure.${DOMAIN}/"
