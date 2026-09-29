#!/bin/sh
# Creates or completes .env from .env.example (OPS-03). Idempotent: an existing value is never overwritten;
# only missing, empty or CHANGE_ME entries are filled, so it is safe to re-run after upgrades.
#
# Nostr keys come from the offline key generator (apps/key-generator) when the dependencies are installed
# (npm ci): the relay signing key and the mirror identity (hex, they live in .env) and the relay owner, whose
# secret never touches .env: only RELAY_OWNER_PUBKEY does, and the key goes to an encrypted NIP-49 backup.
# Without the dependencies, service keys fall back to 32 random bytes and the owner is skipped.
#
#   ENV_FILE             file to create/complete (default .env)
#   OWNER_BACKUP         owner backup path (default .data/relay-owner.ncryptsec.json)
#   OWNER_PASSWORD_FILE  backup password for non-interactive runs (otherwise it is asked on the terminal)
set -eu
umask 077
ROOT=$(cd "$(dirname "$0")/.." && pwd)
ENV_FILE=${ENV_FILE:-.env}
OWNER_BACKUP=${OWNER_BACKUP:-.data/relay-owner.ncryptsec.json}

if [ ! -f "$ENV_FILE" ]; then
  cp "$ROOT/.env.example" "$ENV_FILE"
  echo "$ENV_FILE created from .env.example"
fi
chmod 600 "$ENV_FILE"

rand() { od -An -tx1 -N"$1" /dev/urandom | tr -d ' \n'; }
current() { sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1; }
missing() {
  v=$(current "$1")
  [ -z "$v" ] || [ "$v" = CHANGE_ME ]
}
is_hex64() {
  case "$1" in *[!0-9a-f]* | '') return 1 ;; esac
  [ ${#1} -eq 64 ]
}
set_value() {
  if grep -q "^$1=" "$ENV_FILE"; then
    tmp=$(mktemp)
    sed "s|^$1=.*|$1=$2|" "$ENV_FILE" > "$tmp" && cat "$tmp" > "$ENV_FILE"
    rm -f "$tmp"
  else
    printf '%s=%s\n' "$1" "$2" >> "$ENV_FILE"
  fi
  echo "  $1 generated"
}
fill_random() { if missing "$1"; then set_value "$1" "$(rand "$2")"; fi; }

has_keygen() { command -v node > /dev/null 2>&1 && [ -x "$ROOT/node_modules/.bin/tsx" ]; }
keygen() { "$ROOT/node_modules/.bin/tsx" "$ROOT/apps/key-generator/src/cli.ts" "$@"; }

# Service identity kept in .env as 64 hex chars.
fill_service_key() {
  missing "$1" || return 0
  if has_keygen; then
    k=$(keygen service-key --i-understand | sed -n 's/^secret_hex=//p')
    is_hex64 "$k" || { echo "key generator failed for $1" >&2; exit 1; }
  else
    echo "  $1: key generator unavailable (run 'npm ci' first to use it); using 32 random bytes"
    k=$(rand 32)
  fi
  set_value "$1" "$k"
}

fill_random POSTGRES_PASSWORD 24
fill_random REDIS_PASSWORD 24
fill_random S3_ACCESS_KEY 12
fill_random S3_SECRET_KEY 24
fill_random VAULT_S3_ACCESS_KEY 12
fill_random VAULT_S3_SECRET_KEY 24
fill_random BUZZ_GIT_HOOK_HMAC_SECRET 32
fill_service_key BUZZ_RELAY_PRIVATE_KEY
fill_service_key INDEXER_NSEC

if missing RELAY_OWNER_PUBKEY; then
  skip="RELAY_OWNER_PUBKEY left empty; set it to an existing pubkey (hex) or re-run this script"
  if ! has_keygen; then
    echo "  $skip after 'npm ci'"
  elif [ -e "$OWNER_BACKUP" ]; then
    echo "  $OWNER_BACKUP already exists: $skip after moving it away"
  elif [ -z "${OWNER_PASSWORD_FILE:-}" ] && [ ! -t 0 ]; then
    echo "  $skip interactively or with OWNER_PASSWORD_FILE"
  else
    mkdir -p "$(dirname "$OWNER_BACKUP")"
    out=$(mktemp)
    echo "Relay owner key (offline generator). Its secret is only written to an encrypted backup (NIP-49)."
    if [ -n "${OWNER_PASSWORD_FILE:-}" ]; then
      keygen --out "$OWNER_BACKUP" --password-file "$OWNER_PASSWORD_FILE" | tee "$out"
    else
      keygen --out "$OWNER_BACKUP" | tee "$out"
    fi
    pk=$(sed -n 's/^pubkey hex: *//p' "$out")
    rm -f "$out"
    is_hex64 "$pk" || { echo "key generator failed for RELAY_OWNER_PUBKEY" >&2; exit 1; }
    set_value RELAY_OWNER_PUBKEY "$pk"
    echo "Owner backup written to $OWNER_BACKUP: move it offline and keep the password separately."
    echo "Verify it with: npm run keygen -- verify $OWNER_BACKUP"
  fi
fi

echo "$ENV_FILE ready. Review it before 'docker compose up -d'."
