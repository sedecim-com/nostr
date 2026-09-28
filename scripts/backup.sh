#!/bin/sh
# Operator backup of the self-hosted stack (docs/runbooks/restore.md, NFR-003). Run from the repo root
# next to the running `docker compose` stack:
#
#   sh scripts/backup.sh [--no-env] [DIR]        (default DIR: .data/backups/<UTC timestamp>)
#
# - Postgres: pg_dump (custom format) of Buzz's database and of the platform database (mirror, identity,
#   managed-signer registry).
# - Volumes: tar of relay-git, seaweedfs-data (Buzz media), blob-data (encrypted attachments),
#   secure-relay-data and, when those services run, managed-vault, tor-data and secure-relay-onion-data. Each service is paused
#   (`docker compose pause`) during its copy, so the archive is a consistent snapshot (a few seconds).
# - .env (relay key and every stack secret), unless --no-env: keep the backup directory encrypted/offline.
# - SHA256SUMS over everything, checked by scripts/restore.sh.
# Redis is not backed up: it only holds caches and pub/sub state (docs/rpo-rto.md).
set -eu
umask 077

WITH_ENV=1
if [ "${1:-}" = "--no-env" ]; then WITH_ENV=0; shift; fi
DIR=${1:-.data/backups/$(date -u +%Y%m%dT%H%M%SZ)}
TOOL_IMAGE=${BACKUP_TOOL_IMAGE:-postgres:17-alpine}
ENV_FILE=${ENV_FILE:-.env}

mkdir -p "$DIR"
DIR=$(cd "$DIR" && pwd)
[ -z "$(ls -A "$DIR")" ] || { echo "backup: $DIR is not empty" >&2; exit 1; }

log() { printf '==> %s\n' "$*"; }
sha256() { if command -v sha256sum > /dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }

cid_of() { docker compose ps -q "$1" 2>/dev/null | head -n 1; }
# Name of the volume mounted at $2 in container $1.
volume_at() { docker inspect -f "{{ range .Mounts }}{{ if eq .Destination \"$2\" }}{{ .Name }}{{ end }}{{ end }}" "$1"; }

[ -n "$(cid_of postgres)" ] || { echo "backup: the stack is not running (docker compose up -d)" >&2; exit 1; }

log "Postgres (pg_dump -Fc)"
docker compose exec -T postgres sh -c 'exec pg_dump -U "$POSTGRES_USER" -Fc -d "$POSTGRES_DB"' > "$DIR/postgres-buzz.dump"
docker compose exec -T postgres sh -c 'exec pg_dump -U "$POSTGRES_USER" -Fc -d "$PLATFORM_DB"' > "$DIR/postgres-platform.dump"

paused=
cleanup() { [ -z "$paused" ] || docker compose unpause "$paused" > /dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM

# service  mount path  archive name
for entry in relay:/data/git:relay-git seaweedfs:/data:seaweedfs-data blob-store:/data:blob-data \
  secure-relay:/usr/src/app/db:secure-relay-data secure-relay-onion:/usr/src/app/db:secure-relay-onion-data \
  managed-signer:/data:managed-vault tor:/var/lib/tor:tor-data; do
  svc=${entry%%:*}
  rest=${entry#*:}
  path=${rest%%:*}
  name=${rest#*:}
  cid=$(cid_of "$svc")
  if [ -z "$cid" ]; then
    log "$name: service $svc not running, skipped"
    continue
  fi
  vol=$(volume_at "$cid" "$path")
  [ -n "$vol" ] || { echo "backup: no volume mounted at $path in $svc" >&2; exit 1; }
  log "$name (volume $vol, $svc paused during the copy)"
  docker compose pause "$svc" > /dev/null
  paused=$svc
  docker run --rm -v "$vol:/src:ro" -v "$DIR:/backup" --entrypoint tar "$TOOL_IMAGE" \
    --numeric-owner -C /src -czf "/backup/$name.tgz" .
  docker compose unpause "$svc" > /dev/null
  paused=
done

if [ "$WITH_ENV" -eq 1 ]; then
  [ -f "$ENV_FILE" ] || { echo "backup: $ENV_FILE not found (use --no-env to skip it)" >&2; exit 1; }
  cp "$ENV_FILE" "$DIR/.env"
fi

{
  echo "created=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "commit=$(git rev-parse HEAD 2>/dev/null || echo unknown)"
  sed -n 's/^BUZZ_IMAGE=/buzz_image=/p' infra/buzz/PIN 2>/dev/null || true
} > "$DIR/INFO"

# Every name here is ours (dumps, archives, INFO, .env): no spaces.
# The list is built outside DIR: a temporary file inside it would be listed by the glob (and then renamed away).
sums=$(mktemp)
(cd "$DIR" && for f in * .env; do if [ -f "$f" ]; then sha256 "$f"; fi; done) > "$sums"
mv "$sums" "$DIR/SHA256SUMS"
log "backup written to $DIR ($(du -sh "$DIR" | cut -f1))"
[ "$WITH_ENV" -eq 0 ] || echo "   it contains .env (every secret of the stack): store it encrypted and offline"
