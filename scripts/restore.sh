#!/bin/sh
# Restores a backup made by scripts/backup.sh on a CLEAN host (docs/runbooks/restore.md, NFR-003):
#
#   sh scripts/restore.sh DIR
#
# 1. Verifies SHA256SUMS.   2. Puts DIR/.env in place if there is no .env (an existing one must match).
# 3. `docker compose up --no-start` creates the volumes (none may exist before); the volume archives replace
#    whatever the images seeded into them.
# 4. Starts Postgres alone (its init script creates the platform database) and pg_restores both dumps.
# 5. Starts the whole stack. Wait for it with scripts/wait-stack.sh and run the drill checks.
# The Continuity Vault comes back with them: its rows in the platform dump, its envelopes in seaweedfs-data.
# Optional services (managed-signer, tor) are restored when their profile is enabled (COMPOSE_PROFILES).
set -eu
umask 077

DIR=${1:?usage: restore.sh BACKUP_DIR}
[ -d "$DIR" ] || { echo "restore: $DIR not found" >&2; exit 1; }
DIR=$(cd "$DIR" && pwd)
TOOL_IMAGE=${BACKUP_TOOL_IMAGE:-postgres:17-alpine}
ENV_FILE=${ENV_FILE:-.env}
TIMEOUT=${RESTORE_TIMEOUT:-300}

log() { printf '==> %s\n' "$*"; }
die() { echo "restore: $*" >&2; exit 1; }
sha256_check() { if command -v sha256sum > /dev/null 2>&1; then sha256sum -c --quiet SHA256SUMS; else shasum -a 256 -c --quiet SHA256SUMS; fi; }
cid_of() { docker compose ps -a -q "$1" 2>/dev/null | head -n 1; }
volume_at() { docker inspect -f "{{ range .Mounts }}{{ if eq .Destination \"$2\" }}{{ .Name }}{{ end }}{{ end }}" "$1"; }

log "checking $DIR/SHA256SUMS"
[ -f "$DIR/SHA256SUMS" ] || die "$DIR/SHA256SUMS missing: not a scripts/backup.sh backup"
(cd "$DIR" && sha256_check) || die "checksum mismatch: the backup is damaged"

if [ -f "$DIR/.env" ]; then
  if [ ! -f "$ENV_FILE" ]; then
    cp "$DIR/.env" "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    log "$ENV_FILE restored from the backup"
  elif ! cmp -s "$DIR/.env" "$ENV_FILE"; then
    die "$ENV_FILE differs from the one in the backup: move it away (the relay key must be the backed-up one)"
  fi
fi
[ -f "$ENV_FILE" ] || die "no $ENV_FILE: restore it from its offline copy first"

[ -z "$(docker compose ps -a -q 2>/dev/null)" ] || die "the stack already has containers: restore needs a clean host (docker compose down -v)"
PROJECT=${COMPOSE_PROJECT_NAME:-sedecim-nostr}
[ -z "$(docker volume ls -q --filter "label=com.docker.compose.project=$PROJECT")" ] ||
  die "the stack already has volumes: restore needs a clean host (docker compose down -v)"

log "creating containers and empty volumes (docker compose up --no-start)"
docker compose up --no-start

for entry in relay:/data/git:relay-git seaweedfs:/data:seaweedfs-data blob-store:/data:blob-data \
  secure-relay:/usr/src/app/db:secure-relay-data secure-relay-onion:/usr/src/app/db:secure-relay-onion-data \
  managed-signer:/data:managed-vault tor:/var/lib/tor:tor-data; do
  svc=${entry%%:*}
  rest=${entry#*:}
  path=${rest%%:*}
  name=${rest#*:}
  [ -f "$DIR/$name.tgz" ] || continue
  cid=$(cid_of "$svc")
  if [ -z "$cid" ]; then
    log "$name: service $svc is not enabled here (COMPOSE_PROFILES?), NOT restored"
    continue
  fi
  vol=$(volume_at "$cid" "$path")
  [ -n "$vol" ] || die "no volume mounted at $path in $svc"
  # The volume was created just now (no volumes existed above); anything in it was copied from the image
  # (e.g. seaweedfs ships /data), so it is replaced by the backed-up content.
  log "$name → volume $vol"
  docker run --rm -v "$vol:/dst" -v "$DIR:/backup:ro" --entrypoint sh "$TOOL_IMAGE" -c \
    'find /dst -mindepth 1 -delete && tar --numeric-owner -C /dst -xzpf "/backup/$1.tgz"' sh "$name"
done

log "starting Postgres"
docker compose up -d postgres
start=$(date +%s)
# TCP check: the entrypoint's temporary init server only listens on the socket; this waits for the real one
# (and thus for 01-platform-db.sh).
until docker compose exec -T postgres sh -c 'pg_isready -q -h 127.0.0.1 -U "$POSTGRES_USER" -d "$PLATFORM_DB"' 2>/dev/null; do
  [ $(( $(date +%s) - start )) -lt "$TIMEOUT" ] || die "timeout waiting for Postgres"
  sleep 2
done

log "pg_restore: Buzz database"
docker compose exec -T postgres sh -c 'exec pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --no-owner --exit-on-error' < "$DIR/postgres-buzz.dump"
log "pg_restore: platform database"
docker compose exec -T postgres sh -c 'exec pg_restore -U "$POSTGRES_USER" -d "$PLATFORM_DB" --no-owner --exit-on-error' < "$DIR/postgres-platform.dump"

log "starting the stack"
docker compose up -d
log "restored from $DIR. Next: sh scripts/wait-stack.sh && npm run test:interop (see docs/runbooks/restore.md)"
