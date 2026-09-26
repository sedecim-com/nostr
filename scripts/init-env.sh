#!/bin/sh
# Generates .env with random secrets from .env.example. Never overwrites an existing .env.
set -eu
[ -f .env ] && { echo ".env already exists; not overwriting"; exit 1; }
rand() { od -An -tx1 -N"$1" /dev/urandom | tr -d ' \n'; }
sed -e "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$(rand 24)/" \
    -e "s/^REDIS_PASSWORD=.*/REDIS_PASSWORD=$(rand 24)/" \
    -e "s/^S3_ACCESS_KEY=.*/S3_ACCESS_KEY=$(rand 12)/" \
    -e "s/^S3_SECRET_KEY=.*/S3_SECRET_KEY=$(rand 24)/" \
    -e "s/^BUZZ_RELAY_PRIVATE_KEY=.*/BUZZ_RELAY_PRIVATE_KEY=$(rand 32)/" \
    -e "s/^BUZZ_GIT_HOOK_HMAC_SECRET=.*/BUZZ_GIT_HOOK_HMAC_SECRET=$(rand 32)/" \
    .env.example > .env
chmod 600 .env
echo ".env created. Review it before 'docker compose up -d'."
