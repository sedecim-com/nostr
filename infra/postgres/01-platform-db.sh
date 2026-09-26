#!/bin/sh
# Creates the platform database (indexer + identity-service) next to Buzz's own database.
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-SQL
  CREATE DATABASE ${PLATFORM_DB:-sedecim};
SQL
