#!/bin/sh
# FR025-08: watches npm for the stable releases the Marmot provider waits for (docs/marmot.md).
# Today marmot-adapter pins @internet-privacy/marmot-ts 0.5.1 (alpha) on ts-mls 2.0.0-rc.16 (override):
# there is no stable ts-mls 2.x nor marmot-ts 1.x yet. This script only detects and reports; the
# migration itself is a reviewed PR (checklist printed by `body`).
#
#   sh scripts/marmot-upstream.sh check
#       Queries the npm registry and prints key=value lines (for $GITHUB_OUTPUT):
#       ts_mls / marmot_ts         newest stable version at or above the target major (empty if none)
#       pinned_ts_mls / pinned_marmot_ts   what the repo pins now
#       available                  true if at least one of them has a stable release
#   sh scripts/marmot-upstream.sh body TS_MLS MARMOT_TS
#       Prints the issue body (Markdown) with the versions found and the migration checklist.
#
# Needs curl and jq. NPM_REGISTRY (default https://registry.npmjs.org), TS_MLS_MIN_MAJOR (2) and
# MARMOT_TS_MIN_MAJOR (1) can be overridden.
set -eu
REGISTRY=${NPM_REGISTRY:-https://registry.npmjs.org}
TS_MLS_MIN_MAJOR=${TS_MLS_MIN_MAJOR:-2}
MARMOT_TS_MIN_MAJOR=${MARMOT_TS_MIN_MAJOR:-1}
ADAPTER=packages/marmot-adapter/package.json

# Newest stable (no prerelease/build suffix) version of package $1 with major >= $2, or nothing.
newest_stable() {
  # Scoped names are URL-encoded as @scope%2fname.
  name=$(printf '%s' "$1" | sed 's|/|%2f|')
  doc=$(curl -fsSL -H 'Accept: application/vnd.npm.install-v1+json' "$REGISTRY/$name") || return 1
  printf '%s' "$doc" | jq -r --argjson min "$2" '
      [.versions | keys[] | select(test("^[0-9]+\\.[0-9]+\\.[0-9]+$"))
        | split(".") | map(tonumber) | select(.[0] >= $min)]
      | sort | last // empty | map(tostring) | join(".")'
}

pinned() { jq -r --arg dep "$1" '.dependencies[$dep] // empty' "$ADAPTER"; }

check() {
  ts_mls=$(newest_stable ts-mls "$TS_MLS_MIN_MAJOR") || { echo "could not query $REGISTRY for ts-mls" >&2; exit 1; }
  marmot_ts=$(newest_stable @internet-privacy/marmot-ts "$MARMOT_TS_MIN_MAJOR") || { echo "could not query $REGISTRY for @internet-privacy/marmot-ts" >&2; exit 1; }
  # Registry data ends up in $GITHUB_OUTPUT and in an issue: keep only well-formed versions.
  printf '%s' "$ts_mls" | grep -Eq '^([0-9]+\.[0-9]+\.[0-9]+)?$' || ts_mls=''
  printf '%s' "$marmot_ts" | grep -Eq '^([0-9]+\.[0-9]+\.[0-9]+)?$' || marmot_ts=''
  echo "ts_mls=$ts_mls"
  echo "marmot_ts=$marmot_ts"
  echo "pinned_ts_mls=$(pinned ts-mls)"
  echo "pinned_marmot_ts=$(pinned @internet-privacy/marmot-ts)"
  if [ -n "$ts_mls" ] || [ -n "$marmot_ts" ]; then echo "available=true"; else echo "available=false"; fi
}

body() {
  ts_mls=${1:-} marmot_ts=${2:-}
  echo "La revisión mensual de Marmot upstream (FR025-08, \`scripts/marmot-upstream.sh\`) encontró versiones estables:"
  echo
  echo "| Paquete | Fijado | Estable disponible |"
  echo "|---|---|---|"
  echo "| \`ts-mls\` | \`$(pinned ts-mls)\` (override) | ${ts_mls:-ninguna ≥ $TS_MLS_MIN_MAJOR.0.0} |"
  echo "| \`@internet-privacy/marmot-ts\` | \`$(pinned @internet-privacy/marmot-ts)\` | ${marmot_ts:-ninguna ≥ $MARMOT_TS_MIN_MAJOR.0.0} |"
  echo
  echo "Migración (una PR revisada; no se migra solo):"
  echo
  echo "- [ ] Leer los changelogs: kinds, extensiones MLS (0xf2ee, last_resort, SelfRemove/\`mls_proposals\`), formato de kind 445 y del key package."
  echo "- [ ] Subir la dependencia en \`packages/marmot-adapter/package.json\` y el \`overrides\` de \`ts-mls\` en \`package.json\` (quitar el override si marmot-ts ya pide un ts-mls estable ≥ 2.0.0-rc.11); \`npm install\` y commit de \`package-lock.json\`."
  echo "- [ ] Actualizar \`MARMOT_TS_VERSION\` / \`TS_MLS_VERSION\` en \`packages/marmot-adapter/src/marmot-ts.ts\` y la tabla de docs/marmot.md."
  echo "- [ ] \`npx vitest run packages/marmot-adapter tests/fuzz\` en verde (conformidad + fuzz del codec MLS)."
  echo "- [ ] La autoprueba \`assertRemovalSecrecy\` pasa (la ejecuta la suite de marmot-adapter y cada \`openSession\`): el expulsado no descifra la época siguiente."
  echo "- [ ] Job \`marmot-mdk\` de CI (interop con MDK, \`tests/interop/marmot-mdk.interop.test.ts\`) en verde; revisar si se resuelven las incompatibilidades conocidas (\`mls_proposals\`, lifetime) y actualizar \`docs/interop/\`."
  echo "- [ ] \`MARMOT_RELAY_URL=ws://localhost:7000 npm run test:interop\` contra el secure-relay (job \`stack\`)."
}

case "${1:-}" in
  check) check ;;
  body) shift; body "$@" ;;
  *) echo "usage: $0 check | body TS_MLS MARMOT_TS" >&2; exit 2 ;;
esac
