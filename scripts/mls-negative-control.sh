#!/usr/bin/env bash
# FR020-05: negative control of the MLS self-test (FR025-02).
#
# ts-mls <= 2.0.0-rc.10 sent a single Remove without an UpdatePath, so the removed member could read the next epoch
# (docs/marmot.md). The repository overrides ts-mls to a fixed release, and every session runs `assertRemovalSecrecy`
# before opening groups and fails closed. This script proves the guard still catches the bug:
#   1. swaps every installed copy of ts-mls for 2.0.0-rc.10 (the npm tarball, pinned by its integrity);
#   2. the self-test must fail closed (scripts/mls-selftest.ts exits 3);
#   3. restores the installed copies; the self-test must pass again.
# The copies are restored on any exit, also when a step fails.
#
# Requirements: node + npm ci, access to the npm registry (npm pack).
# Usage: bash scripts/mls-negative-control.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
TSX="$ROOT/node_modules/.bin/tsx"
VULNERABLE=2.0.0-rc.10
# npm view ts-mls@2.0.0-rc.10 dist.integrity
INTEGRITY='sha512-4FFbkysQkJlVaUv4fs7ZC4wuiwTOCgX/bEMo2fFGngy/QofC/lvWWgsScKuGxEIhEf4e2Q8APfJ7DknP0VRCoA=='

[ -x "$TSX" ] || { echo "mls-negative-control: run npm ci first ($TSX missing)" >&2; exit 2; }

# Every copy node can load: hoisted, or nested under a dependency or a workspace.
mapfile -t COPIES < <(find node_modules apps/*/node_modules packages/*/node_modules services/*/node_modules \
  -type d -path '*/node_modules/ts-mls' -prune 2> /dev/null | sort)
[ "${#COPIES[@]}" -gt 0 ] || { echo "mls-negative-control: ts-mls is not installed" >&2; exit 2; }

version() { node -p "require('./$1/package.json').version"; }
selftest() { # selftest : exit code of scripts/mls-selftest.ts
  local code=0
  "$TSX" scripts/mls-selftest.ts || code=$?
  return "$code"
}

WORK=$(mktemp -d)
SWAPPED=()
restore() {
  local i
  for i in "${!SWAPPED[@]}"; do
    rm -rf "${SWAPPED[$i]}"
    mv "$WORK/installed-$i" "${SWAPPED[$i]}"
  done
  SWAPPED=()
}
cleanup() {
  set +e
  restore
  rm -rf "$WORK"
}
trap cleanup EXIT

INSTALLED=()
for dir in "${COPIES[@]}"; do
  INSTALLED+=("$(version "$dir")")
  echo "installed: $dir (ts-mls ${INSTALLED[-1]})"
  if [ "${INSTALLED[-1]}" = "$VULNERABLE" ]; then
    echo "mls-negative-control: $dir is already the vulnerable $VULNERABLE (check the override in package.json)" >&2
    exit 1
  fi
done

# --- baseline: the installed copies pass
code=0
selftest || code=$?
[ "$code" = 0 ] || { echo "mls-negative-control: the self-test fails with the installed ts-mls (exit $code)" >&2; exit 1; }

# --- the vulnerable release, verified against the pinned integrity
TARBALL=$(npm pack "ts-mls@$VULNERABLE" --pack-destination "$WORK" --silent | tail -n 1)
GOT="sha512-$(node -e "process.stdout.write(require('node:crypto').createHash('sha512').update(require('node:fs').readFileSync(process.argv[1])).digest('base64'))" "$WORK/$TARBALL")"
if [ "$GOT" != "$INTEGRITY" ]; then
  echo "mls-negative-control: integrity mismatch for ts-mls@$VULNERABLE: $GOT" >&2
  exit 1
fi
mkdir "$WORK/vulnerable"
tar -xzf "$WORK/$TARBALL" -C "$WORK/vulnerable" --strip-components=1

for i in "${!COPIES[@]}"; do
  mv "${COPIES[$i]}" "$WORK/installed-$i"
  SWAPPED[i]=${COPIES[$i]}
  cp -R "$WORK/vulnerable" "${COPIES[$i]}"
  [ "$(version "${COPIES[$i]}")" = "$VULNERABLE" ] || { echo "mls-negative-control: swap failed in ${COPIES[$i]}" >&2; exit 1; }
  echo "swapped: ${COPIES[$i]} (ts-mls $VULNERABLE)"
done

code=0
selftest || code=$?
if [ "$code" != 3 ]; then
  echo "mls-negative-control: FAIL: with ts-mls $VULNERABLE the self-test must fail closed (exit 3), got exit $code" >&2
  exit 1
fi
echo "with ts-mls $VULNERABLE: the self-test fails closed, as it must"

# --- restored: the installed copies pass again
restore
for i in "${!COPIES[@]}"; do
  [ "$(version "${COPIES[$i]}")" = "${INSTALLED[$i]}" ] || { echo "mls-negative-control: ${COPIES[$i]} was not restored" >&2; exit 1; }
done
code=0
selftest || code=$?
[ "$code" = 0 ] || { echo "mls-negative-control: the self-test fails after restoring ts-mls (exit $code)" >&2; exit 1; }
echo "mls-negative-control: OK (fails closed with $VULNERABLE, passes with ${INSTALLED[*]})"
