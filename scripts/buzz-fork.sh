#!/bin/sh
# Controlled Buzz fork workflow (spec §6.3). Run inside your fork clone of block/buzz.
#   vendor/upstream  : exact mirror of the pinned upstream commit (never modified)
#   product/main     : our minimal patches (prefer adapters in this repo over relay patches)
set -eu
. "$(dirname "$0")/../infra/buzz/PIN"
git remote get-url upstream >/dev/null 2>&1 || git remote add upstream "$BUZZ_UPSTREAM"
git fetch upstream "$BUZZ_COMMIT"
git branch -f vendor/upstream "$BUZZ_COMMIT"
echo "vendor/upstream -> $BUZZ_COMMIT"
echo "Next: git checkout product/main && git merge --no-ff vendor/upstream"
echo "Then run the interop gate against the new build: BUZZ_RELAY_URL=ws://... npm run test:interop"
