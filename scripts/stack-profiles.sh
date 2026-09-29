#!/bin/sh
# NFR006-04: the optional profiles of the stack (managed, push, institutional, tor) also run in the CI `stack` job, and
# their logs are scanned for secrets with the rest (NFR006-03, scripts/scan-logs.sh).
#
#   sh scripts/stack-profiles.sh configure [ENV_FILE]   turn the profiles on (COMPOSE_PROFILES) with the secrets
#        they need, generated here so that the scan knows them: the managed signer's KEK, the push gateway's keys,
#        the allowlist sync token (added to POLICY_SERVICE_TOKENS) and an admin key of the policy-engine for the
#        institutional check (FR023-13). The Acceso pool is a placeholder: the signer starts and turns every token
#        away, so nobody can sign in. For test stacks, never for a real deployment.
#   sh scripts/stack-profiles.sh exercise [ENV_FILE]    send each service a request carrying a canary credential,
#        kept in ENV_FILE as STACK_CANARY_TOKEN, so the scan also checks that no service logs what it is sent.
#   sh scripts/stack-profiles.sh logged LOGFILE         fail unless every service of the stack wrote to LOGFILE
#        (`docker compose logs --no-color`): a service that logged nothing was not scanned.
set -eu

PROFILES=managed,push,institutional,tor
cmd=${1:-}
[ $# -gt 0 ] && shift

rand() { od -An -tx1 -N"$1" /dev/urandom | tr -d ' \n'; }
current() { sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1; }
set_value() {
  tmp=$(mktemp)
  grep -v "^$1=" "$ENV_FILE" > "$tmp" || true
  printf '%s=%s\n' "$1" "$2" >> "$tmp"
  cat "$tmp" > "$ENV_FILE"
  rm -f "$tmp"
}
fill() {
  v=$(current "$1")
  if [ -z "$v" ] || [ "$v" = CHANGE_ME ]; then set_value "$1" "$2"; fi
}

case "$cmd" in
  configure)
    ENV_FILE=${1:-.env}
    [ -f "$ENV_FILE" ] || { echo "stack-profiles: $ENV_FILE not found (run scripts/init-env.sh first)" >&2; exit 2; }
    # Idempotent, like init-env.sh: what is already set stays.
    profiles=$(current COMPOSE_PROFILES)
    for p in $(echo "$PROFILES" | tr ',' ' '); do
      case ",$profiles," in *",$p,"*) ;; *) profiles=${profiles:+$profiles,}$p ;; esac
    done
    set_value COMPOSE_PROFILES "$profiles"
    fill MANAGED_SIGNER_KEK "$(rand 32)"
    fill COGNITO_USER_POOL_ID us-east-1_stackci
    fill COGNITO_CLIENT_ID stack-ci
    fill NOTIFY_NSEC "$(rand 32)"
    # A P-256 private key (base64url), as generateVapidKeys makes it; without one the gateway uses an ephemeral key.
    fill NOTIFY_VAPID_PRIVATE_KEY "$(node -e "console.log(require('node:crypto').generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({ format: 'jwk' }).d)")"
    fill RELAY_ALLOWLIST_POLICY_TOKEN "$(rand 24)"
    token=$(current RELAY_ALLOWLIST_POLICY_TOKEN)
    tokens=$(current POLICY_SERVICE_TOKENS)
    case ",$tokens," in *",$token:"*) ;; *) set_value POLICY_SERVICE_TOKENS "${tokens:+$tokens,}$token:relay-allowlist" ;; esac
    # FR023-13: an admin of the policy-engine for the institutional check (tests/interop/institutional.interop.test.ts).
    # Its secret only lives here, where the scan also looks for it; the allowlist syncs every 2 s instead of 30 s.
    if [ -z "$(current POLICY_ADMIN_SECRET_KEY)" ]; then
      keys=$(node --input-type=module -e "import { schnorr } from '@noble/curves/secp256k1.js'; const sk = schnorr.utils.randomSecretKey(); const hex = (b) => Buffer.from(b).toString('hex'); console.log(hex(sk), hex(schnorr.getPublicKey(sk)))")
      set_value POLICY_ADMIN_SECRET_KEY "${keys% *}"
      admins=$(current POLICY_ADMIN_PUBKEYS)
      set_value POLICY_ADMIN_PUBKEYS "${admins:+$admins,}${keys#* }"
    fi
    fill ALLOWLIST_SYNC_INTERVAL_MS 2000
    echo "stack-profiles: $profiles on in $ENV_FILE"
    ;;
  exercise)
    ENV_FILE=${1:-.env}
    canary=$(rand 24)
    set_value STACK_CANARY_TOKEN "$canary"
    # Where a credential goes: Acceso tokens (managed signer, identity service), service tokens (policy engine),
    # device sessions and push registrations. Each answer is only printed: the scan decides.
    for target in \
      "GET http://localhost:8084/v1/keys" \
      "POST http://localhost:8084/v1/device-sessions" \
      "GET http://localhost:8086/v1/relays" \
      "POST http://localhost:8086/v1/subscriptions" \
      "GET http://localhost:8083/v1/relay/allowlist" \
      "GET http://localhost:8082/v1/accounts/me/external-logins"; do
      method=${target%% *}
      url=${target#* }
      set -- -s -o /dev/null -w '%{http_code}' -X "$method" -H "Authorization: Bearer $canary"
      [ "$method" = GET ] || set -- "$@" -H 'Content-Type: application/json' --data "{\"token\":\"$canary\",\"endpoint\":\"https://push.example/$canary\"}"
      code=$(curl "$@" "$url" || true)
      echo "$method $url -> ${code:-no answer}"
    done
    ;;
  logged)
    LOG=${1:?usage: stack-profiles.sh logged LOGFILE}
    missing=0
    for service in $(docker compose config --services); do
      if ! grep -q "^$service-[0-9][0-9]* *|" "$LOG"; then
        echo "stack-profiles: $service wrote nothing to $LOG, so its logs were not scanned"
        missing=1
      fi
    done
    [ "$missing" -eq 0 ] && echo "stack-profiles: every service of the stack is in $LOG"
    exit "$missing"
    ;;
  *)
    echo "usage: sh scripts/stack-profiles.sh configure|exercise [ENV_FILE] | logged LOGFILE" >&2
    exit 2
    ;;
esac
