#!/usr/bin/env bash
# Builds the Kubernetes Secret `acceso-nostr-secrets` from AWS Secrets Manager.
#
#   SECRET_ID                     JSON key/value secret (default k8s/stage/acceso-nostr, created by
#                                 deploy/terraform without a value)
#   SIGNER_CREDENTIALS_SECRET_ID  {"id","secret"} of the managed-signer IAM user (Terraform)
#   SECRET_FILE                   output (default deploy/k8s/secret.yaml, git-ignored, mode 600)
#
# --bootstrap fills SECRET_ID the first time: values generated with scripts/init-env.sh (same generator as
# the self-hosted .env) and stored with put-secret-value. It never overwrites an existing value.
# DRY_RUN=1 (default) only reports what it would do; DRY_RUN=0 or --yes writes.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

DRY_RUN="${DRY_RUN:-1}"
BOOTSTRAP=0
WITH_SIGNER=1

usage() {
  cat <<EOF
Uso: $0 [--bootstrap] [--no-signer] [--yes|--dry-run]

Genera ${SECRET_FILE} desde Secrets Manager (${SECRET_ID}).
  --bootstrap   Si ${SECRET_ID} no tiene valor, lo crea con scripts/init-env.sh
  --no-signer   No incluir las credenciales del managed-signer (${SIGNER_CREDENTIALS_SECRET_ID})
  --yes, -y     Escribe (DRY_RUN=0)
  --dry-run     Solo muestra el plan (default)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bootstrap) BOOTSTRAP=1; shift ;;
    --no-signer) WITH_SIGNER=0; shift ;;
    --yes|-y) DRY_RUN=0; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "arg desconocido: $1" ;;
  esac
done

command -v aws >/dev/null || die "falta aws CLI"
command -v python3 >/dev/null || die "falta python3"

REQUIRED=(POSTGRES_PASSWORD REDIS_PASSWORD S3_ACCESS_KEY S3_SECRET_KEY BUZZ_RELAY_PRIVATE_KEY BUZZ_GIT_HOOK_HMAC_SECRET INDEXER_NSEC GRAFANA_ADMIN_PASSWORD)
OPTIONAL=(MIRROR_AT_REST_KEY POLICY_SERVICE_TOKENS INDEXER_POLICY_ENGINE_TOKEN RELAY_ALLOWLIST_POLICY_TOKEN MANAGED_SIGNER_REVOCATION_TOKENS)

get_secret() {
  aws secretsmanager get-secret-value --region "${AWS_REGION}" --secret-id "$1" --query SecretString --output text 2>/dev/null
}

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT
chmod 700 "${TMP}"

if ! get_secret "${SECRET_ID}" > "${TMP}/stack.json"; then
  [[ "${BOOTSTRAP}" -eq 1 ]] || die "${SECRET_ID} no existe o no tiene valor (terraform apply del módulo + $0 --bootstrap)"
  log "bootstrap de ${SECRET_ID} con scripts/init-env.sh"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "  (dry-run) generaría ${REQUIRED[*]} y aws secretsmanager put-secret-value --secret-id ${SECRET_ID}"
    exit 0
  fi
  # Non-interactive: without OWNER_PASSWORD_FILE and a terminal, init-env.sh skips the relay owner key.
  ENV_FILE="${TMP}/stack.env" sh "${ROOT}/scripts/init-env.sh" < /dev/null > /dev/null
  printf 'GRAFANA_ADMIN_PASSWORD=%s\n' "$(od -An -tx1 -N24 /dev/urandom | tr -d ' \n')" >> "${TMP}/stack.env"
  python3 - "${TMP}/stack.env" "${TMP}/stack.json" "${REQUIRED[@]}" "${OPTIONAL[@]}" <<'PY'
import json, sys
env, out, keys = sys.argv[1], sys.argv[2], sys.argv[3:]
vals = {}
for line in open(env, encoding="utf-8"):
    line = line.rstrip("\n")
    if "=" in line and not line.lstrip().startswith("#"):
        k, v = line.split("=", 1)
        vals[k] = v
json.dump({k: vals.get(k, "") for k in keys}, open(out, "w", encoding="utf-8"))
PY
  aws secretsmanager put-secret-value --region "${AWS_REGION}" --secret-id "${SECRET_ID}" \
    --secret-string "file://${TMP}/stack.json" > /dev/null
  log "${SECRET_ID} inicializado"
fi

if [[ "${WITH_SIGNER}" -eq 1 ]]; then
  get_secret "${SIGNER_CREDENTIALS_SECRET_ID}" > "${TMP}/signer.json" \
    || die "no se pudo leer ${SIGNER_CREDENTIALS_SECRET_ID} (terraform: create_iam_users = true) o usa --no-signer"
else
  echo '{}' > "${TMP}/signer.json"
fi

if [[ "${DRY_RUN}" -eq 1 ]]; then
  python3 - "${TMP}/stack.json" "${REQUIRED[@]}" <<'PY'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
missing = [k for k in sys.argv[2:] if not data.get(k)]
print("  (dry-run) claves presentes:", ", ".join(sorted(k for k, v in data.items() if v)))
if missing:
    sys.exit("faltan claves obligatorias: " + ", ".join(missing))
PY
  echo "  (dry-run) escribiría ${SECRET_FILE} (namespace ${NAMESPACE})"
  exit 0
fi

umask 077
python3 - "${TMP}/stack.json" "${TMP}/signer.json" "${SECRET_FILE}" "${NAMESPACE}" "${REQUIRED[*]}" "${OPTIONAL[*]}" "${WITH_SIGNER}" <<'PY'
import json, sys
stack_path, signer_path, out, ns, required, optional, with_signer = sys.argv[1:]
stack = json.load(open(stack_path, encoding="utf-8"))
signer = json.load(open(signer_path, encoding="utf-8"))
data = {k: str(stack.get(k, "")) for k in required.split() + optional.split()}
missing = [k for k in required.split() if not data[k]]
if with_signer == "1":
    data["MANAGED_SIGNER_AWS_ACCESS_KEY_ID"] = str(signer.get("id", ""))
    data["MANAGED_SIGNER_AWS_SECRET_ACCESS_KEY"] = str(signer.get("secret", ""))
    missing += [k for k in ("MANAGED_SIGNER_AWS_ACCESS_KEY_ID", "MANAGED_SIGNER_AWS_SECRET_ACCESS_KEY") if not data[k]]
if missing:
    sys.exit("faltan claves obligatorias: " + ", ".join(missing))
lines = ["apiVersion: v1", "kind: Secret", "metadata:", "  name: acceso-nostr-secrets", f"  namespace: {ns}",
         "  labels:", "    app.kubernetes.io/part-of: acceso-nostr", "type: Opaque", "stringData:"]
# json.dumps yields valid double-quoted YAML scalars for any value.
lines += [f"  {k}: {json.dumps(v)}" for k, v in sorted(data.items())]
with open(out, "w", encoding="utf-8") as fh:
    fh.write("\n".join(lines) + "\n")
PY
chmod 600 "${SECRET_FILE}"
log "escrito ${SECRET_FILE} (no se versiona; no lo copies a logs)"
