#!/usr/bin/env bash
# Deletes the acceso-nostr namespace in stage (workloads, Services, PVCs and their EBS volumes).
# Does NOT touch ECR, Terraform (KMS key, Secrets Manager, S3) or kops. Idempotent.
# Dry-run by default: nothing is deleted without --yes. Take a backup first (docs/runbooks/restore.md).
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

DRY_RUN=1
PURGE_SECRETS=0
NS_DELETE_TIMEOUT="${NS_DELETE_TIMEOUT:-300s}"

usage() {
  cat <<EOF
Uso: $0 [opciones]

  --dry-run          Solo muestra el plan (default)
  --yes, -y          Borra el namespace ${NAMESPACE}
  --purge-secrets    Borra también ${SECRET_FILE} local (Secrets Manager no se toca)
  -h, --help         Ayuda

No toca ECR, Terraform ni kops.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --yes|-y) DRY_RUN=0; shift ;;
    --purge-secrets) PURGE_SECRETS=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "arg desconocido: $1" ;;
  esac
done

command -v kubectl >/dev/null || die "kubectl no encontrado"
ensure_stage_context

ns_exists() { kubectl get ns "${NAMESPACE}" >/dev/null 2>&1; }

if [[ "${DRY_RUN}" -eq 1 ]]; then
  log "DRY-RUN: plan de teardown (sin mutar)"
  if ns_exists; then
    log "  borraría namespace ${NAMESPACE} (--wait, timeout ${NS_DELETE_TIMEOUT}), incluidos PVCs:"
    kubectl -n "${NAMESPACE}" get pvc --no-headers 2>/dev/null | awk '{print "    - " $1 " (" $4 ")"}' || true
  else
    log "  namespace ${NAMESPACE} ya ausente (idempotente)"
  fi
  if [[ "${PURGE_SECRETS}" -eq 1 ]]; then log "  borraría ${SECRET_FILE}"; else log "  ${SECRET_FILE}: se conserva"; fi
  log "  ECR / Terraform / kops / Secrets Manager: no se tocan"
  exit 0
fi

if ns_exists; then
  log "borrando namespace ${NAMESPACE}"
  kubectl delete namespace "${NAMESPACE}" --wait=true --timeout="${NS_DELETE_TIMEOUT}"
else
  log "namespace ${NAMESPACE} ya ausente"
fi
if [[ "${PURGE_SECRETS}" -eq 1 ]]; then
  rm -f "${SECRET_FILE}"
  log "borrado ${SECRET_FILE}"
fi

cat <<EOF

Teardown stage.
  Namespace ${NAMESPACE}: $(ns_exists && echo presente || echo ausente)
  Secret local: $([[ -f "${SECRET_FILE}" ]] && echo presente || echo ausente)
  ECR / Terraform / kops / Secrets Manager: no se tocaron
EOF
