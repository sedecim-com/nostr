#!/usr/bin/env bash
# Updates a stack already deployed in stage (namespace acceso-nostr) without deleting the namespace or
# PVCs. Rebuilds our images for the current commit; third-party mirrors only with --mirror.
# The one-shot Job seaweedfs-init is recreated only if it is missing or Failed (never when Complete).
# Dry-run by default: nothing changes without --yes.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

DRY_RUN=1
DO_SECRET=1
DO_MIRROR=0
DO_BUILD=1
IMAGE_TAG="${IMAGE_TAG:-$(default_image_tag)}"

usage() {
  cat <<EOF
Uso: $0 [opciones]

  --dry-run        Solo muestra el plan (default)
  --yes, -y        Actualiza
  --tag TAG        Tag de las imágenes propias (default: commit actual, ${IMAGE_TAG})
  --skip-secret    No regenera el Secret desde Secrets Manager
  --skip-build     No construye/sube imágenes propias (usa --tag existente en ECR)
  --mirror         Espeja también las imágenes de terceros (opt-in)
  -h, --help       Ayuda

No borra el namespace ${NAMESPACE} ni sus PVCs.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --yes|-y) DRY_RUN=0; shift ;;
    --tag) [[ $# -ge 2 ]] || die "--tag requiere valor"; IMAGE_TAG="$2"; shift 2 ;;
    --tag=*) IMAGE_TAG="${1#*=}"; shift ;;
    --skip-secret) DO_SECRET=0; shift ;;
    --skip-build) DO_BUILD=0; shift ;;
    --mirror) DO_MIRROR=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "arg desconocido: $1" ;;
  esac
done
export IMAGE_TAG

command -v kubectl >/dev/null || die "kubectl no encontrado"
cd "${ROOT}"
ensure_stage_context
kubectl get ns "${NAMESPACE}" >/dev/null 2>&1 || die "namespace ${NAMESPACE} no existe; primero: deploy/k8s/scripts/deploy.sh --yes"

job_state() {
  local c f
  kubectl -n "${NAMESPACE}" get job seaweedfs-init >/dev/null 2>&1 || { echo absent; return; }
  c="$(kubectl -n "${NAMESPACE}" get job seaweedfs-init -o 'jsonpath={.status.conditions[?(@.type=="Complete")].status}' 2>/dev/null || true)"
  f="$(kubectl -n "${NAMESPACE}" get job seaweedfs-init -o 'jsonpath={.status.conditions[?(@.type=="Failed")].status}' 2>/dev/null || true)"
  if [[ "${c}" == True ]]; then echo complete; elif [[ "${f}" == True ]]; then echo failed; else echo running; fi
}

RENDER="$(mktemp -d)"
trap 'rm -rf "${RENDER}"' EXIT
render_manifests "${RENDER}/all.yaml" "${IMAGE_TAG}"
check_rendered_config "${RENDER}/all.yaml" "${DRY_RUN}"
# Jobs are immutable: apply everything else, handle the Job by state.
python3 - "${RENDER}/all.yaml" "${RENDER}/without-jobs.yaml" "${RENDER}/jobs.yaml" <<'PY'
import sys
src, rest, jobs = sys.argv[1:]
docs = open(src, encoding="utf-8").read().split("\n---\n")
is_job = lambda d: any(line == "kind: Job" for line in d.splitlines())
open(rest, "w", encoding="utf-8").write("\n---\n".join(d for d in docs if not is_job(d)) + "\n")
open(jobs, "w", encoding="utf-8").write("\n---\n".join(d for d in docs if is_job(d)) + "\n")
PY

JOB="$(job_state)"
if [[ "${DRY_RUN}" -eq 1 ]]; then
  log "DRY-RUN: plan de actualización (sin apply ni push)"
  log "  tag imágenes propias: ${IMAGE_TAG} (build: $([ "${DO_BUILD}" -eq 1 ] && echo sí || echo no))"
  log "  mirror terceros: $([ "${DO_MIRROR}" -eq 1 ] && echo sí || echo no)"
  log "  secret: $([ "${DO_SECRET}" -eq 1 ] && echo "regenerar desde ${SECRET_ID}" || echo "reutilizar ${SECRET_FILE}")"
  log "  job/seaweedfs-init: ${JOB} → $(case "${JOB}" in complete) echo skip ;; failed) echo recrear ;; absent) echo aplicar ;; *) echo esperar ;; esac)"
  kubectl apply --dry-run=server -f "${RENDER}/without-jobs.yaml" > /dev/null && log "  manifiestos válidos contra el API server (dry-run=server)"
  [[ "${DO_SECRET}" -eq 0 ]] || "${SCRIPTS}/generate-secret.sh" --dry-run
  log "  namespace ${NAMESPACE}: no se borra"
  exit 0
fi

[[ "${DO_MIRROR}" -eq 0 ]] || DRY_RUN=0 "${SCRIPTS}/mirror-ecr-deps.sh"
[[ "${DO_BUILD}" -eq 0 ]] || DRY_RUN=0 "${SCRIPTS}/build-push.sh"
if [[ "${DO_SECRET}" -eq 1 ]]; then
  "${SCRIPTS}/generate-secret.sh" --yes
else
  [[ -f "${SECRET_FILE}" ]] || die "falta ${SECRET_FILE} (--skip-secret)"
fi

log "aplicando secret y manifiestos (sin Jobs)"
kubectl apply -f "${SECRET_FILE}"
kubectl apply -f "${RENDER}/without-jobs.yaml"
case "${JOB}" in
  complete) log "job/seaweedfs-init Complete: skip" ;;
  failed) kubectl -n "${NAMESPACE}" delete job seaweedfs-init; kubectl apply -f "${RENDER}/jobs.yaml" ;;
  absent) kubectl apply -f "${RENDER}/jobs.yaml" ;;
  *) log "job/seaweedfs-init en curso" ;;
esac

# Secret changes do not roll pods by themselves (ConfigMaps do: hashed names).
log "reiniciando workloads para recoger el Secret"
kubectl -n "${NAMESPACE}" rollout restart deployment
kubectl -n "${NAMESPACE}" rollout restart statefulset
for d in relay indexer identity-service policy-engine blob-store managed-signer web edge prometheus blackbox-exporter alertmanager grafana; do
  kubectl -n "${NAMESPACE}" rollout status "deployment/${d}" --timeout=300s
done
for s in postgres redis seaweedfs secure-relay; do
  # postgres is absent with components/rds-postgres (RDS, NFR001-03).
  has_workload "${RENDER}/all.yaml" StatefulSet "${s}" || continue
  kubectl -n "${NAMESPACE}" rollout status "statefulset/${s}" --timeout=300s
done

cat <<EOF

Stack stage actualizado (tag ${IMAGE_TAG}).
  web:    ${PUBLIC_SCHEME}://${PUBLIC_HOST}
  health: ${PUBLIC_SCHEME}://${PUBLIC_HOST}/_edge_health
Bajar solo el namespace (no toca ECR/Terraform/kops): deploy/k8s/scripts/teardown-stage.sh --yes
EOF
