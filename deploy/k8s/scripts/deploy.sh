#!/usr/bin/env bash
# First install of Acceso Nostr on the stage cluster (sedecim-stage.k8s.local):
#   1) preflight (aws/docker/kubectl + context)   2) Secret from Secrets Manager
#   3) mirror third-party images → ECR             4) build + push our images → ECR
#   5) kubectl apply of deploy/k8s/overlays/stage and wait for the rollouts
#
# Dry-run by default: nothing is pushed or applied without --yes.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

DRY_RUN=1
DO_SECRET=1
DO_MIRROR=1
DO_BUILD=1
DO_APPLY=1
BOOTSTRAP=0
IMAGE_TAG="${IMAGE_TAG:-$(default_image_tag)}"

usage() {
  cat <<EOF
Uso: $0 [opciones]

Instala el stack en stage (secret → ECR → kubectl apply). Sin --yes solo muestra el plan.

  --dry-run           Plan solamente (default)
  --yes, -y           Ejecuta (push ECR + apply)
  --tag TAG           Tag de acceso-nostr-service/web (default: commit actual, ${IMAGE_TAG})
  --bootstrap-secret  Si ${SECRET_ID} está vacío, lo inicializa (generate-secret.sh --bootstrap)
  --skip-secret       No regenera el Secret (usa ${SECRET_FILE})
  --skip-mirror       No espeja imágenes de terceros
  --skip-build        No construye/sube imágenes propias
  --skip-apply        Solo imágenes/secret; no toca el cluster
  --apply-only        Solo secret + apply (imágenes ya en ECR)

Variables: deploy/k8s/values.env (ECR_REGISTRY, EXPECTED_CONTEXT_SUBSTR, SECRET_ID, ...)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --yes|-y) DRY_RUN=0; shift ;;
    --tag) [[ $# -ge 2 ]] || die "--tag requiere valor"; IMAGE_TAG="$2"; shift 2 ;;
    --tag=*) IMAGE_TAG="${1#*=}"; shift ;;
    --bootstrap-secret) BOOTSTRAP=1; shift ;;
    --skip-secret) DO_SECRET=0; shift ;;
    --skip-mirror) DO_MIRROR=0; shift ;;
    --skip-build) DO_BUILD=0; shift ;;
    --skip-apply|--images-only) DO_APPLY=0; shift ;;
    --apply-only) DO_MIRROR=0; DO_BUILD=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "arg desconocido: $1 (usa --help)" ;;
  esac
done
export IMAGE_TAG

yn() { [[ "$1" -eq 1 ]] && echo yes || echo skip; }

preflight() {
  log "preflight"
  command -v kubectl >/dev/null || die "falta kubectl"
  if [[ "${DO_SECRET}" -eq 1 || "${DO_MIRROR}" -eq 1 || "${DO_BUILD}" -eq 1 ]]; then
    command -v aws >/dev/null || die "falta aws CLI"
    if [[ "${DRY_RUN}" -eq 0 ]]; then
      aws sts get-caller-identity --query Account --output text >/dev/null || die "AWS no autenticado (sts)"
    fi
  fi
  if [[ "${DRY_RUN}" -eq 0 && ( "${DO_MIRROR}" -eq 1 || "${DO_BUILD}" -eq 1 ) ]]; then
    command -v docker >/dev/null || die "falta docker"
    docker info >/dev/null 2>&1 || die "docker daemon no responde"
  fi
  if [[ "${DO_APPLY}" -eq 1 ]]; then
    ensure_stage_context
  fi
}

print_plan() {
  cat <<EOF

=== plan deploy acceso-nostr (stage) ===
  namespace:   ${NAMESPACE}
  overlay:     ${OVERLAY}
  host:        ${PUBLIC_SCHEME}://${PUBLIC_HOST}  (NodePort ${NODE_PORT:-31810} → ALB)
  ECR:         ${ECR_REGISTRY}
  image tag:   ${IMAGE_TAG}
  secret:      ${SECRET_ID} → ${SECRET_FILE}
  dry-run:     ${DRY_RUN}
  steps:
    secret:    $(yn "${DO_SECRET}")
    mirror:    $(yn "${DO_MIRROR}")
    build:     $(yn "${DO_BUILD}")
    kubectl:   $(yn "${DO_APPLY}")
EOF
}

run_secret() {
  [[ "${DO_SECRET}" -eq 1 ]] || { [[ "${DO_APPLY}" -eq 0 || -f "${SECRET_FILE}" || "${DRY_RUN}" -eq 1 ]] || die "falta ${SECRET_FILE} (--skip-secret)"; return 0; }
  log "secret desde Secrets Manager"
  local args=()
  [[ "${BOOTSTRAP}" -eq 1 ]] && args+=(--bootstrap)
  if [[ "${DRY_RUN}" -eq 1 ]]; then args+=(--dry-run); else args+=(--yes); fi
  "${SCRIPTS}/generate-secret.sh" "${args[@]}"
}

run_mirror() {
  [[ "${DO_MIRROR}" -eq 1 ]] || return 0
  log "espejo de imágenes de terceros → ECR"
  DRY_RUN="${DRY_RUN}" "${SCRIPTS}/mirror-ecr-deps.sh"
}

run_build() {
  [[ "${DO_BUILD}" -eq 1 ]] || return 0
  log "build + push de imágenes propias"
  DRY_RUN="${DRY_RUN}" "${SCRIPTS}/build-push.sh"
}

run_apply() {
  [[ "${DO_APPLY}" -eq 1 ]] || return 0
  log "render ${OVERLAY} (tag ${IMAGE_TAG})"
  render_manifests "${RENDER}/all.yaml" "${IMAGE_TAG}"
  check_rendered_config "${RENDER}/all.yaml" "${DRY_RUN}"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    kubectl apply --dry-run=client -f "${RENDER}/all.yaml" > /dev/null
    echo "  (dry-run) $(grep -c '^kind:' "${RENDER}/all.yaml") objetos válidos (kubectl --dry-run=client)"
    return 0
  fi
  # Namespace first, then the Secret (workloads reference it), then everything else.
  kubectl apply -f "${K8S}/base/namespace.yaml"
  kubectl apply -f "${SECRET_FILE}"
  kubectl apply -f "${RENDER}/all.yaml"
  log "esperando rollouts"
  kubectl -n "${NAMESPACE}" rollout status statefulset/postgres --timeout=300s
  kubectl -n "${NAMESPACE}" rollout status statefulset/redis --timeout=180s
  kubectl -n "${NAMESPACE}" rollout status statefulset/seaweedfs --timeout=300s
  kubectl -n "${NAMESPACE}" wait --for=condition=complete job/seaweedfs-init --timeout=300s
  for d in relay indexer identity-service policy-engine blob-store managed-signer web edge prometheus blackbox-exporter alertmanager grafana; do
    kubectl -n "${NAMESPACE}" rollout status "deployment/${d}" --timeout=300s
  done
  kubectl -n "${NAMESPACE}" rollout status statefulset/secure-relay --timeout=180s
}

RENDER="$(mktemp -d)"
trap 'rm -rf "${RENDER}"' EXIT

cd "${ROOT}"
preflight
print_plan
run_secret
run_mirror
run_build
run_apply

log "listo"
if [[ "${DRY_RUN}" -eq 1 ]]; then
  echo "  (fue dry-run: nada se subió ni aplicó)  real: $0 --yes"
else
  echo "  web:    ${PUBLIC_SCHEME}://${PUBLIC_HOST}"
  echo "  health: ${PUBLIC_SCHEME}://${PUBLIC_HOST}/_edge_health"
  echo "  actualizar: deploy/k8s/scripts/update-stage.sh --yes   bajar: deploy/k8s/scripts/teardown-stage.sh --yes"
fi
