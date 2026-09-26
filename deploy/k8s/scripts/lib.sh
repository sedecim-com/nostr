#!/usr/bin/env bash
# Shared helpers for deploy/k8s/scripts (sourced, not executed).
# shellcheck disable=SC2034
ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
K8S="${ROOT}/deploy/k8s"
SCRIPTS="${K8S}/scripts"
VALUES="${VALUES:-${K8S}/values.env}"

# shellcheck disable=SC1090
[[ -f "${VALUES}" ]] && source "${VALUES}"

ECR_REGISTRY="${ECR_REGISTRY:-212568716371.dkr.ecr.us-east-1.amazonaws.com}"
AWS_REGION="${AWS_REGION:-us-east-1}"
EXPECTED_CONTEXT_SUBSTR="${EXPECTED_CONTEXT_SUBSTR:-sedecim-stage}"
NAMESPACE="${NAMESPACE:-acceso-nostr}"
OVERLAY="${OVERLAY:-deploy/k8s/overlays/stage}"
PUBLIC_HOST="${PUBLIC_HOST:-nostr-stage.ai.acce.so}"
PUBLIC_SCHEME="${PUBLIC_SCHEME:-https}"
SECRET_ID="${SECRET_ID:-k8s/stage/acceso-nostr}"
SIGNER_CREDENTIALS_SECRET_ID="${SIGNER_CREDENTIALS_SECRET_ID:-acceso_nostr_managed_signer_stage_credentials}"
SECRET_FILE="${SECRET_FILE:-${K8S}/secret.yaml}"

log() { printf '==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# Image tag of our own images: the commit being deployed (clean tree) unless IMAGE_TAG is set.
default_image_tag() {
  local sha
  sha="$(git -C "${ROOT}" rev-parse --short=12 HEAD 2>/dev/null || echo local)"
  if [[ -n "$(git -C "${ROOT}" status --porcelain 2>/dev/null)" ]]; then
    sha="${sha}-dirty"
  fi
  printf '%s' "${sha}"
}

ensure_stage_context() {
  local ctx
  ctx="$(kubectl config current-context 2>/dev/null || true)"
  [[ -n "${ctx}" ]] || die "sin contexto kubectl (kops export kubecfg --name sedecim-stage.k8s.local --state <s3-state>)"
  [[ "${ctx}" == *"${EXPECTED_CONTEXT_SUBSTR}"* ]] || die "contexto '${ctx}' no contiene '${EXPECTED_CONTEXT_SUBSTR}'"
  log "kubectl context: ${ctx}"
}

# Renders the overlay with our images at IMAGE_TAG into $1.
render_manifests() {
  local dest="$1" tag="$2"
  if command -v kustomize >/dev/null; then
    kustomize build "${ROOT}/${OVERLAY}" > "${dest}.raw"
  else
    kubectl kustomize "${ROOT}/${OVERLAY}" > "${dest}.raw"
  fi
  sed -e "s|/acceso-nostr-service:stage$|/acceso-nostr-service:${tag}|" \
      -e "s|/acceso-nostr-web:stage$|/acceso-nostr-web:${tag}|" "${dest}.raw" > "${dest}"
  rm -f "${dest}.raw"
}

# The managed signer refuses to start without Acceso (Cognito) settings: fail before applying
# (only a warning in dry-run, so the rest of the plan is still shown).
check_rendered_config() {
  local file="$1" dry_run="${2:-0}" msg
  if grep -q '^  COGNITO_USER_POOL_ID: ""$' "${file}" || grep -q '^  COGNITO_CLIENT_ID: ""$' "${file}"; then
    msg="COGNITO_USER_POOL_ID / COGNITO_CLIENT_ID vacíos en ${OVERLAY}/kustomization.yaml (y en files/web-config.json)"
    [[ "${dry_run}" -eq 1 ]] || die "${msg}"
    printf 'aviso: %s: el apply real se negará\n' "${msg}" >&2
  fi
}
