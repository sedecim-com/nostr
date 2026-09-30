#!/usr/bin/env bash
# Mirrors third-party images to the private ECR (the cluster never pulls from Docker Hub or ghcr).
# Copies the manifest list as is (`docker buildx imagetools create`), so digest pins stay valid: the
# relay keeps the digest of infra/buzz/PIN. DRY_RUN=1 (default) only prints.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

DRY_RUN="${DRY_RUN:-1}"
PIN_FILE="${ROOT}/infra/buzz/PIN"
BUZZ_IMAGE="$(sed -n 's/^BUZZ_IMAGE=//p' "${PIN_FILE}")"
[[ "${BUZZ_IMAGE}" == *@sha256:* ]] || die "infra/buzz/PIN: BUZZ_IMAGE sin digest"

# source → ECR repository:tag (digest sources keep their digest; the tag only names it in ECR).
IMAGES=(
  "${BUZZ_IMAGE}|acceso-nostr-buzz:$(sed -n 's/^BUZZ_COMMIT=//p' "${PIN_FILE}" | cut -c1-12)"
  "chrislusf/seaweedfs@sha256:ce9e796f1fe6f06968f4c04bdaf8f678dad9c8acdfef3d244133d71bfa6bf882|acceso-nostr-seaweedfs:4.47"
  "scsibug/nostr-rs-relay@sha256:48d54c2d2781577cf3ed2951112f0953dc2c5e7c9d2ea20c64e8c0fa37d16e4d|acceso-nostr-secure-relay:0.10.0"
  "postgres@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24|acceso-nostr-postgres:17.11-alpine3.24"
  "redis@sha256:858f009f9709ce576febc734aa78b8f6d624b82571f9ddb6bda4377c833b3499|acceso-nostr-redis:7.4.11-alpine3.21"
  "nginx@sha256:df221db836e1754089190208cee7eeda94f233197056426eda74a43ab1abeac2|acceso-nostr-nginx:1.31.6-alpine3.24"
  "prom/prometheus@sha256:63805ebb8d2b3920190daf1cb14a60871b16fd38bed42b857a3182bc621f4996|acceso-nostr-prometheus:v3.5.0"
  "prom/blackbox-exporter@sha256:a50c4c0eda297baa1678cd4dc4712a67fdea713b832d43ce7fcc5f9bea05094d|acceso-nostr-blackbox-exporter:v0.27.0"
  "prom/alertmanager@sha256:27c475db5fb156cab31d5c18a4251ac7ed567746a2483ff264516437a39b15ba|acceso-nostr-alertmanager:v0.28.1"
  "grafana/grafana@sha256:a1701c2180249361737a99a01bc770db39381640e4d631825d38ff4535efa47d|acceso-nostr-grafana:12.1.1"
)

echo "ECR=${ECR_REGISTRY} region=${AWS_REGION} DRY_RUN=${DRY_RUN}"
if [[ "${DRY_RUN}" != "1" ]]; then
  aws ecr get-login-password --region "${AWS_REGION}" | docker login --username AWS --password-stdin "${ECR_REGISTRY}"
fi

for entry in "${IMAGES[@]}"; do
  src="${entry%%|*}"
  dest="${ECR_REGISTRY}/${entry##*|}"
  repo="${entry##*|}"
  repo="${repo%%:*}"
  echo "--- ${src} → ${dest}"
  if [[ "${DRY_RUN}" == "1" ]]; then
    echo "  (dry-run) docker buildx imagetools create --tag ${dest} ${src}"
    continue
  fi
  # Repositories come from Terraform (deploy/terraform, var.ecr_repositories); fail loudly if missing.
  aws ecr describe-repositories --region "${AWS_REGION}" --repository-names "${repo}" > /dev/null \
    || die "repositorio ECR ${repo} ausente: terraform apply del módulo acceso-nostr"
  docker buildx imagetools create --tag "${dest}" "${src}"
done
echo "Listo. Imágenes propias: deploy/k8s/scripts/build-push.sh"
