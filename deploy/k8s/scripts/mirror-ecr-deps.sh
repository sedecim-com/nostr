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
  "scsibug/nostr-rs-relay@sha256:03f54bfbffff80a50db62c9287913bd25a2dec08033b56d2122bc2550363d5c5|acceso-nostr-secure-relay:0.9.0"
  "postgres:17-alpine|acceso-nostr-postgres:17-alpine"
  "redis:7-alpine|acceso-nostr-redis:7-alpine"
  "nginx:1.31-alpine|acceso-nostr-nginx:1.31-alpine"
  "prom/prometheus:v3.5.0|acceso-nostr-prometheus:v3.5.0"
  "prom/blackbox-exporter:v0.27.0|acceso-nostr-blackbox-exporter:v0.27.0"
  "prom/alertmanager:v0.28.1|acceso-nostr-alertmanager:v0.28.1"
  "grafana/grafana:12.1.1|acceso-nostr-grafana:12.1.1"
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
