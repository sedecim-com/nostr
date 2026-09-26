#!/usr/bin/env bash
# Builds this repo's images (Dockerfile targets `service` and `web`) and pushes them to ECR with the tag
# of the commit being deployed. One `service` image serves every TypeScript service: the Deployment sets
# SERVICE (the Dockerfile CMD reads it at runtime). DRY_RUN=1 (default) only prints.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

DRY_RUN="${DRY_RUN:-1}"
TAG="${IMAGE_TAG:-$(default_image_tag)}"
PLATFORM="${PLATFORM:-linux/amd64}"

[[ "${TAG}" != *-dirty || "${DRY_RUN}" == "1" || "${ALLOW_DIRTY:-0}" == "1" ]] \
  || die "árbol con cambios sin commit: haz commit (o ALLOW_DIRTY=1 IMAGE_TAG=...)"

SERVICE_IMAGE="${ECR_REGISTRY}/acceso-nostr-service:${TAG}"
WEB_IMAGE="${ECR_REGISTRY}/acceso-nostr-web:${TAG}"
echo "Build → ${SERVICE_IMAGE}, ${WEB_IMAGE}  platform=${PLATFORM} DRY_RUN=${DRY_RUN}"

if [[ "${DRY_RUN}" == "1" ]]; then
  echo "(dry-run) docker build --platform ${PLATFORM} --target service --build-arg SERVICE=indexer -t ${SERVICE_IMAGE} ."
  echo "(dry-run) docker build --platform ${PLATFORM} --target web -t ${WEB_IMAGE} ."
  echo "(dry-run) docker push ${SERVICE_IMAGE} ${WEB_IMAGE}"
  exit 0
fi

cd "${ROOT}"
aws ecr get-login-password --region "${AWS_REGION}" | docker login --username AWS --password-stdin "${ECR_REGISTRY}"
docker build --platform "${PLATFORM}" --target service --build-arg SERVICE=indexer -t "${SERVICE_IMAGE}" .
docker build --platform "${PLATFORM}" --target web -t "${WEB_IMAGE}" .
docker push "${SERVICE_IMAGE}"
docker push "${WEB_IMAGE}"
echo "Pushed ${SERVICE_IMAGE} ${WEB_IMAGE}"
