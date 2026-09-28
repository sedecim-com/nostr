# syntax=docker/dockerfile:1.27.0@sha256:bde3983e9c939224420ddaf6b784cc30e09b035a4dea01f581230c50809f372e
# One image for all TypeScript services; select with --build-arg SERVICE=<indexer|identity-service|policy-engine|managed-signer|blob-store|notification-gateway|continuity-vault>
# NFR010-03: reproducible. Base images are pinned by digest (bump tag and digest together) and release
# images are built with scripts/build-image.sh (SOURCE_DATE_EPOCH + rewrite-timestamp, docs/building.md).
ARG NODE_IMAGE=node:26.10.0-alpine3.24@sha256:0b36e8c136b94cd4fcf02188228e76c31ad5872eef3fec8cbd2eee500cfd9e80
ARG NGINX_IMAGE=nginx:1.31.6-alpine3.24@sha256:df221db836e1754089190208cee7eeda94f233197056426eda74a43ab1abeac2

FROM ${NODE_IMAGE} AS deps
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages ./packages
COPY services ./services
COPY apps ./apps
RUN npm ci --ignore-scripts --no-audit --no-fund

FROM deps AS web-build
COPY infra/web/flags.json infra/web/flags.json
COPY infra/buzz/PIN infra/buzz/PIN
RUN npm run build:web && npm run build:admin

FROM ${NGINX_IMAGE} AS web
COPY --chmod=644 infra/web/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=web-build /app/apps/web-saas/dist /usr/share/nginx/html
# Admin console (OPS-07) under /admin/, same CSP and nonce handling.
COPY --from=web-build /app/apps/admin-console/dist /usr/share/nginx/html/admin

FROM ${NODE_IMAGE} AS service
ARG SERVICE
ENV NODE_ENV=production SERVICE=${SERVICE}
WORKDIR /app
COPY --from=deps /app /app
# adduser writes the current day into /etc/shadow; the account is locked, so clear that field to keep
# the layer identical across build days.
RUN addgroup -S app && adduser -S app -G app && mkdir -p /data && chown app:app /data \
  && sed -i -E 's/^(app:[^:]*):[0-9]*:/\1::/' /etc/shadow
USER app
CMD ["sh", "-c", "exec node_modules/.bin/tsx services/${SERVICE}/src/main.ts"]
