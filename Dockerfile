# syntax=docker/dockerfile:1.7
# One image for all TypeScript services; select with --build-arg SERVICE=<indexer|identity-service|policy-engine|managed-signer>
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages ./packages
COPY services ./services
COPY apps ./apps
RUN npm ci --ignore-scripts --no-audit --no-fund

FROM deps AS web-build
RUN node apps/web-saas/build.mjs

FROM nginx:1.27-alpine AS web
COPY infra/web/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=web-build /app/apps/web-saas/public /usr/share/nginx/html
RUN rm -f /usr/share/nginx/html/app.js.map

FROM node:22-alpine AS service
ARG SERVICE
ENV NODE_ENV=production SERVICE=${SERVICE}
WORKDIR /app
COPY --from=deps /app /app
RUN addgroup -S app && adduser -S app -G app && mkdir -p /data && chown app:app /data
USER app
CMD ["sh", "-c", "exec node_modules/.bin/tsx services/${SERVICE}/src/main.ts"]
