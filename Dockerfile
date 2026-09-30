# syntax=docker/dockerfile:1.27.0@sha256:bde3983e9c939224420ddaf6b784cc30e09b035a4dea01f581230c50809f372e
# One image for all TypeScript services; select with --build-arg SERVICE=<indexer|identity-service|policy-engine|managed-signer|blob-store|notification-gateway|continuity-vault|rotation-worker>
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

# NFR010-04: the services run without devDependencies (test runners, bundlers, types). tsx, which runs them,
# is a dependency. scripts/image-sbom-check.mjs fails the build of a release image that carries one.
FROM ${NODE_IMAGE} AS prod-deps
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages ./packages
COPY services ./services
COPY apps ./apps
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund

# FR020-06: what the sovereign CLI runs and nothing else. npm lists the production closure of apps/sovereign-client
# (tsx, which runs it, included) and `node - APP OUT LIST` copies those packages to /out with the same layout: the
# workspace packages without their tests, their node_modules links and the root manifest. No services, no web apps,
# no dependency of another workspace, and no optional peer that only development installs (typescript for
# nostr-tools). npm ls exits non-zero on any problem it reports; the listing is still complete, and the copy fails if
# it lacks tsx or the CLI.
FROM prod-deps AS sovereign-files
RUN npm ls --omit=dev --all --parseable --workspace=@sedecim/sovereign-client --include-workspace-root > /tmp/closure || true
RUN node - /app /out /tmp/closure <<'EOF'
const fs = require('node:fs');
const [app, out, list] = process.argv.slice(2);
const lock = JSON.parse(fs.readFileSync(`${app}/package-lock.json`, 'utf8')).packages ?? {};
const devOnly = (p) => ['dev', 'devOptional'].some((flag) => lock[p.slice(app.length + 1)]?.[flag] === true);
const keep = new Set(fs.readFileSync(list, 'utf8').split('\n').filter((p) => p.startsWith(`${app}/`) && !devOnly(p)).map((p) => fs.realpathSync(p)));
for (const need of [`${app}/node_modules/tsx`, `${app}/apps/sovereign-client`]) if (!keep.has(need)) throw new Error(`npm ls did not list ${need}`);
const copy = (from, filter) => fs.cpSync(from, out + from.slice(app.length), { recursive: true, verbatimSymlinks: true, filter });
const workspace = (p) => { const [dir, name, more] = p.slice(app.length + 1).split('/'); return ['packages', 'apps', 'services'].includes(dir) && !!name && more === undefined; };
for (const p of keep) copy(p, workspace(p) ? (src) => src !== `${p}/test` : undefined);
for (const name of fs.readdirSync(`${app}/node_modules/@sedecim`)) {
  const link = `${app}/node_modules/@sedecim/${name}`;
  if (keep.has(fs.realpathSync(link))) copy(link);
}
fs.copyFileSync(`${app}/package.json`, `${out}/package.json`);
EOF

# FR020-06: the sovereign CLI as a one-off container of the compose `tor` profile (docs/sovereign-tor.md):
#   docker compose run --rm sovereign <command>
# The unprivileged user of the services, no EXPOSE. Its stores go to /data/sovereign (a volume in compose), sealed with
# the passphrase of the secret file SOVEREIGN_PASSPHRASE_FILE names: no secret is an ARG or ENV of this image. Without
# a command it prints the maturity of each profile, which opens no store. Before `service`, the default (last) stage.
FROM ${NODE_IMAGE} AS sovereign
ENV NODE_ENV=production SOVEREIGN_DATA_DIR=/data/sovereign SOVEREIGN_PASSPHRASE_FILE=/run/secrets/sovereign_passphrase
WORKDIR /app
COPY --from=sovereign-files /out /app
# The interop gate's deployment flags, which `dm send` follows (no NIP-17 while the gate is red), as the web image does.
COPY infra/web/flags.json infra/web/flags.json
RUN addgroup -S app && adduser -S app -G app && mkdir -p /data/sovereign && chown -R app:app /data \
  && sed -i -E 's/^(app:[^:]*):[0-9]*:/\1::/' /etc/shadow
USER app
ENTRYPOINT ["node", "--import", "tsx", "apps/sovereign-client/src/cli.ts"]
CMD ["maturity"]

FROM ${NODE_IMAGE} AS service
ARG SERVICE
ENV NODE_ENV=production SERVICE=${SERVICE}
WORKDIR /app
COPY --from=prod-deps /app /app
# adduser writes the current day into /etc/shadow; the account is locked, so clear that field to keep
# the layer identical across build days.
RUN addgroup -S app && adduser -S app -G app && mkdir -p /data && chown app:app /data \
  && sed -i -E 's/^(app:[^:]*):[0-9]*:/\1::/' /etc/shadow
USER app
CMD ["sh", "-c", "exec node_modules/.bin/tsx services/${SERVICE}/src/main.ts"]
