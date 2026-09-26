# Acceso Nostr

**Acceso Nostr** (familia Acceso de Sedecim) implementa la especificación *"Plataforma Nostr Soberana / SaaS"* (v0.1, 25/09/2026):
un mismo protocolo Nostr con grados configurables de soberanía, anonimato, resiliencia, custodia y
control institucional. **La centralización es una capa voluntaria de conveniencia, no la base.**

> ⚠️ Early release. No apto para perfiles de alto riesgo hasta una revisión de seguridad independiente
> (ver [SECURITY.md](SECURITY.md)). NIP-17/NIP-44 no ofrecen forward secrecy; el modo *managed* es custodial.

## Qué incluye

| Área | Dónde | Estado |
|---|---|---|
| SDK Nostr propio (desacoplado de Buzz) | `packages/*` | ✅ |
| Identidad, personas, custodia (local, offline, NIP-46, NIP-07, managed) | `packages/identity`, `packages/signer` | ✅ |
| Máquina de estados de entrega + outbox cifrada + quorum multi-relay | `packages/delivery-engine` | ✅ |
| DMs NIP-17 (NIP-44 + NIP-59) tras feature flag, canales NIP-29 | `packages/messaging` | ✅ gate ejecutado contra Buzz `02c6309` (requiere adaptador de jitter acotado) |
| Grupos high-security Marmot/MLS | `packages/marmot-adapter`, `docs/marmot.md` | ✅ marmot-ts + ts-mls (alpha upstream; vía relay secundario, Buzz no acepta los kinds) |
| Blossom con saneamiento EXIF y cifrado cliente | `packages/blossom-client`, `services/blob-store` | ✅ (cifrados → blob-store; Buzz `/media` solo imágenes en claro) |
| Sovereign Tor Mode (fail closed, DNS remoto, circuitos por persona) | `packages/tor-network`, `apps/sovereign-client` | ✅ |
| Panel de soberanía con consecuencias verificables | `packages/profiles`, `apps/web-saas` | ✅ |
| Generador de llaves offline standalone (bundle reproducible + checksum, QR, hoja imprimible, HTML air-gapped) | `apps/key-generator`, `packages/qr` | ✅ |
| Web SaaS como cliente Nostr de primera clase (React 19 + MUI 7 + Vite; personas, canales, DMs, adjuntos) | `apps/web-saas` | ✅ vault IndexedDB (ADR 0007), login de Acceso en SaaS (ADR 0008) |
| Indexer / mirror ciphertext-first (Postgres) | `services/indexer` | ✅ |
| Servicio de identidad (NIP-98, vínculos con consentimiento) | `services/identity-service` | ✅ |
| Managed signer custodial y opt-in (AWS Secrets Manager + KMS en us-east-1, registro en Postgres, firma autorizada con el token de Acceso) | `services/managed-signer`, [ADR 0009](docs/adr/0009-custodia-managed-region-y-marco-legal.md) | ✅ (términos pendientes de legal; enclave Nitro pendiente) |
| Modo institucional: RBAC/ABAC, device trust, revocación, auditoría | `services/policy-engine` | ✅ (persistencia en memoria) |
| Stack self-hosted Docker Compose (Buzz fijado por digest, Tor opcional) | `docker-compose.yml`, `infra/` | ✅ |
| Buzz upstream sin fork, fijado por digest | `infra/buzz/PIN`, `docs/adr/0002-subset-y-pin-de-buzz.md`, `docs/buzz-integration.md` | ✅ (política de actualización: ADR 0003) |

Trazabilidad completa FR/NFR → tests: [docs/requirements-traceability.md](docs/requirements-traceability.md).
Backlog con tareas atómicas, prioridad, dependencias y sprint: vive en [GitHub Issues](https://github.com/sedecim-com/nostr/issues?q=label%3Abacklog) (milestones = sprints, epics con sub-issues) y se sincroniza a [docs/backlog/](docs/backlog/README.md) con una PR automática (ver [GITHUB.md](docs/backlog/GITHUB.md)).
Arquitectura: [docs/architecture.md](docs/architecture.md) · Threat model: [docs/threat-model.md](docs/threat-model.md).
Releases firmados (cosign keyless + provenance SLSA), build desde source y verificación: [docs/building.md](docs/building.md) (`sh scripts/verify-release.sh <tag>`).

## Inicio rápido

### Desarrollo (sin Docker)
```bash
npm install
npm run check                 # typecheck + 100+ tests (unitarios y E2E en proceso)
npm run dev:relay             # relay de desarrollo en memoria: ws://localhost:7777
npm run dev:web                # web en http://localhost:5173 (Vite); npm run build:web → apps/web-saas/dist
```

### Self-hosted soberano (spec §4.1)
```bash
git clone <repo> && cd nostr
sh scripts/init-env.sh        # genera o completa .env sin sobrescribir valores (tras `npm ci`, llaves del keygen offline)
docker compose up -d          # relay Buzz, postgres, redis, SeaweedFS (S3), indexer, identity, policy, blob-store, secure-relay, web
docker compose --profile tor up -d       # + Tor SOCKS y relay .onion
docker compose --profile managed up -d   # + managed signer (CUSTODIAL, opt-in)
```
Web: http://localhost:8080 · Relay: ws://localhost:3000 · Indexer: http://localhost:8081

`scripts/init-env.sh` rellena solo las claves vacías o `CHANGE_ME` y nunca sobrescribe un valor, así que se puede
volver a ejecutar. Las llaves Nostr las genera el generador offline: la llave del relay y la identidad del mirror
van en hexadecimal al `.env`. La del owner del relay solo deja `RELAY_OWNER_PUBKEY` en el `.env`: la secreta se
guarda cifrada (NIP-49) en `.data/relay-owner.ncryptsec.json`, con una contraseña que se pide por terminal
(`OWNER_PASSWORD_FILE` para ejecuciones no interactivas). Ese backup se mueve a un lugar offline. Sin `npm ci`,
las llaves de servicio se generan con bytes aleatorios y el owner se omite.

### Web: self-hosted o SaaS
La web lee `config.json` (compose monta `infra/web/config.json`; otro archivo con `WEB_CONFIG=...`):
- `"mode": "self-hosted"`: sin login externo; la identidad es solo tu llave Nostr.
- `"mode": "saas"`: exige entrar con la cuenta de **Acceso** (Cognito) antes de abrir identidades. Ver
  `infra/web/config.saas.example.json` y [ADR 0008](docs/adr/0008-login-acceso-en-saas.md). El
  identity-service verifica los tokens con `COGNITO_REGION`, `COGNITO_USER_POOL_ID` y `COGNITO_CLIENT_ID`.

Las llaves viven en un vault de IndexedDB cifrado con tu contraseña. Solo el perfil convenience puede
usar una llave del dispositivo sin contraseña ([ADR 0007](docs/adr/0007-almacenamiento-local-cifrado.md)).

### Llave offline
```bash
npm run keygen -- --out backup.json          # NIP-49 ncryptsec, sin red (primitivas bloqueadas)
npm run keygen -- --out backup.json --qr qr/ --print backup.html   # + QR SVG de npub/ncryptsec y hoja imprimible local
npm run keygen -- verify backup.json
node apps/key-generator/build.mjs             # dist/keygen.mjs + .sha256 para distribución air-gapped
node apps/key-generator/build-html.mjs        # dist/keygen.html + .sha256: generador en un solo HTML, CSP sin red
npm run sovereign -- persona import --backup backup.json --label NOMBRE --relay wss://…   # importar el backup
```

`dist/keygen.html` funciona abierto desde el disco (`file://`): genera la llave con `crypto.getRandomValues`,
la cifra con NIP-49 y muestra npub, ncryptsec, sus QR y la hoja imprimible. Su CSP (`default-src 'none'`,
script y estilos fijados por SHA-256) impide cualquier conexión; compara el checksum antes de usarlo.
Uso air-gapped verificable con un release firmado, paso a paso: [docs/keygen-air-gapped.md](docs/keygen-air-gapped.md).

### Cliente soberano (CLI)
```bash
export SOVEREIGN_PASSPHRASE='…'
npm run sovereign -- persona create --label Personal --relay ws://localhost:3000
npm run sovereign -- channel send --persona <id> --group <h> "hola"
npm run sovereign -- outbox --persona <id>      # estado por relay: aceptado ≠ recibido ≠ leído
npm run sovereign -- disclose --persona <id>    # consecuencias de cada ajuste
```

## Pruebas
| Comando | Qué cubre |
|---|---|
| `npm test` | Unitarios + E2E contra relay/Blossom/SOCKS en memoria (NIP-42, quorum, offline, Tor fail-closed, NIP-46, interop con nostr-tools) |
| `npm run test:pg` | Repositorios Postgres del indexer e identity-service (`TEST_DATABASE_URL`) |
| `npm run test:keygen-html` | Generador HTML air-gapped abierto desde `file://` sin red |
| `npm run lint:claims` | Prohíbe afirmaciones absolutas de privacidad en todo el copy |
| `npm run test:browser` | Web en Chromium (Playwright): personas, canales, DMs con ruteo 10050, adjuntos, receipts, panel aplicado y persistido, vault, nsec que no sale del navegador, axe-core, modo SaaS con Acceso |
| `BUZZ_RELAY_URL=… npx tsx tests/browser/web-buzz.e2e.ts` | Web contra Buzz real: crear canal, unirse, enviar y leer (FR015-03; job `stack` de CI) |
| `npm run test:interop` | Gate contra Buzz real (`BUZZ_RELAY_URL`), genera `interop-report.json` |

## Estructura
```
packages/   SDK compartido (nostr-core, relay-pool, signer, delivery-engine, encrypted-store, identity,
            messaging, marmot-adapter, blossom-client, tor-network, telemetry-policy, profiles,
            policy-client, sync, service-kit, test-relay)
apps/       web-saas, sovereign-client, key-generator
services/   indexer, identity-service, managed-signer, policy-engine, blob-store
infra/      buzz (pin), tor, postgres, web
docs/       arquitectura, threat model, trazabilidad, integración Buzz, Tor, runbooks
```

## Pendiente (roadmap §22)
- F2: NIP-77 Negentropy; persistencia en Postgres del policy-engine; notification-gateway.
- F3: auditoría independiente de fugas; cliente móvil/desktop dedicado para Tor.
- F4: interoperabilidad verificada con MDK; MIP-04 (media en grupos); unificar Marmot en Buzz si upstream acepta sus kinds.
- F5: admin-console, directorio con passkeys/attestation, legal hold.
- Primer release firmado con `release.yml` (falta configurar el entorno `release`), QR en el generador offline, enclave Nitro para managed.

## Licencia
Apache-2.0 (ver `LICENSE` y `NOTICE`). El relay Buzz (Apache-2.0) se usa sin modificar como imagen upstream fijada por digest.
