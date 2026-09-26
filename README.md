# Plataforma Nostr Soberana / SaaS

Implementación v0.1 de la especificación *"Plataforma Nostr Soberana / SaaS"* (v0.1, 25/09/2026):
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
| Grupos high-security Marmot/MLS | `packages/marmot-adapter` | ⏳ interfaz + conformidad; sin proveedor (fail closed) |
| Blossom con saneamiento EXIF y cifrado cliente | `packages/blossom-client`, `services/blob-store` | ✅ (cifrados → blob-store; Buzz `/media` solo imágenes en claro) |
| Sovereign Tor Mode (fail closed, DNS remoto, circuitos por persona) | `packages/tor-network`, `apps/sovereign-client` | ✅ |
| Panel de soberanía con consecuencias verificables | `packages/profiles`, `apps/web-saas` | ✅ |
| Generador de llaves offline standalone (bundle reproducible + checksum) | `apps/key-generator` | ✅ (QR/impresión pendiente) |
| Web SaaS como cliente Nostr de primera clase | `apps/web-saas` | ✅ |
| Indexer / mirror ciphertext-first (Postgres) | `services/indexer` | ✅ |
| Servicio de identidad (NIP-98, vínculos con consentimiento) | `services/identity-service` | ✅ |
| Managed signer + vault (envelope local / AWS Secrets Manager) | `services/managed-signer` | ✅ (enclave Nitro pendiente) |
| Modo institucional: RBAC/ABAC, device trust, revocación, auditoría | `services/policy-engine` | ✅ (persistencia en memoria) |
| Stack self-hosted Docker Compose (Buzz fijado por digest, Tor opcional) | `docker-compose.yml`, `infra/` | ✅ |
| Fork controlado de Buzz | `infra/buzz/PIN`, `scripts/buzz-fork.sh`, `docs/buzz-integration.md` | ✅ proceso; sin parches propios |

Trazabilidad completa FR/NFR → tests: [docs/requirements-traceability.md](docs/requirements-traceability.md).
Arquitectura: [docs/architecture.md](docs/architecture.md) · Threat model: [docs/threat-model.md](docs/threat-model.md).

## Inicio rápido

### Desarrollo (sin Docker)
```bash
npm install
npm run check                 # typecheck + 100+ tests (unitarios y E2E en proceso)
npm run dev:relay             # relay de desarrollo en memoria: ws://localhost:7777
npm run build:web && python3 -m http.server -d apps/web-saas/public 8080
```

### Self-hosted soberano (spec §4.1)
```bash
git clone <repo> && cd nostr
sh scripts/init-env.sh        # genera .env con secretos aleatorios (cp .env.example .env)
docker compose up -d          # relay Buzz, postgres, redis, minio, indexer, identity, policy, web
docker compose --profile tor up -d       # + Tor SOCKS y relay .onion
docker compose --profile managed up -d   # + managed signer (CUSTODIAL, opt-in)
```
Web: http://localhost:8080 · Relay: ws://localhost:3000 · Indexer: http://localhost:8081

### Llave offline
```bash
npm run keygen -- --out backup.json          # NIP-49 ncryptsec, sin red (primitivas bloqueadas)
npm run keygen -- verify backup.json
node apps/key-generator/build.mjs             # dist/keygen.mjs + .sha256 para distribución air-gapped
```

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
| `npm run test:browser` | Web SaaS en Chromium (Playwright): lectura/envío interoperable, flag NIP-17, panel |
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
- F0/F0.5: repetir `test:interop` con el stack Docker completo (MinIO) para validar la subida de imágenes en claro a Buzz `/media`.
- F2: NIP-77 Negentropy; persistencia en Postgres del policy-engine; notification-gateway.
- F3: auditoría independiente de fugas; cliente móvil/desktop dedicado para Tor.
- F4: proveedor Marmot (MDK fijado) que pase `runConformance`.
- F5: admin-console, directorio con passkeys/attestation, legal hold.
- Firma de releases (claves del proyecto), QR en el generador offline, enclave Nitro para managed.

## Licencia
MIT (ver `LICENSE`). El relay Buzz es Apache-2.0 y se usa como imagen/fork separado.
