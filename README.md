# Acceso Nostr

**Acceso Nostr** (familia Acceso de Sedecim) implementa la especificación *"Plataforma Nostr Soberana / SaaS"* (v0.1, 25/09/2026):
un mismo protocolo Nostr con grados configurables de soberanía, anonimato, resiliencia, custodia y
control institucional. **La centralización es una capa voluntaria de conveniencia, no la base.**

> ⚠️ Early release. No apto para perfiles de alto riesgo hasta una revisión de seguridad independiente
> (ver [SECURITY.md](SECURITY.md)). NIP-17/NIP-44 no ofrecen forward secrecy; el modo *managed* es custodial (firma y
> descifra los DMs en el servidor).

## Qué incluye

| Área | Dónde | Estado |
|---|---|---|
| SDK Nostr propio (desacoplado de Buzz) | `packages/*` | ✅ |
| Identidad, personas, custodia (local, offline, NIP-46, NIP-07, managed) | `packages/identity`, `packages/signer` | ✅ |
| Máquina de estados de entrega + outbox cifrada + quorum multi-relay | `packages/delivery-engine` | ✅ |
| DMs NIP-17 (NIP-44 + NIP-59) tras feature flag, canales NIP-29 | `packages/messaging` | ✅ gate en cada CI contra el Buzz fijado en `infra/buzz/PIN` (informe `docs/interop/buzz-upstream-ac4521f3e464-report.json`); requiere el adaptador de jitter acotado (300 s) |
| Grupos high-security Marmot/MLS | `packages/marmot-adapter`, `docs/marmot.md` | ✅ marmot-ts + ts-mls (alpha y RC upstream; vía relay secundario, Buzz no acepta los kinds) |
| Blossom con saneamiento EXIF y cifrado cliente | `packages/blossom-client`, `services/blob-store` | ✅ (cifrados → blob-store; Buzz `/media` solo imágenes en claro) |
| Sovereign Tor Mode (fail closed, DNS remoto, circuitos por persona) | `packages/tor-network`, `apps/sovereign-client` | ✅ |
| Panel de soberanía con consecuencias verificables | `packages/profiles`, `apps/web-saas` | ✅ |
| Generador de llaves offline standalone (bundle reproducible + checksum, QR, hoja imprimible, HTML air-gapped) | `apps/key-generator`, `packages/qr` | ✅ |
| Web SaaS como cliente Nostr de primera clase (React 19 + MUI 7 + Vite; personas, canales, DMs, adjuntos) | `apps/web-saas` | ✅ vault IndexedDB (ADR 0007), login de Acceso en SaaS (ADR 0008) |
| Indexer / mirror ciphertext-first (Postgres) | `services/indexer` | ✅ |
| Servicio de identidad (NIP-98, vínculos con consentimiento) | `services/identity-service` | ✅ |
| Continuity Vault: copia del historial independiente de los relays, en sobres sellados en el cliente con una llave de archivo distinta de la nsec; el operador ve cuenta, tamaño y frecuencia, nunca el contenido | `services/continuity-vault`, `packages/continuity`, [ADR 0011](docs/adr/0011-continuity-vault.md), [threat model](docs/threat-models/continuity-vault.md) | 🟡 servicio y sobres (VAULT-01); la llave de archivo viaja en los backups de la web y del CLI, y ambos sellan y guardan el ledger de entrega (VAULT-02); faltan los eventos y la restauración con relays vacíos (VAULT-03), el estado en el envío (VAULT-04) y el compose (VAULT-06) |
| Managed signer custodial y opt-in (AWS Secrets Manager + KMS en us-east-1, registro en Postgres, firma y NIP-44 en el servidor autorizados con el token de Acceso o una sesión de dispositivo, consentimiento registrado con su versión) | `services/managed-signer`, [ADR 0009](docs/adr/0009-custodia-managed-region-y-marco-legal.md) | ✅ (términos pendientes de legal; tier enclave Nitro: prototipo con attestation verificada localmente, falta probarlo en AWS, [docs/managed-enclave.md](docs/managed-enclave.md)) |
| Modo institucional: RBAC/ABAC, device trust, revocación, auditoría | `services/policy-engine` | ✅ (Postgres, tablas `policy_*`; sin `DATABASE_URL`, en memoria) |
| Consola de administración web (NIP-98; personas, recursos, dispositivos y passkeys, rotaciones, directorio, retención, auditoría) | `apps/admin-console`, [docs/admin-console.md](docs/admin-console.md) | ✅ servida por la imagen web en `/admin/` |
| Notificaciones push opacas por perfil (Web Push VAPID + RFC 8291; sin contenido, remitente ni recuento; deshabilitadas en sovereign/Tor) | `services/notification-gateway`, [ADR 0010](docs/adr/0010-notificaciones-push-por-perfil.md) | 🟡 opt-in (perfil compose `push`; registros en memoria): con los relays fijados el gateway no ve los gift wraps y el aviso no llega (ADR 0010, OPS-06) |
| Stack self-hosted Docker Compose (Buzz fijado por digest, Tor opcional) | `docker-compose.yml`, `infra/` | ✅ |
| Buzz upstream sin fork, fijado por digest | `infra/buzz/PIN`, `docs/adr/0002-subset-y-pin-de-buzz.md`, `docs/buzz-integration.md` | ✅ (política de actualización: ADR 0003) |

Trazabilidad completa FR/NFR → tests: [docs/requirements-traceability.md](docs/requirements-traceability.md).
Backlog con tareas atómicas, prioridad, dependencias y sprint: vive en [GitHub Issues](https://github.com/sedecim-com/nostr/issues?q=label%3Abacklog) (milestones = sprints, epics con sub-issues) y se sincroniza a [docs/backlog/](docs/backlog/README.md) con una PR automática (ver [GITHUB.md](docs/backlog/GITHUB.md)).
Arquitectura: [docs/architecture.md](docs/architecture.md) · Threat model: [docs/threat-model.md](docs/threat-model.md).
Releases firmados (cosign keyless + provenance SLSA), imágenes reproducibles, build desde source y verificación: [docs/building.md](docs/building.md) (`sh scripts/verify-release.sh <tag>`, `sh scripts/rebuild-image.sh <tag> <servicio>`). Definition of Done de un release: [docs/release-checklist.md](docs/release-checklist.md); notas: [docs/releases/](docs/releases/).

## Inicio rápido

### Desarrollo (sin Docker)
```bash
npm install
npm run check                 # typecheck + tests (unitarios y E2E en proceso)
npm run dev:relay             # relay de desarrollo en memoria: ws://localhost:7777
npm run dev:web                # web en http://localhost:5173 (Vite); npm run build:web → apps/web-saas/dist
npm run dev:admin              # consola de administración en http://localhost:5174; npm run build:admin
```

### Self-hosted soberano (spec §4.1)
```bash
git clone <repo> && cd nostr
sh scripts/init-env.sh        # genera o completa .env sin sobrescribir valores (tras `npm ci`, llaves del keygen offline)
docker compose up -d          # relay Buzz, postgres, redis, SeaweedFS (S3), indexer, identity, policy, blob-store, secure-relay, web
docker compose --profile tor up -d       # + Tor SOCKS y relay .onion
docker compose --profile managed up -d   # + managed signer (CUSTODIAL, opt-in; requiere Acceso: COGNITO_*)
```
Web: http://localhost:8080 · Consola de administración: http://localhost:8080/admin/ · Relay: ws://localhost:3000 · Indexer: http://localhost:8081

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
- `"managedTerms"` (con `managedSigner`): `{ "url", "version" }` de los términos publicados de la custodia gestionada
  ([borrador](docs/legal/custodia-managed.md), pendiente de legal). La aceptación enlaza esos términos y el
  managed-signer guarda su versión con la llave (FR005-08). Sin ella, la web avisa de que no están publicados y
  lo registra así.
- `"continuityVault"` (opcional): URL de `services/continuity-vault` ([ADR 0011](docs/adr/0011-continuity-vault.md)). La
  tarjeta «Continuity Vault» explica qué ve el operador, sella el ledger de entrega en el navegador con la llave de
  archivo de la persona y comprueba que se abre. La llave viaja en el backup de la persona (v2), también cuando su
  llave vive en un signer.
- `"discoveryRelays"` (opcional): relays donde también se buscan las listas de relays de DM de los destinatarios
  (kinds 10050 y 10002), además de los de la persona. Cada búsqueda les dice a qué npub vas a escribir. Si al
  escribir un DM no se encuentra la lista (por ejemplo, sin red), cada reintento la vuelve a buscar antes de
  publicar: el mensaje no se queda en tus relays (FR010-03).

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
npm run sovereign -- vault push --persona <id> --vault URL   # sella el ledger aquí y lo guarda en el Continuity Vault
npm run sovereign -- dm send --persona <id> --to NPUB "hola"  # a los relays de DM (10050) del destinatario, como la web
npm run sovereign -- dm watch --persona <id>    # DMs y acuses según llegan a tus relays de DM (Ctrl-C para salir)
```

## Pruebas
| Comando | Qué cubre |
|---|---|
| `npm test` | Unitarios + E2E contra relay/Blossom/SOCKS en memoria (NIP-42, quorum, offline, Tor fail-closed, NIP-46, interop con nostr-tools) |
| `npm run test:pg` | Pruebas sobre Postgres de los servicios: indexer, identity-service, policy-engine, managed-signer y continuity-vault (`TEST_DATABASE_URL`) |
| `npm run test:keygen-html` | Generador HTML air-gapped abierto desde `file://` sin red |
| `npm run lint:claims` | Prohíbe afirmaciones absolutas de privacidad en todo el copy |
| `npm run test:browser` | Web en Chromium (Playwright): personas, canales, DMs con ruteo 10050, adjuntos, receipts, panel aplicado y persistido, vault, nsec que no sale del navegador, axe-core, modo SaaS con Acceso; grupos Marmot, fugas por WebRTC y previews, consola de administración |
| `npm run test:leak` | Captura de red real (netns + tcpdump) del CLI soberano, perfiles Tor y directo, con controles negativos (job `leak-tests`) |
| `BUZZ_RELAY_URL=… npx tsx tests/browser/web-buzz.e2e.ts` | Web contra Buzz real: crear canal, unirse, enviar y leer (FR015-03; job `stack` de CI) |
| `npm run test:interop` | Gate contra Buzz real (`BUZZ_RELAY_URL`), genera `interop-report.json` |
| `sh scripts/backup.sh` / `sh scripts/restore.sh DIR` | Backup y restore del stack self-hosted (`docs/runbooks/restore.md`; drill nocturno `restore-drill.yml`) |
| `sh scripts/scan-logs.sh compose.log .env` | Busca secretos en los logs del stack: reglas de gitleaks + valores de `.env` (job `stack` de CI) |

## Estructura
```
packages/   SDK compartido (nostr-core, relay-pool, signer, delivery-engine, encrypted-store, identity,
            messaging, marmot-adapter, blossom-client, tor-network, telemetry-policy, metrics, profiles,
            policy-client, sync, service-kit, qr, rotation-worker, continuity, test-relay)
apps/       web-saas, admin-console, sovereign-client, key-generator
services/   indexer, identity-service, managed-signer, policy-engine, blob-store, notification-gateway,
            continuity-vault
infra/      buzz (pin), secure-relay, tor, caddy (TLS), postgres, web
deploy/     Kubernetes (kustomize) y Terraform del SaaS en staging, monitorización de SLO (deploy/README.md)
docs/       arquitectura, ADR, threat models por perfil, seguridad (alcance, inventario criptográfico, revisión
            interna), trazabilidad, integración Buzz, Tor, runbooks, SLO, RPO/RTO, notas de release
```

## Pendiente (roadmap §22)
- F2: transportes push nativos (APNs/FCM/UnifiedPush) tras la interfaz del notification-gateway, solo con app nativa
  (fuera de este programa); con los relays de referencia el push web no se dispara (OPS-06). NIP-77 Negentropy ya
  está en `packages/sync`, con fallback a REQ por ventanas.
- F3: auditoría independiente de fugas y captura de red también para DMs, grupos y media (FR020-05); cliente
  dedicado para Tor (FR020-02, después de v1.0).
- F4: unificar Marmot en Buzz si upstream acepta sus kinds; que MDK pueda añadir miembros marmot-ts por su key
  package actual (`mls_proposals`, abierto upstream); ts-mls y marmot-ts estables (FR025-08).
- F5: worker de rotaciones como servicio y sesiones de dispositivo en la web managed (FR024-05); auditoría y
  retención legal coherentes con la confidencialidad (FR023-12); CI del modo institucional (FR023-13).
- Primer release firmado con `release.yml` (falta configurar el entorno `release` y aprobar el waiver de v0.1.0) y
  enclave Nitro para managed en AWS real (EIF medida, attestation real; FR005-05).

## Licencia
Apache-2.0 (ver `LICENSE` y `NOTICE`). El relay Buzz (Apache-2.0) se usa sin modificar como imagen upstream fijada por digest.
