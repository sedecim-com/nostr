# Acceso Nostr

**Acceso Nostr** (familia Acceso de Sedecim) implementa la especificación *"Plataforma Nostr Soberana / SaaS"* (v0.1, 25/09/2026):
un mismo protocolo Nostr con grados configurables de soberanía, anonimato, resiliencia, custodia y
control institucional. **La centralización es una capa voluntaria de conveniencia, no la base.**

> ⚠️ Early release. No apto para perfiles de alto riesgo hasta una revisión de seguridad independiente
> (ver [SECURITY.md](SECURITY.md)). NIP-17/NIP-44 no ofrecen forward secrecy; el modo *managed* es custodial (firma y
> descifra los DMs en el servidor).

## Qué incluye

| Área | Dónde | Notas |
|---|---|---|
| SDK Nostr propio (desacoplado de Buzz) | `packages/*` | — |
| Identidad, personas, custodia (local, offline, NIP-46, NIP-07, managed) | `packages/identity`, `packages/signer` | — |
| Máquina de estados de entrega + outbox cifrada + quorum multi-relay | `packages/delivery-engine` | — |
| DMs NIP-17 (NIP-44 + NIP-59) tras feature flag, canales NIP-29 | `packages/messaging` | gate en cada CI contra el Buzz fijado en `infra/buzz/PIN` (informe `docs/interop/buzz-upstream-ac4521f3e464-report.json`); requiere el adaptador de jitter acotado (300 s) |
| Grupos high-security Marmot/MLS | `packages/marmot-adapter`, `docs/marmot.md` | marmot-ts + ts-mls (alpha y RC upstream; vía relay secundario, Buzz no acepta los kinds) |
| Blossom con saneamiento EXIF y cifrado cliente | `packages/blossom-client`, `services/blob-store` | cifrados → blob-store; Buzz `/media` solo imágenes en claro |
| Sovereign Tor Mode (fail closed, DNS remoto, circuitos por persona) | `packages/tor-network`, `apps/sovereign-client` | — |
| Panel de soberanía con consecuencias verificables | `packages/profiles`, `apps/web-saas` | — |
| Generador de llaves offline standalone (bundle reproducible + checksum, QR, hoja imprimible, HTML air-gapped) | `apps/key-generator`, `packages/qr` | — |
| Web SaaS como cliente Nostr de primera clase (React 19 + MUI 9 + Vite; personas, canales, DMs, adjuntos) | `apps/web-saas` | vault IndexedDB (ADR 0007), login de Acceso en SaaS (ADR 0008) |
| Indexer / mirror ciphertext-first (Postgres) | `services/indexer` | — |
| Servicio de identidad (NIP-98, vínculos con consentimiento) | `services/identity-service` | — |
| Continuity Vault: copia del historial independiente de los relays, en sobres sellados en el cliente con una llave de archivo distinta de la nsec; el operador ve cuenta, tamaño y frecuencia, nunca el contenido | `services/continuity-vault`, `packages/continuity`, [ADR 0011](docs/adr/0011-continuity-vault.md), [threat model](docs/threat-models/continuity-vault.md) | servicio y sobres (VAULT-01); la llave de archivo viaja en los backups de la web y del CLI (VAULT-02); la web y el CLI sellan el historial (canales, DMs, mensajes de grupo, ledger y estado MLS) y un dispositivo limpio lo recupera con relays vacíos (VAULT-03); cada envío se copia según la política de la persona (off, best-effort o required-for-resilient), con `CONTINUITY_BACKED_UP` aparte de los ACK (VAULT-04); retención por cuenta dentro del máximo del operador, exportación a un JSON abierto y borrado de la cuenta entera (VAULT-05); en el compose, con sus sobres en un bucket propio de SeaweedFS (o en un directorio o cualquier S3-compatible), en el backup y en el restore drill (VAULT-06); en Kubernetes es un componente opt-in que stage aún no activa |
| Managed signer custodial y opt-in (AWS Secrets Manager + KMS en us-east-1, registro en Postgres, firma y NIP-44 en el servidor autorizados con el token de Acceso o una sesión de dispositivo, consentimiento registrado con su versión) | `services/managed-signer`, [ADR 0009](docs/adr/0009-custodia-managed-region-y-marco-legal.md) | (términos pendientes de legal; tier enclave Nitro: prototipo con attestation verificada localmente, también en el navegador, que sella hacia el enclave los secretos de importación y la contraseña de exportación (FR005-10); falta probarlo en AWS, [docs/managed-enclave.md](docs/managed-enclave.md)) |
| Modo institucional: RBAC/ABAC, device trust, revocación, auditoría | `services/policy-engine` | Postgres, tablas `policy_*`; sin `DATABASE_URL`, en memoria |
| Consola de administración web (NIP-98; personas, recursos, dispositivos y passkeys, rotaciones, directorio, retención, auditoría) | `apps/admin-console`, [docs/admin-console.md](docs/admin-console.md) | servida por la imagen web en `/admin/` |
| Notificaciones push opacas por perfil (Web Push VAPID + RFC 8291; sin contenido, remitente ni recuento; deshabilitadas en sovereign/Tor) | `services/notification-gateway`, [ADR 0010](docs/adr/0010-notificaciones-push-por-perfil.md) | opt-in (perfil compose `push`; registros en memoria). El gateway solo acepta registros en relays donde su canario ve actividad sin leer DMs. Con Buzz y el secure relay fijados no la ve: no hay push web y la web explica por qué (matriz por relay en el ADR 0010, OPS-06) |
| Trazas de los servicios con muestreo y atributos acotados (método, ruta como plantilla, estado, duración), sin IPs, pubkeys, tokens ni contenido. Los clientes no trazan | `packages/telemetry-policy`, `packages/service-kit`, [docs/slo.md](docs/slo.md#trazas-nfr007-02) | apagadas por defecto (`TRACE_SAMPLE_RATE=0`), y siempre con `TELEMETRY_LEVEL=none` o hacia un `.onion`; van al log del servicio y, si el operador lo configura, a su colector OTLP |
| Stack self-hosted Docker Compose (Buzz fijado por digest, Tor opcional) | `docker-compose.yml`, `infra/` | — |
| Buzz upstream sin fork, fijado por digest | `infra/buzz/PIN`, `docs/adr/0002-subset-y-pin-de-buzz.md`, `docs/buzz-integration.md` | política de actualización: ADR 0003 |

## Estado por perfil y capacidad (OPS-19)

<!-- status:start (scripts/traceability.mjs desde los issues del backlog; no editar a mano) -->
> ⚠️ Ningún perfil ni capacidad tiene todavía una auditoría externa ni está activo en producción: no es apto para perfiles de alto riesgo (ver [SECURITY.md](SECURITY.md)).

Cada fila tiene el nivel de evidencia más bajo que alcanzan todas sus tareas del programa: **Merged** → **CI Verified** → **Stage Verified** → **Externally Audited** → **Production Enabled** (labels `evidencia:*`, OPS-17). Las tareas hechas antes de OPS-17 cuentan como Merged. Mientras falte alguna, la fila está **En curso**. Detalle: [docs/status.md](docs/status.md) y [docs/requirements-traceability.md](docs/requirements-traceability.md).

| Perfil o capacidad | Tipo | Nivel de evidencia | Tareas hechas | Abiertas (sprint) |
|---|---|---|---:|---|
| convenience (SaaS) | Perfil | En curso | 10 de 15 | NFR001-01 (S10), NFR001-02 (S10), NFR001-03 (S10), NFR004-02 (S11), NFR001-04 (S11) y 1 más |
| private-resilient | Perfil | En curso | 13 de 14 | VAULT-07 (S10) |
| institutional | Perfil | Merged | 14 de 14 | — |
| sovereign (self-hosted) | Perfil | En curso | 9 de 10 | NFR003-03 (S11), NFR003-04 (Diferido) |
| sovereign-tor | Perfil | Merged | 7 de 7 | FR020-02 (Diferido) |
| Identidad, personas y custodia en el dispositivo | Capacidad | En curso | 27 de 30 | FR003-06 (S9), FR003-07 (S9), FR007-06 (S10) |
| Custodia gestionada y Nitro Enclave | Capacidad | En curso | 13 de 16 | FR005-05 (S14), FR026-04 (S11), FR005-13 (S11), FR005-09 (Diferido), FR005-10 (Diferido) |
| Entrega fiable (outbox, quorum, acuses) | Capacidad | En curso | 19 de 20 | NFR002-03 (S11) |
| DMs NIP-17 y canales NIP-29 | Capacidad | Merged | 8 de 8 | — |
| Grupos Marmot/MLS | Capacidad | Merged | 9 de 9 | FR025-08 (Diferido), FR025-14 (Diferido) |
| Continuity Vault | Capacidad | En curso | 6 de 7 | VAULT-07 (S10) |
| Adjuntos Blossom sin metadatos | Capacidad | Merged | 8 de 8 | — |
| Panel de soberanía, madurez y disclosures | Capacidad | En curso | 5 de 7 | FR028-02 (S13), VAULT-07 (S10), NFR007-03 (Diferido) |
| Notificaciones push | Capacidad | Merged | 2 de 2 | DEC-13 (Diferido) |
| Sin telemetría ni secretos en los logs | Capacidad | Merged | 7 de 7 | — |
| Releases firmados, SBOM e imágenes reproducibles | Capacidad | En curso | 3 de 5 | FR003-06 (S9), NFR010-02 (S9) |
| Accesibilidad | Capacidad | En curso | 1 de 2 | NFR009-02 (S10) |
<!-- status:end -->

## Madurez por perfil y función

Antes de v1.0 nada es GA: falta la revisión externa (SEC-01 y SEC-02). La web, el CLI (`sovereign maturity`) y las notas de release muestran la misma tabla.

<!-- maturity:start (scripts/maturity.ts desde packages/profiles/src/maturity.ts; no editar a mano) -->
| Perfil o función | Tipo | Hoy | Por qué | En v1.0 |
|---|---|---|---|---|
| convenience (SaaS) | Perfil | Early release | Sin revisión externa ni stage en AWS todavía. | GA controlado, con SEC-01, SEC-02, el stage y la release firmada. |
| private-resilient | Perfil | Early release | Sin revisión externa. Sin Continuity Vault en el despliegue, el historial depende de los relays y el perfil queda en Beta. | GA controlado, solo con el Continuity Vault. |
| institutional | Perfil | Early release | Sin pentest sobre stage todavía. | GA controlado, con el pentest sobre stage y la auditoría. |
| sovereign (self-hosted) | Perfil | Early release | Todavía no hay una release firmada. | GA técnico, con la release firmada, la instalación reproducible y el restore drill. |
| sovereign-tor | Perfil | Experimental | Falla cerrado y tiene pruebas de fugas propias, pero ni el cliente ni sus dependencias tienen revisión independiente. | Experimental: nada lo declara apto para alto riesgo sin una auditoría específica y un cliente dedicado. |
| DMs NIP-17 | Función | Early release | Solo se habilitan con el gate de interoperabilidad contra el Buzz fijado en verde. No ofrecen forward secrecy. | Con el perfil que los usa, y siempre detrás del gate de interoperabilidad. |
| Grupos Marmot/MLS | Función | Beta | marmot-ts es alpha y ts-mls está en release candidate. | Beta mientras marmot-ts o ts-mls sean alpha o release candidate. |
| Continuity Vault | Función | Early release | Falta aprobar su threat model (VAULT-07) y la revisión externa. | Con private-resilient. |
| Custodia gestionada básica | Función | Early release | Espera la aprobación legal (DEC-12) y la validación en AWS; el gate de release no la deja en producción. | GA opcional, con la aprobación legal y KMS y Secrets Manager reales. |
| Custodia en Nitro Enclave | Función | Preview | Prototipo: la attestation solo se verificó en local, y va apagada en producción. | Preview: EIF, PCR, attestation y KMS reales más auditoría. |
| Notificaciones push | Función | Experimental | Con Buzz y el secure relay, el gateway no puede ver la actividad sin leer DMs, así que no se ofrecen. | Experimental, detrás de un flag. |
| Estado de presencia (NIP-38) | Función | Experimental | Solo en la web y apagado salvo que la persona lo active. No está probado contra el Buzz fijado: el gate de interoperabilidad registra si acepta el kind 30315, sin exigirlo. | Fuera del programa de v1.0: sigue Experimental. |
<!-- maturity:end -->

Trazabilidad FR/NFR → tareas → tests y tablero de estado, generados desde los issues y el código (CI comprueba que toda la evidencia citada exista): [docs/requirements-traceability.md](docs/requirements-traceability.md) · [docs/status.md](docs/status.md).
Backlog con tareas atómicas, prioridad, dependencias y sprint: vive en [GitHub Issues](https://github.com/sedecim-com/nostr/issues?q=label%3Abacklog) (milestones = sprints, epics con sub-issues) y se sincroniza a [docs/backlog/](docs/backlog/README.md) con una PR automática (ver [GITHUB.md](docs/backlog/GITHUB.md)).
Arquitectura: [docs/architecture.md](docs/architecture.md) · Threat model: [docs/threat-model.md](docs/threat-model.md).
SDK: referencia con TypeDoc (`npm run docs:api`, portada en [docs/sdk.md](docs/sdk.md)) · APIs HTTP de los servicios: [docs/openapi/](docs/openapi/README.md) (OpenAPI 3.1, `npm run docs:openapi`) · distribución del SDK: [ADR 0013](docs/adr/0013-distribucion-del-sdk.md).
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
docker compose up -d          # relay Buzz, postgres, redis, SeaweedFS (S3), indexer, identity, policy, blob-store, continuity-vault, secure-relay, web
docker compose --profile tor up -d       # + Tor SOCKS y relay .onion
docker compose run --rm sovereign persona list   # el CLI soberano en un contenedor que solo sale por tor:9050
docker compose --profile managed up -d   # + managed signer (CUSTODIAL, opt-in; requiere Acceso: COGNITO_*)
```
El CLI como servicio del perfil `tor`, con la passphrase en un fichero secreto (`SOVEREIGN_PASSPHRASE_FILE`), sus
backups y qué pasa si tor cae: [docs/sovereign-tor.md](docs/sovereign-tor.md#el-cli-como-servicio-del-perfil-tor-fr020-06).
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
- `"managedEnclave"` (con `managedSigner` y `MANAGED_SIGNER_BACKEND=enclave`): `{ "pcr0", "pcr1", "pcr2", "pcr8"? }`, los
  PCR de la imagen del enclave publicada (`nitro-cli build-enclave` o `describe-eif`; los valores de `enclave_pcr*` en
  Terraform), 96 caracteres hex cada uno. Con él, la web verifica en el navegador la attestation del enclave y sella la
  contraseña de exportación hacia él, así que el managed-signer no la recibe en claro (FR005-10,
  [managed-enclave.md](docs/managed-enclave.md)). Mal formado, la app no arranca. Sin él, la exportación va como antes.
- `"continuityVault"` (opcional): URL de `services/continuity-vault` ([ADR 0011](docs/adr/0011-continuity-vault.md)); el
  compose lo levanta en `http://localhost:8088` y `infra/web/config.json` ya lo apunta ahí (VAULT-06). La
  tarjeta «Continuity Vault» explica qué ve el operador, sella el historial de la persona en el navegador con su llave
  de archivo (canales, DMs, mensajes de grupo, ledger de entrega y estado MLS) y comprueba que se abre. En un
  navegador limpio, tras importar el backup, «Restaurar desde el vault» lo recupera aunque los relays lo hayan
  perdido. La llave viaja en el backup de la persona (v2), también cuando su llave vive en un signer. VAULT-04: el
  control `continuity` del panel copia cada envío (`best-effort`) o lo retiene hasta tener su copia
  (`required-for-resilient`, el de private-resilient). La columna «Vault» de Entrega muestra el estado. VAULT-05:
  la tarjeta elige cuánto se guardan los archivos (dentro del máximo del operador, `VAULT_RETENTION_DAYS`), exporta
  el vault a un JSON abierto (`sedecim-vault-export`) y lo borra entero, con confirmación.
- `"discoveryRelays"` (opcional): relays donde también se buscan las listas de relays de DM de los destinatarios
  (kinds 10050 y 10002), además de los de la persona. Cada búsqueda les dice a qué npub vas a escribir. Si al
  escribir un DM no se encuentra la lista (por ejemplo, sin red), cada reintento la vuelve a buscar antes de
  publicar: el mensaje no se queda en tus relays (FR010-03).
- En producción, `managedSigner`, `managedTerms`, `managedEnclave` y `notificationGateway` solo aparecen con su
  evidencia: la aprobación legal y los informes de SEC-01 y SEC-02 para la custodia gestionada, salir de Preview para el
  enclave, y un disparador seguro en los relays para push. Lo comprueba `node scripts/release-gate.mjs config` (OPS-20,
  [`deploy/production-gates.json`](deploy/production-gates.json)).

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
npm run sovereign -- vault push --persona <id> --vault URL   # sella aquí el historial y lo guarda en el Continuity Vault
npm run sovereign -- vault restore --persona <id> --vault URL   # lo recupera y lo vuelve a publicar en tus relays
npm run sovereign -- persona continuity --persona <id> best-effort --vault URL   # copia cada envío (o required-for-resilient)
npm run sovereign -- group history --persona <id>   # mensajes de grupo leídos, enviados o restaurados
npm run sovereign -- dm send --persona <id> --to NPUB "hola"  # a los relays de DM (10050) del destinatario, como la web
npm run sovereign -- dm watch --persona <id>    # DMs y acuses según llegan a tus relays de DM (Ctrl-C para salir)
npm run sovereign -- persona create --label Fuente --relay ws://<onion>.onion --onion-only   # solo Tor y .onion
npm run sovereign -- persona import --key-file llave.txt --npub npub1… --label Fuente --relay ws://<onion>.onion --tor   # nsec o ncryptsec: custodia local
npm run sovereign -- persona connect --bunker-file bunker.txt --label Fuente --relay ws://<onion>.onion --tor   # signer NIP-46 por Tor: custodia external
```
Custodia de cada persona según su llave real, signer NIP-46 (`bunker://` o `nostrconnect://`) por Tor y qué ve cada
parte: [docs/sovereign-tor.md](docs/sovereign-tor.md#custodia-llave-en-el-dispositivo-o-signer-nip-46-fr004-08).

## Pruebas
| Comando | Qué cubre |
|---|---|
| `npm test` | Unitarios + E2E contra relay/Blossom/SOCKS en memoria (NIP-42, quorum, offline, Tor fail-closed, NIP-46, interop con nostr-tools) |
| `npm run test:pg` | Pruebas sobre Postgres de los servicios: indexer, identity-service, policy-engine, managed-signer y continuity-vault (`TEST_DATABASE_URL`) |
| `npm run test:keygen-html` | Generador HTML air-gapped abierto desde `file://` sin red |
| `npm run lint:claims` | Prohíbe afirmaciones absolutas de privacidad en todo el copy |
| `npm run test:browser` | Web en Chromium (Playwright): personas, canales, DMs con ruteo 10050, adjuntos, receipts, panel aplicado y persistido, vault, nsec que no sale del navegador, axe-core, modo SaaS con Acceso; grupos Marmot (con varios dispositivos por persona, propuestas, rotación y archivos cifrados), fugas por WebRTC y previews, consola de administración |
| `npm run test:leak` | Captura de red real (netns + tcpdump) del CLI soberano, perfiles Tor y directo, con controles negativos (job `leak-tests`) |
| `BUZZ_RELAY_URL=… npx tsx tests/browser/web-buzz.e2e.ts` | Web contra Buzz real: crear canal, unirse, enviar y leer (FR015-03; job `stack` de CI) |
| `npm run test:interop` | Gate contra Buzz real (`BUZZ_RELAY_URL`), genera `interop-report.json` |
| `sh scripts/backup.sh` / `sh scripts/restore.sh DIR` | Backup y restore del stack self-hosted (`docs/runbooks/restore.md`; drill nocturno `restore-drill.yml`) |
| `sh scripts/scan-logs.sh compose.log .env` | Busca secretos en los logs del stack: reglas de gitleaks + valores de `.env` (job `stack` de CI) |
| `sh scripts/stack-profiles.sh configure\|exercise\|logged` | Solo stacks de prueba: activa los perfiles opcionales (managed, push, institutional, tor) con secretos generados, les envía una credencial canario y exige que cada servicio salga en el log escaneado (job `stack` de CI) |

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
