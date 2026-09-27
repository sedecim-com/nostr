# Trazabilidad de requisitos (v0.1)

Estado: ✅ implementado y con test automático · 🟡 parcial · ⏳ pendiente (fase indicada).
Los tests se ejecutan con `npm test` (unitarios + E2E en proceso), `npm run test:pg` (Postgres),
`npm run test:browser` (Chromium) y `npm run test:interop` (contra Buzz real).

| ID | Requisito | Estado | Evidencia |
|----|-----------|--------|-----------|
| FR-001 | Crear identidad local | ✅ | `packages/identity/test/identity.test.ts` (crea, firma, verifica); `packages/nostr-core` `selfTestKey` |
| FR-002 | Importar identidad | ✅ | `identity.test.ts` (nsec/ncryptsec con validación de pubkey, bunker, managed; backups `sedecim-offline-key` y `acceso-nostr-key-backup` con `parseKeyBackup`/`openKeyBackup`), `sovereign-client/test/import.test.ts` (`persona import --backup`) |
| FR-003 | Generador offline | ✅ | `apps/key-generator/test/keygen.test.ts` (primitivas de red bloqueadas; bundle reproducible con checksum; `--qr`; hoja `--print` sin recursos remotos; HTML air-gapped con CSP por hash), `packages/qr/test` (vectores de referencia + decodificador independiente), `tests/browser/keygen-html.e2e.ts` (file:// con red bloqueada) |
| FR-004 | External signer NIP-46 | ✅ | `packages/signer/test/signer.test.ts` (bunker ↔ cliente sobre relay, permisos por kind) |
| FR-005 | Managed key | ✅ | `services/managed-signer/test` (vault dedicado; logs/uso/archivos sin secreto) |
| FR-006 | Múltiples personas | ✅ | `identity.test.ts` (≥3 personas, stores y relays independientes) |
| FR-007 | Identity linking | ✅ | `identity.test.ts` + `services/identity-service/test` (confirmación explícita, auditoría, visibilidad); vínculo público opcional firmado por ambas personas (`public-link.test.ts`, `docs/public-link.md`) |
| FR-008 | Persistir antes de transmitir | ✅ | `packages/delivery-engine/test/engine.test.ts` |
| FR-009 | Relay ack ≠ recepción | ✅ | `engine.test.ts`, `relay-pool/test/pool.test.ts` (estados separados) |
| FR-010 | Multi-relay + quorum | ✅ | `engine.test.ts` (2 de 3) |
| FR-011 | Reintento desde outbox | ✅ | `engine.test.ts` (offline → online, mismo event id; estadísticas y clases de fallo por relay); métricas de outbox en `packages/metrics/test` |
| FR-012 | Deduplicación | ✅ | `pool.test.ts`, `sync.test.ts` |
| FR-013 | Sync tras reinstalar | ✅ | `packages/sync`: NIP-77 (Negentropy, solo se transfieren los faltantes) con fallback automático a REQ por ventanas si el relay no lo soporta o aborta la sesión (`sync.test.ts`); gift wraps con timestamps de hasta 2 días sin pérdidas (`gift-wrap-window.test.ts`); E2E reinstalar → restaurar backup → canales, DMs y outbox iguales (`tests/e2e/reinstall-history.test.ts`) |
| FR-014 | SaaS mirror | ✅ | `services/indexer/test` + `tests/browser/web-saas.e2e.ts` |
| FR-015 | SaaS send | ✅ | `tests/browser/web-saas.e2e.ts` (web → relay → otro cliente) |
| FR-016 | NIP-42 | ✅ | `pool.test.ts` (challenge/response, auth-required recuperable) |
| FR-017 | NIP-17 con gate | ✅ | Feature flag + `tests/interop` ejecutado contra Buzz `02c6309`: requiere adaptador de jitter acotado (`docs/interop/buzz-02c6309-report.json`) |
| FR-018 | Blossom | ✅ | `packages/blossom-client/test`, `services/blob-store/test` (cifrados); Buzz `/media` rechaza blobs cifrados → blob-store; lista de servidores del usuario (kind 10063, BUD-03) en `server-list.test.ts` |
| FR-019 | Saneamiento EXIF | ✅ | `blossom.test.ts` (JPEG APP1/COM, PNG tEXt, WebP EXIF/XMP/ICCP con flags VP8X; HEIC/HEIF/AVIF rechazado con `requireSanitizable`) |
| FR-020 | Tor-only fail closed | ✅ | `tor-network/test`, `delivery-engine/test`, `apps/sovereign-client/test`; FR020-03: `scripts/leak-test.sh` (captura netns + pcap del CLI real: cero DNS/IPv6/conexiones fuera del proxy, con controles negativos; job `leak-tests`), `tests/leak/leak.test.ts` |
| FR-021 | Relay .onion | ✅ | `tor.test.ts`, `sovereign.test.ts` (SOCKS5h, DNS remoto, sin lookups locales); FR021-02: `scripts/tor-profile-check.sh` (compose `--profile tor`, CLI contra los .onion de relay y secure-relay; job `tor-profile`) |
| FR-022 | Sin telemetría | ✅ | `telemetry-policy/test` (nivel none bloquea endpoints); `sovereign.test.ts`; FR022-02: `scripts/leak-test.sh` (todo destino capturado está en la allowlist del perfil de la persona; negativo con un destino fuera) |
| FR-023 | RBAC/ABAC | ✅ | `policy-client/test`, `services/policy-engine/test` (memoria y Postgres, reinicio, directorio, retención, WebAuthn, allowlist de relays); `indexer/test/policy.test.ts`, `tests/e2e/institutional-policy.test.ts` (lecturas filtradas, retención); ver `docs/institutional.md` |
| FR-024 | Revocación | ✅ | `policy-engine.test.ts` (sesiones invalidadas, rotación señalada) |
| FR-025 | Grupo Marmot | ✅ | `MarmotTsProvider` (marmot-ts + ts-mls rc.16): `packages/marmot-adapter/test`, `apps/sovereign-client/test/groups.test.ts` (alta, expulsión sin fuga, rotación PCS, estado cifrado, Tor). FR025-06 multi-dispositivo (una hoja por dispositivo, key package por `d`, alta de todos los dispositivos, expulsión de todas las hojas; restaurar un backup entra como hoja nueva y elimina la clonada) y FR025-09 propuestas de miembros + commit del admin (rechazo de commits no admin, propuestas obsoletas entre épocas): `marmot-adapter/test/multidevice.test.ts`, `groups.test.ts`. FR025-05 MIP-04 (`mip04-v2`: clave del exporter MLS de la época, ChaCha20-Poly1305, `imeta`, subida a la lista Blossom kind 10063 / blob-store; expulsado no descifra media nueva): mismos tests. Buzz no acepta los kinds → relay secundario (`docs/marmot.md`). Interop con MDK 0.8.0: `tests/interop/marmot-mdk.interop.test.ts` (job `marmot-mdk`; MDK no puede invitar a marmot-ts por `mls_proposals`, abierta upstream). Versiones estables vigiladas por `marmot-upstream.yml` |
| FR-026 | Migración de custodia | ✅ | `managed-signer.test.ts` (export → prueba de posesión → retención → borrado) |
| FR-027 | Backup restore | ✅ | `identity.test.ts` (dispositivo limpio; backup v2 cifrado con relays, panel, estado MLS y outbox; compatibilidad v1), `groups.test.ts` (grupo MLS operativo tras restaurar, como hoja nueva vía `group rejoin`; la hoja clonada no envía), `identity-service/test/backup-vault.test.ts` (vault en la nube solo ciphertext: rechazo de texto plano, aislamiento entre cuentas, versiones, restauración con login de Acceso), `web-saas.e2e.ts` (subida y restauración en un dispositivo nuevo) |
| FR-028 | Disclosures | ✅ | `profiles/test`, `web-saas.e2e.ts`, `npm run lint:claims` en CI (`tests/scripts/lint-claims.test.ts`) |

| ID | Requisito | Estado | Evidencia / nota |
|----|-----------|--------|------------------|
| NFR-001 | Disponibilidad SaaS | 🟡 | IaC de staging (`deploy/k8s`, `deploy/terraform`, validados en CI job `deploy-config`); SLO 99,9 % con alertas multi-ventana (`deploy/monitoring`, `docs/slo.md`, `promtool test rules`). Despliegue en staging pendiente de credenciales AWS |
| NFR-002 | 0 pérdidas LOCAL_PERSISTED | ✅ | `engine.test.ts` (reinicio con FileBackend atómico + fsync); `encrypted-store/test/crash.test.ts` (30 kill -9 a mitad de escritura: valor viejo o nuevo, nunca corrupto) |
| NFR-003 | RPO/RTO | ✅ | `docs/rpo-rto.md` (aprobada el 2026-09-27); `scripts/backup.sh` / `scripts/restore.sh`; drill nocturno `restore-drill.yml` (host limpio + datos sembrados + `test:interop`, en verde desde el 2026-09-27) |
| NFR-004 | Latencia P95 | 🟡 | Exportador Prometheus por perfil (`packages/metrics/test`: histograma de ACK por relay/región, outbox, nada con perfil `none`); reglas P95/P99 y alertas de degradación (`deploy/monitoring`, `promtool test rules`, `docs/slo.md#latencia`); chip "degradado · P95" en la web (`tests/browser`). Medición real en staging pendiente |
| NFR-005 | Escalabilidad | 🟡 | Indexer sin estado + Postgres; relay según Buzz |
| NFR-006 | Sin secretos en logs | ✅ | `telemetry.test.ts`, `managed-signer.test.ts`; gitleaks en CI; logs del stack completo escaneados (`scripts/scan-logs.sh`: reglas de gitleaks + canario con los secretos de `.env`, job `stack`) |
| NFR-007 | Telemetría por perfil | ✅ | `TelemetryPolicy` + tests de endpoints permitidos |
| NFR-008 | Portabilidad | ✅ | NIP-49 ncryptsec, eventos Nostr crudos, backup JSON abierto; historial exportable/importable como JSONL de eventos firmados (`exportEventsJsonl`/`importEventsJsonl`, `sovereign history export/import`, verificado con nostr-tools) |
| NFR-009 | Accesibilidad | 🟡 | Navegación por teclado, labels, contraste claro/oscuro; auditoría formal pendiente |
| NFR-010 | Auditabilidad | 🟡 | SBOM (`npm run sbom`), checksums de keygen en CI; firma de releases pendiente de claves del proyecto |
