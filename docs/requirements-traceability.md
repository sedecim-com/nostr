# Trazabilidad de requisitos (v0.1)

Estado: ✅ implementado y con test automático · 🟡 parcial · ⏳ pendiente (fase indicada).
Los tests se ejecutan con `npm test` (unitarios + E2E en proceso), `npm run test:pg` (Postgres),
`npm run test:browser` (Chromium) y `npm run test:interop` (contra Buzz real).

| ID | Requisito | Estado | Evidencia |
|----|-----------|--------|-----------|
| FR-001 | Crear identidad local | ✅ | `packages/identity/test/identity.test.ts` (crea, firma, verifica); `packages/nostr-core` `selfTestKey` |
| FR-002 | Importar identidad | ✅ | `identity.test.ts` (nsec/ncryptsec con validación de pubkey, bunker, managed) |
| FR-003 | Generador offline | ✅ | `apps/key-generator/test/keygen.test.ts` (todas las primitivas de red bloqueadas; bundle reproducible con checksum) |
| FR-004 | External signer NIP-46 | ✅ | `packages/signer/test/signer.test.ts` (bunker ↔ cliente sobre relay, permisos por kind) |
| FR-005 | Managed key | ✅ | `services/managed-signer/test` (vault dedicado; logs/uso/archivos sin secreto) |
| FR-006 | Múltiples personas | ✅ | `identity.test.ts` (≥3 personas, stores y relays independientes) |
| FR-007 | Identity linking | ✅ | `identity.test.ts` + `services/identity-service/test` (confirmación explícita, auditoría, visibilidad) |
| FR-008 | Persistir antes de transmitir | ✅ | `packages/delivery-engine/test/engine.test.ts` |
| FR-009 | Relay ack ≠ recepción | ✅ | `engine.test.ts`, `relay-pool/test/pool.test.ts` (estados separados) |
| FR-010 | Multi-relay + quorum | ✅ | `engine.test.ts` (2 de 3) |
| FR-011 | Reintento desde outbox | ✅ | `engine.test.ts` (offline → online, mismo event id) |
| FR-012 | Deduplicación | ✅ | `pool.test.ts`, `sync.test.ts` |
| FR-013 | Sync tras reinstalar | 🟡 | `packages/sync` fallback por ventanas/paginación ✅; NIP-77 detectado pero no implementado (F2) |
| FR-014 | SaaS mirror | ✅ | `services/indexer/test` + `tests/browser/web-saas.e2e.ts` |
| FR-015 | SaaS send | ✅ | `tests/browser/web-saas.e2e.ts` (web → relay → otro cliente) |
| FR-016 | NIP-42 | ✅ | `pool.test.ts` (challenge/response, auth-required recuperable) |
| FR-017 | NIP-17 con gate | ✅ | Feature flag + `tests/interop` ejecutado contra Buzz `02c6309`: requiere adaptador de jitter acotado (`docs/interop/buzz-02c6309-report.json`) |
| FR-018 | Blossom | ✅ | `packages/blossom-client/test`, `services/blob-store/test` (cifrados); Buzz `/media` rechaza blobs cifrados → blob-store |
| FR-019 | Saneamiento EXIF | ✅ | `blossom.test.ts` (JPEG APP1/COM, PNG tEXt) |
| FR-020 | Tor-only fail closed | ✅ | `tor-network/test`, `delivery-engine/test`, `apps/sovereign-client/test` |
| FR-021 | Relay .onion | ✅ | `tor.test.ts`, `sovereign.test.ts` (SOCKS5h, DNS remoto, sin lookups locales) |
| FR-022 | Sin telemetría | ✅ | `telemetry-policy/test` (nivel none bloquea endpoints); `sovereign.test.ts` |
| FR-023 | RBAC/ABAC | ✅ | `policy-client/test`, `services/policy-engine/test` |
| FR-024 | Revocación | ✅ | `policy-engine.test.ts` (sesiones invalidadas, rotación señalada) |
| FR-025 | Grupo Marmot | ⏳ F4 | Interfaz `GroupCryptoProvider` + suite de conformidad; proveedor MDK no integrado (fail closed) |
| FR-026 | Migración de custodia | ✅ | `managed-signer.test.ts` (export → prueba de posesión → retención → borrado) |
| FR-027 | Backup restore | ✅ | `identity.test.ts` (dispositivo limpio) |
| FR-028 | Disclosures | ✅ | `profiles/test`, `web-saas.e2e.ts` |

| ID | Requisito | Estado | Evidencia / nota |
|----|-----------|--------|------------------|
| NFR-001 | Disponibilidad SaaS | ⏳ | Requiere despliegue operado; healthchecks en compose |
| NFR-002 | 0 pérdidas LOCAL_PERSISTED | ✅ | `engine.test.ts` (reinicio con FileBackend atómico + fsync) |
| NFR-003 | RPO/RTO | 🟡 | `docs/runbooks/restore.md`; drill automatizado pendiente |
| NFR-004 | Latencia P95 | 🟡 | Latencia por relay registrada en ledger y `RelayHealth`; métricas exportables pendientes |
| NFR-005 | Escalabilidad | 🟡 | Indexer sin estado + Postgres; relay según Buzz |
| NFR-006 | Sin secretos en logs | ✅ | `telemetry.test.ts`, `managed-signer.test.ts`; gitleaks en CI |
| NFR-007 | Telemetría por perfil | ✅ | `TelemetryPolicy` + tests de endpoints permitidos |
| NFR-008 | Portabilidad | ✅ | NIP-49 ncryptsec, eventos Nostr crudos, backup JSON abierto |
| NFR-009 | Accesibilidad | 🟡 | Navegación por teclado, labels, contraste claro/oscuro; auditoría formal pendiente |
| NFR-010 | Auditabilidad | 🟡 | SBOM (`npm run sbom`), checksums de keygen en CI; firma de releases pendiente de claves del proyecto |
