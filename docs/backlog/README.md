# Backlog — Acceso Nostr

> Fuente: [GitHub Issues](https://github.com/sedecim-com/nostr/issues?q=label%3Abacklog) (ver [GITHUB.md](GITHUB.md)). `backlog.json`, este archivo y `backlog.csv` se regeneran desde los issues; no editar a mano.
> Base: Scope_Plataforma_Nostr_Soberana_SaaS_v0.1 (25/09/2026) y PRD de cierre de brechas v0.3 (27/09/2026). Estado del código: `main@75a18e5` (2026-09-28).

## Resumen

- **246 tareas** · 148 hechas · 22 parciales · 70 pendientes · 6 descartadas
- **322 story points** pendientes en 16 sprints de 14 días (velocidad supuesta: 50 SP/sprint, equipo de ~4 personas; ajustar tras S1)
- Prioridades: **P0** Bloquea release o seguridad · **P1** Necesario para la fase · **P2** Importante, planificable · **P3** Deseable
- Estados: **Hecho** (con evidencia en el repo) · **Parcial** (existe base, falta completar) · **Pendiente** · **Descartado** (fuera de alcance por una decisión; la evidencia cita el ADR)
- IDs: `FRnnn-xx` / `NFRnnn-xx` por requisito; `DEC`, `BUZZ`, `OPS`, `PANEL`, `SEC`, `REL` para decisiones, Buzz upstream, operación, panel y gates.

## Plan de sprints

| Sprint | Fechas | Fase | Objetivo | Tareas | SP | P0 |
|---|---|---|---|---:|---:|---:|
| v0.1 (cerrado) | hasta 2026-09-26 | — | Entregado | 50 | 116 | 31 |
| S1 (cerrado) | 2026-09-28 → 2026-10-09 | F0 | Cierre F0 y gate de interoperabilidad | 11 | 19 | 5 |
| S2 (cerrado) | 2026-10-12 → 2026-10-23 | F0.5 | Web SaaS como cliente completo | 17 | 47 | 0 |
| S3 (cerrado) | 2026-10-26 → 2026-11-06 | F1 | Identidad, llaves y custodia | 18 | 43 | 1 |
| S4 (cerrado) | 2026-11-09 → 2026-11-20 | F2 | OSS soberano, sync y operación | 12 | 30 | 0 |
| S5 (cerrado) | 2026-11-23 → 2026-12-04 | F3 | Privacidad, Tor y observabilidad | 9 | 24 | 1 |
| S6 (cerrado) | 2026-12-07 → 2026-12-18 | F4 | Grupos high-security | 5 | 23 | 0 |
| S7 (cerrado) | 2027-01-04 → 2027-01-15 | F5 | Modo institucional | 10 | 38 | 1 |
| S8 (cerrado) | 2027-01-18 → 2027-01-29 | Release | Hardening, escalabilidad y release | 2 | 8 | 0 |
| S9 | 2026-09-28 → 2026-10-09 | G0 | Main endurecido y v0.1.0 firmada | 25 | 51 | 10 |
| S10 | 2026-10-12 → 2026-10-23 | G1–G2 | Continuity Vault y stage en AWS | 14 | 47 | 6 |
| S11 | 2026-10-26 → 2026-11-06 | G1–G2 | Restauración sin relays y operación real | 12 | 51 | 7 |
| S12 | 2026-11-09 → 2026-11-20 | G2–G3 | Freeze de auditoría y v1.0.0-rc.1 | 15 | 43 | 4 |
| S13 | 2026-11-23 → 2026-12-04 | G4 | Auditoría externa en campo | 7 | 12 | 0 |
| S14 | 2026-12-07 → 2026-12-18 | G4 | Informes externos y Nitro en Preview | 3 | 21 | 1 |
| S15 | 2027-01-04 → 2027-01-15 | G4 | Remediación, retest y v1.0.0-rc.2 | 2 | 16 | 2 |
| S16 | 2027-01-18 → 2027-01-29 | G5 | v1.0.0 firmada para despliegues controlados | 2 | 4 | 1 |
| Diferido | sin fecha | — | Después de v1.0: fuera del programa de cierre | 26 | 105 | 0 |

## Cobertura de requisitos

| Requisito | Tareas | Hechas | Pendientes (sprint) |
|---|---:|---:|---|
| FR-001 | 5 | 5 | — |
| FR-002 | 4 | 3 | FR004-08 (Diferido) |
| FR-003 | 7 | 5 | FR003-06 (S9), FR003-07 (S9) |
| FR-004 | 7 | 6 | FR004-08 (Diferido) |
| FR-005 | 12 | 8 | FR005-05 (S14), FR005-13 (S11), FR005-11 (S12), FR005-10 (Diferido) |
| FR-006 | 4 | 3 | FR006-04 (Diferido) |
| FR-007 | 5 | 4 | FR007-05 (S10) |
| FR-008 | 3 | 2 | VAULT-04 (S11) |
| FR-009 | 3 | 2 | FR009-03 (S10) |
| FR-010 | 5 | 4 | FR017-06 (S10) |
| FR-011 | 8 | 5 | VAULT-04 (S11), FR025-12 (S12), FR011-06 (S13) |
| FR-012 | 1 | 1 | — |
| FR-013 | 6 | 4 | VAULT-01 (S10), VAULT-03 (S11) |
| FR-014 | 5 | 3 | FR014-05 (S10), FR014-04 (Diferido) |
| FR-015 | 3 | 3 | — |
| FR-016 | 2 | 2 | — |
| FR-017 | 6 | 5 | FR017-06 (S10) |
| FR-018 | 5 | 5 | — |
| FR-019 | 4 | 4 | — |
| FR-020 | 6 | 2 | FR020-02 (Diferido), FR025-12 (S12), FR020-05 (S13), FR020-06 (Diferido) |
| FR-021 | 2 | 2 | — |
| FR-022 | 2 | 2 | — |
| FR-023 | 9 | 7 | FR023-10 (S11), FR023-13 (S12) |
| FR-024 | 5 | 3 | FR024-03 (S12), FR024-05 (S12) |
| FR-025 | 12 | 10 | FR025-08 (Diferido), FR025-14 (Diferido) |
| FR-026 | 5 | 3 | FR026-04 (S11), FR005-09 (Diferido) |
| FR-027 | 6 | 3 | VAULT-01 (S10), VAULT-02 (S10), VAULT-03 (S11) |
| FR-028 | 8 | 4 | FR028-02 (S13), VAULT-07 (S10), PANEL-07 (S12), NFR007-03 (Diferido) |
| NFR-001 | 5 | 0 | NFR001-01 (S10), NFR001-02 (S10), NFR001-03 (S10), NFR001-04 (S11), NFR001-05 (Diferido) |
| NFR-002 | 3 | 2 | NFR002-03 (S12) |
| NFR-003 | 5 | 2 | VAULT-06 (S11), NFR003-03 (S11), NFR003-04 (Diferido) |
| NFR-004 | 4 | 2 | NFR004-02 (S12), FR011-06 (S13) |
| NFR-005 | 2 | 1 | NFR005-02 (S11) |
| NFR-006 | 4 | 3 | NFR006-04 (S13) |
| NFR-007 | 2 | 2 | — |
| NFR-008 | 3 | 2 | VAULT-05 (S11) |
| NFR-009 | 2 | 1 | NFR009-02 (S10) |
| NFR-010 | 5 | 2 | FR003-06 (S9), NFR010-02 (S9), NFR010-04 (S12) |

## S1 · Cierre F0 y gate de interoperabilidad (F0, 2026-09-28 → 2026-10-09) — 19 SP

| ID | Prio | Tarea | Requisito | Tipo | SP | Depende de | Estado | Criterio de hecho |
|---|---|---|---|---|---:|---|---|---|
| [BUZZ-01](https://github.com/sedecim-com/nostr/issues/46) | P0 | Crear repositorio fork con ramas vendor/upstream y product/main | §6.3 | Infra | 1 | DEC-02 | Descartado | Fork creado; vendor/upstream = commit fijado; protección de ramas |
| [DEC-01](https://github.com/sedecim-com/nostr/issues/35) | P0 | Decidir nombre y licencia del proyecto open source | §25.1-1 | Decisión | 2 | — | Hecho | ADR aprobado; LICENSE, NOTICE y package.json actualizados |
| [DEC-02](https://github.com/sedecim-com/nostr/issues/36) | P0 | Decidir fork o Buzz upstream y fijar la versión de F0 | §25.1-2 | Decisión | 2 | — | Hecho | ADR aprobado; commit y digest en infra/buzz/PIN |
| [FR014-02](https://github.com/sedecim-com/nostr/issues/123) | P0 | Verificar el mirror contra Buzz en el stack Docker completo | FR-014 | QA | 2 | OPS-01 | Hecho | test:interop + indexer contra el relay del compose en CI |
| [FR018-03](https://github.com/sedecim-com/nostr/issues/136) | P0 | Validar la subida de imágenes en claro a Buzz /media con MinIO | FR-018 | QA | 1 | OPS-01 | Hecho | Informe del gate con plainImage.accepted = true |
| [OPS-01](https://github.com/sedecim-com/nostr/issues/52) | P0 | CI: construir todas las imágenes y levantar el stack completo con smoke test | §4.1 | Infra | 3 | — | Hecho | Job que hace docker compose up, espera healthchecks y ejecuta test:interop |
| [BUZZ-02](https://github.com/sedecim-com/nostr/issues/47) | P1 | Revisar obligaciones Apache-2.0 del fork (LICENSE, NOTICE, cambios marcados) | §21.2 | Doc | 1 | BUZZ-01, DEC-01 | Descartado | Checklist legal aprobado y NOTICE en el fork |
| [BUZZ-03](https://github.com/sedecim-com/nostr/issues/48) | P1 | Build reproducible de la imagen del relay desde el fork | §6.3 | Infra | 3 | BUZZ-01 | Descartado | Imagen construida en CI a partir de product/main con digest publicado |
| [DEC-03](https://github.com/sedecim-com/nostr/issues/37) | P1 | Definir política de pin y actualización de Buzz upstream | §25.1-3 | Decisión | 1 | DEC-02 | Hecho | Cadencia de sync, criterios de adopción y de rollback documentados |
| [DEC-04](https://github.com/sedecim-com/nostr/issues/38) | P1 | Elegir biblioteca Nostr base para Rust y Flutter | §25.1-4 | Decisión | 2 | — | Hecho | ADR con evaluación de TS (noble, decidido), Rust (rust-nostr/MDK) y Flutter |
| [DEC-06](https://github.com/sedecim-com/nostr/issues/40) | P1 | Definir receipt de aplicación y política de read receipts | §25.1-6 | Decisión | 1 | — | Hecho | Formato del rumor (kind definitivo) y opt-in por perfil aprobados; kind provisional 16914 reemplazado |
| [DEC-07](https://github.com/sedecim-com/nostr/issues/41) | P1 | Ratificar proveedor Marmot y ruta de relay (secure-relay vs parche Buzz) | §25.1-7 | Decisión | 1 | — | Hecho | ADR aprobado; marmot-ts/ts-mls fijados; ruta de relay decidida |
| [FR017-03](https://github.com/sedecim-com/nostr/issues/131) | P1 | Activar el flag NIP-17 por entorno a partir de interop-report.json en CI | FR-017 | Infra | 2 | FR014-02 | Hecho | El despliegue lee enableFlag y recommendedJitterSeconds del gate |
| [OPS-02](https://github.com/sedecim-com/nostr/issues/53) | P1 | Proxy TLS (Caddy) y URLs públicas en el compose de producción | §4.1 | Infra | 2 | OPS-01 | Hecho | Override compose.tls.yml con certificados automáticos y RELAY_URL wss:// |

## S2 · Web SaaS como cliente completo (F0.5, 2026-10-12 → 2026-10-23) — 47 SP

| ID | Prio | Tarea | Requisito | Tipo | SP | Depende de | Estado | Criterio de hecho |
|---|---|---|---|---|---:|---|---|---|
| [BUZZ-05](https://github.com/sedecim-com/nostr/issues/50) | P1 | Revisión mensual automática de la imagen upstream de Buzz con el gate | §6.3 | Infra | 3 | OPS-01 | Hecho | Workflow programado detecta un digest nuevo de ghcr.io/block/buzz, ejecuta stack + gate contra él y abre la PR del pin si pasa (ADR 0003) |
| [DEC-05](https://github.com/sedecim-com/nostr/issues/39) | P1 | Definir storage local cifrado por plataforma | §25.1-5 | Decisión | 2 | — | Hecho | ADR: IndexedDB (web), Keychain/Keystore (móvil), archivo cifrado (desktop/CLI) |
| [FR001-05](https://github.com/sedecim-com/nostr/issues/70) | P1 | E2E en navegador: la nsec nunca sale del cliente | FR-001 | QA | 2 | FR001-03 | Hecho | Test que inspecciona todas las peticiones y WebSocket y no encuentra nsec ni la llave en claro |
| [FR006-02](https://github.com/sedecim-com/nostr/issues/94) | P1 | Selector de persona en la web con banner "Enviando como…" | FR-006, §16.1 | Dev | 3 | FR006-01 | Hecho | Cambiar de persona cambia signer, relays y store; banner siempre visible |
| [FR010-02](https://github.com/sedecim-com/nostr/issues/113) | P1 | Selección de relays por destinatario (NIP-65 kind 10002 y kind 10050) | FR-010 | Dev | 3 | FR010-01 | Hecho | Los DMs se publican en los relays de inbox del destinatario |
| [FR015-02](https://github.com/sedecim-com/nostr/issues/126) | P1 | Descubrimiento de canales (39000) y unión (9021) en la web | FR-015 | Dev | 3 | FR015-01 | Hecho | Lista de canales visibles y botón de unirse |
| [FR015-03](https://github.com/sedecim-com/nostr/issues/127) | P1 | E2E de la web contra Buzz real (crear canal, unirse, enviar, leer) | FR-015 | QA | 2 | FR015-02, OPS-01 | Hecho | Test en navegador contra el relay del compose |
| [PANEL-02](https://github.com/sedecim-com/nostr/issues/63) | P1 | Aplicar la configuración del panel al comportamiento real del cliente web | §9 | Dev | 5 | PANEL-01 | Hecho | Red, telemetría, receipts, previews y quorum usan la configuración elegida (hoy solo se muestra) |
| [BUZZ-04](https://github.com/sedecim-com/nostr/issues/49) | P2 | Branding del fork (desktop Tauri/React) | §22 F0 | Dev | 3 | BUZZ-01, DEC-01 | Descartado | Nombre, iconos y textos propios sin tocar el protocolo |
| [FR001-04](https://github.com/sedecim-com/nostr/issues/69) | P2 | Backend IndexedDB para encrypted-store en navegador | FR-001, FR-008 | Dev | 3 | DEC-05 | Hecho | Stores de llave y outbox sobre IndexedDB con tests en Chromium |
| [FR009-02](https://github.com/sedecim-com/nostr/issues/111) | P2 | Pasar a RECIPIENT_ACKED/READ con los receipts entrantes | FR-009, §11 | Dev | 3 | DEC-06, FR009-01 | Hecho | Receipts gift-wrapped recibidos actualizan el estado de la operación |
| [FR011-02](https://github.com/sedecim-com/nostr/issues/115) | P2 | Lanzar resume() al recuperar conectividad (eventos online / reconexión del pool) | FR-011 | Dev | 2 | FR011-01 | Hecho | La web y el CLI reanudan solos la outbox al volver la red |
| [FR014-03](https://github.com/sedecim-com/nostr/issues/124) | P2 | Vistas derivadas: no leídos por canal y búsqueda respetando la política | FR-014, §15.2 | Dev | 3 | FR014-01 | Hecho | Endpoints de no leídos y búsqueda solo sobre contenido permitido |
| [FR017-04](https://github.com/sedecim-com/nostr/issues/132) | P2 | Publicar y leer la lista de relays DM (kind 10050) | FR-017 | Dev | 2 | FR010-02 | Hecho | Onboarding publica 10050; el emisor la usa para enrutar |
| [FR018-04](https://github.com/sedecim-com/nostr/issues/137) | P2 | Adjuntos en la web (kind 15 en DMs, imágenes en canales) | FR-018, FR-019 | Dev | 5 | FR018-02, FR019-01 | Hecho | Subida con saneamiento, cifrado opcional y descarga verificada desde la UI |
| [NFR009-01](https://github.com/sedecim-com/nostr/issues/187) | P2 | Auditoría de accesibilidad automatizada (axe-core) en el E2E de navegador | NFR-009 | QA | 2 | FR015-01 | Hecho | Cero violaciones serias en la web |
| [OPS-03](https://github.com/sedecim-com/nostr/issues/54) | P2 | Instalador/configurador de llaves y secretos del stack | §4.1 | Infra | 2 | FR003-01 | Hecho | scripts/init-env genera también la llave del relay y del owner con el keygen offline |
| [PANEL-03](https://github.com/sedecim-com/nostr/issues/64) | P2 | Persistir la configuración del panel por persona | §9 | Dev | 2 | PANEL-02, FR006-02 | Hecho | Config cifrada en el store de la persona; se restaura al desbloquear |

## S3 · Identidad, llaves y custodia (F1, 2026-10-26 → 2026-11-06) — 43 SP

| ID | Prio | Tarea | Requisito | Tipo | SP | Depende de | Estado | Criterio de hecho |
|---|---|---|---|---|---:|---|---|---|
| [FR005-03](https://github.com/sedecim-com/nostr/issues/88) | P0 | Persistir el registro de llaves y el log de uso en Postgres | FR-005 | Dev | 3 | FR005-01 | Hecho | Sobrevive reinicios (hoy el registro vive en memoria y el vault en disco) |
| [DEC-09](https://github.com/sedecim-com/nostr/issues/43) | P1 | Definir región cloud y requisitos legales de la custodia managed | §25.1-9 | Decisión | 2 | — | Hecho | Región, marco legal y retención decididos en un ADR; términos de custodia redactados |
| [FR004-04](https://github.com/sedecim-com/nostr/issues/84) | P1 | UI de permisos mínimos visibles al conectar un signer | FR-004, §8.3 | Dev | 2 | FR004-01 | Hecho | La web lista los métodos y kinds solicitados antes de conectar |
| [FR005-04](https://github.com/sedecim-com/nostr/issues/89) | P1 | Autorización por usuario final (sesión SaaS firmada), no solo bearer de servicio | FR-005 | Seguridad | 3 | FR005-03 | Hecho | x-account-id respaldado por token de sesión verificable; tests de suplantación |
| [FR005-07](https://github.com/sedecim-com/nostr/issues/92) | P1 | Opt-in explícito de custodia managed en el onboarding web | FR-005, §1 | Dev | 2 | FR005-04, PANEL-02 | Hecho | Confirmación con el disclosure "la plataforma puede firmar"; nunca por defecto |
| [FR002-03](https://github.com/sedecim-com/nostr/issues/73) | P2 | Importar el backup del key-generator (sedecim-offline-key) en web y CLI | FR-002 | Dev | 2 | FR002-01, FR003-01 | Hecho | Importar el JSON del generador offline valida npub y crea la persona |
| [FR003-03](https://github.com/sedecim-com/nostr/issues/76) | P2 | Exportación QR de npub y ncryptsec sin dependencias de red | FR-003 | Dev | 3 | FR003-01 | Hecho | Codificador QR embebido; test de ida y vuelta |
| [FR003-05](https://github.com/sedecim-com/nostr/issues/78) | P2 | Versión HTML standalone air-gapped del generador (un solo archivo) | FR-003 | Dev | 3 | FR003-01 | Hecho | Archivo único que funciona abierto desde disco sin red; CSP estricta |
| [FR004-03](https://github.com/sedecim-com/nostr/issues/83) | P2 | Flujo nostrconnect:// iniciado por el cliente (QR) | FR-004 | Dev | 3 | FR004-01 | Hecho | La web muestra un QR nostrconnect y completa la conexión |
| [FR005-02](https://github.com/sedecim-com/nostr/issues/87) | P2 | Adaptador real de AWS Secrets Manager + KMS | FR-005, §8.4 | Dev | 3 | FR005-01, DEC-09 | Hecho | SecretsManagerVault con el SDK de AWS; tests contra un emulador de AWS (moto) en CI |
| [FR007-03](https://github.com/sedecim-com/nostr/issues/98) | P2 | UI de vínculos con advertencia de desanonimización | FR-007, §25 | Dev | 2 | FR007-02, FR006-02 | Hecho | Diálogo que explica las consecuencias antes de vincular |
| [FR019-02](https://github.com/sedecim-com/nostr/issues/140) | P2 | Soporte WebP/HEIC o rechazo según el perfil sensible | FR-019 | Dev | 3 | FR019-01 | Hecho | Saneamiento o rechazo explícito con requireSanitizable |
| [FR026-03](https://github.com/sedecim-com/nostr/issues/102) | P2 | UI de migración de custodia en la web con verificación | FR-026 | Dev | 3 | FR026-01, FR005-04 | Hecho | Asistente paso a paso con verificación de posesión y confirmación del borrado |
| [FR027-02](https://github.com/sedecim-com/nostr/issues/104) | P2 | Incluir en el backup la configuración completa (relays, panel, grupos MLS) | FR-027 | Dev | 3 | FR027-01, PANEL-03 | Hecho | La restauración recupera relays, perfil y estado MLS cifrado |
| [FR003-04](https://github.com/sedecim-com/nostr/issues/77) | P3 | Plantilla imprimible del backup (HTML local, sin CDN) | FR-003 | Dev | 2 | FR003-03 | Hecho | Hoja con npub, QR y ncryptsec; sin recursos remotos |
| [FR004-05](https://github.com/sedecim-com/nostr/issues/85) | P3 | Soporte de auth_url del signer remoto | FR-004 | Dev | 1 | FR004-01 | Hecho | La UI abre auth_url y espera la respuesta real |
| [FR028-03](https://github.com/sedecim-com/nostr/issues/108) | P3 | Lint en CI que prohíbe afirmaciones absolutas en toda la UI | FR-028, §2.2 | QA | 1 | FR028-01 | Hecho | assertNoAbsoluteClaims aplicado a todo el copy de la web |
| [PANEL-04](https://github.com/sedecim-com/nostr/issues/65) | P3 | Indicadores visuales por dimensión respaldados por declaraciones verificables | §9.1 | Dev | 2 | PANEL-02 | Hecho | Cada indicador enlaza a sus disclosures; sin score único |

## S4 · OSS soberano, sync y operación (F2, 2026-11-09 → 2026-11-20) — 30 SP

| ID | Prio | Tarea | Requisito | Tipo | SP | Depende de | Estado | Criterio de hecho |
|---|---|---|---|---|---:|---|---|---|
| [FR013-03](https://github.com/sedecim-com/nostr/issues/120) | P1 | E2E: reinstalar y reconstruir historial (canales, DMs, outbox) en un dispositivo limpio | FR-013 | QA | 3 | FR013-01, FR027-01 | Hecho | Tras restaurar el backup, el cliente recupera historia y estados |
| [NFR003-01](https://github.com/sedecim-com/nostr/issues/175) | P1 | Definir RPO/RTO por tier | NFR-003 | Doc | 1 | DEC-09 | Hecho | Tabla aprobada por tier (self-hosted, SaaS, institucional) |
| [NFR003-02](https://github.com/sedecim-com/nostr/issues/176) | P1 | Restore drill automatizado (nightly) | NFR-003 | Infra | 5 | NFR003-01, OPS-01 | Hecho | Job que restaura en un host limpio y ejecuta test:interop |
| [SEC-03](https://github.com/sedecim-com/nostr/issues/194) | P1 | Fuzz/property tests de serialización y criptografía | §20.3 | Seguridad | 3 | — | Hecho | fast-check sobre eventos, NIP-44, NIP-49, codec MLS y parsers de TLV |
| [FR013-02](https://github.com/sedecim-com/nostr/issues/119) | P2 | Cliente NIP-77 (Negentropy) con detección y fallback | FR-013, §12.1 | Dev | 5 | FR013-01 | Hecho | Reconciliación con un relay NIP-77; fallback automático si no lo soporta |
| [FR013-04](https://github.com/sedecim-com/nostr/issues/121) | P2 | Sync de gift wraps con timestamps aleatorios (ventana ampliada) | FR-013 | QA | 1 | FR013-01 | Hecho | Test con wraps de hasta 2 días de antigüedad; ningún mensaje perdido |
| [FR027-03](https://github.com/sedecim-com/nostr/issues/105) | P2 | Vault de backup en la nube: solo ciphertext con clave del usuario | FR-027, §12 | Dev | 3 | FR027-02 | Hecho | Subida/descarga del backup cifrado; el operador nunca ve la clave |
| [NFR002-02](https://github.com/sedecim-com/nostr/issues/174) | P2 | Test de crash con kill -9 durante la escritura | NFR-002 | QA | 2 | NFR002-01 | Hecho | Proceso matado a mitad de escritura; el store sigue consistente |
| [NFR006-03](https://github.com/sedecim-com/nostr/issues/183) | P2 | Test de integración que analiza los logs de los servicios en busca de secretos | NFR-006 | QA | 2 | OPS-01 | Hecho | Stack completo en CI; los logs se escanean con las reglas de gitleaks |
| [NFR008-02](https://github.com/sedecim-com/nostr/issues/186) | P2 | Exportar el historial completo (JSONL de eventos firmados) | NFR-008 | Dev | 2 | FR013-01 | Hecho | Export/import de eventos canónicos entre clientes |
| [OPS-09](https://github.com/sedecim-com/nostr/issues/60) | P2 | Documentación de build desde source | §21.2 | Doc | 2 | — | Hecho | Guía reproducible para todos los artefactos (servicios, web, keygen) |
| [FR017-05](https://github.com/sedecim-com/nostr/issues/133) | P3 | Seguir el issue upstream #4192 y retirar el adaptador cuando se corrija | FR-017, §25 | QA | 1 | BUZZ-05 | Hecho | Re-ejecutar el gate en cada sync; volver al jitter estándar si pasa |

## S5 · Privacidad, Tor y observabilidad (F3, 2026-11-23 → 2026-12-04) — 24 SP

| ID | Prio | Tarea | Requisito | Tipo | SP | Depende de | Estado | Criterio de hecho |
|---|---|---|---|---|---:|---|---|---|
| [FR020-03](https://github.com/sedecim-com/nostr/issues/143) | P0 | Tests de fugas con captura de red real (netns/pcap): DNS, IPv6, conexiones directas | FR-020, §20.3 | Seguridad | 5 | — | Hecho | Suite que prueba cero tráfico fuera de Tor con el cliente soberano real (CLI); la app desktop, cuando exista, reutiliza la suite |
| [FR021-02](https://github.com/sedecim-com/nostr/issues/145) | P1 | Validar el perfil tor del compose (onion services de relay y secure-relay) | FR-021 | QA | 2 | OPS-01 | Hecho | Arranque real y conexión del CLI a las direcciones .onion generadas |
| [FR022-02](https://github.com/sedecim-com/nostr/issues/147) | P1 | Test en CI de endpoints de salida permitidos por perfil | FR-022, NFR-007 | QA | 3 | FR020-03 | Hecho | Allowlist de egress por perfil verificada con el cliente real |
| [SEC-05](https://github.com/sedecim-com/nostr/issues/148) | P1 | Tests de fugas por WebRTC y previews remotas en la web | §20.3 | Seguridad | 2 | — | Hecho | Sin candidatos ICE ni peticiones de previews en perfiles sensibles (la app desktop, cuando exista, reutiliza la suite) |
| [DEC-08](https://github.com/sedecim-com/nostr/issues/42) | P2 | Definir modelo de notificaciones móviles por perfil | §25.1-8 | Decisión | 2 | — | Hecho | Matriz perfil × (push, privacy-push, none) con metadatos expuestos |
| [NFR004-01](https://github.com/sedecim-com/nostr/issues/177) | P2 | Exportar métricas (latencia P95 de ACK por relay y región) | NFR-004 | Dev | 3 | — | Hecho | Exportador Prometheus respetando el perfil de telemetría |
| [FR007-04](https://github.com/sedecim-com/nostr/issues/99) | P3 | Publicar opcionalmente un vínculo público como evento Nostr firmado | FR-007 | Dev | 3 | FR007-02 | Hecho | Formato definido, firmado por ambas personas y verificable |
| [FR011-03](https://github.com/sedecim-com/nostr/issues/116) | P3 | Métricas de outbox (profundidad, antigüedad, fallos por relay) | FR-011, NFR-004 | Dev | 2 | FR011-01, NFR004-01 | Hecho | Expuestas al exportador de métricas respetando el perfil |
| [FR018-05](https://github.com/sedecim-com/nostr/issues/138) | P3 | Lista de servidores Blossom del usuario (kind 10063) | FR-018 | Dev | 2 | FR018-01 | Hecho | El cliente publica y respeta la lista de servidores |

## S6 · Grupos high-security (F4, 2026-12-07 → 2026-12-18) — 23 SP

| ID | Prio | Tarea | Requisito | Tipo | SP | Depende de | Estado | Criterio de hecho |
|---|---|---|---|---|---:|---|---|---|
| [FR025-04](https://github.com/sedecim-com/nostr/issues/152) | P1 | Interoperabilidad verificada con MDK/whitenoise | FR-025 | QA | 5 | DEC-07 | Hecho | Grupo mixto marmot-ts ↔ MDK con mensajes en ambos sentidos |
| [FR025-05](https://github.com/sedecim-com/nostr/issues/153) | P2 | MIP-04: media cifrada en grupos | FR-025, §13 | Dev | 5 | FR025-01, FR018-02 | Hecho | Subida y descarga de media con claves derivadas del exporter MLS |
| [FR025-06](https://github.com/sedecim-com/nostr/issues/154) | P2 | Multi-dispositivo: varios key packages por persona y sincronización del estado | FR-025 | Dev | 5 | FR025-01 | Hecho | Un usuario con 2 dispositivos participa en el mismo grupo |
| [FR025-07](https://github.com/sedecim-com/nostr/issues/155) | P2 | UI de grupos high-security en la web | FR-025 | Dev | 5 | FR025-06, FR001-04 | Hecho | Crear, invitar, chatear y expulsar desde la web con estado cifrado |
| [BUZZ-06](https://github.com/sedecim-com/nostr/issues/51) | P3 | Integración progresiva del cliente móvil Flutter de Buzz | §6.1 | Dev | 8 | BUZZ-03, DEC-04 | Descartado | Mobile compila contra el relay del fork y pasa smoke test NIP-29 |
| [FR025-09](https://github.com/sedecim-com/nostr/issues/157) | P3 | Flujo de propuestas de miembros no admin y commit por el admin | FR-025 | Dev | 3 | FR025-01 | Hecho | Un miembro propone y el admin compromete; tests |
| [FR025-10](https://github.com/sedecim-com/nostr/issues/158) | P3 | Parche en el fork de Buzz para los kinds Marmot (solo si DEC-07 lo aprueba) | FR-025, DEC-07 | Dev | 5 | DEC-07, BUZZ-01 | Descartado | El relay acepta 30443/445/10051 sin romper el tratamiento de #h de NIP-29 |

## S7 · Modo institucional (F5, 2027-01-04 → 2027-01-15) — 38 SP

| ID | Prio | Tarea | Requisito | Tipo | SP | Depende de | Estado | Criterio de hecho |
|---|---|---|---|---|---:|---|---|---|
| [FR023-03](https://github.com/sedecim-com/nostr/issues/161) | P0 | Persistencia del policy-engine en Postgres | FR-023 | Dev | 3 | FR023-02 | Hecho | Sujetos, recursos, dispositivos y auditoría sobreviven reinicios |
| [FR023-04](https://github.com/sedecim-com/nostr/issues/162) | P1 | Sincronizar el allowlist NIP-42 del relay con el policy-engine | FR-023, §16 | Dev | 3 | FR023-03 | Hecho | Allowlist NIP-42 de Buzz (configuración de la imagen upstream) y del secure-relay actualizado desde /v1/relay/allowlist |
| [FR023-05](https://github.com/sedecim-com/nostr/issues/163) | P1 | Aplicar la política en el indexer y las APIs derivadas | FR-023 | Dev | 3 | FR023-03, FR014-03 | Hecho | Lecturas filtradas por evaluate(); tests de denegación |
| [FR024-02](https://github.com/sedecim-com/nostr/issues/168) | P1 | Ejecutar la rotación MLS automáticamente al revocar (commit Remove) | FR-024 | Dev | 3 | FR024-01, FR025-01, FR023-03 | Hecho | La revocación dispara removeMember en los grupos afectados |
| [SEC-04](https://github.com/sedecim-com/nostr/issues/195) | P1 | Pruebas de pérdida de dispositivo de extremo a extremo | §20.3 | QA | 3 | FR024-02 | Hecho | Revocar → sin sesión → grupos rotados → el dispositivo robado no lee |
| [FR005-06](https://github.com/sedecim-com/nostr/issues/91) | P2 | Rate limiting y alertas de uso anómalo de firma | FR-005 | Seguridad | 2 | FR005-03 | Hecho | Límites por llave/kind y alerta en auditoría |
| [FR023-06](https://github.com/sedecim-com/nostr/issues/164) | P2 | Directorio organizacional (cargos ↔ npubs) opcional | FR-023, §16 | Dev | 3 | FR023-03 | Hecho | Mapeo gestionado desde admin-console, sin publicar vínculos |
| [FR023-07](https://github.com/sedecim-com/nostr/issues/165) | P2 | Device trust con passkeys/attestation | §16 | Dev | 5 | FR023-03 | Hecho | Registro de dispositivos con WebAuthn y nivel attested |
| [FR023-08](https://github.com/sedecim-com/nostr/issues/166) | P2 | Retención por workspace/canal y legal hold donde el modelo lo permita | §16, §12.2 | Dev | 5 | FR023-03 | Hecho | Políticas configurables y aviso de que borrar no borra copias replicadas |
| [OPS-07](https://github.com/sedecim-com/nostr/issues/58) | P2 | App admin-console (organizaciones, políticas, dispositivos, auditoría) | §17.1 | Dev | 8 | FR023-03 | Hecho | Consola web autenticada por NIP-98 sobre policy-engine e identity-service |

## S8 · Hardening, escalabilidad y release (Release, 2027-01-18 → 2027-01-29) — 8 SP

| ID | Prio | Tarea | Requisito | Tipo | SP | Depende de | Estado | Criterio de hecho |
|---|---|---|---|---|---:|---|---|---|
| [NFR010-03](https://github.com/sedecim-com/nostr/issues/191) | P2 | Imágenes Docker reproducibles | NFR-010 | Infra | 3 | OPS-01 | Hecho | Dos builds del mismo commit producen el mismo digest |
| [NFR005-01](https://github.com/sedecim-com/nostr/issues/179) | P3 | Indexer escalable horizontalmente (reparto por relay y upserts idempotentes) | NFR-005 | Dev | 5 | FR014-01 | Hecho | N réplicas sin duplicados ni pérdidas; test de concurrencia |

## S9 · Main endurecido y v0.1.0 firmada (G0, 2026-09-28 → 2026-10-09) — 51 SP

| ID | Prio | Tarea | Requisito | Tipo | SP | Depende de | Estado | Criterio de hecho |
|---|---|---|---|---|---:|---|---|---|
| [FR023-09](https://github.com/sedecim-com/nostr/issues/226) | P0 | B1: editar una persona revocada no la reactiva; reactivar es explícito y auditado | FR-023 | Seguridad | 1 | FR023-03 | Hecho | PUT /v1/subjects conserva suspended; ruta de reactivación con entrada de auditoría; test de regresión |
| [FR024-04](https://github.com/sedecim-com/nostr/issues/227) | P0 | B2: el propagador de revocaciones no pierde eventos | FR-024 | Dev | 2 | FR024-01 | Hecho | Cursor persistido sobre la auditoría o endpoint /v1/revocations; test con más de 100 entradas entre revocación y propagación sin pérdidas |
| [FR025-11](https://github.com/sedecim-com/nostr/issues/224) | P0 | G1: las invitaciones a grupos seguros llegan con el secure relay real | FR-025, FR-016 | Dev | 5 | FR025-07, FR016-01 | Hecho | AUTH NIP-42 temprano en relays con nip42_dms (hoy nostr-rs-relay descarta en silencio los kind 1059 sin AUTH y los clientes solo se autentican bajo demanda); E2E de grupos en web y CLI contra nostr-rs-relay real en CI; relay_url correcto para el .onion |
| [NFR010-02](https://github.com/sedecim-com/nostr/issues/190) | P0 | Firma de releases y provenance (SLSA/cosign) | NFR-010, §21.2, PRD GC-E02 | Seguridad | 3 | OPS-08 | Parcial | v0.1.0 publicada con imágenes y artefactos firmados con cosign keyless, provenance SLSA, SHA256SUMS y SBOM; verify-release.sh pasa desde fuera |
| [OPS-08](https://github.com/sedecim-com/nostr/issues/59) | P0 | Separación de funciones en releases (quién construye vs quién publica) | §21.2, PRD GC-E01 | Infra | 1 | OPS-12 | Parcial | Entorno release con aprobadores distintos al autor, «Prevent self-review», sin bypass de admin y protección de tags v* |
| [OPS-12](https://github.com/sedecim-com/nostr/issues/220) | P0 | Gobierno del repositorio: proteger main, activar private vulnerability reporting y nombrar un segundo mantenedor | §21.2 | Infra | 1 | — | Pendiente | main exige 1 aprobación y los checks de CI, CodeQL y dependency-review; private vulnerability reporting activo; una segunda persona puede aprobar PRs y entornos |
| [OPS-17](https://github.com/sedecim-com/nostr/issues/221) | P0 | Estados de evidencia y nada «Hecho» desde una rama | PRD GC-F01, GC-F02 | Infra | 3 | — | Hecho | Estados Proposed, In PR, Merged, CI Verified, Stage Verified, Externally Audited y Production Enabled documentados en GITHUB.md y visibles en los issues; backlog-sync solo acepta Hecho si la evidencia cita un SHA ancestro de main y avisa del resto |
| [REL-01](https://github.com/sedecim-com/nostr/issues/196) | P0 | Checklist de Definition of Done automatizado en el pipeline de release | Apéndice D, PRD GC-E03 | Infra | 3 | NFR010-02, NFR003-02, FR020-03, DEC-10, OPS-08 | Parcial | El primer tag ejecuta el gate completo (CI, interop, restore, fugas, evidencia de auditoría o waiver, SBOM y firma) y además comprueba threat models aprobados, alertas de CodeQL y Dependabot, la aprobación del waiver y --prerelease en -rc |
| [REL-02](https://github.com/sedecim-com/nostr/issues/197) | P0 | Release notes con los cambios de trust model por release | Apéndice D, PRD GC-E04 | Doc | 1 | REL-01 | Parcial | Notas de v0.1.0 corregidas y publicadas como cuerpo del GitHub Release, con los cambios de confianza y privacidad explícitos |
| [SEC-06](https://github.com/sedecim-com/nostr/issues/222) | P0 | IR-15: ligar el payload sellado del mirror a su event_id con AAD versionado | §20.3, PRD GC-A02 | Seguridad | 3 | — | Pendiente | Intercambiar ciphertext entre filas falla la autenticación; migración compatible hacia atrás probada; internal-review actualizado (IR-04, IR-05, IR-16, IR-19 e IR-20 ya se corrigieron en la PR #216) |
| [DEC-10](https://github.com/sedecim-com/nostr/issues/45) | P1 | Formalizar threat models por perfil (convenience, resilient, institutional, sovereign, Tor) | §25.1-10, §20.3 | Seguridad | 3 | — | Parcial | Un documento por perfil con activos, adversarios, mitigaciones y riesgos residuales, y threat-model.md general al día; aprobados por alguien distinto del autor y versionados para v0.1.0; se vuelven a aprobar con el vault para el tag de auditoría (SEC-11) |
| [FR003-06](https://github.com/sedecim-com/nostr/issues/79) | P1 | Firma de las releases del generador | FR-003, NFR-010 | Seguridad | 2 | FR003-02, NFR010-02 | Parcial | keygen.html y keygen.mjs firmados en v0.1.0 y verificados con el procedimiento documentado |
| [FR003-07](https://github.com/sedecim-com/nostr/issues/80) | P1 | Guía de uso air-gapped verificable | FR-003, PRD GC-E05 | Doc | 1 | FR003-06 | Parcial | Procedimiento paso a paso (verificar checksum y firma, generar, verificar backup) ejecutado de punta a punta con el keygen firmado de v0.1.0 en un equipo sin red, con registro |
| [FR004-06](https://github.com/sedecim-com/nostr/issues/232) | P1 | Permisos NIP-46 completos para los kinds que firma la web | FR-004, §8.3 | Dev | 1 | FR004-04 | Hecho | WEB_NIP46_PERMISSIONS incluye 10063, 30443, 30078 y los demás kinds firmados; test que los contrasta |
| [FR005-08](https://github.com/sedecim-com/nostr/issues/234) | P1 | Textos de la custodia gestionada listos para la revisión legal | FR-005, FR-028 | Dev | 3 | FR005-07 | Hecho | Login sin «tu llave no sale del navegador» en managed; aviso de descifrado NIP-44 en servidor; enlace a los términos; consentimiento registrado con su versión |
| [FR005-12](https://github.com/sedecim-com/nostr/issues/225) | P1 | Retirar el modo legado del managed-signer (token de servicio + x-account-id) | FR-005, ADR 0009 | Seguridad | 1 | FR005-04 | Hecho | Solo se firma con el token de Acceso o una sesión de dispositivo; test que rechaza el modo legado |
| [FR010-03](https://github.com/sedecim-com/nostr/issues/228) | P1 | D1: un DM escrito sin red no queda mal enrutado | FR-010, FR-011 | Dev | 3 | FR010-02 | Hecho | No se cachea un descubrimiento vacío; la ruta 10050 se resuelve al publicar; relays de descubrimiento configurables; test offline→online |
| [FR010-04](https://github.com/sedecim-com/nostr/issues/231) | P1 | Avisar cuando el quorum supera el número de relays | FR-010 | Dev | 1 | FR010-01 | Hecho | El panel y el motor rechazan o avisan en lugar de recortar el quorum en silencio |
| [FR011-04](https://github.com/sedecim-com/nostr/issues/229) | P1 | D2: el cliente soberano reintenta lo pendiente al abrir sesión | FR-011 | Dev | 1 | FR011-02 | Hecho | resume() al abrir la persona en el CLI; test entre dos procesos |
| [FR019-03](https://github.com/sedecim-com/nostr/issues/230) | P1 | D3: los adjuntos de DM no conservan metadatos no saneables (HEIC con GPS) | FR-019 | Dev | 1 | FR019-02 | Hecho | requireSanitizable también en DMs cuando stripFileMetadata está activo; E2E con un HEIC con GPS |
| [OPS-11](https://github.com/sedecim-com/nostr/issues/235) | P1 | Corregir la deriva documental | Apéndice D, PRD GC-F05 | Doc | 2 | — | Hecho | README, notas v0.1.0, architecture.md, ADR 0002/0009, buzz-integration.md, institutional.md, threat-model.md, SECURITY.md y baseline del backlog coinciden con main; internal-review refleja la PR #216 |
| [PANEL-05](https://github.com/sedecim-com/nostr/issues/233) | P1 | Panel veraz: perfil validado al crear persona, Tor-only sin clearnet en la web, declaraciones desde la custodia real | §9.1, FR-028 | Dev | 3 | PANEL-04, FR028-01 | Hecho | isValid al crear persona; con tor-only la web no lee relays ni publica 10050; disclosures según la custodia real (también en el CLI Tor); texto para stripFileMetadata; se retiran «Marmot fijada y auditada» y las promesas de tracing y crash reports; se añaden los avisos de alto riesgo que faltan en --high-risk y en los presets soberanos |
| [SEC-07](https://github.com/sedecim-com/nostr/issues/223) | P1 | Vectores oficiales de NIP-44 y vectores JSON exportables | §20.3, §21.1 | Seguridad | 2 | SEC-03 | Pendiente | nip44.vectors.json oficial corre en CI; vectores de NIP-44, NIP-49 y NIP-59 exportables en JSON para futuros clientes en otros lenguajes (ADR 0004) |
| [BUZZ-07](https://github.com/sedecim-com/nostr/issues/236) | P2 | Adoptar el pin de Buzz ac4521f3e464 (issue #201) tras revisar el changelog | §6.3 | Infra | 1 | BUZZ-05 | Hecho | PR del pin fusionada con el gate de interoperabilidad en verde; ADR 0003 seguido |
| [OPS-10](https://github.com/sedecim-com/nostr/issues/61) | P2 | Backlog vivo en GitHub Issues con sincronización automática a docs/backlog | Proceso, PRD GC-E06 | Infra | 3 | — | Parcial | Cada tarea es un issue (milestone = sprint, labels de prioridad/epic/estado, campos Priority/Effort/fechas, sub-issues del epic y "blocked by"); un workflow regenera docs/backlog desde los issues y abre la PR de sync sin intervención, con Actions autorizado a abrir PRs. No bloquea el RC |

## S10 · Continuity Vault y stage en AWS (G1–G2, 2026-10-12 → 2026-10-23) — 47 SP

| ID | Prio | Tarea | Requisito | Tipo | SP | Depende de | Estado | Criterio de hecho |
|---|---|---|---|---|---:|---|---|---|
| [NFR001-01](https://github.com/sedecim-com/nostr/issues/170) | P0 | Infraestructura como código del SaaS (Helm/Terraform) | NFR-001, PRD GC-C01 | Infra | 8 | OPS-02 | Parcial | Stage desplegado con terraform apply en infrastructure y deploy de Kubernetes reales; smoke e interop contra los hosts de stage; kubeconform en CI |
| [NFR001-02](https://github.com/sedecim-com/nostr/issues/171) | P0 | Monitorización de SLO (99,9 % mensual) y alertas | NFR-001, PRD GC-C02 | Infra | 3 | NFR001-01 | Parcial | Dashboard de disponibilidad y alertas por servicio desplegados en stage (Prometheus, Grafana, receptores y sonda externa); 7 días de señal útil antes del RC |
| [NFR001-03](https://github.com/sedecim-com/nostr/issues/172) | P0 | Postgres de alta disponibilidad y backups gestionados | NFR-001, PRD GC-C03 | Infra | 3 | NFR001-01 | Parcial | RDS aplicado y datos migrados; failover real y restore point probados en stage; runbook con los tiempos observados |
| [VAULT-01](https://github.com/sedecim-com/nostr/issues/237) | P0 | Continuity Vault: contrato y almacenamiento opaco, separado del indexer | PRD GC-B01, FR-013, FR-027 | Dev | 8 | FR027-03 | Pendiente | ADR del vault; servicio con API de sobres de archivo opacos por cuenta (subir, listar, bajar y borrar) autenticada con NIP-98 o Acceso, que rechaza texto plano como la bóveda de backup de FR027-03; separado del indexer; tests |
| [VAULT-02](https://github.com/sedecim-com/nostr/issues/238) | P0 | Sobre de archivo cifrado en el cliente con una backup key separada de la nsec | PRD GC-B02, FR-027 | Seguridad | 5 | VAULT-01 | Pendiente | Web y CLI sellan cada sobre en el cliente; la backup key es distinta de la nsec y viaja en el backup de identidad; restaurar con un logN excesivo se rechaza; test que demuestra que ni la base ni el object store contienen texto ni eventos legibles |
| [VAULT-07](https://github.com/sedecim-com/nostr/issues/239) | P0 | Threat model y disclosure del Continuity Vault | PRD GC-B07, FR-028 | Seguridad | 2 | VAULT-01 | Pendiente | Threat model del vault aprobado; la UI explica los metadatos que ve el operador (cuenta, tamaño y frecuencia) y que no tiene la llave de descifrado; textos incluidos en la revisión legal y de UX (FR028-02) |
| [FR009-03](https://github.com/sedecim-com/nostr/issues/240) | P1 | Acuses que llegan al emisor y DMs recibidos en segundo plano | FR-009, §15.1 | Dev | 3 | FR009-02 | Pendiente | Los acuses se publican en los 10050 del emisor y llevan la operación a RECIPIENT_ACKED; suscripción de fondo a los 10050 propios |
| [FR014-05](https://github.com/sedecim-com/nostr/issues/242) | P1 | El mirror comprueba la membresía NIP-29 y respeta la moderación | FR-014, §10.1 | Dev | 3 | FR014-03 | Pendiente | Lecturas y búsqueda solo sobre canales de los que eres miembro; tombstone para kind 9005 |
| [FR017-06](https://github.com/sedecim-com/nostr/issues/241) | P1 | El cliente soberano enruta DMs por 10050 y publica el suyo | FR-017, FR-010 | Dev | 2 | FR017-04 | Pendiente | CLI con el mismo ruteo que la web y test de interoperabilidad web ↔ CLI |
| [NFR009-02](https://github.com/sedecim-com/nostr/issues/188) | P1 | Corregir los hallazgos de accesibilidad y revisión manual con lector de pantalla | NFR-009 | Dev | 3 | NFR009-01 | Parcial | Informe de la revisión manual y correcciones aplicadas antes de la GA de la web |
| [OPS-06](https://github.com/sedecim-com/nostr/issues/57) | P1 | Servicio notification-gateway con perfiles de privacidad | §17.1, ADR 0010, PRD GC-G01, GC-G02 | Dev | 3 | DEC-08 | Parcial | Push opaco sin contenido ni remitente y deshabilitado en perfiles Tor, detrás de un flag apagado por defecto donde el relay no permite un disparador seguro; la web no muestra avisos activos si el gateway no puede observar la actividad; ninguna solución da al gateway lectura de DMs ni metadatos adicionales; ADR 0010 con la matriz real por relay |
| [FR006-06](https://github.com/sedecim-com/nostr/issues/243) | P2 | Test de aislamiento de circuitos Tor por persona | §14.1 | QA | 1 | FR006-03 | Pendiente | Credenciales SOCKS distintas por persona verificadas contra un servidor SOCKS con autenticación |
| [FR007-05](https://github.com/sedecim-com/nostr/issues/245) | P2 | «Enviando como…» muestra el nivel de vínculo | §16.1, FR-007 | Dev | 1 | FR007-03, FR006-02 | Pendiente | El banner del composer indica identidad, custodia, red y nivel de vínculo (ninguno, privado, selectivo o público) en la web y en el CLI |
| [FR021-03](https://github.com/sedecim-com/nostr/issues/244) | P2 | Endurecimiento del modo Tor | §14, §18.1 | Dev | 2 | FR020-01 | Pendiente | Opción onion-only en el cliente soberano, mensaje de fallo unificado «No enviado: red de privacidad no disponible» y relays sin IPs en los logs de los perfiles soberanos |

## S11 · Restauración sin relays y operación real (G1–G2, 2026-10-26 → 2026-11-06) — 51 SP

| ID | Prio | Tarea | Requisito | Tipo | SP | Depende de | Estado | Criterio de hecho |
|---|---|---|---|---|---:|---|---|---|
| [FR005-13](https://github.com/sedecim-com/nostr/issues/255) | P0 | KMS y Secrets Manager validados en la cuenta y región reales | FR-005, ADR 0009, PRD GC-D02 | Seguridad | 3 | NFR001-01 | Pendiente | Crear, firmar y exportar-borrar contra AWS real en stage; IAM de mínimo privilegio revisado y documentado en ADR 0009 |
| [FR026-04](https://github.com/sedecim-com/nostr/issues/253) | P0 | Salida de la custodia, borrado verificable y derechos ARCO | §8.5, FR-026, PRD GC-D03 | Dev | 5 | FR026-01, FR005-13 | Pendiente | Cancelar sin migrar (API y UI) con confirmación y descarga del backup antes de borrar; npub en el JSON de migración; borrado por el operador de cuentas cerradas; ventanas de Secrets Manager y logs verificadas en AWS; el usuario ve el estado de eliminación |
| [NFR003-03](https://github.com/sedecim-com/nostr/issues/251) | P0 | Simulacro completo de RPO/RTO en stage | NFR-003, PRD GC-C05 | Infra | 3 | NFR001-03 | Pendiente | Restore nocturno de RDS (PITR) y del almacenamiento S3 con interop, más un drill manual en un entorno limpio con los tiempos reales documentados |
| [NFR005-02](https://github.com/sedecim-com/nostr/issues/180) | P0 | Pruebas de carga del relay y el indexer | NFR-005, PRD GC-C04 | QA | 5 | NFR005-01, NFR001-01 | Parcial | Throughput, p95/p99, saturación y límites medidos contra el Buzz de stage y el indexer en docs/load-testing.md; capacity baseline y estrategia de escalado de los relays aprobados |
| [OPS-18](https://github.com/sedecim-com/nostr/issues/250) | P0 | Trazabilidad y estado generados desde la fuente, con check en CI | PRD GC-F03 | Infra | 5 | OPS-17 | Pendiente | requirements-traceability.md y un tablero de estado se regeneran desde los issues y el código; CI falla si una referencia o evidencia (archivo, prueba, SHA o ADR) no existe |
| [OPS-20](https://github.com/sedecim-com/nostr/issues/252) | P0 | Feature gates de producción para managed, enclave y push | PRD GC-D05, GC-A03, GC-G01 | Seguridad | 3 | OPS-06, REL-01 | Pendiente | Con legal o auditoría pendientes, el onboarding managed no aparece en la configuración de producción; enclave y su exportación apagados mientras sean Preview; push apagado donde no hay disparador seguro; el gate de release comprueba la configuración |
| [VAULT-03](https://github.com/sedecim-com/nostr/issues/246) | P0 | Respaldo de eventos canónicos y restauración con relays vacíos | PRD GC-B03, FR-013, FR-027 | Dev | 5 | VAULT-02 | Pendiente | Se respaldan NIP-29, la copia propia de NIP-17, los eventos Marmot con el estado MLS necesario y el ledger/outbox; un dispositivo limpio con la backup key y relays vacíos reconstruye el 100 % del fixture de conversaciones y el ledger, en web y CLI, dentro de CI |
| [FR023-10](https://github.com/sedecim-com/nostr/issues/254) | P1 | Aplicar «publicar» por recurso en los relays | FR-023 | Dev | 8 | FR023-04 | Pendiente | Admisión por #h en el secure relay y en Buzz, y sincronía de la membresía NIP-29 con el policy-engine; test de denegación |
| [NFR001-04](https://github.com/sedecim-com/nostr/issues/256) | P1 | Alta disponibilidad en stage | NFR-001 | Infra | 5 | NFR001-02, NFR001-03 | Pendiente | Réplicas y PDB; Redis, SeaweedFS y secure relay en HA o gestionados; blob-store con allowlist o cuotas; el SLO de 99,9 % queda instrumentado sobre una topología que puede cumplirlo |
| [VAULT-04](https://github.com/sedecim-com/nostr/issues/247) | P1 | El vault en la máquina de estados de entrega | PRD GC-B04, FR-008, FR-011 | Dev | 3 | VAULT-02 | Pendiente | Publicación en relays y subida al vault independientes; política off / best-effort / required-for-resilient en el panel; estado CONTINUITY_BACKED_UP separado del ACK de relays; solo required-for-resilient puede retener el envío |
| [VAULT-05](https://github.com/sedecim-com/nostr/issues/248) | P1 | Retención, borrado y exportación del vault | PRD GC-B05, NFR-008 | Dev | 3 | VAULT-03 | Pendiente | Retención configurable; exportación portable; borrar elimina las copias del servidor según la política y queda documentado |
| [VAULT-06](https://github.com/sedecim-com/nostr/issues/249) | P1 | Backend self-hosted del vault | PRD GC-B06, NFR-003 | Infra | 3 | VAULT-01 | Pendiente | El mismo contrato sobre almacenamiento local o S3-compatible (SeaweedFS del compose) sin depender del SaaS de Sedecim; incluido en el compose y en el restore drill |

## S12 · Freeze de auditoría y v1.0.0-rc.1 (G2–G3, 2026-11-09 → 2026-11-20) — 43 SP

| ID | Prio | Tarea | Requisito | Tipo | SP | Depende de | Estado | Criterio de hecho |
|---|---|---|---|---|---:|---|---|---|
| [NFR004-02](https://github.com/sedecim-com/nostr/issues/178) | P0 | Dashboard de latencia y degradación sin ocultarla | NFR-004, PRD GC-C02 | Infra | 2 | NFR004-01, NFR001-02 | Parcial | Panel P95/P99 por relay con alertas de degradación en vivo en stage, con scrape por pod del indexer (hoy mide una sola réplica) |
| [PANEL-07](https://github.com/sedecim-com/nostr/issues/259) | P0 | Etiquetas de madurez por perfil y función en web, CLI y documentación | FR-028, PRD §12 | Dev | 3 | PANEL-05 | Pendiente | Beta para Marmot/MLS, Experimental para Sovereign Tor y push, Preview para el enclave y ninguna GA de private-resilient sin el vault; visibles en la web, el CLI, el README y las notas de release; NIP-17 solo habilitado con el gate de interop en verde |
| [SEC-11](https://github.com/sedecim-com/nostr/issues/257) | P0 | Tag de auditoría firmado y v1.0.0-rc.1 | §20.3, PRD GC-A04, GC-F05 | Seguridad | 3 | SEC-06, SEC-07, FR025-11, VAULT-03, VAULT-04, FR026-04, FR005-13, OPS-18, DEC-10, REL-01 | Pendiente | Tag audit-2026-11 firmado sobre main con internal-review, threat models y backlog sin contradicciones; v1.0.0-rc.1 publicada desde ese commit con el gate y waiver de auditoría; durante el trabajo de campo, cambiar cripto, custodia o continuidad exige waiver y nuevo baseline |
| [SEC-12](https://github.com/sedecim-com/nostr/issues/258) | P0 | Inventario de la superficie de ataque de Buzz desplegado | §20.3, PRD GC-A07 | Seguridad | 3 | NFR001-01, BUZZ-07 | Pendiente | Rutas y capacidades realmente alcanzables del Buzz de stage documentadas para el pentest; opcionales innecesarios deshabilitados |
| [FR005-11](https://github.com/sedecim-com/nostr/issues/264) | P1 | Recuperar la persona gestionada en un navegador nuevo | §8.1, FR-005 | Dev | 3 | FR005-04 | Pendiente | Con el login de Acceso se reabre la llave gestionada; el usuario ve su log de uso y revoca sus sesiones |
| [FR024-05](https://github.com/sedecim-com/nostr/issues/265) | P1 | Rotaciones como servicio, sesiones de dispositivo en la web y runbook de pérdida | FR-024 | Dev | 5 | FR024-02, FR024-04 | Pendiente | Worker de rotaciones en compose y k8s; la persona managed de la web usa sesiones de dispositivo revocables; docs/runbooks/device-loss.md |
| [FR025-12](https://github.com/sedecim-com/nostr/issues/269) | P1 | Outbox para mensajes y commits MLS | FR-011, FR-020 | Dev | 3 | FR025-11 | Pendiente | Con Tor caído o sin red, un mensaje o commit de grupo queda pendiente y se reintenta, en lugar de fallar |
| [NFR002-03](https://github.com/sedecim-com/nostr/issues/263) | P1 | Simulacros de fallo de dependencias en stage | NFR-002, PRD GC-C06 | QA | 5 | NFR001-04 | Pendiente | Caída de un relay, de una réplica del indexer, failover de Postgres y object storage degradado no corrompen la outbox ni los estados; 0 LOCAL_PERSISTED perdidos en las pruebas de crash |
| [NFR010-04](https://github.com/sedecim-com/nostr/issues/261) | P1 | SBOM fiel a cada imagen | NFR-010, PRD GC-E02 | Infra | 3 | NFR010-01 | Pendiente | SBOM por imagen (syft) atestado, sin devDependencies en runtime; también para la imagen de Buzz fijada |
| [OPS-19](https://github.com/sedecim-com/nostr/issues/260) | P1 | README con el estado por release, no con checkmarks | PRD GC-F04 | Doc | 2 | OPS-18, PANEL-07 | Pendiente | El README muestra el estado de cada perfil y capacidad por nivel de evidencia (Merged, CI, stage, auditado, producción), generado por OPS-18 y con la advertencia de no aptitud para alto riesgo |
| [FR011-05](https://github.com/sedecim-com/nostr/issues/268) | P2 | Identificador de operación estable en la UI | §11.2 | Dev | 2 | FR011-01 | Pendiente | Reintentar desde la web o el CLI no crea otro evento ni otro rumor; los wraps se crean después de persistir |
| [FR023-12](https://github.com/sedecim-com/nostr/issues/266) | P2 | Auditoría y retención legal coherentes con el modelo de confidencialidad | §16, §12.2 | Dev | 3 | FR023-08 | Pendiente | Retención propia para las entradas de evaluate; legal hold solo donde el modelo lo permite; reemplazables respetan la retención legal |
| [FR023-13](https://github.com/sedecim-com/nostr/issues/267) | P2 | CI del modo institucional | FR-023 | QA | 2 | OPS-07 | Pendiente | El perfil institutional del compose y el componente k8s se validan en CI; E2E de la consola contra el policy-engine real |
| [FR024-03](https://github.com/sedecim-com/nostr/issues/169) | P2 | Revocar sesiones NIP-46 y tokens de managed-signer ligados al dispositivo | FR-024 | Dev | 2 | FR024-01, FR005-04, FR024-04, FR024-05 | Parcial | Tras revocar, el signer rechaza al dispositivo también en la web y sin depender de que alguien ejecute el CLI |
| [OPS-13](https://github.com/sedecim-com/nostr/issues/262) | P2 | Higiene de la cadena de suministro en CI | §21.2 | Infra | 2 | OPS-05 | Pendiente | Acciones por SHA, imágenes por digest, checksums de herramientas, Dependabot para infra/tor y compose, npm audit y CodeQL como gate |

## S13 · Auditoría externa en campo (G4, 2026-11-23 → 2026-12-04) — 12 SP

| ID | Prio | Tarea | Requisito | Tipo | SP | Depende de | Estado | Criterio de hecho |
|---|---|---|---|---|---:|---|---|---|
| [DEC-12](https://github.com/sedecim-com/nostr/issues/44) | P1 | Aprobación legal de los términos de custodia managed y del aviso de privacidad | §25.1-9, PRD GC-D01 | Decisión | 1 | DEC-09, FR005-08 | Parcial | Asesoría legal aprueba docs/legal/custodia-managed.md y el aviso de privacidad, versionados, antes de habilitar managed en producción |
| [FR020-05](https://github.com/sedecim-com/nostr/issues/270) | P1 | Suite de fugas completa en el cliente soberano | FR-020, Apéndice D | Seguridad | 3 | FR020-03 | Pendiente | La captura real también cubre dm, group, media y rotation-worker, con MLS por Tor; control negativo de ts-mls rc.10 en CI |
| [FR028-02](https://github.com/sedecim-com/nostr/issues/107) | P1 | Revisión legal/UX de los textos de disclosure | FR-028 | Doc | 2 | FR028-01, DEC-09, PANEL-05, VAULT-07, PANEL-07 | Parcial | Textos aprobados por legal y UX y versionados, incluidos los del vault y las etiquetas de madurez |
| [DEC-11](https://github.com/sedecim-com/nostr/issues/198) | P2 | Búsqueda y registro de la marca "Acceso Nostr" | §25.1-1 | Decisión | 1 | DEC-01 | Pendiente | Búsqueda de anterioridades y solicitud de registro presentada, o marca alternativa decidida |
| [FR011-06](https://github.com/sedecim-com/nostr/issues/272) | P2 | Métricas de outbox reales o alerta retirada | FR-011, NFR-004 | Infra | 2 | FR011-03 | Pendiente | La alerta OutboxOldestPendingTooOld se alimenta de un proceso real o se retira del monitoreo del SaaS |
| [DEC-15](https://github.com/sedecim-com/nostr/issues/273) | P3 | Estructura de repositorios | §21.1 | Decisión | 1 | — | Pendiente | ADR que justifica el monorepo frente a los seis repositorios sugeridos por el scope |
| [NFR006-04](https://github.com/sedecim-com/nostr/issues/271) | P3 | Escaneo de secretos en logs con todos los perfiles | NFR-006 | QA | 2 | NFR006-03 | Pendiente | El job stack también levanta managed, push, institutional y tor y escanea sus logs |

## S14 · Informes externos y Nitro en Preview (G4, 2026-12-07 → 2026-12-18) — 21 SP

| ID | Prio | Tarea | Requisito | Tipo | SP | Depende de | Estado | Criterio de hecho |
|---|---|---|---|---|---:|---|---|---|
| [SEC-01](https://github.com/sedecim-com/nostr/issues/192) | P0 | Revisión criptográfica independiente (NIP-44/49/59, MLS, key service) | §20.3, PRD GC-A05 | Seguridad | 8 | SEC-03, FR005-03, SEC-06, SEC-07, SEC-11 | Parcial | Informe independiente sobre el tag de auditoría (NIP-44/49/59, MLS, key service y vault) sin hallazgos críticos abiertos |
| [FR005-05](https://github.com/sedecim-com/nostr/issues/90) | P1 | Tier enclave: firma dentro de Nitro Enclave con KMS condicionado por attestation | FR-005, §8.4, PRD GC-D04 | Dev | 8 | FR005-02, DEC-09 | Parcial | EIF reproducible con PCR medidos en CI, attestation y KMS condicionado probados en una instancia Nitro real y alarma CloudTrail; sigue etiquetado Preview y apagado en producción (OPS-20) |
| [OPS-14](https://github.com/sedecim-com/nostr/issues/274) | P2 | Documentación del SDK y de las APIs | §17, §26 | Doc | 5 | — | Pendiente | TypeDoc de los paquetes, OpenAPI de cada servicio y ADR sobre cómo se distribuye el SDK |

## S15 · Remediación, retest y v1.0.0-rc.2 (G4, 2027-01-04 → 2027-01-15) — 16 SP

| ID | Prio | Tarea | Requisito | Tipo | SP | Depende de | Estado | Criterio de hecho |
|---|---|---|---|---|---:|---|---|---|
| [SEC-02](https://github.com/sedecim-com/nostr/issues/193) | P0 | Pentest de API, relay, key service y cliente | §20.3, PRD GC-A06, GC-A07 | Seguridad | 8 | OPS-02, FR005-04, FR023-03, NFR001-01, SEC-11, SEC-12, SEC-08 | Parcial | Pentest sobre stage (API, relays con Buzz desplegado, key service y cliente); críticos y altos corregidos y verificados en el retest; medios con plan o aceptación |
| [SEC-08](https://github.com/sedecim-com/nostr/issues/275) | P0 | Corregir los hallazgos críticos y altos de SEC-01 y SEC-02 | §20.3, PRD GC-A05, GC-A06 | Seguridad | 8 | SEC-01 | Pendiente | Cada crítico o alto con corrección, test de regresión y verificación del auditor; medios con plan o aceptación explícita; v1.0.0-rc.2 publicada para el retest |

## S16 · v1.0.0 firmada para despliegues controlados (G5, 2027-01-18 → 2027-01-29) — 4 SP

| ID | Prio | Tarea | Requisito | Tipo | SP | Depende de | Estado | Criterio de hecho |
|---|---|---|---|---|---:|---|---|---|
| [REL-03](https://github.com/sedecim-com/nostr/issues/277) | P0 | v1.0.0 firmada con la Definition of Done completa y sin waiver | Apéndice D, PRD G5 | Infra | 3 | SEC-01, SEC-02, SEC-08, REL-01, OPS-20, NFR003-03, REL-04 | Pendiente | Informes externos en docs/security/audits/v1.0.0.md, threat models aprobados, restore drills self-hosted y SaaS, fugas, artefactos firmados con SBOM y provenance, y feature gates de producción correctos |
| [REL-04](https://github.com/sedecim-com/nostr/issues/276) | P1 | Revisión final de afirmaciones y etiquetas de madurez | §2.3, PRD §12 | Doc | 1 | PANEL-07, OPS-19, SEC-08 | Pendiente | Ninguna función parcial aparece como GA; Sovereign Tor sigue Experimental y el README conserva la advertencia de no aptitud para alto riesgo; notas de trust model de v1.0.0 |

## Diferido · Después de v1.0: fuera del programa de cierre (—, sin fecha) — 105 SP

| ID | Prio | Tarea | Requisito | Tipo | SP | Depende de | Estado | Criterio de hecho |
|---|---|---|---|---|---:|---|---|---|
| [FR005-09](https://github.com/sedecim-com/nostr/issues/279) | P1 | Exportar desde el enclave exige una prueba del usuario verificada dentro del enclave | FR-026, IR-01, PRD GC-A03 | Seguridad | 5 | FR005-05 | Pendiente | JWT con JWKS fijado en la imagen o firma de la llave de destino; sin ella el enclave se niega; test. Requisito para sacar el enclave de Preview |
| [NFR001-05](https://github.com/sedecim-com/nostr/issues/281) | P1 | Entorno de producción del SaaS | NFR-001 | Infra | 8 | NFR001-04, OPS-20 | Pendiente | Overlay de producción con la topología HA probada en stage, los feature gates de OPS-20, sonda externa y el SLO de 99,9 % medido |
| [SEC-10](https://github.com/sedecim-com/nostr/issues/278) | P1 | Revisión criptográfica delta de MLS estable | §20.3 | Seguridad | 3 | FR025-08 | Pendiente | Informe externo del delta tras FR025-08 sin críticos abiertos; requisito de la etiqueta high-security |
| [DEC-13](https://github.com/sedecim-com/nostr/issues/297) | P2 | ADR de un aviso de notificación separado del mensaje | ADR 0010, PRD GC-G03 | Decisión | 1 | OPS-06 | Pendiente | Diseño evaluado cuando se retome un cliente móvil; no bloquea el RC |
| [DEC-14](https://github.com/sedecim-com/nostr/issues/292) | P2 | Modelo comercial del SaaS: organizaciones, planes y facturación | §15.2 | Decisión | 1 | — | Pendiente | ADR con el modelo de tenants, planes y proveedor de cobro |
| [FR004-08](https://github.com/sedecim-com/nostr/issues/290) | P2 | Cliente soberano con signer NIP-46 e importación de nsec/ncryptsec | §14, FR-002, FR-004 | Dev | 3 | FR004-01 | Pendiente | Perfiles Tor con signer externo (§14: offline/signer) y custodia declarada según la llave real |
| [FR005-10](https://github.com/sedecim-com/nostr/issues/280) | P2 | Importar al enclave sin exponer la llave ni la contraseña al padre | FR-005 | Seguridad | 3 | FR005-05 | Pendiente | El ncryptsec se cifra hacia la clave atestada del enclave; test |
| [FR006-04](https://github.com/sedecim-com/nostr/issues/283) | P2 | Perfil público por persona (kind 0: nombre y avatar) | §7, FR-006 | Dev | 3 | FR006-02 | Pendiente | Se publica y se muestra en canales, DMs y grupos; en perfiles seudónimos no se publica nada salvo elección explícita |
| [FR006-07](https://github.com/sedecim-com/nostr/issues/287) | P2 | Compartimentación: avisar antes de reutilizar un contacto o un archivo entre personas | §14.1 | Dev | 3 | FR006-01 | Pendiente | Aviso con confirmación explícita en la web y en el CLI, también para archivos (recordUsage) |
| [FR014-04](https://github.com/sedecim-com/nostr/issues/284) | P2 | La web usa el mirror: no leídos por canal y búsqueda | FR-014, §15.2 | Dev | 3 | FR014-05, FR023-05 | Pendiente | Contadores de no leídos y búsqueda en la web vía NIP-98, respetando la política |
| [FR015-04](https://github.com/sedecim-com/nostr/issues/285) | P2 | Reacciones, hilos y borrado en canales | §15.1 | Dev | 5 | FR015-02 | Pendiente | Kinds 7, respuestas con e/q y borrado 5/9005 en la web, con E2E contra Buzz |
| [FR020-06](https://github.com/sedecim-com/nostr/issues/291) | P2 | Cliente soberano como servicio del perfil tor | FR-020 | Infra | 2 | FR021-02 | Pendiente | docker compose run --rm sovereign … con TOR_SOCKS=tor:9050, documentado |
| [FR023-11](https://github.com/sedecim-com/nostr/issues/289) | P2 | Device trust en uso: passkey del propio usuario | §16 | Dev | 5 | FR023-07 | Pendiente | El usuario registra la passkey en su dispositivo y cada sesión pide una aserción WebAuthn |
| [FR025-08](https://github.com/sedecim-com/nostr/issues/156) | P2 | Migrar a marmot-ts v2 / ts-mls estable cuando se publiquen | FR-025 | Dev | 3 | FR025-04 | Parcial | Dependencias estables con conformidad y autoprueba en verde, o excepción documentada. Hace falta para la etiqueta high-security, no para v1.0 |
| [FR025-14](https://github.com/sedecim-com/nostr/issues/288) | P2 | Grupos completos en la web: multi-dispositivo, rotación, propuestas y media cifrada | FR-025 | Dev | 5 | FR025-11 | Pendiente | Lo que hoy solo ofrece el CLI (FR025-05/06/09 y rotate) disponible en «Grupos seguros» |
| [NFR003-04](https://github.com/sedecim-com/nostr/issues/282) | P2 | Copia en una segunda región para el tier institucional | NFR-003 | Infra | 5 | NFR001-03, NFR003-01 | Pendiente | Datos y WAL replicados según el RPO/RTO aprobado; restauración probada |
| [OPS-15](https://github.com/sedecim-com/nostr/issues/293) | P2 | Organizaciones y planes en el SaaS | §15.2 | Dev | 8 | DEC-14 | Pendiente | Tenants y organizaciones en identity y policy; planes y cobro según DEC-14 |
| [PANEL-06](https://github.com/sedecim-com/nostr/issues/286) | P2 | Expiración de mensajes por perfil (NIP-40) y borrado con aviso | §12.2 | Dev | 5 | PANEL-02, VAULT-05 | Pendiente | Expiración configurable por persona y conversación; borrar mensajes propios con el aviso de que las copias replicadas pueden seguir existiendo; coherente con la retención del vault |
| [FR004-07](https://github.com/sedecim-com/nostr/issues/301) | P3 | Signer de hardware (opcional en el scope) | §8.2 | Dev | 5 | — | Pendiente | Spike con un dispositivo de hardware y decisión documentada |
| [FR013-05](https://github.com/sedecim-com/nostr/issues/299) | P3 | Caché local cifrada de eventos y NIP-77 con estado local | §7, §12 | Dev | 5 | — | Pendiente | Lectura sin conexión, reanudación por since y NIP-77 con conjunto local (interop con strfry) |
| [FR015-05](https://github.com/sedecim-com/nostr/issues/298) | P3 | Presencia (NIP-38) opt-in por perfil | §15.1 | Dev | 3 | — | Pendiente | Estado de presencia solo en perfiles que lo permiten |
| [FR018-06](https://github.com/sedecim-com/nostr/issues/300) | P3 | Política de tamaño, MIME y antivirus compatible con la confidencialidad | §13.1 | Doc | 2 | — | Pendiente | Política documentada y comprobación de tamaño en el cliente |
| [FR020-02](https://github.com/sedecim-com/nostr/issues/142) | P3 | Cliente desktop dedicado con Tor embebido | FR-020, §25 | Dev | 8 | DEC-04 | Pendiente | App desktop (Tauri) que usa el SDK con Tor integrado y el perfil sovereign-tor |
| [NFR007-02](https://github.com/sedecim-com/nostr/issues/295) | P3 | Tracing con muestreo y redacción según el perfil | §18 | Dev | 3 | NFR007-01 | Pendiente | Trazas en los servicios con muestreo y redacción, apagadas en perfiles Tor. Hasta entonces PANEL-05 retira la promesa |
| [NFR007-03](https://github.com/sedecim-com/nostr/issues/296) | P3 | Crash reports opt-in con limpieza y exportación manual local | §18, FR-028 | Dev | 3 | NFR007-01 | Pendiente | Implementados según el perfil. Hasta entonces PANEL-05 retira la promesa |
| [OPS-16](https://github.com/sedecim-com/nostr/issues/294) | P3 | Webhooks y eventos para integraciones empresariales | §15.2, §17.2 | Dev | 5 | — | Pendiente | El policy-engine emite eventos firmados (sustituye el sondeo de la auditoría); webhooks con reintentos |

## Entregado en v0.1 — 50 tareas

| ID | Tarea | Requisito | Evidencia |
|---|---|---|---|
| [OPS-04](https://github.com/sedecim-com/nostr/issues/55) | SECURITY.md y proceso de disclosure | §21.2 | `SECURITY.md` |
| [OPS-05](https://github.com/sedecim-com/nostr/issues/56) | Dependabot/Renovate con revisión | §21.2 | `.github/dependabot.yml` |
| [PANEL-01](https://github.com/sedecim-com/nostr/issues/62) | Modelo de configuración del panel, presets del Apéndice B y validación | §9 | `packages/profiles` |
| [FR001-01](https://github.com/sedecim-com/nostr/issues/66) | Generar llave con CSPRNG y self-test de derivación + firma BIP-340 | FR-001 | `packages/nostr-core/src/keys.ts` |
| [FR001-02](https://github.com/sedecim-com/nostr/issues/67) | Crear persona local con llave cifrada NIP-49 en su store | FR-001 | `packages/identity` |
| [FR001-03](https://github.com/sedecim-com/nostr/issues/68) | Flujo "crear llave local" en la web SaaS | FR-001 | `apps/web-saas/src/session.ts` |
| [FR002-01](https://github.com/sedecim-com/nostr/issues/71) | Importar nsec/ncryptsec validando la correspondencia pubkey/secret | FR-002 | `packages/identity/test` |
| [FR002-02](https://github.com/sedecim-com/nostr/issues/72) | Registrar persona con signer externo (bunker) o managed | FR-002 | `packages/identity` |
| [FR003-01](https://github.com/sedecim-com/nostr/issues/74) | Generador CLI offline con todas las primitivas de red bloqueadas | FR-003 | `apps/key-generator` |
| [FR003-02](https://github.com/sedecim-com/nostr/issues/75) | Bundle reproducible con checksum SHA-256 | FR-003 | `apps/key-generator/build.mjs` |
| [FR004-01](https://github.com/sedecim-com/nostr/issues/81) | Cliente NIP-46 (Nip46Signer) sin almacenar la nsec | FR-004 | `packages/signer/src/nip46.ts` |
| [FR004-02](https://github.com/sedecim-com/nostr/issues/82) | Bunker NIP-46 con permisos por kind y auditoría de peticiones | FR-004 | `packages/signer/test` |
| [FR005-01](https://github.com/sedecim-com/nostr/issues/86) | Servicio managed-signer con vault envelope y logs sin secretos | FR-005 | `services/managed-signer` |
| [FR006-01](https://github.com/sedecim-com/nostr/issues/93) | Gestión de ≥3 personas con stores, relays y signer independientes | FR-006 | `packages/identity` |
| [FR006-03](https://github.com/sedecim-com/nostr/issues/95) | Aislamiento de circuitos Tor por persona | FR-006, §14.1 | `packages/tor-network` |
| [FR007-01](https://github.com/sedecim-com/nostr/issues/96) | Vínculos entre personas con confirmación explícita y auditoría | FR-007 | `packages/identity` |
| [FR007-02](https://github.com/sedecim-com/nostr/issues/97) | API del identity-service con visibilidad private/selective/public | FR-007 | `services/identity-service` |
| [FR026-01](https://github.com/sedecim-com/nostr/issues/100) | Migración managed → local con prueba de posesión y política de retención | FR-026 | `services/managed-signer/test` |
| [FR026-02](https://github.com/sedecim-com/nostr/issues/101) | Migración local → managed (importación explícita) | FR-026 | `services/managed-signer/src/api.ts` |
| [FR027-01](https://github.com/sedecim-com/nostr/issues/103) | Backup cifrado que restaura la identidad en un dispositivo limpio | FR-027 | `packages/identity/test` |
| [FR028-01](https://github.com/sedecim-com/nostr/issues/106) | Disclosures por opción con consecuencias y supuestos de confianza | FR-028 | `packages/profiles` |
| [FR008-01](https://github.com/sedecim-com/nostr/issues/109) | Persistir el evento firmado en la outbox local antes de transmitir | FR-008 | `packages/delivery-engine` |
| [FR009-01](https://github.com/sedecim-com/nostr/issues/110) | Ledger por relay: intento, hora, resultado, OK, latencia y último error | FR-009 | `packages/delivery-engine` |
| [FR010-01](https://github.com/sedecim-com/nostr/issues/112) | Publicación a N relays con quorum configurable | FR-010 | `packages/delivery-engine` |
| [FR011-01](https://github.com/sedecim-com/nostr/issues/114) | Reintentos con backoff + jitter reutilizando el mismo event id | FR-011 | `packages/delivery-engine` |
| [FR012-01](https://github.com/sedecim-com/nostr/issues/117) | Deduplicar por event_id entre relays en cliente e indexer | FR-012 | `packages/relay-pool, services/indexer` |
| [FR013-01](https://github.com/sedecim-com/nostr/issues/118) | Sync de respaldo por ventanas de tiempo con paginación | FR-013 | `packages/sync` |
| [FR014-01](https://github.com/sedecim-com/nostr/issues/122) | Indexer/mirror ciphertext-first sin APIs propietarias de Buzz | FR-014 | `services/indexer` |
| [FR015-01](https://github.com/sedecim-com/nostr/issues/125) | La web publica eventos que ven otros clientes del mismo relay | FR-015 | `tests/browser/web-saas.e2e.ts` |
| [FR016-01](https://github.com/sedecim-com/nostr/issues/128) | NIP-42 challenge/response con auth-required recuperable | FR-016 | `packages/relay-pool` |
| [FR017-01](https://github.com/sedecim-com/nostr/issues/129) | NIP-17 (NIP-44 + NIP-59) detrás de un feature flag | FR-017 | `packages/messaging` |
| [FR017-02](https://github.com/sedecim-com/nostr/issues/130) | Adaptador explícito de jitter para Buzz, derivado del gate | FR-017 | `packages/messaging/src/adapters.ts` |
| [FR018-01](https://github.com/sedecim-com/nostr/issues/134) | Cliente Blossom: subir, referenciar, descargar y verificar el hash | FR-018 | `packages/blossom-client` |
| [FR018-02](https://github.com/sedecim-com/nostr/issues/135) | blob-store agnóstico al contenido para adjuntos cifrados | FR-018, §13 | `services/blob-store` |
| [FR019-01](https://github.com/sedecim-com/nostr/issues/139) | Quitar EXIF/XMP/IPTC en JPEG y chunks de texto/tiempo en PNG | FR-019 | `packages/blossom-client/src/sanitize.ts` |
| [FR020-01](https://github.com/sedecim-com/nostr/issues/141) | NetworkGuard Tor-only que falla cerrado, sin fallback clearnet | FR-020 | `packages/tor-network` |
| [FR021-01](https://github.com/sedecim-com/nostr/issues/144) | Conexión a relays .onion vía SOCKS5h con aislamiento por persona | FR-021 | `apps/sovereign-client/test` |
| [FR022-01](https://github.com/sedecim-com/nostr/issues/146) | TelemetryPolicy: nivel none bloquea analytics y crash reports | FR-022 | `packages/telemetry-policy` |
| [FR025-01](https://github.com/sedecim-com/nostr/issues/149) | GroupCryptoProvider sobre marmot-ts con estado MLS cifrado | FR-025 | `packages/marmot-adapter` |
| [FR025-02](https://github.com/sedecim-com/nostr/issues/150) | Mitigar ts-mls rc.10 (UpdatePath en un Remove) + autoprueba que falla cerrado | FR-025 | `docs/marmot.md` |
| [FR025-03](https://github.com/sedecim-com/nostr/issues/151) | Comandos de grupo en el cliente soberano (también vía Tor) | FR-025 | `apps/sovereign-client` |
| [FR023-01](https://github.com/sedecim-com/nostr/issues/159) | Evaluador RBAC/ABAC + device trust, deny por defecto | FR-023 | `packages/policy-client` |
| [FR023-02](https://github.com/sedecim-com/nostr/issues/160) | API del policy-engine (sujetos, recursos, dispositivos, evaluate) | FR-023 | `services/policy-engine` |
| [FR024-01](https://github.com/sedecim-com/nostr/issues/167) | Revocar dispositivo: bloquea sesiones y señala rotación de grupos | FR-024 | `services/policy-engine/test` |
| [NFR002-01](https://github.com/sedecim-com/nostr/issues/173) | Cero eventos LOCAL_PERSISTED perdidos tras un reinicio controlado | NFR-002 | `packages/delivery-engine/test` |
| [NFR006-01](https://github.com/sedecim-com/nostr/issues/181) | Escaneo de secretos que bloquea CI | NFR-006 | `.github/workflows/ci.yml` |
| [NFR006-02](https://github.com/sedecim-com/nostr/issues/182) | Redacción de secretos en logs de todos los servicios | NFR-006 | `packages/telemetry-policy` |
| [NFR007-01](https://github.com/sedecim-com/nostr/issues/184) | Telemetría gobernada por el perfil | NFR-007 | `packages/telemetry-policy` |
| [NFR008-01](https://github.com/sedecim-com/nostr/issues/185) | Exportar identidad y configuración en formato abierto | NFR-008 | `packages/identity` |
| [NFR010-01](https://github.com/sedecim-com/nostr/issues/189) | SBOM por release | NFR-010 | `.github/workflows/ci.yml` |
