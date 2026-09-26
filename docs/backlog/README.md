# Backlog — Acceso Nostr

> Fuente: [GitHub Issues](https://github.com/sedecim-com/nostr/issues?q=label%3Abacklog) (ver [GITHUB.md](GITHUB.md)). `backlog.json`, este archivo y `backlog.csv` se regeneran desde los issues; no editar a mano.
> Base: Scope_Plataforma_Nostr_Soberana_SaaS_v0.1 (25/09/2026). Estado del código: `main@65ed066` (2026-09-26).

## Resumen

- **164 tareas** · 121 hechas · 15 parciales · 22 pendientes · 6 descartadas
- **134 story points** pendientes en 8 sprints de 14 días (velocidad supuesta: 50 SP/sprint, equipo de ~4 personas; ajustar tras S1)
- Prioridades: **P0** Bloquea release o seguridad · **P1** Necesario para la fase · **P2** Importante, planificable · **P3** Deseable
- Estados: **Hecho** (con evidencia en el repo) · **Parcial** (existe base, falta completar) · **Pendiente** · **Descartado** (fuera de alcance por una decisión; la evidencia cita el ADR)
- IDs: `FRnnn-xx` / `NFRnnn-xx` por requisito; `DEC`, `BUZZ`, `OPS`, `PANEL`, `SEC`, `REL` para decisiones, Buzz upstream, operación, panel y gates.

## Plan de sprints

| Sprint | Fechas | Fase | Objetivo | Tareas | SP | P0 |
|---|---|---|---|---:|---:|---:|
| v0.1 | hasta 2026-09-26 | — | Entregado | 50 | 116 | 31 |
| S1 | 2026-09-28 → 2026-10-09 | F0 | Cierre F0 y gate de interoperabilidad | 12 | 22 | 5 |
| S2 | 2026-10-12 → 2026-10-23 | F0.5 | Web SaaS como cliente completo | 17 | 47 | 0 |
| S3 | 2026-10-26 → 2026-11-06 | F1 | Identidad, llaves y custodia | 21 | 49 | 1 |
| S4 | 2026-11-09 → 2026-11-20 | F2 | OSS soberano, sync y operación | 19 | 51 | 0 |
| S5 | 2026-11-23 → 2026-12-04 | F3 | Privacidad, Tor y observabilidad | 11 | 31 | 1 |
| S6 | 2026-12-07 → 2026-12-18 | F4 | Grupos high-security | 6 | 26 | 0 |
| S7 | 2027-01-04 → 2027-01-15 | F5 | Modo institucional | 13 | 51 | 1 |
| S8 | 2027-01-18 → 2027-01-29 | Release | Hardening, escalabilidad y release | 8 | 32 | 2 |
| Diferido | sin fecha | — | Sin planificar: requiere app nativa (ADR 0004) | 1 | 8 | 0 |

## Cobertura de requisitos

| Requisito | Tareas | Hechas | Pendientes (sprint) |
|---|---:|---:|---|
| FR-001 | 5 | 5 | — |
| FR-002 | 3 | 3 | — |
| FR-003 | 7 | 5 | FR003-06 (S4), FR003-07 (S4) |
| FR-004 | 5 | 5 | — |
| FR-005 | 7 | 5 | FR005-05 (S7), FR005-06 (S7) |
| FR-006 | 3 | 3 | — |
| FR-007 | 4 | 4 | — |
| FR-008 | 2 | 2 | — |
| FR-009 | 2 | 2 | — |
| FR-010 | 2 | 2 | — |
| FR-011 | 3 | 3 | — |
| FR-012 | 1 | 1 | — |
| FR-013 | 4 | 4 | — |
| FR-014 | 3 | 3 | — |
| FR-015 | 3 | 3 | — |
| FR-016 | 1 | 1 | — |
| FR-017 | 5 | 5 | — |
| FR-018 | 5 | 5 | — |
| FR-019 | 3 | 3 | — |
| FR-020 | 3 | 2 | FR020-02 (Diferido) |
| FR-021 | 2 | 2 | — |
| FR-022 | 2 | 2 | — |
| FR-023 | 6 | 2 | FR023-03 (S7), FR023-04 (S7), FR023-05 (S7), FR023-06 (S7) |
| FR-024 | 3 | 1 | FR024-02 (S7), FR024-03 (S7) |
| FR-025 | 10 | 9 | FR025-08 (S6) |
| FR-026 | 3 | 3 | — |
| FR-027 | 3 | 3 | — |
| FR-028 | 3 | 2 | FR028-02 (S3) |
| NFR-001 | 3 | 0 | NFR001-01 (S4), NFR001-02 (S4), NFR001-03 (S7) |
| NFR-002 | 2 | 2 | — |
| NFR-003 | 2 | 0 | NFR003-01 (S4), NFR003-02 (S4) |
| NFR-004 | 3 | 2 | NFR004-02 (S5) |
| NFR-005 | 2 | 0 | NFR005-01 (S8), NFR005-02 (S8) |
| NFR-006 | 3 | 3 | — |
| NFR-007 | 2 | 2 | — |
| NFR-008 | 2 | 2 | — |
| NFR-009 | 2 | 1 | NFR009-02 (S3) |
| NFR-010 | 4 | 1 | FR003-06 (S4), NFR010-02 (S4), NFR010-03 (S8) |

## S1 · Cierre F0 y gate de interoperabilidad (F0, 2026-09-28 → 2026-10-09) — 22 SP

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
| [DEC-10](https://github.com/sedecim-com/nostr/issues/45) | P1 | Formalizar threat models por perfil (convenience, resilient, institutional, sovereign, Tor) | §25.1-10, §20.3 | Seguridad | 3 | — | Hecho | Un documento por perfil con activos, adversarios, mitigaciones y riesgos residuales, versionado por release |
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

## S3 · Identidad, llaves y custodia (F1, 2026-10-26 → 2026-11-06) — 49 SP

| ID | Prio | Tarea | Requisito | Tipo | SP | Depende de | Estado | Criterio de hecho |
|---|---|---|---|---|---:|---|---|---|
| [FR005-03](https://github.com/sedecim-com/nostr/issues/88) | P0 | Persistir el registro de llaves y el log de uso en Postgres | FR-005 | Dev | 3 | FR005-01 | Hecho | Sobrevive reinicios (hoy el registro vive en memoria y el vault en disco) |
| [DEC-09](https://github.com/sedecim-com/nostr/issues/43) | P1 | Definir región cloud y requisitos legales de la custodia managed | §25.1-9 | Decisión | 2 | — | Hecho | Región, marco legal y retención decididos en un ADR; términos de custodia redactados |
| [DEC-12](https://github.com/sedecim-com/nostr/issues/44) | P1 | Aprobación legal de los términos de custodia managed y del aviso de privacidad | §25.1-9 | Decisión | 1 | DEC-09 | Parcial | Asesoría legal aprueba docs/legal/custodia-managed.md (LFPDPPP) antes de ofrecer la custodia managed en producción |
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
| [FR028-02](https://github.com/sedecim-com/nostr/issues/107) | P2 | Revisión legal/UX de los textos de disclosure | FR-028 | Doc | 2 | FR028-01, DEC-09 | Parcial | Textos aprobados por legal y UX; versionados |
| [NFR009-02](https://github.com/sedecim-com/nostr/issues/188) | P2 | Corregir los hallazgos de accesibilidad y revisión manual con lector de pantalla | NFR-009 | Dev | 3 | NFR009-01 | Parcial | Informe de la revisión y correcciones aplicadas |
| [FR003-04](https://github.com/sedecim-com/nostr/issues/77) | P3 | Plantilla imprimible del backup (HTML local, sin CDN) | FR-003 | Dev | 2 | FR003-03 | Hecho | Hoja con npub, QR y ncryptsec; sin recursos remotos |
| [FR004-05](https://github.com/sedecim-com/nostr/issues/85) | P3 | Soporte de auth_url del signer remoto | FR-004 | Dev | 1 | FR004-01 | Hecho | La UI abre auth_url y espera la respuesta real |
| [FR028-03](https://github.com/sedecim-com/nostr/issues/108) | P3 | Lint en CI que prohíbe afirmaciones absolutas en toda la UI | FR-028, §2.2 | QA | 1 | FR028-01 | Hecho | assertNoAbsoluteClaims aplicado a todo el copy de la web |
| [PANEL-04](https://github.com/sedecim-com/nostr/issues/65) | P3 | Indicadores visuales por dimensión respaldados por declaraciones verificables | §9.1 | Dev | 2 | PANEL-02 | Hecho | Cada indicador enlaza a sus disclosures; sin score único |

## S4 · OSS soberano, sync y operación (F2, 2026-11-09 → 2026-11-20) — 51 SP

| ID | Prio | Tarea | Requisito | Tipo | SP | Depende de | Estado | Criterio de hecho |
|---|---|---|---|---|---:|---|---|---|
| [FR003-06](https://github.com/sedecim-com/nostr/issues/79) | P1 | Firma de las releases del generador | FR-003, NFR-010 | Seguridad | 2 | FR003-02, NFR010-02 | Parcial | Firma y verificación documentadas (minisign/cosign) |
| [FR013-03](https://github.com/sedecim-com/nostr/issues/120) | P1 | E2E: reinstalar y reconstruir historial (canales, DMs, outbox) en un dispositivo limpio | FR-013 | QA | 3 | FR013-01, FR027-01 | Hecho | Tras restaurar el backup, el cliente recupera historia y estados |
| [NFR001-01](https://github.com/sedecim-com/nostr/issues/170) | P1 | Infraestructura como código del SaaS (Helm/Terraform) | NFR-001 | Infra | 8 | OPS-02 | Parcial | Despliegue reproducible en un entorno de staging |
| [NFR001-02](https://github.com/sedecim-com/nostr/issues/171) | P1 | Monitorización de SLO (99,9 % mensual) y alertas | NFR-001 | Infra | 3 | NFR001-01 | Parcial | Dashboard de disponibilidad y alertas por servicio |
| [NFR003-01](https://github.com/sedecim-com/nostr/issues/175) | P1 | Definir RPO/RTO por tier | NFR-003 | Doc | 1 | DEC-09 | Parcial | Tabla aprobada por tier (self-hosted, SaaS, institucional) |
| [NFR003-02](https://github.com/sedecim-com/nostr/issues/176) | P1 | Restore drill automatizado (nightly) | NFR-003 | Infra | 5 | NFR003-01, OPS-01 | Parcial | Job que restaura en un host limpio y ejecuta test:interop |
| [NFR010-02](https://github.com/sedecim-com/nostr/issues/190) | P1 | Firma de releases y provenance (SLSA/cosign) | NFR-010, §21.2 | Seguridad | 3 | OPS-08 | Parcial | Imágenes y artefactos firmados; verificación documentada |
| [SEC-03](https://github.com/sedecim-com/nostr/issues/194) | P1 | Fuzz/property tests de serialización y criptografía | §20.3 | Seguridad | 3 | — | Hecho | fast-check sobre eventos, NIP-44, NIP-49, codec MLS y parsers de TLV |
| [FR003-07](https://github.com/sedecim-com/nostr/issues/80) | P2 | Guía de uso air-gapped verificable | FR-003 | Doc | 1 | FR003-06 | Parcial | Procedimiento paso a paso: verificar checksum y firma, generar, verificar backup |
| [FR013-02](https://github.com/sedecim-com/nostr/issues/119) | P2 | Cliente NIP-77 (Negentropy) con detección y fallback | FR-013, §12.1 | Dev | 5 | FR013-01 | Hecho | Reconciliación con un relay NIP-77; fallback automático si no lo soporta |
| [FR013-04](https://github.com/sedecim-com/nostr/issues/121) | P2 | Sync de gift wraps con timestamps aleatorios (ventana ampliada) | FR-013 | QA | 1 | FR013-01 | Hecho | Test con wraps de hasta 2 días de antigüedad; ningún mensaje perdido |
| [FR027-03](https://github.com/sedecim-com/nostr/issues/105) | P2 | Vault de backup en la nube: solo ciphertext con clave del usuario | FR-027, §12 | Dev | 3 | FR027-02 | Hecho | Subida/descarga del backup cifrado; el operador nunca ve la clave |
| [NFR002-02](https://github.com/sedecim-com/nostr/issues/174) | P2 | Test de crash con kill -9 durante la escritura | NFR-002 | QA | 2 | NFR002-01 | Hecho | Proceso matado a mitad de escritura; el store sigue consistente |
| [NFR006-03](https://github.com/sedecim-com/nostr/issues/183) | P2 | Test de integración que analiza los logs de los servicios en busca de secretos | NFR-006 | QA | 2 | OPS-01 | Hecho | Stack completo en CI; los logs se escanean con las reglas de gitleaks |
| [NFR008-02](https://github.com/sedecim-com/nostr/issues/186) | P2 | Exportar el historial completo (JSONL de eventos firmados) | NFR-008 | Dev | 2 | FR013-01 | Hecho | Export/import de eventos canónicos entre clientes |
| [OPS-08](https://github.com/sedecim-com/nostr/issues/59) | P2 | Separación de funciones en releases (quién construye vs quién publica) | §21.2 | Infra | 1 | — | Parcial | Entorno de release protegido con aprobadores distintos al autor |
| [OPS-09](https://github.com/sedecim-com/nostr/issues/60) | P2 | Documentación de build desde source | §21.2 | Doc | 2 | — | Hecho | Guía reproducible para todos los artefactos (servicios, web, keygen) |
| [OPS-10](https://github.com/sedecim-com/nostr/issues/61) | P2 | Backlog vivo en GitHub Issues con sincronización automática a docs/backlog | Proceso | Infra | 3 | — | Parcial | Cada tarea es un issue (milestone = sprint, labels de prioridad/epic/estado, campos Priority/Effort/fechas, sub-issues del epic y "blocked by"); un workflow regenera docs/backlog desde los issues y abre la PR de sync |
| [FR017-05](https://github.com/sedecim-com/nostr/issues/133) | P3 | Seguir el issue upstream #4192 y retirar el adaptador cuando se corrija | FR-017, §25 | QA | 1 | BUZZ-05 | Hecho | Re-ejecutar el gate en cada sync; volver al jitter estándar si pasa |

## S5 · Privacidad, Tor y observabilidad (F3, 2026-11-23 → 2026-12-04) — 31 SP

| ID | Prio | Tarea | Requisito | Tipo | SP | Depende de | Estado | Criterio de hecho |
|---|---|---|---|---|---:|---|---|---|
| [FR020-03](https://github.com/sedecim-com/nostr/issues/143) | P0 | Tests de fugas con captura de red real (netns/pcap): DNS, IPv6, conexiones directas | FR-020, §20.3 | Seguridad | 5 | — | Hecho | Suite que prueba cero tráfico fuera de Tor con el cliente soberano real (CLI); la app desktop, cuando exista, reutiliza la suite |
| [FR021-02](https://github.com/sedecim-com/nostr/issues/145) | P1 | Validar el perfil tor del compose (onion services de relay y secure-relay) | FR-021 | QA | 2 | OPS-01 | Hecho | Arranque real y conexión del CLI a las direcciones .onion generadas |
| [FR022-02](https://github.com/sedecim-com/nostr/issues/147) | P1 | Test en CI de endpoints de salida permitidos por perfil | FR-022, NFR-007 | QA | 3 | FR020-03 | Hecho | Allowlist de egress por perfil verificada con el cliente real |
| [SEC-05](https://github.com/sedecim-com/nostr/issues/148) | P1 | Tests de fugas por WebRTC y previews remotas en la web | §20.3 | Seguridad | 2 | — | Hecho | Sin candidatos ICE ni peticiones de previews en perfiles sensibles (la app desktop, cuando exista, reutiliza la suite) |
| [DEC-08](https://github.com/sedecim-com/nostr/issues/42) | P2 | Definir modelo de notificaciones móviles por perfil | §25.1-8 | Decisión | 2 | — | Hecho | Matriz perfil × (push, privacy-push, none) con metadatos expuestos |
| [NFR004-01](https://github.com/sedecim-com/nostr/issues/177) | P2 | Exportar métricas (latencia P95 de ACK por relay y región) | NFR-004 | Dev | 3 | — | Hecho | Exportador Prometheus respetando el perfil de telemetría |
| [OPS-06](https://github.com/sedecim-com/nostr/issues/57) | P2 | Servicio notification-gateway con perfiles de privacidad | §17.1 | Dev | 5 | DEC-08 | Parcial | Push opaco sin contenido ni remitente; deshabilitado en perfiles Tor |
| [FR007-04](https://github.com/sedecim-com/nostr/issues/99) | P3 | Publicar opcionalmente un vínculo público como evento Nostr firmado | FR-007 | Dev | 3 | FR007-02 | Hecho | Formato definido, firmado por ambas personas y verificable |
| [FR011-03](https://github.com/sedecim-com/nostr/issues/116) | P3 | Métricas de outbox (profundidad, antigüedad, fallos por relay) | FR-011, NFR-004 | Dev | 2 | FR011-01, NFR004-01 | Hecho | Expuestas al exportador de métricas respetando el perfil |
| [FR018-05](https://github.com/sedecim-com/nostr/issues/138) | P3 | Lista de servidores Blossom del usuario (kind 10063) | FR-018 | Dev | 2 | FR018-01 | Hecho | El cliente publica y respeta la lista de servidores |
| [NFR004-02](https://github.com/sedecim-com/nostr/issues/178) | P3 | Dashboard de latencia y degradación sin ocultarla | NFR-004 | Infra | 2 | NFR004-01, NFR001-02 | Parcial | Panel P95/P99 por relay con alertas de degradación |

## S6 · Grupos high-security (F4, 2026-12-07 → 2026-12-18) — 26 SP

| ID | Prio | Tarea | Requisito | Tipo | SP | Depende de | Estado | Criterio de hecho |
|---|---|---|---|---|---:|---|---|---|
| [FR025-04](https://github.com/sedecim-com/nostr/issues/152) | P1 | Interoperabilidad verificada con MDK/whitenoise | FR-025 | QA | 5 | DEC-07 | Hecho | Grupo mixto marmot-ts ↔ MDK con mensajes en ambos sentidos |
| [FR025-05](https://github.com/sedecim-com/nostr/issues/153) | P2 | MIP-04: media cifrada en grupos | FR-025, §13 | Dev | 5 | FR025-01, FR018-02 | Hecho | Subida y descarga de media con claves derivadas del exporter MLS |
| [FR025-06](https://github.com/sedecim-com/nostr/issues/154) | P2 | Multi-dispositivo: varios key packages por persona y sincronización del estado | FR-025 | Dev | 5 | FR025-01 | Hecho | Un usuario con 2 dispositivos participa en el mismo grupo |
| [FR025-07](https://github.com/sedecim-com/nostr/issues/155) | P2 | UI de grupos high-security en la web | FR-025 | Dev | 5 | FR025-06, FR001-04 | Hecho | Crear, invitar, chatear y expulsar desde la web con estado cifrado |
| [FR025-08](https://github.com/sedecim-com/nostr/issues/156) | P2 | Migrar a marmot-ts v2 / ts-mls estable cuando se publiquen | FR-025 | Dev | 3 | FR025-04 | Parcial | Dependencias fijadas a versiones estables; conformidad y autoprueba en verde |
| [BUZZ-06](https://github.com/sedecim-com/nostr/issues/51) | P3 | Integración progresiva del cliente móvil Flutter de Buzz | §6.1 | Dev | 8 | BUZZ-03, DEC-04 | Descartado | Mobile compila contra el relay del fork y pasa smoke test NIP-29 |
| [FR025-09](https://github.com/sedecim-com/nostr/issues/157) | P3 | Flujo de propuestas de miembros no admin y commit por el admin | FR-025 | Dev | 3 | FR025-01 | Hecho | Un miembro propone y el admin compromete; tests |
| [FR025-10](https://github.com/sedecim-com/nostr/issues/158) | P3 | Parche en el fork de Buzz para los kinds Marmot (solo si DEC-07 lo aprueba) | FR-025, DEC-07 | Dev | 5 | DEC-07, BUZZ-01 | Descartado | El relay acepta 30443/445/10051 sin romper el tratamiento de #h de NIP-29 |

## S7 · Modo institucional (F5, 2027-01-04 → 2027-01-15) — 51 SP

| ID | Prio | Tarea | Requisito | Tipo | SP | Depende de | Estado | Criterio de hecho |
|---|---|---|---|---|---:|---|---|---|
| [FR023-03](https://github.com/sedecim-com/nostr/issues/161) | P0 | Persistencia del policy-engine en Postgres | FR-023 | Dev | 3 | FR023-02 | Pendiente | Sujetos, recursos, dispositivos y auditoría sobreviven reinicios |
| [FR023-04](https://github.com/sedecim-com/nostr/issues/162) | P1 | Sincronizar el allowlist NIP-42 del relay con el policy-engine | FR-023, §16 | Dev | 3 | FR023-03 | Pendiente | Allowlist NIP-42 de Buzz (configuración de la imagen upstream) y del secure-relay actualizado desde /v1/relay/allowlist |
| [FR023-05](https://github.com/sedecim-com/nostr/issues/163) | P1 | Aplicar la política en el indexer y las APIs derivadas | FR-023 | Dev | 3 | FR023-03, FR014-03 | Pendiente | Lecturas filtradas por evaluate(); tests de denegación |
| [FR024-02](https://github.com/sedecim-com/nostr/issues/168) | P1 | Ejecutar la rotación MLS automáticamente al revocar (commit Remove) | FR-024 | Dev | 3 | FR024-01, FR025-01, FR023-03 | Pendiente | La revocación dispara removeMember en los grupos afectados |
| [SEC-04](https://github.com/sedecim-com/nostr/issues/195) | P1 | Pruebas de pérdida de dispositivo de extremo a extremo | §20.3 | QA | 3 | FR024-02 | Pendiente | Revocar → sin sesión → grupos rotados → el dispositivo robado no lee |
| [FR005-06](https://github.com/sedecim-com/nostr/issues/91) | P2 | Rate limiting y alertas de uso anómalo de firma | FR-005 | Seguridad | 2 | FR005-03 | Pendiente | Límites por llave/kind y alerta en auditoría |
| [FR023-06](https://github.com/sedecim-com/nostr/issues/164) | P2 | Directorio organizacional (cargos ↔ npubs) opcional | FR-023, §16 | Dev | 3 | FR023-03 | Pendiente | Mapeo gestionado desde admin-console, sin publicar vínculos |
| [FR023-07](https://github.com/sedecim-com/nostr/issues/165) | P2 | Device trust con passkeys/attestation | §16 | Dev | 5 | FR023-03 | Pendiente | Registro de dispositivos con WebAuthn y nivel attested |
| [FR023-08](https://github.com/sedecim-com/nostr/issues/166) | P2 | Retención por workspace/canal y legal hold donde el modelo lo permita | §16, §12.2 | Dev | 5 | FR023-03 | Pendiente | Políticas configurables y aviso de que borrar no borra copias replicadas |
| [FR024-03](https://github.com/sedecim-com/nostr/issues/169) | P2 | Revocar sesiones NIP-46 y tokens de managed-signer ligados al dispositivo | FR-024 | Dev | 2 | FR024-01, FR005-04 | Pendiente | Tras revocar, el signer rechaza al dispositivo |
| [NFR001-03](https://github.com/sedecim-com/nostr/issues/172) | P2 | Postgres de alta disponibilidad y backups gestionados | NFR-001 | Infra | 3 | NFR001-01 | Pendiente | Failover probado; backups automáticos |
| [OPS-07](https://github.com/sedecim-com/nostr/issues/58) | P2 | App admin-console (organizaciones, políticas, dispositivos, auditoría) | §17.1 | Dev | 8 | FR023-03 | Pendiente | Consola web autenticada por NIP-98 sobre policy-engine e identity-service |
| [FR005-05](https://github.com/sedecim-com/nostr/issues/90) | P3 | Tier enclave: firma dentro de Nitro Enclave con KMS condicionado por attestation | FR-005, §8.4 | Dev | 8 | FR005-02, DEC-09 | Pendiente | Prototipo con attestation verificada; backend general sin llave en claro |

## S8 · Hardening, escalabilidad y release (Release, 2027-01-18 → 2027-01-29) — 32 SP

| ID | Prio | Tarea | Requisito | Tipo | SP | Depende de | Estado | Criterio de hecho |
|---|---|---|---|---|---:|---|---|---|
| [SEC-01](https://github.com/sedecim-com/nostr/issues/192) | P0 | Revisión criptográfica independiente (NIP-44/49/59, MLS, key service) | §20.3 | Seguridad | 8 | SEC-03, FR025-08, FR005-03 | Pendiente | Informe externo sin hallazgos críticos abiertos |
| [SEC-02](https://github.com/sedecim-com/nostr/issues/193) | P0 | Pentest de API, relay, key service y cliente | §20.3 | Seguridad | 8 | OPS-02, FR005-04, FR023-03 | Pendiente | Informe externo; hallazgos críticos y altos corregidos |
| [REL-01](https://github.com/sedecim-com/nostr/issues/196) | P1 | Checklist de Definition of Done automatizado en el pipeline de release | Apéndice D | Infra | 3 | SEC-01, SEC-02, NFR010-02, NFR003-02, FR020-03 | Pendiente | El release se bloquea si falta: tests, interop, restore, leak tests, firma, SBOM |
| [DEC-11](https://github.com/sedecim-com/nostr/issues/198) | P2 | Búsqueda y registro de la marca "Acceso Nostr" | §25.1-1 | Decisión | 1 | DEC-01 | Pendiente | Búsqueda de anterioridades y solicitud de registro presentada, o marca alternativa decidida |
| [NFR010-03](https://github.com/sedecim-com/nostr/issues/191) | P2 | Imágenes Docker reproducibles | NFR-010 | Infra | 3 | OPS-01 | Pendiente | Dos builds del mismo commit producen el mismo digest |
| [REL-02](https://github.com/sedecim-com/nostr/issues/197) | P2 | Release notes con los cambios de trust model por release | Apéndice D | Doc | 1 | REL-01 | Pendiente | Plantilla y primer release notes publicados |
| [NFR005-01](https://github.com/sedecim-com/nostr/issues/179) | P3 | Indexer escalable horizontalmente (reparto por relay y upserts idempotentes) | NFR-005 | Dev | 5 | FR014-01 | Pendiente | N réplicas sin duplicados ni pérdidas; test de concurrencia |
| [NFR005-02](https://github.com/sedecim-com/nostr/issues/180) | P3 | Pruebas de carga del relay y el indexer | NFR-005 | QA | 3 | NFR005-01 | Pendiente | Informe con throughput y límites |

## Diferido · Sin planificar: requiere app nativa (ADR 0004) (—, sin fecha) — 8 SP

| ID | Prio | Tarea | Requisito | Tipo | SP | Depende de | Estado | Criterio de hecho |
|---|---|---|---|---|---:|---|---|---|
| [FR020-02](https://github.com/sedecim-com/nostr/issues/142) | P3 | Cliente desktop dedicado con Tor embebido | FR-020, §25 | Dev | 8 | DEC-04 | Pendiente | App desktop (Tauri) que usa el SDK con Tor integrado y el perfil sovereign-tor |

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
