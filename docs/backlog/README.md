# Backlog — Plataforma Nostr Soberana / SaaS

> Generado por `node scripts/backlog.mjs` desde `backlog.json` (fuente única). No editar a mano.
> Base: Scope_Plataforma_Nostr_Soberana_SaaS_v0.1 (25/09/2026). Estado del código: `main@65ed066` (2026-09-26).

## Resumen

- **161 tareas** · 56 hechas · 25 parciales · 80 pendientes
- **320 story points** pendientes en 8 sprints de 14 días (velocidad supuesta: 50 SP/sprint, equipo de ~4 personas; ajustar tras S1)
- Prioridades: **P0** Bloquea release o seguridad · **P1** Necesario para la fase · **P2** Importante, planificable · **P3** Deseable
- Estados: **Hecho** (con evidencia en el repo) · **Parcial** (existe base, falta completar) · **Pendiente**
- IDs: `FRnnn-xx` / `NFRnnn-xx` por requisito; `DEC`, `BUZZ`, `OPS`, `PANEL`, `SEC`, `REL` para decisiones, fork, operación, panel y gates.

## Plan de sprints

| Sprint | Fechas | Fase | Objetivo | Tareas | SP | P0 |
|---|---|---|---|---:|---:|---:|
| v0.1 | hasta 2026-09-26 | — | Entregado | 50 | 116 | 31 |
| S1 | 2026-09-28 → 2026-10-09 | F0 | Cierre F0 y gate de interoperabilidad | 15 | 27 | 6 |
| S2 | 2026-10-12 → 2026-10-23 | F0.5 | Web SaaS como cliente completo | 18 | 50 | 0 |
| S3 | 2026-10-26 → 2026-11-06 | F1 | Identidad, llaves y custodia | 20 | 48 | 1 |
| S4 | 2026-11-09 → 2026-11-20 | F2 | OSS soberano, sync y operación | 18 | 48 | 0 |
| S5 | 2026-11-23 → 2026-12-04 | F3 | Privacidad, Tor y observabilidad | 12 | 39 | 1 |
| S6 | 2026-12-07 → 2026-12-18 | F4 | Grupos high-security | 8 | 39 | 0 |
| S7 | 2027-01-04 → 2027-01-15 | F5 | Modo institucional | 13 | 51 | 1 |
| S8 | 2027-01-18 → 2027-01-29 | Release | Hardening, escalabilidad y release | 7 | 31 | 2 |

## Cobertura de requisitos

| Requisito | Tareas | Hechas | Pendientes (sprint) |
|---|---:|---:|---|
| FR-001 | 5 | 3 | FR001-04 (S2), FR001-05 (S2) |
| FR-002 | 3 | 2 | FR002-03 (S3) |
| FR-003 | 7 | 2 | FR003-03 (S3), FR003-04 (S3), FR003-05 (S3), FR003-06 (S4), FR003-07 (S4) |
| FR-004 | 5 | 2 | FR004-03 (S3), FR004-04 (S3), FR004-05 (S3) |
| FR-005 | 7 | 1 | FR005-02 (S3), FR005-03 (S3), FR005-04 (S3), FR005-05 (S7), FR005-06 (S7), FR005-07 (S3) |
| FR-006 | 3 | 2 | FR006-02 (S2) |
| FR-007 | 4 | 2 | FR007-03 (S3), FR007-04 (S5) |
| FR-008 | 2 | 1 | FR001-04 (S2) |
| FR-009 | 2 | 1 | FR009-02 (S2) |
| FR-010 | 2 | 1 | FR010-02 (S2) |
| FR-011 | 3 | 1 | FR011-02 (S2), FR011-03 (S5) |
| FR-012 | 1 | 1 | — |
| FR-013 | 4 | 1 | FR013-02 (S4), FR013-03 (S4), FR013-04 (S4) |
| FR-014 | 3 | 2 | FR014-03 (S2) |
| FR-015 | 3 | 1 | FR015-02 (S2), FR015-03 (S2) |
| FR-016 | 1 | 1 | — |
| FR-017 | 5 | 3 | FR017-04 (S2), FR017-05 (S4) |
| FR-018 | 5 | 3 | FR018-04 (S2), FR018-05 (S5) |
| FR-019 | 3 | 1 | FR018-04 (S2), FR019-02 (S3) |
| FR-020 | 3 | 1 | FR020-02 (S5), FR020-03 (S5) |
| FR-021 | 2 | 1 | FR021-02 (S5) |
| FR-022 | 2 | 1 | FR022-02 (S5) |
| FR-023 | 6 | 2 | FR023-03 (S7), FR023-04 (S7), FR023-05 (S7), FR023-06 (S7) |
| FR-024 | 3 | 1 | FR024-02 (S7), FR024-03 (S7) |
| FR-025 | 10 | 3 | FR025-04 (S6), FR025-05 (S6), FR025-06 (S6), FR025-07 (S6), FR025-08 (S6), FR025-09 (S6), FR025-10 (S6) |
| FR-026 | 3 | 2 | FR026-03 (S3) |
| FR-027 | 3 | 1 | FR027-02 (S3), FR027-03 (S4) |
| FR-028 | 3 | 1 | FR028-02 (S3), FR028-03 (S3) |
| NFR-001 | 3 | 0 | NFR001-01 (S4), NFR001-02 (S4), NFR001-03 (S7) |
| NFR-002 | 2 | 1 | NFR002-02 (S4) |
| NFR-003 | 2 | 0 | NFR003-01 (S4), NFR003-02 (S4) |
| NFR-004 | 3 | 0 | FR011-03 (S5), NFR004-01 (S5), NFR004-02 (S5) |
| NFR-005 | 2 | 0 | NFR005-01 (S8), NFR005-02 (S8) |
| NFR-006 | 3 | 2 | NFR006-03 (S4) |
| NFR-007 | 2 | 1 | FR022-02 (S5) |
| NFR-008 | 2 | 1 | NFR008-02 (S4) |
| NFR-009 | 2 | 0 | NFR009-01 (S2), NFR009-02 (S3) |
| NFR-010 | 4 | 1 | FR003-06 (S4), NFR010-02 (S4), NFR010-03 (S8) |

## S1 · Cierre F0 y gate de interoperabilidad (F0, 2026-09-28 → 2026-10-09) — 27 SP

| ID | Prio | Tarea | Requisito | Tipo | SP | Depende de | Estado | Criterio de hecho |
|---|---|---|---|---|---:|---|---|---|
| BUZZ-01 | P0 | Crear repositorio fork con ramas vendor/upstream y product/main | §6.3 | Infra | 1 | DEC-02 | Parcial | Fork creado; vendor/upstream = commit fijado; protección de ramas |
| DEC-01 | P0 | Decidir nombre y licencia del proyecto open source | §25.1-1 | Decisión | 2 | — | Parcial | ADR aprobado; LICENSE y package.json actualizados; compatibilidad con Apache-2.0 del fork revisada |
| DEC-02 | P0 | Fijar subset de Buzz a forkear y commit/release de F0 | §25.1-2 | Decisión | 2 | — | Parcial | Lista de crates/apps incluidos; commit y digest en infra/buzz/PIN aprobados |
| FR014-02 | P0 | Verificar el mirror contra Buzz en el stack Docker completo | FR-014 | QA | 2 | OPS-01 | Hecho | test:interop + indexer contra el relay del compose en CI |
| FR018-03 | P0 | Validar la subida de imágenes en claro a Buzz /media con MinIO | FR-018 | QA | 1 | OPS-01 | Hecho | Informe del gate con plainImage.accepted = true |
| OPS-01 | P0 | CI: construir todas las imágenes y levantar el stack completo con smoke test | §4.1 | Infra | 3 | — | Hecho | Job que hace docker compose up, espera healthchecks y ejecuta test:interop |
| BUZZ-02 | P1 | Revisar obligaciones Apache-2.0 del fork (LICENSE, NOTICE, cambios marcados) | §21.2 | Doc | 1 | BUZZ-01, DEC-01 | Parcial | Checklist legal aprobado y NOTICE en el fork |
| BUZZ-03 | P1 | Build reproducible de la imagen del relay desde el fork | §6.3 | Infra | 3 | BUZZ-01 | Parcial | Imagen construida en CI a partir de product/main con digest publicado |
| DEC-03 | P1 | Definir política de compatibilidad con upstream Buzz | §25.1-3 | Decisión | 1 | DEC-02 | Parcial | Cadencia de sync, criterios de adopción y de rollback documentados |
| DEC-04 | P1 | Elegir biblioteca Nostr base para Rust y Flutter | §25.1-4 | Decisión | 2 | — | Parcial | ADR con evaluación de TS (noble, decidido), Rust (rust-nostr/MDK) y Flutter |
| DEC-06 | P1 | Definir receipt de aplicación y política de read receipts | §25.1-6 | Decisión | 1 | — | Parcial | Formato del rumor (kind definitivo) y opt-in por perfil aprobados; kind provisional 16914 reemplazado |
| DEC-07 | P1 | Ratificar proveedor Marmot y ruta de relay (secure-relay vs parche Buzz) | §25.1-7 | Decisión | 1 | — | Parcial | ADR aprobado; marmot-ts/ts-mls fijados; decisión sobre parche de kinds 30443/445/10051 en el fork |
| DEC-10 | P1 | Formalizar threat models por perfil (convenience, resilient, institutional, sovereign, Tor) | §25.1-10, §20.3 | Seguridad | 3 | — | Hecho | Un documento por perfil con activos, adversarios, mitigaciones y riesgos residuales, versionado por release |
| FR017-03 | P1 | Activar el flag NIP-17 por entorno a partir de interop-report.json en CI | FR-017 | Infra | 2 | FR014-02 | Hecho | El despliegue lee enableFlag y recommendedJitterSeconds del gate |
| OPS-02 | P1 | Proxy TLS (Caddy) y URLs públicas en el compose de producción | §4.1 | Infra | 2 | OPS-01 | Hecho | Override compose.tls.yml con certificados automáticos y RELAY_URL wss:// |

## S2 · Web SaaS como cliente completo (F0.5, 2026-10-12 → 2026-10-23) — 50 SP

| ID | Prio | Tarea | Requisito | Tipo | SP | Depende de | Estado | Criterio de hecho |
|---|---|---|---|---|---:|---|---|---|
| BUZZ-05 | P1 | Pipeline de sync con upstream que ejecuta el gate de interoperabilidad | §6.3 | Infra | 3 | BUZZ-03, OPS-01 | Pendiente | PR automático de upstream que ejecuta test:interop contra la imagen nueva |
| DEC-05 | P1 | Definir storage local cifrado por plataforma | §25.1-5 | Decisión | 2 | — | Parcial | ADR: IndexedDB (web), Keychain/Keystore (móvil), archivo cifrado (desktop/CLI) |
| FR001-05 | P1 | E2E en navegador: la nsec nunca sale del cliente | FR-001 | QA | 2 | FR001-03 | Pendiente | Test que inspecciona todas las peticiones y WebSocket y no encuentra nsec ni la llave en claro |
| FR006-02 | P1 | Selector de persona en la web con banner "Enviando como…" | FR-006, §16.1 | Dev | 3 | FR006-01 | Parcial | Cambiar de persona cambia signer, relays y store; banner siempre visible |
| FR010-02 | P1 | Selección de relays por destinatario (NIP-65 kind 10002 y kind 10050) | FR-010 | Dev | 3 | FR010-01 | Pendiente | Los DMs se publican en los relays de inbox del destinatario |
| FR015-02 | P1 | Descubrimiento de canales (39000) y unión (9021) en la web | FR-015 | Dev | 3 | FR015-01 | Pendiente | Lista de canales visibles y botón de unirse |
| FR015-03 | P1 | E2E de la web contra Buzz real (crear canal, unirse, enviar, leer) | FR-015 | QA | 2 | FR015-02, OPS-01 | Pendiente | Test en navegador contra el relay del compose |
| PANEL-02 | P1 | Aplicar la configuración del panel al comportamiento real del cliente web | §9 | Dev | 5 | PANEL-01 | Pendiente | Red, telemetría, receipts, previews y quorum usan la configuración elegida (hoy solo se muestra) |
| BUZZ-04 | P2 | Branding del fork (desktop Tauri/React) | §22 F0 | Dev | 3 | BUZZ-01, DEC-01 | Pendiente | Nombre, iconos y textos propios sin tocar el protocolo |
| FR001-04 | P2 | Backend IndexedDB para encrypted-store en navegador | FR-001, FR-008 | Dev | 3 | DEC-05 | Pendiente | Stores de llave y outbox sobre IndexedDB con tests en Chromium |
| FR009-02 | P2 | Pasar a RECIPIENT_ACKED/READ con los receipts entrantes | FR-009, §11 | Dev | 3 | DEC-06, FR009-01 | Pendiente | Receipts gift-wrapped recibidos actualizan el estado de la operación |
| FR011-02 | P2 | Lanzar resume() al recuperar conectividad (eventos online / reconexión del pool) | FR-011 | Dev | 2 | FR011-01 | Pendiente | La web y el CLI reanudan solos la outbox al volver la red |
| FR014-03 | P2 | Vistas derivadas: no leídos por canal y búsqueda respetando la política | FR-014, §15.2 | Dev | 3 | FR014-01 | Pendiente | Endpoints de no leídos y búsqueda solo sobre contenido permitido |
| FR017-04 | P2 | Publicar y leer la lista de relays DM (kind 10050) | FR-017 | Dev | 2 | FR010-02 | Pendiente | Onboarding publica 10050; el emisor la usa para enrutar |
| FR018-04 | P2 | Adjuntos en la web (kind 15 en DMs, imágenes en canales) | FR-018, FR-019 | Dev | 5 | FR018-02, FR019-01 | Pendiente | Subida con saneamiento, cifrado opcional y descarga verificada desde la UI |
| NFR009-01 | P2 | Auditoría de accesibilidad automatizada (axe-core) en el E2E de navegador | NFR-009 | QA | 2 | FR015-01 | Parcial | Cero violaciones serias en la web |
| OPS-03 | P2 | Instalador/configurador de llaves y secretos del stack | §4.1 | Infra | 2 | FR003-01 | Parcial | scripts/init-env genera también la llave del relay y del owner con el keygen offline |
| PANEL-03 | P2 | Persistir la configuración del panel por persona | §9 | Dev | 2 | PANEL-02, FR006-02 | Pendiente | Config cifrada en el store de la persona; se restaura al desbloquear |

## S3 · Identidad, llaves y custodia (F1, 2026-10-26 → 2026-11-06) — 48 SP

| ID | Prio | Tarea | Requisito | Tipo | SP | Depende de | Estado | Criterio de hecho |
|---|---|---|---|---|---:|---|---|---|
| FR005-03 | P0 | Persistir el registro de llaves y el log de uso en Postgres | FR-005 | Dev | 3 | FR005-01 | Pendiente | Sobrevive reinicios (hoy el registro vive en memoria y el vault en disco) |
| DEC-09 | P1 | Definir región cloud y requisitos legales de la custodia managed | §25.1-9 | Decisión | 2 | — | Pendiente | Región, marco legal, retención y términos de custodia aprobados por legal |
| FR004-04 | P1 | UI de permisos mínimos visibles al conectar un signer | FR-004, §8.3 | Dev | 2 | FR004-01 | Pendiente | La web lista los métodos y kinds solicitados antes de conectar |
| FR005-04 | P1 | Autorización por usuario final (sesión SaaS firmada), no solo bearer de servicio | FR-005 | Seguridad | 3 | FR005-03 | Pendiente | x-account-id respaldado por token de sesión verificable; tests de suplantación |
| FR005-07 | P1 | Opt-in explícito de custodia managed en el onboarding web | FR-005, §1 | Dev | 2 | FR005-04, PANEL-02 | Pendiente | Confirmación con el disclosure "la plataforma puede firmar"; nunca por defecto |
| FR002-03 | P2 | Importar el backup del key-generator (sedecim-offline-key) en web y CLI | FR-002 | Dev | 2 | FR002-01, FR003-01 | Pendiente | Importar el JSON del generador offline valida npub y crea la persona |
| FR003-03 | P2 | Exportación QR de npub y ncryptsec sin dependencias de red | FR-003 | Dev | 3 | FR003-01 | Pendiente | Codificador QR embebido; test de ida y vuelta |
| FR003-05 | P2 | Versión HTML standalone air-gapped del generador (un solo archivo) | FR-003 | Dev | 3 | FR003-01 | Pendiente | Archivo único que funciona abierto desde disco sin red; CSP estricta |
| FR004-03 | P2 | Flujo nostrconnect:// iniciado por el cliente (QR) | FR-004 | Dev | 3 | FR004-01 | Pendiente | La web muestra un QR nostrconnect y completa la conexión |
| FR005-02 | P2 | Adaptador real de AWS Secrets Manager + KMS | FR-005, §8.4 | Dev | 3 | FR005-01, DEC-09 | Parcial | SecretsManagerVault con el SDK de AWS; tests contra LocalStack |
| FR007-03 | P2 | UI de vínculos con advertencia de desanonimización | FR-007, §25 | Dev | 2 | FR007-02, FR006-02 | Pendiente | Diálogo que explica las consecuencias antes de vincular |
| FR019-02 | P2 | Soporte WebP/HEIC o rechazo según el perfil sensible | FR-019 | Dev | 3 | FR019-01 | Pendiente | Saneamiento o rechazo explícito con requireSanitizable |
| FR026-03 | P2 | UI de migración de custodia en la web con verificación | FR-026 | Dev | 3 | FR026-01, FR005-04 | Pendiente | Asistente paso a paso con verificación de posesión y confirmación del borrado |
| FR027-02 | P2 | Incluir en el backup la configuración completa (relays, panel, grupos MLS) | FR-027 | Dev | 3 | FR027-01, PANEL-03 | Parcial | La restauración recupera relays, perfil y estado MLS cifrado |
| FR028-02 | P2 | Revisión legal/UX de los textos de disclosure | FR-028 | Doc | 2 | FR028-01, DEC-09 | Pendiente | Textos aprobados por legal y UX; versionados |
| NFR009-02 | P2 | Corregir los hallazgos de accesibilidad y revisión manual con lector de pantalla | NFR-009 | Dev | 3 | NFR009-01 | Pendiente | Informe de la revisión y correcciones aplicadas |
| FR003-04 | P3 | Plantilla imprimible del backup (HTML local, sin CDN) | FR-003 | Dev | 2 | FR003-03 | Pendiente | Hoja con npub, QR y ncryptsec; sin recursos remotos |
| FR004-05 | P3 | Soporte de auth_url del signer remoto | FR-004 | Dev | 1 | FR004-01 | Pendiente | La UI abre auth_url y espera la respuesta real |
| FR028-03 | P3 | Lint en CI que prohíbe afirmaciones absolutas en toda la UI | FR-028, §2.2 | QA | 1 | FR028-01 | Parcial | assertNoAbsoluteClaims aplicado a todo el copy de la web |
| PANEL-04 | P3 | Indicadores visuales por dimensión respaldados por declaraciones verificables | §9.1 | Dev | 2 | PANEL-02 | Parcial | Cada indicador enlaza a sus disclosures; sin score único |

## S4 · OSS soberano, sync y operación (F2, 2026-11-09 → 2026-11-20) — 48 SP

| ID | Prio | Tarea | Requisito | Tipo | SP | Depende de | Estado | Criterio de hecho |
|---|---|---|---|---|---:|---|---|---|
| FR003-06 | P1 | Firma de las releases del generador | FR-003, NFR-010 | Seguridad | 2 | FR003-02, NFR010-02 | Pendiente | Firma y verificación documentadas (minisign/cosign) |
| FR013-03 | P1 | E2E: reinstalar y reconstruir historial (canales, DMs, outbox) en un dispositivo limpio | FR-013 | QA | 3 | FR013-01, FR027-01 | Pendiente | Tras restaurar el backup, el cliente recupera historia y estados |
| NFR001-01 | P1 | Infraestructura como código del SaaS (Helm/Terraform) | NFR-001 | Infra | 8 | OPS-02 | Pendiente | Despliegue reproducible en un entorno de staging |
| NFR001-02 | P1 | Monitorización de SLO (99,9 % mensual) y alertas | NFR-001 | Infra | 3 | NFR001-01 | Pendiente | Dashboard de disponibilidad y alertas por servicio |
| NFR003-01 | P1 | Definir RPO/RTO por tier | NFR-003 | Doc | 1 | DEC-09 | Pendiente | Tabla aprobada por tier (self-hosted, SaaS, institucional) |
| NFR003-02 | P1 | Restore drill automatizado (nightly) | NFR-003 | Infra | 5 | NFR003-01, OPS-01 | Parcial | Job que restaura en un host limpio y ejecuta test:interop |
| NFR010-02 | P1 | Firma de releases y provenance (SLSA/cosign) | NFR-010, §21.2 | Seguridad | 3 | OPS-08 | Pendiente | Imágenes y artefactos firmados; verificación documentada |
| SEC-03 | P1 | Fuzz/property tests de serialización y criptografía | §20.3 | Seguridad | 3 | — | Parcial | fast-check sobre eventos, NIP-44, NIP-49, codec MLS y parsers de TLV |
| FR003-07 | P2 | Guía de uso air-gapped verificable | FR-003 | Doc | 1 | FR003-06 | Pendiente | Procedimiento paso a paso: verificar checksum y firma, generar, verificar backup |
| FR013-02 | P2 | Cliente NIP-77 (Negentropy) con detección y fallback | FR-013, §12.1 | Dev | 5 | FR013-01 | Parcial | Reconciliación con un relay NIP-77; fallback automático si no lo soporta |
| FR013-04 | P2 | Sync de gift wraps con timestamps aleatorios (ventana ampliada) | FR-013 | QA | 1 | FR013-01 | Parcial | Test con wraps de hasta 2 días de antigüedad; ningún mensaje perdido |
| FR027-03 | P2 | Vault de backup en la nube: solo ciphertext con clave del usuario | FR-027, §12 | Dev | 3 | FR027-02 | Pendiente | Subida/descarga del backup cifrado; el operador nunca ve la clave |
| NFR002-02 | P2 | Test de crash con kill -9 durante la escritura | NFR-002 | QA | 2 | NFR002-01 | Pendiente | Proceso matado a mitad de escritura; el store sigue consistente |
| NFR006-03 | P2 | Test de integración que analiza los logs de los servicios en busca de secretos | NFR-006 | QA | 2 | OPS-01 | Pendiente | Stack completo en CI; los logs se escanean con las reglas de gitleaks |
| NFR008-02 | P2 | Exportar el historial completo (JSONL de eventos firmados) | NFR-008 | Dev | 2 | FR013-01 | Pendiente | Export/import de eventos canónicos entre clientes |
| OPS-08 | P2 | Separación de funciones en releases (quién construye vs quién publica) | §21.2 | Infra | 1 | — | Pendiente | Entorno de release protegido con aprobadores distintos al autor |
| OPS-09 | P2 | Documentación de build desde source | §21.2 | Doc | 2 | — | Parcial | Guía reproducible para todos los artefactos (servicios, web, keygen) |
| FR017-05 | P3 | Seguir el issue upstream #4192 y retirar el adaptador cuando se corrija | FR-017, §25 | QA | 1 | BUZZ-05 | Pendiente | Re-ejecutar el gate en cada sync; volver al jitter estándar si pasa |

## S5 · Privacidad, Tor y observabilidad (F3, 2026-11-23 → 2026-12-04) — 39 SP

| ID | Prio | Tarea | Requisito | Tipo | SP | Depende de | Estado | Criterio de hecho |
|---|---|---|---|---|---:|---|---|---|
| FR020-03 | P0 | Tests de fugas con captura de red real (netns/pcap): DNS, IPv6, conexiones directas | FR-020, §20.3 | Seguridad | 5 | FR020-02 | Parcial | Suite que prueba cero tráfico fuera de Tor con el cliente real |
| FR020-02 | P1 | Cliente desktop dedicado con Tor embebido | FR-020, §25 | Dev | 8 | DEC-04 | Pendiente | App desktop (Tauri) que usa el SDK con Tor integrado y el perfil sovereign-tor |
| FR021-02 | P1 | Validar el perfil tor del compose (onion services de relay y secure-relay) | FR-021 | QA | 2 | OPS-01 | Pendiente | Arranque real y conexión del CLI a las direcciones .onion generadas |
| FR022-02 | P1 | Test en CI de endpoints de salida permitidos por perfil | FR-022, NFR-007 | QA | 3 | FR020-03 | Parcial | Allowlist de egress por perfil verificada con el cliente real |
| SEC-05 | P1 | Tests de fugas por WebRTC y previews remotas en web/desktop | §20.3 | Seguridad | 2 | FR020-02 | Pendiente | Sin candidatos ICE ni peticiones de previews en perfiles sensibles |
| DEC-08 | P2 | Definir modelo de notificaciones móviles por perfil | §25.1-8 | Decisión | 2 | — | Pendiente | Matriz perfil × (push, privacy-push, none) con metadatos expuestos |
| NFR004-01 | P2 | Exportar métricas (latencia P95 de ACK por relay y región) | NFR-004 | Dev | 3 | — | Parcial | Exportador Prometheus respetando el perfil de telemetría |
| OPS-06 | P2 | Servicio notification-gateway con perfiles de privacidad | §17.1 | Dev | 5 | DEC-08 | Pendiente | Push opaco sin contenido ni remitente; deshabilitado en perfiles Tor |
| FR007-04 | P3 | Publicar opcionalmente un vínculo público como evento Nostr firmado | FR-007 | Dev | 3 | FR007-02 | Pendiente | Formato definido, firmado por ambas personas y verificable |
| FR011-03 | P3 | Métricas de outbox (profundidad, antigüedad, fallos por relay) | FR-011, NFR-004 | Dev | 2 | FR011-01, NFR004-01 | Pendiente | Expuestas al exportador de métricas respetando el perfil |
| FR018-05 | P3 | Lista de servidores Blossom del usuario (kind 10063) | FR-018 | Dev | 2 | FR018-01 | Pendiente | El cliente publica y respeta la lista de servidores |
| NFR004-02 | P3 | Dashboard de latencia y degradación sin ocultarla | NFR-004 | Infra | 2 | NFR004-01, NFR001-02 | Pendiente | Panel P95/P99 por relay con alertas de degradación |

## S6 · Grupos high-security (F4, 2026-12-07 → 2026-12-18) — 39 SP

| ID | Prio | Tarea | Requisito | Tipo | SP | Depende de | Estado | Criterio de hecho |
|---|---|---|---|---|---:|---|---|---|
| FR025-04 | P1 | Interoperabilidad verificada con MDK/whitenoise | FR-025 | QA | 5 | DEC-07 | Pendiente | Grupo mixto marmot-ts ↔ MDK con mensajes en ambos sentidos |
| FR025-05 | P2 | MIP-04: media cifrada en grupos | FR-025, §13 | Dev | 5 | FR025-01, FR018-02 | Pendiente | Subida y descarga de media con claves derivadas del exporter MLS |
| FR025-06 | P2 | Multi-dispositivo: varios key packages por persona y sincronización del estado | FR-025 | Dev | 5 | FR025-01 | Pendiente | Un usuario con 2 dispositivos participa en el mismo grupo |
| FR025-07 | P2 | UI de grupos high-security en la web | FR-025 | Dev | 5 | FR025-06, FR001-04 | Pendiente | Crear, invitar, chatear y expulsar desde la web con estado cifrado |
| FR025-08 | P2 | Migrar a marmot-ts v2 / ts-mls estable cuando se publiquen | FR-025 | Dev | 3 | FR025-04 | Pendiente | Dependencias fijadas a versiones estables; conformidad y autoprueba en verde |
| BUZZ-06 | P3 | Integración progresiva del cliente móvil Flutter de Buzz | §6.1 | Dev | 8 | BUZZ-03, DEC-04 | Pendiente | Mobile compila contra el relay del fork y pasa smoke test NIP-29 |
| FR025-09 | P3 | Flujo de propuestas de miembros no admin y commit por el admin | FR-025 | Dev | 3 | FR025-01 | Pendiente | Un miembro propone y el admin compromete; tests |
| FR025-10 | P3 | Parche en el fork de Buzz para los kinds Marmot (solo si DEC-07 lo aprueba) | FR-025, DEC-07 | Dev | 5 | DEC-07, BUZZ-01 | Pendiente | El relay acepta 30443/445/10051 sin romper el tratamiento de #h de NIP-29 |

## S7 · Modo institucional (F5, 2027-01-04 → 2027-01-15) — 51 SP

| ID | Prio | Tarea | Requisito | Tipo | SP | Depende de | Estado | Criterio de hecho |
|---|---|---|---|---|---:|---|---|---|
| FR023-03 | P0 | Persistencia del policy-engine en Postgres | FR-023 | Dev | 3 | FR023-02 | Pendiente | Sujetos, recursos, dispositivos y auditoría sobreviven reinicios |
| FR023-04 | P1 | Sincronizar el allowlist NIP-42 del relay con el policy-engine | FR-023, §16 | Dev | 3 | FR023-03, BUZZ-03 | Pendiente | pubkey_allowlist de Buzz / secure-relay actualizado desde /v1/relay/allowlist |
| FR023-05 | P1 | Aplicar la política en el indexer y las APIs derivadas | FR-023 | Dev | 3 | FR023-03, FR014-03 | Pendiente | Lecturas filtradas por evaluate(); tests de denegación |
| FR024-02 | P1 | Ejecutar la rotación MLS automáticamente al revocar (commit Remove) | FR-024 | Dev | 3 | FR024-01, FR025-01, FR023-03 | Pendiente | La revocación dispara removeMember en los grupos afectados |
| SEC-04 | P1 | Pruebas de pérdida de dispositivo de extremo a extremo | §20.3 | QA | 3 | FR024-02 | Pendiente | Revocar → sin sesión → grupos rotados → el dispositivo robado no lee |
| FR005-06 | P2 | Rate limiting y alertas de uso anómalo de firma | FR-005 | Seguridad | 2 | FR005-03 | Pendiente | Límites por llave/kind y alerta en auditoría |
| FR023-06 | P2 | Directorio organizacional (cargos ↔ npubs) opcional | FR-023, §16 | Dev | 3 | FR023-03 | Pendiente | Mapeo gestionado desde admin-console, sin publicar vínculos |
| FR023-07 | P2 | Device trust con passkeys/attestation | §16 | Dev | 5 | FR023-03 | Pendiente | Registro de dispositivos con WebAuthn y nivel attested |
| FR023-08 | P2 | Retención por workspace/canal y legal hold donde el modelo lo permita | §16, §12.2 | Dev | 5 | FR023-03 | Pendiente | Políticas configurables y aviso de que borrar no borra copias replicadas |
| FR024-03 | P2 | Revocar sesiones NIP-46 y tokens de managed-signer ligados al dispositivo | FR-024 | Dev | 2 | FR024-01, FR005-04 | Pendiente | Tras revocar, el signer rechaza al dispositivo |
| NFR001-03 | P2 | Postgres de alta disponibilidad y backups gestionados | NFR-001 | Infra | 3 | NFR001-01 | Pendiente | Failover probado; backups automáticos |
| OPS-07 | P2 | App admin-console (organizaciones, políticas, dispositivos, auditoría) | §17.1 | Dev | 8 | FR023-03 | Pendiente | Consola web autenticada por NIP-98 sobre policy-engine e identity-service |
| FR005-05 | P3 | Tier enclave: firma dentro de Nitro Enclave con KMS condicionado por attestation | FR-005, §8.4 | Dev | 8 | FR005-02, DEC-09 | Pendiente | Prototipo con attestation verificada; backend general sin llave en claro |

## S8 · Hardening, escalabilidad y release (Release, 2027-01-18 → 2027-01-29) — 31 SP

| ID | Prio | Tarea | Requisito | Tipo | SP | Depende de | Estado | Criterio de hecho |
|---|---|---|---|---|---:|---|---|---|
| SEC-01 | P0 | Revisión criptográfica independiente (NIP-44/49/59, MLS, key service) | §20.3 | Seguridad | 8 | SEC-03, FR025-08, FR005-03 | Pendiente | Informe externo sin hallazgos críticos abiertos |
| SEC-02 | P0 | Pentest de API, relay, key service y cliente | §20.3 | Seguridad | 8 | OPS-02, FR005-04, FR023-03 | Pendiente | Informe externo; hallazgos críticos y altos corregidos |
| REL-01 | P1 | Checklist de Definition of Done automatizado en el pipeline de release | Apéndice D | Infra | 3 | SEC-01, SEC-02, NFR010-02, NFR003-02, FR020-03 | Pendiente | El release se bloquea si falta: tests, interop, restore, leak tests, firma, SBOM |
| NFR010-03 | P2 | Imágenes Docker reproducibles | NFR-010 | Infra | 3 | OPS-01 | Pendiente | Dos builds del mismo commit producen el mismo digest |
| REL-02 | P2 | Release notes con los cambios de trust model por release | Apéndice D | Doc | 1 | REL-01 | Pendiente | Plantilla y primer release notes publicados |
| NFR005-01 | P3 | Indexer escalable horizontalmente (reparto por relay y upserts idempotentes) | NFR-005 | Dev | 5 | FR014-01 | Pendiente | N réplicas sin duplicados ni pérdidas; test de concurrencia |
| NFR005-02 | P3 | Pruebas de carga del relay y el indexer | NFR-005 | QA | 3 | NFR005-01 | Pendiente | Informe con throughput y límites |

## Entregado en v0.1 — 50 tareas

| ID | Tarea | Requisito | Evidencia |
|---|---|---|---|
| OPS-04 | SECURITY.md y proceso de disclosure | §21.2 | `SECURITY.md` |
| OPS-05 | Dependabot/Renovate con revisión | §21.2 | `.github/dependabot.yml` |
| PANEL-01 | Modelo de configuración del panel, presets del Apéndice B y validación | §9 | `packages/profiles` |
| FR001-01 | Generar llave con CSPRNG y self-test de derivación + firma BIP-340 | FR-001 | `packages/nostr-core/src/keys.ts` |
| FR001-02 | Crear persona local con llave cifrada NIP-49 en su store | FR-001 | `packages/identity` |
| FR001-03 | Flujo "crear llave local" en la web SaaS | FR-001 | `apps/web-saas/src/session.ts` |
| FR002-01 | Importar nsec/ncryptsec validando la correspondencia pubkey/secret | FR-002 | `packages/identity/test` |
| FR002-02 | Registrar persona con signer externo (bunker) o managed | FR-002 | `packages/identity` |
| FR003-01 | Generador CLI offline con todas las primitivas de red bloqueadas | FR-003 | `apps/key-generator` |
| FR003-02 | Bundle reproducible con checksum SHA-256 | FR-003 | `apps/key-generator/build.mjs` |
| FR004-01 | Cliente NIP-46 (Nip46Signer) sin almacenar la nsec | FR-004 | `packages/signer/src/nip46.ts` |
| FR004-02 | Bunker NIP-46 con permisos por kind y auditoría de peticiones | FR-004 | `packages/signer/test` |
| FR005-01 | Servicio managed-signer con vault envelope y logs sin secretos | FR-005 | `services/managed-signer` |
| FR006-01 | Gestión de ≥3 personas con stores, relays y signer independientes | FR-006 | `packages/identity` |
| FR006-03 | Aislamiento de circuitos Tor por persona | FR-006, §14.1 | `packages/tor-network` |
| FR007-01 | Vínculos entre personas con confirmación explícita y auditoría | FR-007 | `packages/identity` |
| FR007-02 | API del identity-service con visibilidad private/selective/public | FR-007 | `services/identity-service` |
| FR026-01 | Migración managed → local con prueba de posesión y política de retención | FR-026 | `services/managed-signer/test` |
| FR026-02 | Migración local → managed (importación explícita) | FR-026 | `services/managed-signer/src/api.ts` |
| FR027-01 | Backup cifrado que restaura la identidad en un dispositivo limpio | FR-027 | `packages/identity/test` |
| FR028-01 | Disclosures por opción con consecuencias y supuestos de confianza | FR-028 | `packages/profiles` |
| FR008-01 | Persistir el evento firmado en la outbox local antes de transmitir | FR-008 | `packages/delivery-engine` |
| FR009-01 | Ledger por relay: intento, hora, resultado, OK, latencia y último error | FR-009 | `packages/delivery-engine` |
| FR010-01 | Publicación a N relays con quorum configurable | FR-010 | `packages/delivery-engine` |
| FR011-01 | Reintentos con backoff + jitter reutilizando el mismo event id | FR-011 | `packages/delivery-engine` |
| FR012-01 | Deduplicar por event_id entre relays en cliente e indexer | FR-012 | `packages/relay-pool, services/indexer` |
| FR013-01 | Sync de respaldo por ventanas de tiempo con paginación | FR-013 | `packages/sync` |
| FR014-01 | Indexer/mirror ciphertext-first sin APIs propietarias de Buzz | FR-014 | `services/indexer` |
| FR015-01 | La web publica eventos que ven otros clientes del mismo relay | FR-015 | `tests/browser/web-saas.e2e.ts` |
| FR016-01 | NIP-42 challenge/response con auth-required recuperable | FR-016 | `packages/relay-pool` |
| FR017-01 | NIP-17 (NIP-44 + NIP-59) detrás de un feature flag | FR-017 | `packages/messaging` |
| FR017-02 | Adaptador explícito de jitter para Buzz, derivado del gate | FR-017 | `packages/messaging/src/adapters.ts` |
| FR018-01 | Cliente Blossom: subir, referenciar, descargar y verificar el hash | FR-018 | `packages/blossom-client` |
| FR018-02 | blob-store agnóstico al contenido para adjuntos cifrados | FR-018, §13 | `services/blob-store` |
| FR019-01 | Quitar EXIF/XMP/IPTC en JPEG y chunks de texto/tiempo en PNG | FR-019 | `packages/blossom-client/src/sanitize.ts` |
| FR020-01 | NetworkGuard Tor-only que falla cerrado, sin fallback clearnet | FR-020 | `packages/tor-network` |
| FR021-01 | Conexión a relays .onion vía SOCKS5h con aislamiento por persona | FR-021 | `apps/sovereign-client/test` |
| FR022-01 | TelemetryPolicy: nivel none bloquea analytics y crash reports | FR-022 | `packages/telemetry-policy` |
| FR025-01 | GroupCryptoProvider sobre marmot-ts con estado MLS cifrado | FR-025 | `packages/marmot-adapter` |
| FR025-02 | Mitigar ts-mls rc.10 (UpdatePath en un Remove) + autoprueba que falla cerrado | FR-025 | `docs/marmot.md` |
| FR025-03 | Comandos de grupo en el cliente soberano (también vía Tor) | FR-025 | `apps/sovereign-client` |
| FR023-01 | Evaluador RBAC/ABAC + device trust, deny por defecto | FR-023 | `packages/policy-client` |
| FR023-02 | API del policy-engine (sujetos, recursos, dispositivos, evaluate) | FR-023 | `services/policy-engine` |
| FR024-01 | Revocar dispositivo: bloquea sesiones y señala rotación de grupos | FR-024 | `services/policy-engine/test` |
| NFR002-01 | Cero eventos LOCAL_PERSISTED perdidos tras un reinicio controlado | NFR-002 | `packages/delivery-engine/test` |
| NFR006-01 | Escaneo de secretos que bloquea CI | NFR-006 | `.github/workflows/ci.yml` |
| NFR006-02 | Redacción de secretos en logs de todos los servicios | NFR-006 | `packages/telemetry-policy` |
| NFR007-01 | Telemetría gobernada por el perfil | NFR-007 | `packages/telemetry-policy` |
| NFR008-01 | Exportar identidad y configuración en formato abierto | NFR-008 | `packages/identity` |
| NFR010-01 | SBOM por release | NFR-010 | `.github/workflows/ci.yml` |
