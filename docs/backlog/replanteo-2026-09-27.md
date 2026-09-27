# Replanteo de sprints desde el corte del 27 de septiembre de 2026

> Propuesta. Base: `main@5f39e73` y los issues del backlog en GitHub a 2026-09-27, contrastados con *Scope_Plataforma_Nostr_Soberana_SaaS_v0.1* (25/09/2026).
> Este documento no sustituye a `README.md`, `backlog.json` ni `backlog.csv`, que se generan desde GitHub Issues: la sección *Cómo se aplica* explica cómo llevarlo a los issues.

## Resumen

- El plan original S1–S8 (28/09/2026 → 29/01/2027) ya está casi entero en el repositorio: 136 de 158 tareas activas hechas y 80 SP abiertos en 20 parciales y 2 pendientes.
- La revisión confirma 125 de las 136 tareas hechas. Encuentra 9 sobredeclaradas, 2 en riesgo por un defecto de integración (G1), 6 defectos nuevos y 13 brechas del scope que no tenían tarea.
- El replanteo abre **S9–S16 en el mismo calendario** (hasta la GA el 29/01/2027) con 99 tareas: 22 abiertas, 2 reabiertas y 75 nuevas (342 SP). Otras 4 tareas opcionales quedan para después de v1.0 (15 SP).
- El camino crítico es externo: auditor y pentester, asesoría legal, credenciales de AWS y un segundo aprobador de releases. Todo se arranca en S9.

## Resultado de la revisión

| Resultado | Tareas |
|---|---:|
| Hechas y confirmadas | 125 |
| Hechas pero sobredeclaradas | 9 |
| Hechas pero en riesgo (G1) | 2 |
| Parciales o pendientes, bien marcadas | 22 |
| Descartadas con ADR | 6 |
| **Total** | **164** |

Evidencia objetiva del corte: `npm run typecheck` en verde; `vitest run` con 79 archivos en verde, 524 pruebas en verde y 25 omitidas (las suites de interoperabilidad necesitan el stack real y corren en el job `stack` de CI); `npm run lint:claims` y `node scripts/backlog.mjs --check` en verde; CI, CodeQL y reproducible-images en verde en `main@5f39e73`; ningún tag ni release publicado.

### Defectos nuevos

| ID | Prio | Qué pasa | Cómo se verificó | Tarea |
|---|---|---|---|---|
| G1 | P0 | Las invitaciones a grupos seguros no llegan con el secure relay real | Confirmado en el código de nostr-rs-relay 0.9.0 (filtra los kind 1059 sin AUTH y no avisa) y del relay-pool (solo se autentica si el relay lo pide). Las pruebas contra ese relay usan AUTH inmediato; el E2E de la web usa el relay de pruebas | FR025-11 |
| B1 | P0 | Editar una persona revocada en la consola la reactiva | Reproducido: el PUT de sujeto escribe suspended=false | FR023-09 |
| B2 | P0 | El propagador de revocaciones pierde eventos | Reproducido: lee solo las últimas 100 entradas de auditoría y cada evaluate() escribe una | FR024-04 |
| D1 | P1 | Un DM escrito sin red queda enrutado para siempre a los relays del emisor | Reproducido: se cachea 5 minutos un descubrimiento vacío y la ruta se fija al componer | FR010-03 |
| D2 | P1 | El cliente soberano no reintenta lo pendiente entre invocaciones | Reproducido: solo `sovereign resume` lo publica | FR011-04 |
| D3 | P1 | Un HEIC con GPS adjunto a un DM conserva la ubicación | Reproducido: los DMs no exigen archivo saneable aunque stripFileMetadata esté activo | FR019-03 |

### Sobredeclaradas y en riesgo

- **FR024-03** (sobredeclarada): Revocar no propaga (B2) y la web no usa sesiones de dispositivo.
- **FR011-02** (sobredeclarada): La web reanuda la outbox al volver la red; el CLI no (D2).
- **FR011-03** (sobredeclarada): Las métricas de outbox no salen de ningún proceso desplegado; su alerta no puede dispararse.
- **FR019-02** (sobredeclarada): HEIC con metadatos pasa en DMs (D3).
- **PANEL-02** (sobredeclarada): Con perfil Tor-only la web bloquea el envío pero lee relays y publica 10050 por clearnet.
- **FR006-03** (sobredeclarada): El aislamiento de circuitos por persona existe en código pero ningún test lo ejercita.
- **NFR006-03** (sobredeclarada): El escaneo de logs no incluye los perfiles managed, push, institutional ni tor.
- **OPS-05** (sobredeclarada): Dependabot no cubre infra/tor ni las imágenes por tag del compose, y la revisión no es obligatoria.
- **DEC-10** (sobredeclarada): Los threat models siguen en «Propuesto»: nadie los aprobó ni se ligan a un release.
- **FR025-03** (en riesgo): Grupos en el cliente soberano: pasan contra el relay de pruebas, no contra el secure relay real (G1).
- **FR025-07** (en riesgo): Grupos en la web: mismo caso (G1).

### Hechas solo en librería o CLI

- Vínculos entre personas: la librería los soporta, pero no se pueden listar ni retirar (FR007-01/02/03).
- Backup completo con relays, panel y MLS: solo en el CLI; la web exporta solo la llave (FR027-02, FR013-03).
- No leídos y búsqueda del mirror: API sin interfaz; la web lee directo de los relays (FR014-03, FR023-05).
- Worker de rotaciones: CLI manual, sin servicio desplegado (FR024-02).
- Device trust: registro de passkeys sin uso posterior en sesiones (FR023-07).
- Multi-dispositivo, propuestas, rotación y media en grupos: solo en el CLI (FR025-05/06/09).

### Brechas del scope sin tarea previa

| Tema | Qué falta | Tarea nueva |
|---|---|---|
| Perfiles de usuario | No hay kind 0 (nombre, avatar) en ningún cliente (§7). | FR006-04 |
| Colaboración en canales | Sin reacciones, hilos, borrado ni presencia; los DMs no llegan en tiempo real (§15.1). | FR015-04, FR009-03, FR015-05 |
| Retención y expiración | Sin NIP-40 ni borrado por el usuario; el aviso de copias solo existe en la consola (§12.2). | PANEL-06 |
| Compartimentación | Sin aviso al reutilizar archivos o contactos entre personas en la web (§14.1). | FR006-07 |
| Nivel de vínculo visible | «Enviando como…» no muestra el nivel de vínculo (§16.1). | FR007-05 |
| Publicar por recurso | Ningún punto de control evalúa la acción «publicar»; los relays solo filtran por pubkey (FR-023). | FR023-10 |
| Salida de la custodia | No se puede cancelar sin migrar (ARCO) ni salir del tier enclave (§8.5 paso 8). | FR026-04, FR005-09 |
| SaaS comercial | Sin organizaciones, planes, facturación ni webhooks (§15.2). | DEC-14, OPS-15, OPS-16 |
| Observabilidad | Tracing y crash reports prometidos en presets y textos, sin implementación (§18). | NFR007-02, NFR007-03 |
| SDK y APIs | Paquetes privados sin documentación ni OpenAPI (§17, §26). | OPS-14 |
| Disponibilidad | Solo existe stage, con servicios de una réplica: el 99,9 % no es alcanzable (NFR-001). | NFR001-04 |
| Clientes nativos | Sin app de escritorio ni móvil; Buzz Desktop/Mobile no se han probado contra el relay (§2.1, §25). | DEC-13, FR020-02, APP-01…07 |
| Vectores de prueba | Faltan los vectores oficiales de NIP-44 y los exportables que prometía el ADR 0004. | SEC-07 |

### Documentación desfasada (OPS-11)

- README: «persistencia en memoria» del policy-engine, lista de pendientes ya hechos y estructura sin admin-console.
- Notas de v0.1.0: versiones de @noble equivocadas, policy-engine «en memoria» y waiver «aprobado» (está pendiente).
- architecture.md, ADR 0002, ADR 0006, ADR 0009, buzz-integration.md y threat-model.md citan pines, versiones o estados viejos.
- disclose.ts afirma «Implementación Marmot fijada y auditada» y promete crash reports que no existen.
- El backlog declara como base main@65ed066; el código va en 5f39e73.

### Gobierno del repositorio (OPS-12, OPS-13, SEC-06)

- main no está protegida: una actualización mayor de vite se fusionó sin revisión.
- dependency-review falla en todas las PR porque el Dependency graph está apagado; CodeQL no bloquea.
- Todas las aprobaciones (ADR, RPO/RTO, waiver) las firma la misma persona.
- La PR #216 (anti-replay NIP-98 y límites de tasa) está abierta con CodeQL y dependency-review en rojo.

## Plan de sprints

| Sprint | Fechas | Objetivo | Release | Tareas | SP equipo | SP con dependencia externa |
|---|---|---|---|---:|---:|---:|
| S9 | 2026-09-28 → 2026-10-09 | v0.1.0 firmada y frentes externos abiertos | v0.1.0 | 25 | 42 | 8 |
| S10 | 2026-10-12 → 2026-10-23 | SaaS beta en staging y web completa | v0.2.0 | 20 | 42 | 19 |
| S11 | 2026-10-26 → 2026-11-06 | Auditorías en campo, custodia e institucional a fondo | — | 15 | 50 | 8 |
| S12 | 2026-11-09 → 2026-11-20 | Informes externos, remediación, legal y producción | v0.3.0 | 18 | 46 | 20 |
| S13 | 2026-11-23 → 2026-12-04 | Escritorio soberano con Tor y cierre del pentest | v0.4.0 | 7 | 34 | 8 |
| S14 | 2026-12-07 → 2026-12-18 | Organizaciones, webhooks y núcleo móvil | — | 5 | 26 | 5 |
| S15 | 2027-01-04 → 2027-01-15 | App móvil beta | v0.5.0 | 7 | 21 | 9 |
| S16 | 2027-01-18 → 2027-01-29 | GA v1.0 | v1.0.0 | 2 | 1 | 3 |
| Diferido | sin fecha | Después de v1.0 (opcional en el scope) | — | 4 | 15 | 0 |

Capacidad nominal del backlog: 50 SP por sprint. S14–S16 dejan holgura para la remediación de las auditorías y la incertidumbre del móvil. Del 21/12/2026 al 01/01/2027 no hay sprint.

## Releases

| Release | Fecha | Nombre | Qué trae | Depende de |
|---|---|---|---|---|
| v0.1.0 | 2026-10-09 | Early release firmada | Descargar una versión firmada con cosign y provenance SLSA, y verificarla con un solo comando; usar el generador de llaves offline firmado siguiendo la guía air-gapped; instalar el stack self-hosted con imágenes reproducibles bit a bit; contar con los defectos B1, B2 y D1–D3 corregidos | Segunda persona que apruebe el waiver y los entornos; entorno release en GitHub |
| v0.2.0 | 2026-10-23 | SaaS beta en staging | Entrar a la web SaaS con tu cuenta de Acceso; ver nombres y avatares, no leídos y búsqueda; reaccionar, responder en hilo y borrar en canales; recibir DMs y acuses en tiempo real, y avisos push que funcionan con los relays de referencia; instalar la web en el móvil (PWA) | Credenciales de AWS y terraform apply en infrastructure |
| v0.3.0 | 2026-11-20 | Con auditoría externa | Usar una versión con informe externo de criptografía y pentest; aceptar la custodia gestionada con términos aprobados, y salir de ella cuando quieras; firmar en Nitro Enclave con attestation real; publicar en recursos protegidos solo con el rol adecuado; integrar con el SDK y las APIs documentadas | Auditor y pentester contratados en S9; aprobación legal |
| v0.4.0 | 2026-12-04 | Soberano de escritorio | Usar una app de escritorio con Tor embebido que nunca sale por clearnet; operar con pruebas de fugas sobre la propia app y binarios firmados; gestionar organizaciones y planes en el SaaS, e integrarlo por webhooks | DEC-13 aprobado; retest del pentest |
| v0.5.0 | 2027-01-15 | Móvil beta | Usar la app móvil con personas, canales, DMs y grupos seguros; recibir push nativo según tu perfil de privacidad; probar la beta en TestFlight o Google Play | DEC-13 (apps propias); cuentas de desarrollador; ts-mls estable o excepción |
| v1.0.0 | 2027-01-29 | Disponibilidad general | Usar el SaaS en producción con alta disponibilidad (objetivo 99,9 %); verificar un release sin waiver, con informes externos y threat models aprobados; usar el perfil de alto riesgo, solo si la auditoría de fugas lo avala | Todo lo anterior |

## S9 · v0.1.0 firmada y frentes externos abiertos (2026-09-28 → 2026-10-09)

| ID | Cambio | Prio | Tarea | Tipo | SP | Depende de | Criterio de hecho | Quién desbloquea |
|---|---|---|---|---|---:|---|---|---|
| OPS-12 | Nueva | P0 | Gobierno del repositorio: proteger main, activar Dependency graph y private vulnerability reporting, nombrar un segundo mantenedor | Infra | 1 | — | main exige 1 aprobación y los checks de CI; dependency-review en verde en una PR; una segunda persona puede aprobar PRs y entornos | Admin del repo y owner de la organización |
| OPS-08 | Existente | P2 | Separación de funciones en releases (quién construye vs quién publica) | Infra | 1 | OPS-12 | Entorno release con aprobadores distintos al autor, «Prevent self-review», sin bypass de admin y regla de tags v* | Admin del repo |
| OPS-10 | Existente | P2 | Backlog vivo en GitHub Issues con sincronización automática a docs/backlog | Infra | 3 | — | Activar «Allow GitHub Actions to create and approve pull requests»: la sync y el pin de Buzz abren su PR solos | Owner de la organización |
| SEC-06 | En curso (PR #216) | P0 | Cerrar los hallazgos abiertos de la revisión interna antes de congelar el commit de auditoría | Seguridad | 3 | — | PR #216 fusionada con su alerta de CodeQL triada (IR-04, IR-05, IR-16, IR-19, IR-20); IR-15 corregido con migración; internal-review actualizado | Equipo |
| SEC-07 | Nueva | P1 | Vectores oficiales de NIP-44 y vectores JSON exportables; tag de auditoría congelado | Seguridad | 2 | SEC-03 | nip44.vectors.json corre en CI; vectores exportables que Rust y Dart pueden consumir (ADR 0004); tag audit-2026-10 creado | Equipo |
| FR025-11 | Nueva | P0 | G1: las invitaciones a grupos seguros llegan con el secure relay real | Dev | 5 | FR025-07, FR016-01 | AUTH NIP-42 temprano en relays con nip42_dms (hoy nostr-rs-relay descarta en silencio los kind 1059 sin AUTH y los clientes solo se autentican bajo demanda); E2E de grupos en web y CLI contra nostr-rs-relay real en CI; relay_url correcto para el .onion | Equipo |
| FR005-12 | Nueva | P1 | Retirar el modo legado del managed-signer (token de servicio + x-account-id) | Seguridad | 1 | FR005-04 | Solo se firma con el token de Acceso o una sesión de dispositivo; test que rechaza el modo legado | Equipo |
| FR023-09 | Nueva | P0 | B1: editar una persona revocada no la reactiva; reactivar es explícito y auditado | Seguridad | 1 | FR023-03 | PUT /v1/subjects conserva suspended; ruta de reactivación con entrada de auditoría; test de regresión | Equipo |
| FR024-04 | Nueva | P0 | B2: el propagador de revocaciones no pierde eventos | Dev | 2 | FR024-01 | Cursor persistido sobre la auditoría o endpoint /v1/revocations; test con más de 100 entradas entre revocación y propagación sin pérdidas | Equipo |
| FR010-03 | Nueva | P1 | D1: un DM escrito sin red no queda mal enrutado | Dev | 3 | FR010-02 | No se cachea un descubrimiento vacío; la ruta 10050 se resuelve al publicar; relays de descubrimiento configurables; test offline→online | Equipo |
| FR011-04 | Nueva | P1 | D2: el cliente soberano reintenta lo pendiente al abrir sesión | Dev | 1 | FR011-02 | resume() al abrir la persona en el CLI; test entre dos procesos | Equipo |
| FR019-03 | Nueva | P1 | D3: los adjuntos de DM no conservan metadatos no saneables (HEIC con GPS) | Dev | 1 | FR019-02 | requireSanitizable también en DMs cuando stripFileMetadata está activo; E2E con un HEIC con GPS | Equipo |
| FR010-04 | Nueva | P1 | Avisar cuando el quorum supera el número de relays | Dev | 1 | FR010-01 | El panel y el motor rechazan o avisan en lugar de recortar el quorum en silencio | Equipo |
| FR004-06 | Nueva | P1 | Permisos NIP-46 completos para los kinds que firma la web | Dev | 1 | FR004-04 | WEB_NIP46_PERMISSIONS incluye 10063, 30443, 30078 y los demás kinds firmados; test que los contrasta | Equipo |
| PANEL-05 | Nueva | P1 | Panel veraz: perfil validado al crear persona, Tor-only sin clearnet en la web, declaraciones desde la custodia real | Dev | 3 | PANEL-04, FR028-01 | isValid al crear persona; con tor-only la web no lee relays ni publica 10050; disclosures según la custodia real (también en el CLI Tor); texto para stripFileMetadata; se retira «Marmot fijada y auditada» y se añaden los avisos de alto riesgo que faltan en --high-risk y en los presets soberanos | Equipo |
| FR005-08 | Nueva | P1 | Textos de la custodia gestionada listos para la revisión legal | Dev | 3 | FR005-07 | Login sin «tu llave no sale del navegador» en managed; aviso de descifrado NIP-44 en servidor; enlace a los términos; consentimiento registrado con su versión | Equipo |
| DEC-10 | Reabierta | P1 | Formalizar threat models por perfil (aprobados y versionados por release) | Seguridad | 3 | — | threat-model.md general al día; los cinco perfiles aprobados por alguien distinto del autor; versión ligada al release y comprobada por el gate | Segunda persona (aprobación) |
| OPS-11 | Nueva | P1 | Corregir la deriva documental | Doc | 1 | — | README, notas v0.1.0, architecture.md, ADR 0002/0009, buzz-integration.md, institutional.md, threat-model.md, SECURITY.md y baseline del backlog coinciden con main | Equipo |
| BUZZ-07 | Nueva | P2 | Adoptar el pin de Buzz ac4521f3e464 (issue #201) tras revisar el changelog | Infra | 1 | BUZZ-05, OPS-10 | PR del pin fusionada con el gate en verde; ADR 0003 seguido | Equipo |
| NFR005-02 | Existente | P3 | Pruebas de carga del relay y el indexer | QA | 3 | NFR005-01 | Cifras de load-test.yml contra Buzz en docs/load-testing.md (primer run programado el 28-sep) | Equipo |
| REL-01 | Existente | P1 | Checklist de Definition of Done automatizado en el pipeline de release | Infra | 3 | NFR010-02, NFR003-02, FR020-03, DEC-10, OPS-08 | El gate corre en un release real y además comprueba threat models aprobados, alertas de CodeQL y Dependabot, la aprobación del waiver y --prerelease en -rc _(Se quitan SEC-01 y SEC-02: el gate ya exige informe o waiver)_ | Equipo |
| NFR010-02 | Existente | P1 | Firma de releases y provenance (SLSA/cosign) | Seguridad | 3 | OPS-08 | v0.1.0 publicada con imágenes y artefactos firmados; verify-release.sh pasa desde fuera | Equipo |
| FR003-06 | Existente | P1 | Firma de las releases del generador | Seguridad | 2 | FR003-02, NFR010-02 | keygen.html y keygen.mjs firmados en v0.1.0 y verificados | Equipo |
| FR003-07 | Existente | P2 | Guía de uso air-gapped verificable | Doc | 1 | FR003-06 | Procedimiento ejecutado de punta a punta con v0.1.0 en un equipo sin red, con registro | Equipo |
| REL-02 | Existente | P2 | Release notes con los cambios de trust model por release | Doc | 1 | REL-01 | Notas de v0.1.0 corregidas y publicadas como cuerpo del GitHub Release | Equipo |

## S10 · SaaS beta en staging y web completa (2026-10-12 → 2026-10-23)

| ID | Cambio | Prio | Tarea | Tipo | SP | Depende de | Criterio de hecho | Quién desbloquea |
|---|---|---|---|---|---:|---|---|---|
| NFR001-01 | Existente | P1 | Infraestructura como código del SaaS (Helm/Terraform) | Infra | 8 | OPS-02 | terraform apply en infrastructure, stage desplegado, interop contra stage y kubeconform en CI | Ops de Sedecim con credenciales AWS |
| NFR001-02 | Existente | P1 | Monitorización de SLO (99,9 % mensual) y alertas | Infra | 3 | NFR001-01 | Monitoreo desplegado, receptores de alertas definidos y sonda externa | Responsable de guardias |
| NFR004-02 | Existente | P3 | Dashboard de latencia y degradación sin ocultarla | Infra | 2 | NFR004-01, NFR001-02 | Scrape por pod del indexer (hoy mide una sola réplica) y panel P95/P99 en vivo | Equipo |
| NFR001-03 | Existente | P2 | Postgres de alta disponibilidad y backups gestionados | Infra | 3 | NFR001-01 | RDS aplicado, datos migrados, failover y PITR probados en stage | Ops / AWS |
| NFR003-03 | Nueva | P1 | Simulacro de restauración del SaaS en stage | Infra | 3 | NFR001-03 | Job programado que restaura RDS (PITR) y el almacenamiento S3 y corre la interop | Equipo |
| OPS-06 | Existente | P2 | Servicio notification-gateway con perfiles de privacidad | Dev | 8 | DEC-08, FR025-11 | Con los relays de referencia un DM nuevo produce un aviso opaco: gancho de admisión (nauthz EventAdmit) en el secure relay que agenda el push sin registrar nada, la web recibe sus DMs también ahí con AUTH temprano, E2E con un endpoint push falso; Buzz sin gancho documentado en ADR 0010 _(Pasa de 5 a 8 SP y depende de FR025-11)_ | Equipo |
| NFR009-02 | Existente | P2 | Corregir los hallazgos de accesibilidad y revisión manual con lector de pantalla | Dev | 3 | NFR009-01 | Informe de la revisión manual y correcciones aplicadas | Persona con lector de pantalla (NVDA/VoiceOver) |
| FR006-04 | Nueva | P2 | Perfil público por persona (kind 0: nombre y avatar) | Dev | 3 | FR006-02 | Se publica y se muestra en canales, DMs y grupos; en perfiles seudónimos no se publica nada salvo elección explícita | Equipo |
| FR014-04 | Nueva | P2 | La web usa el mirror: no leídos por canal y búsqueda | Dev | 3 | FR014-03, FR023-05 | Contadores de no leídos y búsqueda en la web vía NIP-98, respetando la política | Equipo |
| FR014-05 | Nueva | P1 | El mirror comprueba la membresía NIP-29 y respeta la moderación | Dev | 3 | FR014-03 | Lecturas y búsqueda solo sobre canales de los que eres miembro; tombstone para kind 9005 | Equipo |
| FR015-04 | Nueva | P2 | Reacciones, hilos y borrado en canales | Dev | 5 | FR015-02 | Kinds 7, respuestas con e/q y borrado 5/9005 en la web, con E2E contra Buzz | Equipo |
| FR009-03 | Nueva | P1 | DMs y acuses en tiempo real | Dev | 3 | FR009-02 | Suscripción de fondo a los 10050 propios; los acuses se publican en los 10050 del emisor | Equipo |
| FR017-06 | Nueva | P1 | El cliente soberano enruta DMs por 10050 y publica el suyo | Dev | 2 | FR017-04 | CLI con el mismo ruteo que la web y test de interoperabilidad web ↔ CLI | Equipo |
| FR006-06 | Nueva | P2 | Test de aislamiento de circuitos Tor por persona | QA | 1 | FR006-03 | Credenciales SOCKS distintas por persona verificadas contra un servidor SOCKS con autenticación | Equipo |
| FR021-03 | Nueva | P2 | Endurecimiento del modo Tor | Dev | 2 | FR020-01 | Opción onion-only en el cliente soberano, mensaje de fallo unificado «No enviado: red de privacidad no disponible» y relays sin IPs en los logs de los perfiles soberanos | Equipo |
| FR020-06 | Nueva | P2 | Cliente soberano como servicio del perfil tor | Infra | 2 | FR021-02 | docker compose run --rm sovereign … con TOR_SOCKS=tor:9050, documentado como paso intermedio hasta la app de escritorio | Equipo |
| APP-01 | Nueva | P2 | Web instalable en el móvil (PWA) | Dev | 2 | — | Manifest, iconos y modo standalone; el push web existente funciona instalada | Equipo |
| BUZZ-08 | Nueva | P2 | Validar Buzz Desktop y Mobile contra nuestro relay | QA | 3 | OPS-01 | Smoke test documentado de canales con Buzz Desktop/Mobile upstream y límites conocidos (DMs, #4677) | Equipo |
| DEC-13 | Nueva | P1 | Estrategia de clientes nativos | Decisión | 1 | BUZZ-08 | ADR: apps propias según ADR 0004 (Tauri y Flutter + núcleo Rust) o Buzz upstream + PWA, con alcance de v1.0 | Responsable de producto |
| DEC-14 | Nueva | P1 | Modelo comercial del SaaS: organizaciones, planes y facturación | Decisión | 1 | — | ADR con el modelo de tenants, planes y proveedor de cobro (o su exclusión explícita de v1.0) | Dirección |

## S11 · Auditorías en campo, custodia e institucional a fondo (2026-10-26 → 2026-11-06)

| ID | Cambio | Prio | Tarea | Tipo | SP | Depende de | Criterio de hecho | Quién desbloquea |
|---|---|---|---|---|---:|---|---|---|
| FR005-05 | Existente | P3 | Tier enclave: firma dentro de Nitro Enclave con KMS condicionado por attestation | Dev | 8 | FR005-02, DEC-09 | Dockerfile de la EIF, helper NSM, puentes vsock, EIF reproducible con PCR en CI, alarma CloudTrail y pruebas en una instancia Nitro real | AWS: instancia Nitro y KMS |
| FR005-09 | Nueva | P1 | Exportar desde el enclave exige una prueba del usuario verificada dentro del enclave | Seguridad | 5 | FR005-05 | JWT con JWKS fijado en la imagen o firma de la llave de destino; sin ella el enclave se niega; test | Equipo |
| FR005-10 | Nueva | P2 | Importar al enclave sin exponer la llave ni la contraseña al padre | Seguridad | 3 | FR005-05 | El ncryptsec se cifra hacia la clave atestada del enclave; test | Equipo |
| FR026-04 | Nueva | P1 | Salida de la custodia y derechos ARCO | Dev | 3 | FR026-01 | Cancelar sin migrar (API y UI), confirmación y descarga del backup antes de borrar, borrado por el operador de cuentas cerradas y backups del vault sin llaves borradas más de 30 días | Equipo |
| FR023-10 | Nueva | P1 | Aplicar «publicar» por recurso en los relays | Dev | 8 | FR023-04 | Admisión por #h en el secure relay y en Buzz, y sincronía de la membresía NIP-29 con el policy-engine; test de denegación | Equipo |
| FR024-05 | Nueva | P1 | Rotaciones como servicio, sesiones de dispositivo en la web y runbook de pérdida | Dev | 5 | FR024-02, FR024-04 | Worker de rotaciones en compose y k8s; la persona managed de la web usa sesiones de dispositivo revocables; docs/runbooks/device-loss.md | Equipo |
| FR024-03 | Reabierta | P2 | Revocar sesiones NIP-46 y tokens de managed-signer ligados al dispositivo | Dev | 2 | FR024-01, FR005-04, FR024-04, FR024-05 | Tras revocar, el signer rechaza al dispositivo también en la web y sin depender de que alguien ejecute el CLI | Equipo |
| FR006-07 | Nueva | P2 | Compartimentación: avisar antes de reutilizar un contacto o un archivo entre personas | Dev | 3 | FR006-01 | Aviso con confirmación explícita en la web y en el CLI, también para archivos (recordUsage) | Equipo |
| FR027-04 | Nueva | P2 | Backup completo en la web y reconstrucción del historial | Dev | 5 | FR027-02 | Backup v2 (relays, panel, MLS y outbox) compatible con el CLI; npub en el JSON de migración; maxLogN en los descifrados del cliente; historial reconstruido al restaurar | Equipo |
| FR011-05 | Nueva | P2 | Identificador de operación estable en la UI | Dev | 2 | FR011-01 | Reintentar desde la web o el CLI no crea otro evento ni otro rumor; los wraps se crean después de persistir | Equipo |
| NFR007-03 | Nueva | P2 | Crash reports opt-in con limpieza y exportación manual local | Dev | 3 | NFR007-01 | Implementados según el perfil, o retirados de presets y disclosures (hoy se prometen y no existen) | Equipo |
| FR025-12 | Nueva | P1 | Outbox para mensajes y commits MLS | Dev | 3 | FR025-11 | Con Tor caído o sin red, un mensaje o commit de grupo queda pendiente y se reintenta, en lugar de fallar | Equipo |
| FR004-08 | Nueva | P2 | Cliente soberano con signer NIP-46 e importación de nsec/ncryptsec | Dev | 3 | FR004-01 | Perfiles Tor con signer externo (§14: offline/signer) y custodia declarada según la llave real | Equipo |
| FR005-11 | Nueva | P2 | Recuperar la persona gestionada en un navegador nuevo | Dev | 3 | FR005-04 | Con el login de Acceso se reabre la llave gestionada; el usuario ve su log de uso y revoca sus sesiones | Equipo |
| FR023-13 | Nueva | P2 | CI del modo institucional | QA | 2 | OPS-07 | El perfil institutional del compose y el componente k8s se validan en CI; E2E de la consola contra el policy-engine real | Equipo |

## S12 · Informes externos, remediación, legal y producción (2026-11-09 → 2026-11-20)

| ID | Cambio | Prio | Tarea | Tipo | SP | Depende de | Criterio de hecho | Quién desbloquea |
|---|---|---|---|---|---:|---|---|---|
| FR023-11 | Nueva | P2 | Device trust en uso: passkey del propio usuario | Dev | 5 | FR023-07 | El usuario registra la passkey en su dispositivo y cada sesión pide una aserción WebAuthn | Equipo |
| PANEL-06 | Nueva | P2 | Expiración de mensajes por perfil (NIP-40) y borrado con aviso | Dev | 5 | PANEL-02 | Expiración configurable por persona y conversación; borrar mensajes propios con el aviso de que las copias replicadas pueden seguir existiendo | Equipo |
| SEC-01 | Existente | P0 | Revisión criptográfica independiente (NIP-44/49/59, MLS, key service) | Seguridad | 8 | SEC-03, FR005-03, SEC-06, SEC-07 | Informe externo sin hallazgos críticos abiertos _(Se quita FR025-08: la migración a MLS estable se revisa aparte (SEC-10))_ | Auditor criptográfico externo (10–15 persona-día) |
| SEC-08 | Nueva | P0 | Corregir los hallazgos críticos y altos de SEC-01 y SEC-02 | Seguridad | 8 | SEC-06 | Cada hallazgo crítico o alto con corrección, test de regresión y verificación del auditor | Equipo |
| DEC-12 | Existente | P1 | Aprobación legal de los términos de custodia managed y del aviso de privacidad | Decisión | 1 | DEC-09 | Asesoría legal aprueba docs/legal/custodia-managed.md antes de ofrecer la custodia en producción | Asesoría legal (LFPDPPP) |
| FR028-02 | Existente | P2 | Revisión legal/UX de los textos de disclosure | Doc | 2 | FR028-01, DEC-09, PANEL-05 | Textos aprobados y versionados (disclosures v1.2.0) | Asesoría legal y UX |
| DEC-11 | Existente | P2 | Búsqueda y registro de la marca «Acceso Nostr» | Decisión | 1 | DEC-01 | Búsqueda de anterioridades y solicitud presentada, o marca alternativa decidida | Abogado de propiedad intelectual |
| NFR001-04 | Nueva | P1 | Producción con alta disponibilidad | Infra | 8 | NFR001-02, NFR001-03 | Overlay de producción, réplicas y PDB; Redis, SeaweedFS y secure relay en HA o gestionados; sonda externa; blob-store con allowlist o cuotas; el 99,9 % es alcanzable | Ops / AWS |
| NFR003-04 | Nueva | P2 | Copia en una segunda región para el tier institucional | Infra | 5 | NFR001-03, NFR003-01 | Datos y WAL replicados según el RPO/RTO aprobado; restauración probada | Equipo |
| NFR005-03 | Nueva | P3 | Escalado de los relays (Buzz y secure relay) | Doc | 2 | NFR005-02 | ADR con límites medidos y estrategia de escalado | Equipo |
| OPS-13 | Nueva | P2 | Higiene de la cadena de suministro en CI | Infra | 2 | OPS-05 | Acciones por SHA, imágenes por digest, checksums de herramientas, Dependabot para infra/tor y compose, npm audit y CodeQL como gate | Equipo |
| NFR010-04 | Nueva | P2 | SBOM fiel a cada imagen | Infra | 3 | NFR010-01 | SBOM por imagen (syft) atestado, sin devDependencies en runtime; SBOM también para la imagen de Buzz fijada | Equipo |
| NFR006-04 | Nueva | P3 | Escaneo de secretos en logs con todos los perfiles | QA | 2 | NFR006-03 | El job stack también levanta managed, push, institutional y tor y escanea sus logs | Equipo |
| FR023-12 | Nueva | P2 | Auditoría y retención legal coherentes con el modelo de confidencialidad | Dev | 3 | FR023-08 | Retención propia para las entradas de evaluate; legal hold solo donde el modelo lo permite; reemplazables respetan la retención legal | Equipo |
| NFR007-02 | Nueva | P3 | Tracing con muestreo y redacción según el perfil | Dev | 3 | NFR007-01 | Trazas en los servicios con muestreo y redacción, apagadas en perfiles Tor; o retiradas del alcance y de los textos | Equipo |
| OPS-14 | Nueva | P2 | Documentación del SDK y de las APIs | Doc | 5 | — | TypeDoc de los paquetes, OpenAPI de cada servicio y ADR sobre cómo se distribuye el SDK | Equipo |
| DEC-15 | Nueva | P3 | Estructura de repositorios | Decisión | 1 | — | ADR que justifica el monorepo frente a los seis repositorios sugeridos por el scope | Equipo |
| FR011-06 | Nueva | P2 | Métricas de outbox reales o alerta retirada | Infra | 2 | FR011-03 | La alerta OutboxOldestPendingTooOld se alimenta de un proceso real o se retira del monitoreo del SaaS | Equipo |

## S13 · Escritorio soberano con Tor y cierre del pentest (2026-11-23 → 2026-12-04)

| ID | Cambio | Prio | Tarea | Tipo | SP | Depende de | Criterio de hecho | Quién desbloquea |
|---|---|---|---|---|---:|---|---|---|
| FR020-05 | Nueva | P1 | Suite de fugas completa en el cliente soberano | Seguridad | 3 | FR020-03 | La captura real también cubre dm, group, media y rotation-worker, con MLS por Tor; control negativo de ts-mls rc.10 en CI | Equipo |
| SEC-02 | Existente | P0 | Pentest de API, relay, key service y cliente | Seguridad | 8 | OPS-02, FR005-04, FR023-03, NFR001-01, SEC-06 | Informe externo; hallazgos críticos y altos corregidos y verificados en el retest _(Se añade NFR001-01: el pentest es sobre stage)_ | Pentester externo (10–15 persona-día + retest) |
| FR020-02 | Existente | P2 | Cliente desktop dedicado con Tor embebido (shell) | Dev | 8 | DEC-04, DEC-13 | Shell Tauri con un sidecar que expone el SDK por IPC (la webview no puede forzar sus conexiones por SOCKS) y CSP con connect-src limitado a IPC _(Sale de «Diferido», pasa de P3 a P2, depende de DEC-13; el alcance real es ~31 SP y se reparte en FR020-02, FR020-07, FR020-08, FR020-04 y FR020-09)_ | Equipo |
| FR020-07 | Nueva | P1 | Tor embebido en la app de escritorio | Dev | 5 | FR020-02 | tor o arti integrado, con bootstrap y estado visibles, circuitos por persona y fallo cerrado | Equipo |
| FR020-08 | Nueva | P2 | Interfaz de la app de escritorio | Dev | 8 | FR020-02 | Personas, canales, DMs y grupos sobre el almacén en archivo cifrado, con el panel y los disclosures | Equipo |
| FR020-09 | Nueva | P1 | Binarios de escritorio firmados y reproducibles | Infra | 5 | FR020-02 | Firma y notarización (macOS, Windows), build reproducible y sin actualizador automático | Equipo |
| FR020-04 | Nueva | P1 | Pruebas de fugas sobre la app de escritorio | Seguridad | 5 | FR020-02, FR020-03, SEC-05 | La suite de fugas (DNS, IPv6, WebRTC, previews) corre contra el binario en un netns | Equipo |

## S14 · Organizaciones, webhooks y núcleo móvil (2026-12-07 → 2026-12-18)

| ID | Cambio | Prio | Tarea | Tipo | SP | Depende de | Criterio de hecho | Quién desbloquea |
|---|---|---|---|---|---:|---|---|---|
| OPS-15 | Nueva | P2 | Organizaciones y planes en el SaaS | Dev | 8 | DEC-14 | Tenants y organizaciones en identity y policy; planes y cobro según DEC-14 | Equipo |
| OPS-16 | Nueva | P3 | Webhooks y eventos para integraciones empresariales | Dev | 5 | — | El policy-engine emite eventos firmados (sustituye el sondeo de la auditoría); webhooks con reintentos | Equipo |
| SEC-09 | Nueva | P1 | Auditoría independiente de fugas de metadatos del release Sovereign Tor | Seguridad | 5 | FR020-04 | Informe externo sobre el CLI y la app de escritorio sin hallazgos altos abiertos | Auditor externo de privacidad de red |
| APP-02 | Nueva | P2 | Núcleo Rust para móvil (rust-nostr y MDK con flutter_rust_bridge) | Dev | 8 | DEC-13, SEC-07 | Pasa los vectores compartidos de NIP-44/49/59 y la interop MDK | Equipo |
| APP-04 | Nueva | P2 | Push nativo en el móvil (APNs, FCM y UnifiedPush) | Dev | 5 | OPS-06 | Transportes nativos detrás del notification-gateway, con la matriz de privacidad por perfil | Equipo |

## S15 · App móvil beta (2027-01-04 → 2027-01-15)

| ID | Cambio | Prio | Tarea | Tipo | SP | Depende de | Criterio de hecho | Quién desbloquea |
|---|---|---|---|---|---:|---|---|---|
| FR025-14 | Nueva | P2 | Grupos completos en la web: multi-dispositivo, rotación, propuestas y media cifrada | Dev | 5 | FR025-11 | Lo que hoy solo ofrece el CLI (FR025-05/06/09 y rotate) disponible en «Grupos seguros» | Equipo |
| APP-03 | Nueva | P2 | App móvil: almacén seguro, personas, canales y mensajes directos | Dev | 8 | APP-02 | Keychain/Keystore, personas, canales NIP-29 y DMs NIP-17 contra el relay de referencia | Equipo |
| APP-05 | Nueva | P2 | Grupos seguros en el móvil | Dev | 5 | APP-03, FR025-04 | Grupos Marmot con MDK interoperables con la web y el CLI | Equipo |
| APP-06 | Nueva | P2 | Backup, restauración y multi-dispositivo en el móvil | Dev | 3 | APP-03, FR027-04 | Mismo formato v2 que web y CLI; segundo dispositivo en grupos MLS | Equipo |
| APP-07 | Nueva | P2 | Beta en TestFlight y Google Play | Infra | 3 | APP-03 | Builds firmados en pruebas internas con fichas de privacidad | Cuentas de Apple y Google |
| FR025-08 | Existente | P2 | Migrar a marmot-ts v2 / ts-mls estable cuando se publiquen | Dev | 3 | FR025-04 | Dependencias estables con conformidad y autoprueba en verde, o excepción documentada si upstream no publica | Upstream: ts-mls 2.0.0 y marmot-ts 1.0 |
| SEC-10 | Nueva | P1 | Revisión criptográfica delta: MLS estable y núcleo Rust del móvil | Seguridad | 3 | FR025-08, APP-02 | Informe externo del delta sin críticos abiertos | Auditor criptográfico externo |

## S16 · GA v1.0 (2027-01-18 → 2027-01-29)

| ID | Cambio | Prio | Tarea | Tipo | SP | Depende de | Criterio de hecho | Quién desbloquea |
|---|---|---|---|---|---:|---|---|---|
| REL-03 | Nueva | P0 | v1.0.0 con la Definition of Done completa y sin waiver | Infra | 3 | SEC-01, SEC-02, SEC-08, NFR001-04, DEC-12, REL-01 | Informes externos en docs/security/audits/v1.0.0.md, threat models aprobados, simulacros de restauración self-hosted y SaaS, fugas, artefactos firmados y producción en marcha | Segunda persona (aprobaciones del release) |
| REL-04 | Nueva | P1 | Revisión de afirmaciones para perfiles de alto riesgo | Doc | 1 | SEC-09, REL-03 | Solo se ofrece sovereign-tor a alto riesgo si SEC-01, SEC-02 y SEC-09 pasaron; notas de trust model de v1.0.0 | Equipo |

## Diferido · Después de v1.0 (opcional en el scope)

| ID | Cambio | Prio | Tarea | Tipo | SP | Depende de | Criterio de hecho | Quién desbloquea |
|---|---|---|---|---|---:|---|---|---|
| FR015-05 | Nueva | P3 | Presencia (NIP-38) opt-in por perfil | Dev | 3 | — | Estado de presencia solo en perfiles que lo permiten | Equipo |
| FR013-05 | Nueva | P3 | Caché local cifrada de eventos y NIP-77 con estado local | Dev | 5 | — | Lectura sin conexión, reanudación por since y NIP-77 con conjunto local (interop con strfry) | Equipo |
| FR018-06 | Nueva | P3 | Política de tamaño, MIME y antivirus compatible con la confidencialidad | Doc | 2 | — | Política documentada y comprobación de tamaño en el cliente | Equipo |
| FR004-07 | Nueva | P3 | Signer de hardware (opcional en el scope) | Dev | 5 | — | Spike con un dispositivo de hardware y decisión documentada | Equipo |

## Tareas nuevas por epic

| Epic | Nuevas | SP |
|---|---:|---:|
| OPS · Despliegue y DevSecOps | 6 | 22 |
| SEC/REL · Gates de seguridad y release | 7 | 25 |
| FR · Grupos high-security (Marmot/MLS) | 3 | 13 |
| FR · Identidad, llaves y custodia | 11 | 35 |
| FR · Modo institucional | 7 | 26 |
| FR · Mensajería, entrega y resiliencia | 14 | 36 |
| PANEL · Panel de soberanía y privacidad | 2 | 8 |
| BUZZ · Early release sobre Buzz | 2 | 4 |
| NFR · Requisitos no funcionales | 8 | 29 |
| FR · Privacidad y Sovereign Tor | 9 | 34 |
| APP · Clientes nativos y web instalable | 7 | 34 |
| DEC · Decisiones de arquitectura | 3 | 3 |

La epic **APP · Clientes nativos y web instalable** es nueva: agrupa la PWA y la app móvil (la app de escritorio sigue en *FR · Privacidad y Sovereign Tor*).

## Dependencias externas

| Qué hace falta | Por qué | Quién | Para cuándo |
|---|---|---|---|
| Segunda persona con rol de aprobador | Aprueba el waiver, las tres aprobaciones de entorno de cada release y las reviews de PR; sin ella la separación de funciones es nominal | Dirección (hay otros dos admins en la organización) | S9 |
| Ajustes de GitHub | Protección de main, entorno release, Actions que abren PRs, Dependency graph y private vulnerability reporting | Admin del repo / owner de la organización | S9 |
| Credenciales de AWS y terraform apply en infrastructure | Bloquean stage, monitoreo, RDS, el pentest sobre stage, el enclave real y producción | Ops de Sedecim | S9–S10 |
| Auditor criptográfico y pentester | SEC-01 y SEC-02 exigen informes externos; contratar lleva semanas | Dirección (presupuesto) | Contrato en S9, campo en S11 |
| Asesoría legal (LFPDPPP) y UX | Términos de custodia gestionada, aviso de privacidad y los 42 textos de disclosure | Legal | Envío en S9, aprobación en S12 |
| Abogado de propiedad intelectual | Búsqueda y registro de la marca | Legal | S9 (el registro tarda meses) |
| Revisor con lector de pantalla | NFR009-02 pide revisión manual con NVDA/VoiceOver | Producto | S10 |
| Versiones estables de ts-mls y marmot-ts | FR025-08; ya no bloquea SEC-01 tras desacoplarlo | Upstream | S15 o excepción documentada |
| Cuentas de Apple y Google | Firma y beta de la app móvil | Dirección | S14 |

## Cómo se aplica

1. **`meta.sprints`**: una PR añade S9–S16 a `docs/backlog/backlog.json`, renombra `Diferido` a «Después de v1.0 (opcional en el scope)» y actualiza `meta.baseline`/`meta.version`. `meta` no se regenera desde los issues, y sin esos sprints el validador rechaza los milestones nuevos.
2. **Milestones**: crear «S9 · …» … «S16 · …» con `due_on` al fin de cada sprint (o lanzar `backlog-sync` con `seed`, que crea los milestones que falten desde `meta.sprints`).
3. **Issues existentes**: mover las 22 tareas abiertas a su milestone nuevo (tabla de cada sprint). Reabrir FR024-03 (#169) y DEC-10 (#45) con `status:parcial` y la evidencia de la revisión.
4. **Issues nuevos**: crear las 79 tareas con la plantilla *Tarea del backlog* (título `[ID] …`, prioridad, epic, milestone, sección *Depende de* y relaciones *blocked by*). Crear el issue de epic `[Epic] APP · Clientes nativos y web instalable`.
5. **Dependencias**: SEC-01 deja de depender de FR025-08; SEC-02 pasa a depender de NFR001-01; REL-01 deja de depender de SEC-01/SEC-02 (el gate ya exige informe o waiver); OPS-06 depende de FR025-11; FR020-02 sale de *Diferido*, pasa a P2 y depende de DEC-13.
6. **Sincronización**: `backlog-sync` regenera `README.md`, `backlog.csv` y `backlog.json` desde los issues y abre su PR.
