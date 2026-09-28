# Replanteo de sprints desde el corte del 27 de septiembre de 2026

> Base: `main@5f39e73` (revisión del backlog contra el código) y `main@d479bc5` (tras las PR #216 y #217), los issues del backlog a 2026-09-27, *Scope_Plataforma_Nostr_Soberana_SaaS_v0.1* (25/09/2026) y el *PRD de cierre de brechas y preparación para release* v0.3 (27/09/2026).
> `backlog.json`, `README.md` y `backlog.csv` se generan desde GitHub Issues; este documento explica el replanteo que llevan. La sección *Cómo se aplicó* describe cómo pasó a los issues.

## Resumen

- El plan original S1–S8 (28/09/2026 → 29/01/2027) ya está casi entero en el repositorio: 136 de 158 tareas activas hechas y 80 SP abiertos en 20 parciales y 2 pendientes.
- La revisión confirma 125 de las 136 tareas hechas. Encuentra 9 sobredeclaradas (se reabren FR024-03 y DEC-10), 2 en riesgo por un defecto de integración (G1), 6 defectos nuevos y 13 brechas del scope sin tarea.
- El PRD de cierre de brechas coincide y fija el marco: **feature freeze hasta RC1**, fuera del programa las apps propias de móvil y escritorio, y una brecha nueva de producto, el **Continuity Vault**: hoy el historial depende de que los relays conserven los eventos.
- S9–S16 sigue el mismo calendario y avanza por los gates G0–G5 del PRD hasta **v1.0.0 firmada para despliegues controlados el 29/01/2027**: 80 tareas (20 abiertas, 2 reabiertas y 58 nuevas; 245 SP). Otras 26 tareas (105 SP) quedan para después de v1.0.
- El camino crítico es externo: auditor y pentester, asesoría legal, credenciales de AWS y un segundo aprobador de releases. Todo se arranca en S9.

## Decisiones del PRD que adopta el replanteo

| Decisión | Resultado |
|---|---|
| Login de Acceso (Cognito) obligatorio en el SaaS | Se mantiene. La soberanía plena sigue en self-hosted y en los modos de llave no custodiales |
| Buzz upstream fijado por digest y sin fork | Se mantiene. Un fork solo con ADR y un bloqueo P0/P1 demostrado |
| Buzz Desktop y Mobile como early release | Fuera de este programa; se tratará en un PRD aparte |
| Continuity Vault | Se agrega como requisito de private-resilient y de la promesa de continuidad |
| Nitro Enclave | Tier reforzado en Preview; no es requisito de la custodia gestionada básica |
| Marmot con upstream alpha/RC | Beta; sin claim de alta seguridad |
| Push parcial | No bloquea el RC y no se amplían permisos para forzarlo |
| Estado «Hecho» | Solo tras el merge a main y con la evidencia requerida |

**Fuera de este programa** (no se crean issues ni dependencias de release):

- Cliente móvil propio: ni app iOS o Android, ni tiendas, push nativo o ejecución en segundo plano.
- Cliente de escritorio propio: ni Tauri o Electron, ni instaladores, auto-update o notarización.
- Quitar Acceso/Cognito del SaaS o sustituirlo por acceso anónimo.
- Volver a un fork de Buzz sin una necesidad técnica demostrada.
- Hacer Nitro obligatorio para la custodia gestionada básica.
- Prometer aptitud para alto riesgo antes de una auditoría independiente.

**Cómo se trabaja:**

- **Feature freeze hasta RC1.** Solo entran correcciones, resiliencia, operación, auditoría y lo que pide el PRD.
- **Main manda.** Nada está «Hecho» si la evidencia vive en una rama o en una PR abierta.
- **Fail closed.** Lo incompleto queda apagado por defecto, no a medio funcionar.
- **Sin degradar privacidad.** Ni en push, ni en backup, ni en custodia, para cerrar una brecha.
- **El evento firmado es canónico.** Una base de datos derivada no se presenta como fuente.

**Niveles de evidencia:** Propuesto → En PR → Fusionado → Verificado en CI → Verificado en stage → Auditado externamente → Habilitado en producción. Una tarea solo pasa a «Hecho» con su evidencia en main (OPS-17). Hoy todo lo construido está fusionado y verificado en CI; nada está verificado en stage, auditado ni habilitado en producción.

## Madurez que declarará v1.0

| Perfil o función | Hoy | En v1.0 | Qué lo permite |
|---|---|---|---|
| SaaS convenience | Fusionado y verificado en CI; stage sin desplegar | GA controlado | SEC-01 y SEC-02, stage y release firmada |
| Private-resilient | Fusionado y en CI, pero el historial depende de los relays | GA controlado | Continuity Vault, restauración con relays vacíos, SEC-01 y SEC-02 |
| Self-hosted soberano | Fusionado, en CI e imágenes reproducibles; sin release | GA técnico | Release firmada, instalación reproducible y restore drill |
| Custodia gestionada básica | Fusionado y en CI con KMS simulado | GA opcional | Aprobación legal, KMS y Secrets Manager reales, SEC-01 y SEC-02 |
| Custodia en Nitro Enclave | Prototipo | Preview | EIF, PCR, attestation y KMS reales más auditoría; no bloquea la básica |
| Institucional | Fusionado y en CI; defectos B1 y B2 | GA controlado | Pentest en stage, persistencia, pruebas de políticas y auditoría |
| Grupos Marmot/MLS | Fusionado y en CI; defecto G1; upstream alpha y RC | Beta | SEC-01; el aviso sigue mientras upstream sea alpha o RC |
| Sovereign Tor | Fusionado, con pruebas de fugas internas | Experimental | Ningún claim de alto riesgo sin auditoría específica ni cliente dedicado |
| Notificaciones push | Parcial: no se disparan con los relays de referencia | Experimental, tras flag | No se amplían los permisos del relay para habilitarlas |

## Resultado de la revisión

| Resultado | Tareas |
|---|---:|
| Hechas y confirmadas | 125 |
| Hechas pero sobredeclaradas | 9 |
| Hechas pero en riesgo (G1) | 2 |
| Parciales o pendientes, bien marcadas | 22 |
| Descartadas con ADR | 6 |
| **Total** | **164** |

Evidencia objetiva del corte: `npm run typecheck` en verde; `vitest run` con 79 archivos en verde, 524 pruebas en verde y 25 omitidas (las suites de interoperabilidad necesitan el stack real y corren en el job `stack` de CI); `npm run lint:claims` y `node scripts/backlog.mjs --check` en verde; CI, CodeQL y reproducible-images en verde en `main@5f39e73`; ningún tag ni release publicado. En `main@d479bc5`: 87 archivos, 559 pruebas en verde y 27 omitidas.

### Defectos nuevos

| ID | Prio | Qué pasa | Cómo se verificó | Tarea |
|---|---|---|---|---|
| G1 | P0 | Las invitaciones a grupos seguros no llegan con el secure relay real | Confirmado en el código de nostr-rs-relay 0.9.0 (filtra los kind 1059 sin AUTH y no avisa) y del relay-pool (solo se autentica si el relay lo pide). Las pruebas contra ese relay usan AUTH inmediato; el E2E de la web usa el relay de pruebas | FR025-11 (S9) |
| B1 | P0 | Editar una persona revocada en la consola la reactiva | Reproducido: el PUT de sujeto escribe suspended=false | FR023-09 (S9) |
| B2 | P0 | El propagador de revocaciones pierde eventos | Reproducido: lee solo las últimas 100 entradas de auditoría y cada evaluate() escribe una | FR024-04 (S9) |
| D1 | P1 | Un DM escrito sin red queda enrutado para siempre a los relays del emisor | Reproducido: se cachea 5 minutos un descubrimiento vacío y la ruta se fija al componer | FR010-03 (S9) |
| D2 | P1 | El cliente soberano no reintenta lo pendiente entre invocaciones | Reproducido: solo `sovereign resume` lo publica | FR011-04 (S9) |
| D3 | P1 | Un HEIC con GPS adjunto a un DM conserva la ubicación | Reproducido: los DMs no exigen archivo saneable aunque stripFileMetadata esté activo | FR019-03 (S9) |

### Sobredeclaradas y en riesgo

- **FR024-03** (sobredeclarada): Revocar no propaga (B2) y la web no usa sesiones de dispositivo. Se reabre.
- **FR011-02** (sobredeclarada): La web reanuda la outbox al volver la red; el CLI no (D2).
- **FR011-03** (sobredeclarada): Las métricas de outbox no salen de ningún proceso desplegado; su alerta no puede dispararse.
- **FR019-02** (sobredeclarada): HEIC con metadatos pasa en DMs (D3).
- **PANEL-02** (sobredeclarada): Con perfil Tor-only la web bloquea el envío pero lee relays y publica 10050 por clearnet.
- **FR006-03** (sobredeclarada): El aislamiento de circuitos por persona existe en código pero ningún test lo ejercita.
- **NFR006-03** (sobredeclarada): El escaneo de logs no incluye los perfiles managed, push, institutional ni tor.
- **OPS-05** (sobredeclarada): Dependabot no cubre infra/tor ni las imágenes por tag del compose, y la revisión no es obligatoria.
- **DEC-10** (sobredeclarada): Los threat models siguen en «Propuesto»: nadie los aprobó ni se ligan a un release. Se reabre.
- **FR025-03** (en riesgo): Grupos en el cliente soberano: pasan contra el relay de pruebas, no contra el secure relay real (G1).
- **FR025-07** (en riesgo): Grupos en la web: mismo caso (G1).

### Hechas solo en librería o CLI

- Vínculos entre personas: la librería los soporta, pero no se pueden listar ni retirar (FR007-01/02/03).
- Backup completo con relays, panel y MLS: solo en el CLI; la web exporta solo la llave (FR027-02, FR013-03).
- No leídos y búsqueda del mirror: API sin interfaz; la web lee directo de los relays (FR014-03, FR023-05).
- Worker de rotaciones: CLI manual, sin servicio desplegado (FR024-02).
- Device trust: registro de passkeys sin uso posterior en sesiones (FR023-07).
- Multi-dispositivo, propuestas, rotación y media en grupos: solo en el CLI (FR025-05/06/09).

### Brechas sin tarea previa

| Tema | Qué falta | Tarea y cuándo |
|---|---|---|
| Continuidad del historial | Si todos los relays pierden o podan eventos no hay copia independiente: el backup guarda identidad y estado, y el indexer no es un backup. Es la brecha principal que señala el PRD (epic B). | VAULT-01 (S10), VAULT-03 (S11) |
| Perfiles de usuario | No hay kind 0 (nombre, avatar) en ningún cliente (§7). | FR006-04 (después de v1.0) |
| Colaboración en canales | Sin reacciones, hilos, borrado ni presencia; los acuses no llegan al emisor (§15.1). | FR009-03 (S10), FR015-04 (después de v1.0), FR015-05 (después de v1.0) |
| Retención y expiración | Sin NIP-40 ni borrado por el usuario; el aviso de copias solo existe en la consola (§12.2). | PANEL-06 (después de v1.0) |
| Compartimentación | Sin aviso al reutilizar archivos o contactos entre personas en la web (§14.1). | FR006-07 (después de v1.0) |
| Nivel de vínculo visible | «Enviando como…» no muestra el nivel de vínculo (§16.1). | FR007-05 (S10) |
| Publicar por recurso | Ningún punto de control evalúa la acción «publicar»; los relays solo filtran por pubkey (FR-023). | FR023-10 (S11) |
| Salida de la custodia | No se puede cancelar sin migrar (ARCO) ni salir del tier enclave (§8.5 paso 8). | FR026-04 (S11), FR005-09 (después de v1.0) |
| SaaS comercial | Sin organizaciones, planes, facturación ni webhooks (§15.2). | DEC-14 (después de v1.0), OPS-15 (después de v1.0), OPS-16 (después de v1.0) |
| Observabilidad | Tracing y crash reports prometidos en presets y textos, sin implementación (§18). | PANEL-05 (S9), NFR007-02 (después de v1.0), NFR007-03 (después de v1.0) |
| SDK y APIs | Paquetes privados sin documentación ni OpenAPI (§17, §26). | OPS-14 (S14) |
| Disponibilidad | Solo existe stage, con servicios de una réplica: el 99,9 % no es alcanzable (NFR-001). | NFR001-04 (S11), NFR001-05 (después de v1.0) |
| Vectores de prueba | Faltan los vectores oficiales de NIP-44 y los exportables que prometía el ADR 0004. | SEC-07 (S9) |
| Clientes nativos | Sin app de escritorio ni móvil propias (§2.1, §25). El PRD las deja para un PRD aparte. | Fuera del programa |

### Documentación desfasada (OPS-11)

- README: «persistencia en memoria» del policy-engine, lista de pendientes ya hechos y estructura sin admin-console.
- Notas de v0.1.0: versiones de @noble equivocadas, policy-engine «en memoria» y waiver «aprobado» (está pendiente).
- architecture.md, ADR 0002, ADR 0006, ADR 0009, buzz-integration.md y threat-model.md citan pines, versiones o estados viejos.
- disclose.ts afirma «Implementación Marmot fijada y auditada» y promete crash reports que no existen.
- El backlog declaraba como base main@65ed066; este replanteo la lleva a main@d479bc5.

### Gobierno del repositorio (OPS-12, OPS-13, OPS-17, SEC-06)

- main no está protegida: una actualización mayor de vite se fusionó sin revisión, y CodeQL y dependency-review no bloquean el merge.
- Todas las aprobaciones (ADR, RPO/RTO, waiver) las firma la misma persona.
- Después del corte se fusionó la PR #216: corrige IR-04 (replay de NIP-98), IR-05 (límites de tasa), IR-16, IR-19 e IR-20. Queda abierto IR-15.
- El PRD advertía que el issue de SEC-02 describía correcciones que solo vivían en la PR #216. Ya están en main, y OPS-17 impide que un issue vuelva a adelantarse a main.

## Gates

| Gate | Cierra en | Trabajo | Tareas | Salida |
|---|---|---|---|---|
| G0 · Main endurecido | S9 | PR #216 (ya fusionada), IR-15, defectos G1, B1, B2 y D1–D3, deriva documental y gobierno del repositorio | SEC-06, FR025-11, FR023-09, FR024-04, OPS-11, OPS-12, OPS-17 | main sin hallazgos internos medios sin corregir o aceptar |
| G1 · Continuidad completa | S11 | Continuity Vault (epic B del PRD) | VAULT-01, VAULT-02, VAULT-03, VAULT-04, VAULT-05, VAULT-06, VAULT-07 | private-resilient no depende de los relays para el historial |
| G2 · Stage real | S12 | Stage en AWS, SLO, RDS, carga, restore drill, caos y KMS real | NFR001-01, NFR001-02, NFR001-03, NFR001-04, NFR003-03, NFR005-02, NFR002-03, NFR004-02, FR005-13 | stack real con métricas, failover y línea base de carga |
| G3 · Freeze de auditoría | S12 | Tag de auditoría, trazabilidad generada, threat models y etiquetas de madurez | SEC-11, SEC-12, OPS-18, OPS-19, PANEL-07, DEC-10 | tag firmado y documentación consistente |
| G4 · Garantía externa | S15 | Revisión criptográfica, pentest sobre stage, remediación y retest | SEC-01, SEC-02, SEC-08 | evidencia independiente |
| G5 · Release firmada | S16 | Release integrity, feature gates y legal de la custodia si se habilita | REL-01, REL-02, REL-03, REL-04, OPS-20, DEC-12 | release verificable con los feature gates correctos |

G3 no empieza mientras haya cambios P0 pendientes de criptografía, custodia o continuidad. La custodia gestionada no se habilita en producción sin la aprobación legal (DEC-12).

## Plan de sprints

| Sprint | Fechas | Gate | Objetivo | Release | Tareas | SP equipo | SP con dependencia externa |
|---|---|---|---|---|---:|---:|---:|
| S9 | 2026-09-28 → 2026-10-09 | G0 | Main endurecido y v0.1.0 firmada | v0.1.0 | 25 | 43 | 8 |
| S10 | 2026-10-12 → 2026-10-23 | G1–G2 | Continuity Vault y stage en AWS | — | 14 | 30 | 17 |
| S11 | 2026-10-26 → 2026-11-06 | G1–G2 | Restauración sin relays y operación real | v0.2.0 | 12 | 43 | 8 |
| S12 | 2026-11-09 → 2026-11-20 | G2–G3 | Freeze de auditoría y v1.0.0-rc.1 | v1.0.0-rc.1 | 15 | 43 | 0 |
| S13 | 2026-11-23 → 2026-12-04 | G4 | Auditoría externa en campo | — | 7 | 8 | 4 |
| S14 | 2026-12-07 → 2026-12-18 | G4 | Informes externos y Nitro en Preview | — | 3 | 5 | 16 |
| S15 | 2027-01-04 → 2027-01-15 | G4 | Remediación, retest y v1.0.0-rc.2 | v1.0.0-rc.2 | 2 | 8 | 8 |
| S16 | 2027-01-18 → 2027-01-29 | G5 | v1.0.0 firmada para despliegues controlados | v1.0.0 | 2 | 1 | 3 |
| Diferido | sin fecha | — | Después de v1.0: fuera del programa de cierre | — | 26 | 90 | 15 |

Capacidad nominal del backlog: 50 SP por sprint. S13–S16 dejan capacidad para acompañar a los auditores y corregir lo que encuentren; lo que sobre puede adelantar trabajo de *Después de v1.0* siempre que se fusione después del tag v1.0.0. Del 21/12/2026 al 01/01/2027 no hay sprint. Los sprints S1–S8 quedan como histórico: todas sus tareas están hechas o pasan a S9–S16.

## Releases

| Release | Fecha | Nombre | Qué trae | Depende de |
|---|---|---|---|---|
| v0.1.0 | 2026-10-09 | Main endurecido y firmado | Descargar una versión firmada con cosign, con provenance SLSA y SBOM, y verificarla con un solo comando; usar el generador de llaves offline firmado siguiendo la guía air-gapped; instalar el stack self-hosted con imágenes reproducibles bit a bit; contar con G1, B1, B2, D1–D3 e IR-15 corregidos y un panel que no promete de más | Segunda persona que apruebe el waiver y los entornos; entorno release protegido |
| v0.2.0 | 2026-11-06 | Continuidad sin depender de los relays | Guardar tu historial cifrado en el Continuity Vault, con una llave de respaldo distinta de tu nsec; restaurar conversaciones y estados de entrega en un dispositivo nuevo aunque los relays estén vacíos; usar el mismo vault en self-hosted, sin el SaaS de Sedecim; probar el SaaS en un stage real en AWS con SLO, failover de RDS, pruebas de carga y restore drill | Credenciales de AWS y terraform apply en infrastructure |
| v1.0.0-rc.1 | 2026-11-20 | Candidato para la auditoría | Auditar un commit congelado y firmado, con documentación y trazabilidad que coinciden con el código; ver en la web, el CLI y el README qué es GA, Beta, Preview o Experimental; verificar un SBOM por imagen y los feature gates de producción | Vault y stage completos; threat models aprobados |
| v1.0.0-rc.2 | 2027-01-15 | Corregido tras la auditoría | Usar una versión con los hallazgos críticos y altos corregidos; consultar el informe del retest | Informes de SEC-01 y SEC-02 entregados a tiempo |
| v1.0.0 | 2027-01-29 | Primera release para despliegues controlados | Usar SaaS convenience, private-resilient e institucional como GA controlado, y self-hosted como GA técnico; activar la custodia gestionada básica si su revisión legal está aprobada; verificar una release sin waiver: informes externos, threat models aprobados, restore drills, fugas y firma; ver Marmot como Beta, el enclave como Preview, y Sovereign Tor y push como Experimental | Retest aprobado y segunda persona para las aprobaciones |

## S9 · Main endurecido y v0.1.0 firmada (G0, 2026-09-28 → 2026-10-09)

| ID | Cambio | Prio | Tarea | Tipo | SP | Depende de | Criterio de hecho | Quién desbloquea |
|---|---|---|---|---|---:|---|---|---|
| OPS-12 | Nueva | P0 | Gobierno del repositorio: proteger main, activar private vulnerability reporting y nombrar un segundo mantenedor | Infra | 1 | — | main exige 1 aprobación y los checks de CI, CodeQL y dependency-review; private vulnerability reporting activo; una segunda persona puede aprobar PRs y entornos | Admin del repo y owner de la organización |
| OPS-08 | Existente | P0 (antes P2) | Separación de funciones en releases (quién construye vs quién publica) | Infra | 1 | OPS-12 | Entorno release con aprobadores distintos al autor, «Prevent self-review», sin bypass de admin y protección de tags v* _(Pasa de P2 a P0 (GC-E01) y depende de OPS-12)_ | Admin del repo |
| OPS-10 | Existente | P2 | Backlog vivo en GitHub Issues con sincronización automática a docs/backlog | Infra | 3 | — | Cada tarea es un issue (milestone = sprint, labels de prioridad/epic/estado, campos Priority/Effort/fechas, sub-issues del epic y "blocked by"); un workflow regenera docs/backlog desde los issues y abre la PR de sync sin intervención, con Actions autorizado a abrir PRs. No bloquea el RC | Owner de la organización |
| OPS-17 | Nueva | P0 | Estados de evidencia y nada «Hecho» desde una rama | Infra | 3 | — | Estados Proposed, In PR, Merged, CI Verified, Stage Verified, Externally Audited y Production Enabled documentados en GITHUB.md y visibles en los issues; backlog-sync solo acepta Hecho si la evidencia cita un SHA ancestro de main y avisa del resto | Equipo |
| SEC-06 | Nueva | P0 | IR-15: ligar el payload sellado del mirror a su event_id con AAD versionado | Seguridad | 3 | — | Intercambiar ciphertext entre filas falla la autenticación; migración compatible hacia atrás probada; internal-review actualizado (IR-04, IR-05, IR-16, IR-19 e IR-20 ya se corrigieron en la PR #216) | Equipo |
| SEC-07 | Nueva | P1 | Vectores oficiales de NIP-44 y vectores JSON exportables | Seguridad | 2 | SEC-03 | nip44.vectors.json oficial corre en CI; vectores de NIP-44, NIP-49 y NIP-59 exportables en JSON para futuros clientes en otros lenguajes (ADR 0004) | Equipo |
| FR025-11 | Nueva | P0 | G1: las invitaciones a grupos seguros llegan con el secure relay real | Dev | 5 | FR025-07, FR016-01 | AUTH NIP-42 temprano en relays con nip42_dms (hoy nostr-rs-relay descarta en silencio los kind 1059 sin AUTH y los clientes solo se autentican bajo demanda); E2E de grupos en web y CLI contra nostr-rs-relay real en CI; relay_url correcto para el .onion | Equipo |
| FR005-12 | Nueva | P1 | Retirar el modo legado del managed-signer (token de servicio + x-account-id) | Seguridad | 1 | FR005-04 | Solo se firma con el token de Acceso o una sesión de dispositivo; test que rechaza el modo legado | Equipo |
| FR023-09 | Nueva | P0 | B1: editar una persona revocada no la reactiva; reactivar es explícito y auditado | Seguridad | 1 | FR023-03 | PUT /v1/subjects conserva suspended; ruta de reactivación con entrada de auditoría; test de regresión | Equipo |
| FR024-04 | Nueva | P0 | B2: el propagador de revocaciones no pierde eventos | Dev | 2 | FR024-01 | Cursor persistido sobre la auditoría o endpoint /v1/revocations; test con más de 100 entradas entre revocación y propagación sin pérdidas | Equipo |
| FR010-03 | Nueva | P1 | D1: un DM escrito sin red no queda mal enrutado | Dev | 3 | FR010-02 | No se cachea un descubrimiento vacío; la ruta 10050 se resuelve al publicar; relays de descubrimiento configurables; test offline→online | Equipo |
| FR011-04 | Nueva | P1 | D2: el cliente soberano reintenta lo pendiente al abrir sesión | Dev | 1 | FR011-02 | resume() al abrir la persona en el CLI; test entre dos procesos | Equipo |
| FR019-03 | Nueva | P1 | D3: los adjuntos de DM no conservan metadatos no saneables (HEIC con GPS) | Dev | 1 | FR019-02 | requireSanitizable también en DMs cuando stripFileMetadata está activo; E2E con un HEIC con GPS | Equipo |
| FR010-04 | Nueva | P1 | Avisar cuando el quorum supera el número de relays | Dev | 1 | FR010-01 | El panel y el motor rechazan o avisan en lugar de recortar el quorum en silencio | Equipo |
| FR004-06 | Nueva | P1 | Permisos NIP-46 completos para los kinds que firma la web | Dev | 1 | FR004-04 | WEB_NIP46_PERMISSIONS incluye 10063, 30443, 30078 y los demás kinds firmados; test que los contrasta | Equipo |
| PANEL-05 | Nueva | P1 | Panel veraz: perfil validado al crear persona, Tor-only sin clearnet en la web, declaraciones desde la custodia real | Dev | 3 | PANEL-04, FR028-01 | isValid al crear persona; con tor-only la web no lee relays ni publica 10050; disclosures según la custodia real (también en el CLI Tor); texto para stripFileMetadata; se retiran «Marmot fijada y auditada» y las promesas de tracing y crash reports; se añaden los avisos de alto riesgo que faltan en --high-risk y en los presets soberanos | Equipo |
| FR005-08 | Nueva | P1 | Textos de la custodia gestionada listos para la revisión legal | Dev | 3 | FR005-07 | Login sin «tu llave no sale del navegador» en managed; aviso de descifrado NIP-44 en servidor; enlace a los términos; consentimiento registrado con su versión | Equipo |
| DEC-10 | Reabierta | P1 | Formalizar threat models por perfil (convenience, resilient, institutional, sovereign, Tor) | Seguridad | 3 | — | Un documento por perfil con activos, adversarios, mitigaciones y riesgos residuales, y threat-model.md general al día; aprobados por alguien distinto del autor y versionados para v0.1.0; se vuelven a aprobar con el vault para el tag de auditoría (SEC-11) | Segunda persona (aprobación) |
| OPS-11 | Nueva | P1 | Corregir la deriva documental | Doc | 2 | — | README, notas v0.1.0, architecture.md, ADR 0002/0009, buzz-integration.md, institutional.md, threat-model.md, SECURITY.md y baseline del backlog coinciden con main; internal-review refleja la PR #216 | Equipo |
| BUZZ-07 | Nueva | P2 | Adoptar el pin de Buzz ac4521f3e464 (issue #201) tras revisar el changelog | Infra | 1 | BUZZ-05 | PR del pin fusionada con el gate de interoperabilidad en verde; ADR 0003 seguido | Equipo |
| REL-01 | Existente | P0 (antes P1) | Checklist de Definition of Done automatizado en el pipeline de release | Infra | 3 | NFR010-02, NFR003-02, FR020-03, DEC-10, OPS-08 | El primer tag ejecuta el gate completo (CI, interop, restore, fugas, evidencia de auditoría o waiver, SBOM y firma) y además comprueba threat models aprobados, alertas de CodeQL y Dependabot, la aprobación del waiver y --prerelease en -rc _(Pasa de P1 a P0 (GC-E03). Se quitan SEC-01 y SEC-02 (el gate ya exige informe o waiver) y se añaden DEC-10 y OPS-08)_ | Equipo |
| NFR010-02 | Existente | P0 (antes P1) | Firma de releases y provenance (SLSA/cosign) | Seguridad | 3 | OPS-08 | v0.1.0 publicada con imágenes y artefactos firmados con cosign keyless, provenance SLSA, SHA256SUMS y SBOM; verify-release.sh pasa desde fuera _(Pasa de P1 a P0 (GC-E02))_ | Equipo |
| FR003-06 | Existente | P1 | Firma de las releases del generador | Seguridad | 2 | FR003-02, NFR010-02 | keygen.html y keygen.mjs firmados en v0.1.0 y verificados con el procedimiento documentado | Equipo |
| FR003-07 | Existente | P1 (antes P2) | Guía de uso air-gapped verificable | Doc | 1 | FR003-06 | Procedimiento paso a paso (verificar checksum y firma, generar, verificar backup) ejecutado de punta a punta con el keygen firmado de v0.1.0 en un equipo sin red, con registro _(Pasa de P2 a P1 (GC-E05))_ | Equipo |
| REL-02 | Existente | P0 (antes P2) | Release notes con los cambios de trust model por release | Doc | 1 | REL-01 | Notas de v0.1.0 corregidas y publicadas como cuerpo del GitHub Release, con los cambios de confianza y privacidad explícitos _(Pasa de P2 a P0 (GC-E04))_ | Equipo |

## S10 · Continuity Vault y stage en AWS (G1–G2, 2026-10-12 → 2026-10-23)

| ID | Cambio | Prio | Tarea | Tipo | SP | Depende de | Criterio de hecho | Quién desbloquea |
|---|---|---|---|---|---:|---|---|---|
| VAULT-01 | Nueva | P0 | Continuity Vault: contrato y almacenamiento opaco, separado del indexer | Dev | 8 | FR027-03 | ADR del vault; servicio con API de sobres de archivo opacos por cuenta (subir, listar, bajar y borrar) autenticada con NIP-98 o Acceso, que rechaza texto plano como la bóveda de backup de FR027-03; separado del indexer; tests | Equipo |
| VAULT-02 | Nueva | P0 | Sobre de archivo cifrado en el cliente con una backup key separada de la nsec | Seguridad | 5 | VAULT-01 | Web y CLI sellan cada sobre en el cliente; la backup key es distinta de la nsec y viaja en el backup de identidad; restaurar con un logN excesivo se rechaza; test que demuestra que ni la base ni el object store contienen texto ni eventos legibles | Equipo |
| VAULT-07 | Nueva | P0 | Threat model y disclosure del Continuity Vault | Seguridad | 2 | VAULT-01 | Threat model del vault aprobado; la UI explica los metadatos que ve el operador (cuenta, tamaño y frecuencia) y que no tiene la llave de descifrado; textos incluidos en la revisión legal y de UX (FR028-02) | Equipo |
| NFR001-01 | Existente | P0 (antes P1) | Infraestructura como código del SaaS (Helm/Terraform) | Infra | 8 | OPS-02 | Stage desplegado con terraform apply en infrastructure y deploy de Kubernetes reales; smoke e interop contra los hosts de stage; kubeconform en CI _(Pasa de P1 a P0 (GC-C01))_ | Ops de Sedecim con credenciales AWS |
| NFR001-02 | Existente | P0 (antes P1) | Monitorización de SLO (99,9 % mensual) y alertas | Infra | 3 | NFR001-01 | Dashboard de disponibilidad y alertas por servicio desplegados en stage (Prometheus, Grafana, receptores y sonda externa); 7 días de señal útil antes del RC _(Pasa de P1 a P0 (GC-C02))_ | Responsable de guardias |
| NFR001-03 | Existente | P0 (antes P2) | Postgres de alta disponibilidad y backups gestionados | Infra | 3 | NFR001-01 | RDS aplicado y datos migrados; failover real y restore point probados en stage; runbook con los tiempos observados _(Pasa de P2 a P0 (GC-C03))_ | Ops / AWS |
| OPS-06 | Existente | P1 (antes P2 · antes 5 SP) | Servicio notification-gateway con perfiles de privacidad | Dev | 3 | DEC-08 | Push opaco sin contenido ni remitente y deshabilitado en perfiles Tor, detrás de un flag apagado por defecto donde el relay no permite un disparador seguro; la web no muestra avisos activos si el gateway no puede observar la actividad; ninguna solución da al gateway lectura de DMs ni metadatos adicionales; ADR 0010 con la matriz real por relay _(Se cierra por de-scope seguro (PRD, epic G): de 5 a 3 SP y de P2 a P1. El disparador completo espera a que se retome un cliente móvil (DEC-13))_ | Equipo |
| NFR009-02 | Existente | P1 (antes P2) | Corregir los hallazgos de accesibilidad y revisión manual con lector de pantalla | Dev | 3 | NFR009-01 | Informe de la revisión manual y correcciones aplicadas antes de la GA de la web _(Pasa de P2 a P1 (el PRD lo pide antes de la GA de la web))_ | Persona con lector de pantalla (NVDA/VoiceOver) |
| FR009-03 | Nueva | P1 | Acuses que llegan al emisor y DMs recibidos en segundo plano | Dev | 3 | FR009-02 | Los acuses se publican en los 10050 del emisor y llevan la operación a RECIPIENT_ACKED; suscripción de fondo a los 10050 propios | Equipo |
| FR017-06 | Nueva | P1 | El cliente soberano enruta DMs por 10050 y publica el suyo | Dev | 2 | FR017-04 | CLI con el mismo ruteo que la web y test de interoperabilidad web ↔ CLI | Equipo |
| FR014-05 | Nueva | P1 | El mirror comprueba la membresía NIP-29 y respeta la moderación | Dev | 3 | FR014-03 | Lecturas y búsqueda solo sobre canales de los que eres miembro; tombstone para kind 9005 | Equipo |
| FR006-06 | Nueva | P2 | Test de aislamiento de circuitos Tor por persona | QA | 1 | FR006-03 | Credenciales SOCKS distintas por persona verificadas contra un servidor SOCKS con autenticación | Equipo |
| FR021-03 | Nueva | P2 | Endurecimiento del modo Tor | Dev | 2 | FR020-01 | Opción onion-only en el cliente soberano, mensaje de fallo unificado «No enviado: red de privacidad no disponible» y relays sin IPs en los logs de los perfiles soberanos | Equipo |
| FR007-05 | Nueva | P2 | «Enviando como…» muestra el nivel de vínculo | Dev | 1 | FR007-03, FR006-02 | El banner del composer indica identidad, custodia, red y nivel de vínculo (ninguno, privado, selectivo o público) en la web y en el CLI | Equipo |

## S11 · Restauración sin relays y operación real (G1–G2, 2026-10-26 → 2026-11-06)

| ID | Cambio | Prio | Tarea | Tipo | SP | Depende de | Criterio de hecho | Quién desbloquea |
|---|---|---|---|---|---:|---|---|---|
| VAULT-03 | Nueva | P0 | Respaldo de eventos canónicos y restauración con relays vacíos | Dev | 5 | VAULT-02 | Se respaldan NIP-29, la copia propia de NIP-17, los eventos Marmot con el estado MLS necesario y el ledger/outbox; un dispositivo limpio con la backup key y relays vacíos reconstruye el 100 % del fixture de conversaciones y el ledger, en web y CLI, dentro de CI | Equipo |
| VAULT-04 | Nueva | P1 | El vault en la máquina de estados de entrega | Dev | 3 | VAULT-02 | Publicación en relays y subida al vault independientes; política off / best-effort / required-for-resilient en el panel; estado CONTINUITY_BACKED_UP separado del ACK de relays; solo required-for-resilient puede retener el envío | Equipo |
| VAULT-05 | Nueva | P1 | Retención, borrado y exportación del vault | Dev | 3 | VAULT-03 | Retención configurable; exportación portable; borrar elimina las copias del servidor según la política y queda documentado | Equipo |
| VAULT-06 | Nueva | P1 | Backend self-hosted del vault | Infra | 3 | VAULT-01 | El mismo contrato sobre almacenamiento local o S3-compatible (SeaweedFS del compose) sin depender del SaaS de Sedecim; incluido en el compose y en el restore drill | Equipo |
| OPS-18 | Nueva | P0 | Trazabilidad y estado generados desde la fuente, con check en CI | Infra | 5 | OPS-17 | requirements-traceability.md y un tablero de estado se regeneran desde los issues y el código; CI falla si una referencia o evidencia (archivo, prueba, SHA o ADR) no existe | Equipo |
| NFR003-03 | Nueva | P0 | Simulacro completo de RPO/RTO en stage | Infra | 3 | NFR001-03 | Restore nocturno de RDS (PITR) y del almacenamiento S3 con interop, más un drill manual en un entorno limpio con los tiempos reales documentados | Equipo |
| NFR005-02 | Existente | P0 (antes P3 · antes 3 SP) | Pruebas de carga del relay y el indexer | QA | 5 | NFR005-01, NFR001-01 | Throughput, p95/p99, saturación y límites medidos contra el Buzz de stage y el indexer en docs/load-testing.md; capacity baseline y estrategia de escalado de los relays aprobados _(Pasa de P3 a P0 y de 3 a 5 SP (GC-C04): absorbe la estrategia de escalado de relays y depende de NFR001-01)_ | Equipo |
| OPS-20 | Nueva | P0 | Feature gates de producción para managed, enclave y push | Seguridad | 3 | OPS-06, REL-01 | Con legal o auditoría pendientes, el onboarding managed no aparece en la configuración de producción; enclave y su exportación apagados mientras sean Preview; push apagado donde no hay disparador seguro; el gate de release comprueba la configuración | Equipo |
| FR026-04 | Nueva | P0 | Salida de la custodia, borrado verificable y derechos ARCO | Dev | 5 | FR026-01, FR005-13 | Cancelar sin migrar (API y UI) con confirmación y descarga del backup antes de borrar; npub en el JSON de migración; borrado por el operador de cuentas cerradas; ventanas de Secrets Manager y logs verificadas en AWS; el usuario ve el estado de eliminación | Equipo |
| FR023-10 | Nueva | P1 | Aplicar «publicar» por recurso en los relays | Dev | 8 | FR023-04 | Admisión por #h en el secure relay y en Buzz, y sincronía de la membresía NIP-29 con el policy-engine; test de denegación | Equipo |
| FR005-13 | Nueva | P0 | KMS y Secrets Manager validados en la cuenta y región reales | Seguridad | 3 | NFR001-01 | Crear, firmar y exportar-borrar contra AWS real en stage; IAM de mínimo privilegio revisado y documentado en ADR 0009 | Ops / AWS |
| NFR001-04 | Nueva | P1 | Alta disponibilidad en stage | Infra | 5 | NFR001-02, NFR001-03 | Réplicas y PDB; Redis, SeaweedFS y secure relay en HA o gestionados; blob-store con allowlist o cuotas; el SLO de 99,9 % queda instrumentado sobre una topología que puede cumplirlo | Ops / AWS |

## S12 · Freeze de auditoría y v1.0.0-rc.1 (G2–G3, 2026-11-09 → 2026-11-20)

| ID | Cambio | Prio | Tarea | Tipo | SP | Depende de | Criterio de hecho | Quién desbloquea |
|---|---|---|---|---|---:|---|---|---|
| SEC-11 | Nueva | P0 | Tag de auditoría firmado y v1.0.0-rc.1 | Seguridad | 3 | SEC-06, SEC-07, FR025-11, VAULT-03, VAULT-04, FR026-04, FR005-13, OPS-18, DEC-10, REL-01 | Tag audit-2026-11 firmado sobre main con internal-review, threat models y backlog sin contradicciones; v1.0.0-rc.1 publicada desde ese commit con el gate y waiver de auditoría; durante el trabajo de campo, cambiar cripto, custodia o continuidad exige waiver y nuevo baseline | Equipo |
| SEC-12 | Nueva | P0 | Inventario de la superficie de ataque de Buzz desplegado | Seguridad | 3 | NFR001-01, BUZZ-07 | Rutas y capacidades realmente alcanzables del Buzz de stage documentadas para el pentest; opcionales innecesarios deshabilitados | Equipo |
| PANEL-07 | Nueva | P0 | Etiquetas de madurez por perfil y función en web, CLI y documentación | Dev | 3 | PANEL-05 | Beta para Marmot/MLS, Experimental para Sovereign Tor y push, Preview para el enclave y ninguna GA de private-resilient sin el vault; visibles en la web, el CLI, el README y las notas de release; NIP-17 solo habilitado con el gate de interop en verde | Equipo |
| OPS-19 | Nueva | P1 | README con el estado por release, no con checkmarks | Doc | 2 | OPS-18, PANEL-07 | El README muestra el estado de cada perfil y capacidad por nivel de evidencia (Merged, CI, stage, auditado, producción), generado por OPS-18 y con la advertencia de no aptitud para alto riesgo | Equipo |
| NFR010-04 | Nueva | P1 | SBOM fiel a cada imagen | Infra | 3 | NFR010-01 | SBOM por imagen (syft) atestado, sin devDependencies en runtime; también para la imagen de Buzz fijada | Equipo |
| OPS-13 | Nueva | P2 | Higiene de la cadena de suministro en CI | Infra | 2 | OPS-05 | Acciones por SHA, imágenes por digest, checksums de herramientas, Dependabot para infra/tor y compose, npm audit y CodeQL como gate | Equipo |
| NFR002-03 | Nueva | P1 | Simulacros de fallo de dependencias en stage | QA | 5 | NFR001-04 | Caída de un relay, de una réplica del indexer, failover de Postgres y object storage degradado no corrompen la outbox ni los estados; 0 LOCAL_PERSISTED perdidos en las pruebas de crash | Equipo |
| NFR004-02 | Existente | P0 (antes P3) | Dashboard de latencia y degradación sin ocultarla | Infra | 2 | NFR004-01, NFR001-02 | Panel P95/P99 por relay con alertas de degradación en vivo en stage, con scrape por pod del indexer (hoy mide una sola réplica) _(Pasa de P3 a P0: el PRD lo incluye en GC-C02)_ | Equipo |
| FR005-11 | Nueva | P1 | Recuperar la persona gestionada en un navegador nuevo | Dev | 3 | FR005-04 | Con el login de Acceso se reabre la llave gestionada; el usuario ve su log de uso y revoca sus sesiones | Equipo |
| FR024-05 | Nueva | P1 | Rotaciones como servicio, sesiones de dispositivo en la web y runbook de pérdida | Dev | 5 | FR024-02, FR024-04 | Worker de rotaciones en compose y k8s; la persona managed de la web usa sesiones de dispositivo revocables; docs/runbooks/device-loss.md | Equipo |
| FR024-03 | Reabierta | P2 | Revocar sesiones NIP-46 y tokens de managed-signer ligados al dispositivo | Dev | 2 | FR024-01, FR005-04, FR024-04, FR024-05 | Tras revocar, el signer rechaza al dispositivo también en la web y sin depender de que alguien ejecute el CLI | Equipo |
| FR023-12 | Nueva | P2 | Auditoría y retención legal coherentes con el modelo de confidencialidad | Dev | 3 | FR023-08 | Retención propia para las entradas de evaluate; legal hold solo donde el modelo lo permite; reemplazables respetan la retención legal | Equipo |
| FR023-13 | Nueva | P2 | CI del modo institucional | QA | 2 | OPS-07 | El perfil institutional del compose y el componente k8s se validan en CI; E2E de la consola contra el policy-engine real | Equipo |
| FR011-05 | Nueva | P2 | Identificador de operación estable en la UI | Dev | 2 | FR011-01 | Reintentar desde la web o el CLI no crea otro evento ni otro rumor; los wraps se crean después de persistir | Equipo |
| FR025-12 | Nueva | P1 | Outbox para mensajes y commits MLS | Dev | 3 | FR025-11 | Con Tor caído o sin red, un mensaje o commit de grupo queda pendiente y se reintenta, en lugar de fallar | Equipo |

## S13 · Auditoría externa en campo (G4, 2026-11-23 → 2026-12-04)

| ID | Cambio | Prio | Tarea | Tipo | SP | Depende de | Criterio de hecho | Quién desbloquea |
|---|---|---|---|---|---:|---|---|---|
| DEC-12 | Existente | P1 | Aprobación legal de los términos de custodia managed y del aviso de privacidad | Decisión | 1 | DEC-09, FR005-08 | Asesoría legal aprueba docs/legal/custodia-managed.md y el aviso de privacidad, versionados, antes de habilitar managed en producción _(Depende de FR005-08: la revisión parte de los textos corregidos. Bloquea solo si managed se habilita)_ | Asesoría legal (LFPDPPP) |
| FR028-02 | Existente | P1 (antes P2) | Revisión legal/UX de los textos de disclosure | Doc | 2 | FR028-01, DEC-09, PANEL-05, VAULT-07, PANEL-07 | Textos aprobados por legal y UX y versionados, incluidos los del vault y las etiquetas de madurez _(Pasa de P2 a P1 y depende de PANEL-05, VAULT-07 y PANEL-07)_ | Asesoría legal y UX |
| DEC-11 | Existente | P2 | Búsqueda y registro de la marca "Acceso Nostr" | Decisión | 1 | DEC-01 | Búsqueda de anterioridades y solicitud de registro presentada, o marca alternativa decidida | Abogado de propiedad intelectual |
| FR020-05 | Nueva | P1 | Suite de fugas completa en el cliente soberano | Seguridad | 3 | FR020-03 | La captura real también cubre dm, group, media y rotation-worker, con MLS por Tor; control negativo de ts-mls rc.10 en CI | Equipo |
| NFR006-04 | Nueva | P3 | Escaneo de secretos en logs con todos los perfiles | QA | 2 | NFR006-03 | El job stack también levanta managed, push, institutional y tor y escanea sus logs | Equipo |
| FR011-06 | Nueva | P2 | Métricas de outbox reales o alerta retirada | Infra | 2 | FR011-03 | La alerta OutboxOldestPendingTooOld se alimenta de un proceso real o se retira del monitoreo del SaaS | Equipo |
| DEC-15 | Nueva | P3 | Estructura de repositorios | Decisión | 1 | — | ADR que justifica el monorepo frente a los seis repositorios sugeridos por el scope | Equipo |

## S14 · Informes externos y Nitro en Preview (G4, 2026-12-07 → 2026-12-18)

| ID | Cambio | Prio | Tarea | Tipo | SP | Depende de | Criterio de hecho | Quién desbloquea |
|---|---|---|---|---|---:|---|---|---|
| SEC-01 | Existente | P0 | Revisión criptográfica independiente (NIP-44/49/59, MLS, key service) | Seguridad | 8 | SEC-03, FR005-03, SEC-06, SEC-07, SEC-11 | Informe independiente sobre el tag de auditoría (NIP-44/49/59, MLS, key service y vault) sin hallazgos críticos abiertos _(Se quita FR025-08 (MLS estable bloquea la etiqueta high-security, no el core) y se añaden SEC-06, SEC-07 y SEC-11)_ | Auditor criptográfico externo (10–15 persona-día) |
| FR005-05 | Existente | P1 (antes P3) | Tier enclave: firma dentro de Nitro Enclave con KMS condicionado por attestation | Dev | 8 | FR005-02, DEC-09 | EIF reproducible con PCR medidos en CI, attestation y KMS condicionado probados en una instancia Nitro real y alarma CloudTrail; sigue etiquetado Preview y apagado en producción (OPS-20) _(Pasa de P3 a P1 (GC-D04). No bloquea la custodia gestionada básica ni v1.0.0)_ | AWS: instancia Nitro y KMS |
| OPS-14 | Nueva | P2 | Documentación del SDK y de las APIs | Doc | 5 | — | TypeDoc de los paquetes, OpenAPI de cada servicio y ADR sobre cómo se distribuye el SDK | Equipo |

## S15 · Remediación, retest y v1.0.0-rc.2 (G4, 2027-01-04 → 2027-01-15)

| ID | Cambio | Prio | Tarea | Tipo | SP | Depende de | Criterio de hecho | Quién desbloquea |
|---|---|---|---|---|---:|---|---|---|
| SEC-08 | Nueva | P0 | Corregir los hallazgos críticos y altos de SEC-01 y SEC-02 | Seguridad | 8 | SEC-01 | Cada crítico o alto con corrección, test de regresión y verificación del auditor; medios con plan o aceptación explícita; v1.0.0-rc.2 publicada para el retest | Equipo |
| SEC-02 | Existente | P0 | Pentest de API, relay, key service y cliente | Seguridad | 8 | OPS-02, FR005-04, FR023-03, NFR001-01, SEC-11, SEC-12, SEC-08 | Pentest sobre stage (API, relays con Buzz desplegado, key service y cliente); críticos y altos corregidos y verificados en el retest; medios con plan o aceptación _(Se añaden NFR001-01 (el pentest es sobre stage), SEC-11, SEC-12 y SEC-08 (el retest verifica las correcciones))_ | Pentester externo (10–15 persona-día + retest) |

## S16 · v1.0.0 firmada para despliegues controlados (G5, 2027-01-18 → 2027-01-29)

| ID | Cambio | Prio | Tarea | Tipo | SP | Depende de | Criterio de hecho | Quién desbloquea |
|---|---|---|---|---|---:|---|---|---|
| REL-04 | Nueva | P1 | Revisión final de afirmaciones y etiquetas de madurez | Doc | 1 | PANEL-07, OPS-19, SEC-08 | Ninguna función parcial aparece como GA; Sovereign Tor sigue Experimental y el README conserva la advertencia de no aptitud para alto riesgo; notas de trust model de v1.0.0 | Equipo |
| REL-03 | Nueva | P0 | v1.0.0 firmada con la Definition of Done completa y sin waiver | Infra | 3 | SEC-01, SEC-02, SEC-08, REL-01, OPS-20, NFR003-03, REL-04 | Informes externos en docs/security/audits/v1.0.0.md, threat models aprobados, restore drills self-hosted y SaaS, fugas, artefactos firmados con SBOM y provenance, y feature gates de producción correctos | Segunda persona (aprobaciones del release) |

## Diferido · Después de v1.0: fuera del programa de cierre

| ID | Cambio | Prio | Tarea | Tipo | SP | Depende de | Criterio de hecho | Quién desbloquea |
|---|---|---|---|---|---:|---|---|---|
| FR025-08 | Existente | P2 | Migrar a marmot-ts v2 / ts-mls estable cuando se publiquen | Dev | 3 | FR025-04 | Dependencias estables con conformidad y autoprueba en verde, o excepción documentada. Hace falta para la etiqueta high-security, no para v1.0 _(Sale del programa: bloquea la etiqueta high-security, no el core (PRD))_ | Upstream: ts-mls 2.0.0 y marmot-ts 1.0 |
| SEC-10 | Nueva | P1 | Revisión criptográfica delta de MLS estable | Seguridad | 3 | FR025-08 | Informe externo del delta tras FR025-08 sin críticos abiertos; requisito de la etiqueta high-security | Auditor criptográfico externo |
| FR005-09 | Nueva | P1 | Exportar desde el enclave exige una prueba del usuario verificada dentro del enclave | Seguridad | 5 | FR005-05 | JWT con JWKS fijado en la imagen o firma de la llave de destino; sin ella el enclave se niega; test. Requisito para sacar el enclave de Preview | Equipo |
| FR005-10 | Nueva | P2 | Importar al enclave sin exponer la llave ni la contraseña al padre | Seguridad | 3 | FR005-05 | El ncryptsec se cifra hacia la clave atestada del enclave; test | Equipo |
| NFR001-05 | Nueva | P1 | Entorno de producción del SaaS | Infra | 8 | NFR001-04, OPS-20 | Overlay de producción con la topología HA probada en stage, los feature gates de OPS-20, sonda externa y el SLO de 99,9 % medido | Ops / AWS |
| NFR003-04 | Nueva | P2 | Copia en una segunda región para el tier institucional | Infra | 5 | NFR001-03, NFR003-01 | Datos y WAL replicados según el RPO/RTO aprobado; restauración probada | Equipo |
| FR006-04 | Nueva | P2 | Perfil público por persona (kind 0: nombre y avatar) | Dev | 3 | FR006-02 | Se publica y se muestra en canales, DMs y grupos; en perfiles seudónimos no se publica nada salvo elección explícita | Equipo |
| FR014-04 | Nueva | P2 | La web usa el mirror: no leídos por canal y búsqueda | Dev | 3 | FR014-05, FR023-05 | Contadores de no leídos y búsqueda en la web vía NIP-98, respetando la política | Equipo |
| FR015-04 | Nueva | P2 | Reacciones, hilos y borrado en canales | Dev | 5 | FR015-02 | Kinds 7, respuestas con e/q y borrado 5/9005 en la web, con E2E contra Buzz | Equipo |
| PANEL-06 | Nueva | P2 | Expiración de mensajes por perfil (NIP-40) y borrado con aviso | Dev | 5 | PANEL-02, VAULT-05 | Expiración configurable por persona y conversación; borrar mensajes propios con el aviso de que las copias replicadas pueden seguir existiendo; coherente con la retención del vault | Equipo |
| FR006-07 | Nueva | P2 | Compartimentación: avisar antes de reutilizar un contacto o un archivo entre personas | Dev | 3 | FR006-01 | Aviso con confirmación explícita en la web y en el CLI, también para archivos (recordUsage) | Equipo |
| FR025-14 | Nueva | P2 | Grupos completos en la web: multi-dispositivo, rotación, propuestas y media cifrada | Dev | 5 | FR025-11 | Lo que hoy solo ofrece el CLI (FR025-05/06/09 y rotate) disponible en «Grupos seguros» | Equipo |
| FR023-11 | Nueva | P2 | Device trust en uso: passkey del propio usuario | Dev | 5 | FR023-07 | El usuario registra la passkey en su dispositivo y cada sesión pide una aserción WebAuthn | Equipo |
| FR004-08 | Nueva | P2 | Cliente soberano con signer NIP-46 e importación de nsec/ncryptsec | Dev | 3 | FR004-01 | Perfiles Tor con signer externo (§14: offline/signer) y custodia declarada según la llave real | Equipo |
| FR020-06 | Nueva | P2 | Cliente soberano como servicio del perfil tor | Infra | 2 | FR021-02 | docker compose run --rm sovereign … con TOR_SOCKS=tor:9050, documentado | Equipo |
| DEC-14 | Nueva | P2 | Modelo comercial del SaaS: organizaciones, planes y facturación | Decisión | 1 | — | ADR con el modelo de tenants, planes y proveedor de cobro | Dirección |
| OPS-15 | Nueva | P2 | Organizaciones y planes en el SaaS | Dev | 8 | DEC-14 | Tenants y organizaciones en identity y policy; planes y cobro según DEC-14 | Equipo |
| OPS-16 | Nueva | P3 | Webhooks y eventos para integraciones empresariales | Dev | 5 | — | El policy-engine emite eventos firmados (sustituye el sondeo de la auditoría); webhooks con reintentos | Equipo |
| NFR007-02 | Nueva | P3 | Tracing con muestreo y redacción según el perfil | Dev | 3 | NFR007-01 | Trazas en los servicios con muestreo y redacción, apagadas en perfiles Tor. Hasta entonces PANEL-05 retira la promesa | Equipo |
| NFR007-03 | Nueva | P3 | Crash reports opt-in con limpieza y exportación manual local | Dev | 3 | NFR007-01 | Implementados según el perfil. Hasta entonces PANEL-05 retira la promesa | Equipo |
| DEC-13 | Nueva | P2 | ADR de un aviso de notificación separado del mensaje | Decisión | 1 | OPS-06 | Diseño evaluado cuando se retome un cliente móvil; no bloquea el RC | Equipo |
| FR015-05 | Nueva | P3 | Presencia (NIP-38) opt-in por perfil | Dev | 3 | — | Estado de presencia solo en perfiles que lo permiten | Equipo |
| FR013-05 | Nueva | P3 | Caché local cifrada de eventos y NIP-77 con estado local | Dev | 5 | — | Lectura sin conexión, reanudación por since y NIP-77 con conjunto local (interop con strfry) | Equipo |
| FR018-06 | Nueva | P3 | Política de tamaño, MIME y antivirus compatible con la confidencialidad | Doc | 2 | — | Política documentada y comprobación de tamaño en el cliente | Equipo |
| FR004-07 | Nueva | P3 | Signer de hardware (opcional en el scope) | Dev | 5 | — | Spike con un dispositivo de hardware y decisión documentada | Equipo |
| FR020-02 | Existente | P3 | Cliente desktop dedicado con Tor embebido | Dev | 8 | DEC-04 | App desktop (Tauri) que usa el SDK con Tor integrado y el perfil sovereign-tor _(Sin cambios en el issue: el PRD deja el cliente de escritorio propio para un PRD aparte)_ | Equipo |

### Después de v1.0, por tema

- **Experiencia en la web:** FR006-04, FR014-04, FR015-04, PANEL-06, FR025-14, FR015-05.
- **SaaS comercial y producción:** NFR001-05, DEC-14, OPS-15, OPS-16, NFR003-04.
- **Custodia y soberanía:** FR005-09, FR005-10, FR004-08, FR020-06, FR006-07, FR023-11, FR004-07.
- **Madurez de Marmot:** FR025-08, SEC-10.
- **Observabilidad y datos:** NFR007-02, NFR007-03, FR013-05, FR018-06, DEC-13.

## Fuera de este programa

El PRD los excluye: no se crean issues ni dependencias de release. El SDK, los protocolos y las APIs conservan la compatibilidad para retomarlos en un PRD aparte.

| Qué | Alcance | En el borrador anterior |
|---|---|---|
| App móvil propia | Núcleo Rust, app iOS y Android, push nativo, grupos y backup en el móvil, TestFlight y Google Play, y la web instalable (PWA) | APP-01…07 |
| App de escritorio propia | Tor embebido, interfaz, binarios firmados y pruebas de fugas del binario. FR020-02 sigue en Diferido como referencia | FR020-04, FR020-07, FR020-08, FR020-09 |
| Buzz Desktop y Mobile como early release | El PRD lo trata aparte; sí se puede probar interoperabilidad | BUZZ-08 |
| Aptitud para alto riesgo | Auditoría independiente de fugas de metadatos ligada a un cliente dedicado futuro | SEC-09 |
| Estrategia de clientes nativos | La decide el propio PRD | DEC-13 del borrador anterior |

Tareas del borrador anterior que se integran en otras:

- **NFR005-03**: el escalado de relays entra en NFR005-02 (capacity baseline).
- **FR027-04**: el backup completo de la web y la reconstrucción del historial pasan a VAULT-02 y VAULT-03; el npub del JSON de migración, a FR026-04.

## Del PRD al backlog

| Epic del PRD | Requisito | Tarea |
|---|---|---|
| A · Hardening y freeze de auditoría | GC-A01 | PR #216 (fusionada) |
| A · Hardening y freeze de auditoría | GC-A02 | SEC-06 (S9) |
| A · Hardening y freeze de auditoría | GC-A03 | OPS-20 (S11), FR005-09 (después de v1.0) |
| A · Hardening y freeze de auditoría | GC-A04 | SEC-11 (S12) |
| A · Hardening y freeze de auditoría | GC-A05 | SEC-01 (S14) |
| A · Hardening y freeze de auditoría | GC-A06 | SEC-02 (S15), SEC-08 (S15) |
| A · Hardening y freeze de auditoría | GC-A07 | SEC-12 (S12) |
| B · Encrypted Continuity Vault | GC-B01 | VAULT-01 (S10) |
| B · Encrypted Continuity Vault | GC-B02 | VAULT-02 (S10) |
| B · Encrypted Continuity Vault | GC-B03 | VAULT-03 (S11) |
| B · Encrypted Continuity Vault | GC-B04 | VAULT-04 (S11) |
| B · Encrypted Continuity Vault | GC-B05 | VAULT-05 (S11) |
| B · Encrypted Continuity Vault | GC-B06 | VAULT-06 (S11) |
| B · Encrypted Continuity Vault | GC-B07 | VAULT-07 (S10) |
| C · Stage y operación real | GC-C01 | NFR001-01 (S10) |
| C · Stage y operación real | GC-C02 | NFR001-02 (S10), NFR004-02 (S12) |
| C · Stage y operación real | GC-C03 | NFR001-03 (S10) |
| C · Stage y operación real | GC-C04 | NFR005-02 (S11) |
| C · Stage y operación real | GC-C05 | NFR003-03 (S11) |
| C · Stage y operación real | GC-C06 | NFR002-03 (S12) |
| D · Custodia gestionada | GC-D01 | DEC-12 (S13) |
| D · Custodia gestionada | GC-D02 | FR005-13 (S11) |
| D · Custodia gestionada | GC-D03 | FR026-04 (S11) |
| D · Custodia gestionada | GC-D04 | FR005-05 (S14) |
| D · Custodia gestionada | GC-D05 | OPS-20 (S11) |
| E · Release y cadena de suministro | GC-E01 | OPS-08 (S9), OPS-12 (S9) |
| E · Release y cadena de suministro | GC-E02 | NFR010-02 (S9), NFR010-04 (S12) |
| E · Release y cadena de suministro | GC-E03 | REL-01 (S9) |
| E · Release y cadena de suministro | GC-E04 | REL-02 (S9) |
| E · Release y cadena de suministro | GC-E05 | FR003-06 (S9), FR003-07 (S9) |
| E · Release y cadena de suministro | GC-E06 | OPS-10 (S9) |
| F · Fuente única de verdad | GC-F01 y F02 | OPS-17 (S9) |
| F · Fuente única de verdad | GC-F03 | OPS-18 (S11) |
| F · Fuente única de verdad | GC-F04 | OPS-19 (S12) |
| F · Fuente única de verdad | GC-F05 | OPS-11 (S9), SEC-11 (S12) |
| G · Push por de-scope seguro | GC-G01 | OPS-06 (S10), OPS-20 (S11) |
| G · Push por de-scope seguro | GC-G02 | OPS-06 (S10) |
| G · Push por de-scope seguro | GC-G03 | DEC-13 (después de v1.0) |
| H · Madurez y claims | Etiquetas | PANEL-05 (S9), PANEL-07 (S12), REL-04 (S16) |

## Tareas nuevas por epic

| Epic | Nuevas | SP | En el programa | Después de v1.0 |
|---|---:|---:|---:|---:|
| OPS · Despliegue y DevSecOps | 10 | 36 | 8 | 2 |
| SEC/REL · Gates de seguridad y release | 8 | 26 | 7 | 1 |
| FR · Grupos high-security (Marmot/MLS) | 3 | 13 | 2 | 1 |
| FR · Identidad, llaves y custodia | 12 | 36 | 7 | 5 |
| FR · Modo institucional | 7 | 26 | 6 | 1 |
| FR · Mensajería, entrega y resiliencia | 14 | 36 | 9 | 5 |
| PANEL · Panel de soberanía y privacidad | 3 | 11 | 2 | 1 |
| BUZZ · Early release sobre Buzz | 1 | 1 | 1 | 0 |
| VAULT · Encrypted Continuity Vault | 7 | 29 | 7 | 0 |
| FR · Privacidad y Sovereign Tor | 5 | 11 | 3 | 2 |
| NFR · Requisitos no funcionales | 9 | 37 | 5 | 4 |
| DEC · Decisiones de arquitectura | 3 | 3 | 1 | 2 |

La epic **VAULT · Encrypted Continuity Vault** es nueva: agrupa los requisitos GC-B01…B07 del PRD.

## Dependencias externas

| Qué hace falta | Por qué | Quién | Para cuándo |
|---|---|---|---|
| Segunda persona con rol de aprobador | Aprueba el waiver, las aprobaciones de entorno de cada release, las reviews de PR y los threat models; sin ella la separación de funciones es nominal | Dirección (hay otros dos admins en la organización) | S9 |
| Ajustes de GitHub | Protección de main, entorno release, Actions que abren PRs y private vulnerability reporting | Admin del repo / owner de la organización | S9 |
| Credenciales de AWS y terraform apply en infrastructure | Bloquean stage, KMS real, el restore drill, los simulacros, el pentest sobre stage y Nitro | Ops de Sedecim | S9–S10 |
| Auditor criptográfico y pentester | SEC-01 y SEC-02 exigen informes externos sobre el tag de auditoría; contratar lleva semanas | Dirección (presupuesto) | Contrato en S9–S10, campo en S13–S14, retest en S15 |
| Asesoría legal (LFPDPPP) y UX | Términos de custodia gestionada, aviso de privacidad, textos de disclosure y los del vault. Sin aprobación, managed no se habilita en producción | Legal | Envío en S9 y S12, aprobación en S13 |
| Abogado de propiedad intelectual | Búsqueda y registro de la marca | Legal | S9 (el registro tarda meses) |
| Revisor con lector de pantalla | NFR009-02 pide revisión manual con NVDA/VoiceOver antes de la GA de la web | Producto | S10 |
| Instancia Nitro en AWS | FR005-05 (Preview); no bloquea v1.0.0 | Ops de Sedecim | S14 |
| Versiones estables de ts-mls y marmot-ts | FR025-08; bloquean la etiqueta de alta seguridad de los grupos, no v1.0.0 | Upstream | Después de v1.0 |

## Cómo se aplicó

1. **docs/backlog** (PR #218): añadió S9–S16 a `meta.sprints`, renombró `Diferido` a «Después de v1.0: fuera del programa de cierre», actualizó `meta.baseline`, `meta.version` y `meta.source`, creó las 82 tareas nuevas y aplicó los cambios a las 21 existentes (milestone, prioridad, SP, criterio y dependencias) y a las 2 reabiertas.
2. **Siembra** (28/09/2026): al fusionar #218, `backlog-sync` corrió `seed`. Creó los milestones #11–#18 (S9–S16), renombró el #10 (Diferido), creó la epic #219 (`[Epic] VAULT · Encrypted Continuity Vault`) y los issues #220–#301 con labels, campos, sub-issues y 182 relaciones.
3. **Issues existentes**: se actualizaron las 21 existentes (milestone, prioridad, cuerpo y campos) y se reabrieron DEC-10 (#45) y FR024-03 (#169) con `status:parcial`. FR020-02 no cambió. El orden de las ediciones mantuvo válido el backlog en cada paso. El criterio de NFR001-01 dice «Stage desplegado con terraform apply…» porque la herramienta que editó el issue alteraba una línea que empezaba por el comando.
4. **Pendiente**: lanzar `backlog-sync` con `seed` (*Actions → Run workflow*) para alinear los «blocked by» de los issues existentes con su sección *Depende de*: 17 enlaces por añadir y 3 por retirar (REL-01 ← SEC-01 y SEC-02; SEC-01 ← FR025-08). La integración con la que se aplicó el replanteo no puede disparar workflows. El backlog ya es correcto, porque el validador lee *Depende de*.
5. **Sincronización**: la PR #302 trae a `docs/backlog` los números de issue que dejó la sincronización; con ella, `backlog.json` coincide con GitHub Issues.
