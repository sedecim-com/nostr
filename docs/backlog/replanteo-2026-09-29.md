# Replanteo de sprints desde el corte del 29 de septiembre de 2026

> Base: `main@138d242` (tras las PR #321, #322 y #324 a #327) y los issues del backlog a 2026-09-29.
> Actualiza el [replanteo del 27 de septiembre](replanteo-2026-09-27.md) en los sprints, las releases y los gates G1 y G2. Lo demás sigue igual: las decisiones del PRD, la madurez que declarará v1.0, lo que queda fuera del programa y las dependencias externas.
> `backlog.json`, `README.md` y `backlog.csv` se generan desde GitHub Issues. La sección *Cómo se aplicó* describe cómo llegó el replanteo a los issues.

## Resumen

- En los dos primeros días de S9 entraron en main 29 de las 80 tareas del programa (76 de sus 245 SP), cada una con su commit en main como evidencia: 15 de S9, 9 de S10 y 5 de S11. Ya están en main todo el código del Continuity Vault (VAULT-01 a VAULT-06) y los feature gates de producción (OPS-20).
- El código que falta cabe en S9 y S10. Desde rc.1, las fechas no las marca el desarrollo sino terceros: una segunda persona, AWS, legal y los auditores.
- Se mantienen el feature freeze hasta RC1, los gates G0–G5 y la fecha de v1.0.0, el 29/01/2027. Cambian cuatro cosas, descritas abajo.
- 21 tareas cambian de sprint y entran 2 nuevas, OPS-21 y SEC-13. El programa pasa a 82 tareas y 252 SP. Quedan abiertas 53 tareas y 176 SP:
  - 68 SP que el equipo puede cerrar sin esperar a nadie;
  - 108 SP que dependen de terceros.

## Qué cambia

### 1. El código sin bloqueo se hace en S9 y S10

Se adelantan 18 tareas:

| Desde | Tareas | Pasan a |
|---|---|---|
| S11 | OPS-18 | S9 |
| S11 | FR023-10 | S10 |
| S12 | PANEL-07, OPS-19, NFR010-04, OPS-13 | S9 |
| S12 | FR024-05, FR024-03, FR005-11, FR025-12, FR023-12, FR023-13, FR011-05 | S10 |
| S13 | FR011-06, FR020-05, NFR006-04, DEC-15 | S10 |
| S14 | OPS-14 | S10 |

FR026-04 (salida de la custodia) se queda en S11. Su criterio de hecho pide verificar en AWS las ventanas de Secrets Manager y de los logs, y depende de FR005-13. Su código puede adelantarse, pero la tarea se cierra con el stage.

### 2. v0.2.0 ya no espera a AWS

Antes, v0.2.0 era «Continuidad sin depender de los relays», con el vault y el stage, el 06/11/2026. El vault ya está en main, así que entra en v0.1.0. v0.2.0 pasa a ser la release con todo el código del programa, el 23/10/2026, al cerrar S10. El stage sigue siendo condición de rc.1 (G2).

### 3. S11 y S12 dependen de AWS

S11 reúne lo que necesita el stage:

- alta disponibilidad en stage (NFR001-04), el simulacro de RPO/RTO (NFR003-03) y las pruebas de carga (NFR005-02);
- el KMS real (FR005-13) y la salida de la custodia (FR026-04);
- los simulacros de fallo de dependencias (NFR002-03) y el dashboard de latencia (NFR004-02), que vienen de S12;
- el inventario de Buzz (SEC-12), que también viene de S12.

Además entra SEC-13. S12 congela el código y corta rc.1 (SEC-11).

Si las credenciales de AWS llegan después del 12/10/2026, rc.1, rc.2 y v1.0.0 se retrasan lo mismo.

La capacidad del equipo que queda libre en S11 y S12, unos 60 SP (más si AWS se retrasa), se usa en dos cosas:

- corregir lo que salga del stage y de la segunda revisión interna (SEC-13);
- preparar la auditoría: alcance, threat models y trazabilidad.

No se adelantan funciones de *Después de v1.0*. Lo que se adelante después de rc.1 se fusiona tras el tag v1.0.0, para no alterar lo auditado.

### 4. Fechas límite para lo externo

| Dependencia | Qué bloquea | Fecha límite |
|---|---|---|
| Segunda persona y OPS-12 | v0.1.0 y v0.2.0 (waiver, entornos y release protegida), DEC-10, VAULT-07, REL-03 | 2026-10-09 |
| Credenciales de AWS y `terraform apply` (NFR001-01) | Stage, KMS real, restore drill en stage, simulacros, pentest sobre stage y Nitro | 2026-10-12 |
| Términos, disclosures y textos del vault enviados a legal | DEC-12, FR028-02 | 2026-10-23 |
| Contrato del auditor y del pentester | SEC-01 y SEC-02 en campo en S13–S14 | 2026-11-06 |

Si una dependencia llega tarde, su release se retrasa lo mismo. Nunca se recorta un gate.

## Gates

G1 y G2 cierran un sprint antes:

| Gate | Antes | Ahora | Motivo |
|---|---|---|---|
| G1 · Continuidad completa | S11 | S10 | VAULT-01 a VAULT-06 ya están en main; falta aprobar el threat model del vault (VAULT-07) |
| G2 · Stage real | S12 | S11 | El trabajo del stage se reúne en S11 |

G3 sigue en S12, pero OPS-18, OPS-19 y PANEL-07 se adelantan a S9, y SEC-12 a S11. En S12 quedan el tag (SEC-11) y la aprobación de los threat models (DEC-10). SEC-11 depende ahora también de SEC-13.

## Plan de sprints

| Sprint | Fechas | Gate | Objetivo | Release | Abiertas | SP equipo | SP con dependencia externa |
|---|---|---|---|---|---:|---:|---:|
| S9 | 2026-09-28 → 2026-10-09 | G0 | Código de la auditoría y v0.1.0 firmada | v0.1.0 | 16 | 22 | 15 |
| S10 | 2026-10-12 → 2026-10-23 | G1 | Resto del código, vault aprobado y v0.2.0 | v0.2.0 | 18 | 41 | 19 |
| S11 | 2026-10-26 → 2026-11-06 | G2 | Stage real en AWS | — | 9 | 5 | 31 |
| S12 | 2026-11-09 → 2026-11-20 | G3 | Freeze de auditoría y v1.0.0-rc.1 | v1.0.0-rc.1 | 1 | 0 | 3 |
| S13 | 2026-11-23 → 2026-12-04 | G4 | Auditoría en campo y aprobación legal | — | 3 | 0 | 4 |
| S14 | 2026-12-07 → 2026-12-18 | G4 | Informes externos y Nitro en Preview | — | 2 | 0 | 16 |
| S15 | 2027-01-04 → 2027-01-15 | G4 | Remediación, retest y v1.0.0-rc.2 | v1.0.0-rc.2 | 2 | 0 | 16 |
| S16 | 2027-01-18 → 2027-01-29 | G5 | v1.0.0 firmada para despliegues controlados | v1.0.0 | 2 | 0 | 4 |

*Abiertas* cuenta las tareas pendientes o parciales al aplicar el replanteo. Las tareas hechas conservan su sprint, así que S9, S10 y S11 incluyen también 15, 9 y 5 tareas hechas. SEC-06 cuenta como abierta hasta que se fusione la PR #329.

### Qué queda en cada sprint

- **S9.**
  - Código del equipo: SEC-06 (PR #329), SEC-07, OPS-18, PANEL-07, OPS-19, NFR010-04, OPS-13 y OPS-21.
  - Espera a OPS-12 y a una segunda persona: OPS-12, OPS-08, NFR010-02, REL-01, REL-02, FR003-06, FR003-07 y DEC-10.
- **S10.**
  - Código del equipo: FR023-10, FR024-05, FR024-03, FR005-11, FR025-12, FR023-12, FR023-13, FR011-05, FR011-06, FR020-05, NFR006-04, DEC-15 y OPS-14.
  - Espera a terceros:
    - VAULT-07, a su aprobación;
    - NFR001-01, NFR001-02 y NFR001-03, a AWS; el stage arranca aquí si las credenciales llegan antes del 12/10;
    - NFR009-02, a la revisión manual con lector de pantalla.
- **S11.** FR005-13, NFR001-04, NFR003-03, NFR005-02, NFR002-03, NFR004-02, SEC-12 y FR026-04, con AWS. SEC-13, del equipo.
- **S12 a S16.** Quedan, en orden, SEC-11; DEC-12, FR028-02 y DEC-11; SEC-01 y FR005-05; SEC-02 y SEC-08; REL-04 y REL-03.

## Releases

| Release | Fecha | Nombre | Qué trae | Depende de |
|---|---|---|---|---|
| v0.1.0 | 2026-10-09 | Main endurecido, firmado y con Continuity Vault | Descargar una versión firmada con cosign, con provenance SLSA y SBOM, y verificarla con un solo comando. Usar el generador de llaves offline firmado siguiendo la guía air-gapped. Instalar el stack self-hosted con imágenes reproducibles y el vault sobre el SeaweedFS del compose. Guardar tu historial sellado y restaurarlo aunque los relays estén vacíos (private-resilient aún no es GA). Contar con G1, B1, B2, D1–D3 e IR-15 corregidos y con los feature gates de producción en el release | OPS-12, una segunda persona que apruebe el waiver y los entornos, y el entorno release protegido. No depende de AWS |
| v0.2.0 | 2026-10-23 | Todo el código del programa | Ver en la web, el CLI y el README qué es GA, Beta, Preview o Experimental. Reabrir una persona gestionada en otro navegador. En organizaciones: rotaciones como servicio, sesiones de dispositivo en la web, «publicar» aplicado por recurso en los relays y auditoría coherente con la retención legal. Reintentar mensajes y commits de grupos desde la outbox y seguir cada operación por un identificador estable. Consultar una trazabilidad generada desde el código y la documentación del SDK y de las APIs | Lo mismo que v0.1.0. No depende de AWS |
| v1.0.0-rc.1 | 2026-11-20 | Candidato para la auditoría | Auditar un commit congelado y firmado, con documentación y trazabilidad que coinciden con el código. Probar el SaaS en un stage real en AWS con SLO, failover de RDS, KMS real, carga y restore drill. Verificar un SBOM por imagen y los feature gates de producción | Credenciales de AWS antes del 12/10 (NFR001-01), threat models aprobados (DEC-10) y la cadena de release |
| v1.0.0-rc.2 | 2027-01-15 | Corregido tras la auditoría | Usar una versión con los hallazgos críticos y altos corregidos y consultar el informe del retest | Informes de SEC-01 y SEC-02 a tiempo, con el contrato firmado antes del 06/11 |
| v1.0.0 | 2027-01-29 | Primera release para despliegues controlados | Sin cambios respecto al replanteo del 27 de septiembre | Retest aprobado y segunda persona para las aprobaciones |

## Tareas nuevas

| ID | Issue | Sprint | Prio | SP | Criterio de hecho |
|---|---|---|---|---:|---|
| OPS-21 | #330 | S9 | P1 | 2 | `scripts/tor-profile-check.sh` no envía el DM hasta que el 10050 del destinatario está REPLICATED y da a cada lectura por Tor el margen de un circuito lento; si aun así falla, el log dice en qué paso y tras cuánto tiempo; el job `tor-profile` pasa en 5 ejecuciones seguidas |
| SEC-13 | #331 | S11 | P1 | 5 | `docs/security/internal-review-2026-10.md` revisa con el método de la primera revisión lo fusionado desde entonces: Continuity Vault, motor de entrega, feature gates de producción, SEC-06 y SEC-07. Cada hallazgo medio o superior queda corregido, o aceptado con ADR, antes del tag de auditoría, y entra en el paquete de SEC-01 y SEC-02 |

El job `tor-profile` falló en las PR #326 y #329, en el camino por Tor y no por sus cambios; el diagnóstico está en #330.

## Cómo se aplicó

1. **Issues (29/09/2026).** Las 21 tareas cambiaron de milestone, con los campos *Start date* y *Target date* del sprint nuevo. El orden mantuvo válido el backlog en cada paso: PANEL-07 antes que OPS-19, y FR024-05 antes que FR024-03.
2. **Tareas nuevas.** Se crearon OPS-21 (#330, S9) y SEC-13 (#331, S11) como sub-issues de sus epics, con labels y campos. SEC-11 (#257) añade SEC-13 a *Depende de*.
3. **OPS-20 (#252).** Se quitó REL-01 de *Depende de*. OPS-20 amplía el gate de release, que ya está en main; REL-01 sigue parcial hasta el primer release real y los informes externos. El validador rechaza una tarea hecha que depende de otra abierta. Por eso la sincronización fallaba desde que OPS-20 se cerró, el 29/09.
4. **docs/backlog.**
   - Esta PR trae la salida de `backlog-sync`.
   - Después actualiza en `meta` tres cosas: `sprints` (nombre y fase de S9–S16), `version` y `baseline`.
   - Regenera `README.md` y `backlog.csv`.
5. **Pendiente.** Hay que lanzar `backlog-sync` con `seed` (*Actions → backlog-sync → Run workflow*) para dos cosas:
   - renombrar los milestones S9–S16 según `meta.sprints`;
   - alinear los «blocked by» de OPS-21, SEC-13, SEC-11 y OPS-20 con *Depende de*.

   La integración con la que se aplicó el replanteo no puede lanzar workflows. El backlog ya es correcto, porque el validador lee *Depende de*.
