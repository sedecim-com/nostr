# Tablero de estado

> Generado por `node scripts/traceability.mjs` (OPS-18) desde el backlog (GitHub Issues) y el código; no se edita a mano. Detalle por requisito: [requirements-traceability.md](requirements-traceability.md). Plan y criterio de hecho de cada tarea: [backlog/README.md](backlog/README.md).

## Requisitos

| Estado | Cuántos | Cuáles |
|---|---:|---|
| Hecho | 26 | FR-001, FR-002, FR-004, FR-006, FR-008, FR-009, FR-010, FR-011, FR-012, FR-013, FR-014, FR-015, FR-016, FR-017, FR-018, FR-019, FR-020, FR-021, FR-022, FR-023, FR-024, FR-025, FR-027, NFR-006, NFR-007, NFR-008 |
| Parcial | 12 | FR-003, FR-005, FR-007, FR-026, FR-028, NFR-001, NFR-002, NFR-003, NFR-004, NFR-005, NFR-009, NFR-010 |

## Tareas

| Estado | Tareas | Story points |
|---|---:|---:|
| Hecho | 192 | 515 |
| Parcial | 29 | 99 |
| Pendiente | 22 | 94 |
| Descartado | 6 | 21 |

Nivel de evidencia de las tareas hechas (label `evidencia:*`, OPS-17):

| Nivel | Tareas |
|---|---:|
| Production Enabled | 0 |
| Externally Audited | 0 |
| Stage Verified | 0 |
| CI Verified | 0 |
| Merged | 58 |
| Sin label (anteriores a OPS-17) | 134 |

## Sprints abiertos

| Sprint | Fechas | Fase | Objetivo | Hechas | Abiertas | SP abiertos | P0 abiertas |
|---|---|---|---|---:|---:|---:|---:|
| S9 | 2026-09-28 → 2026-10-09 | G0 | Código de la auditoría y v0.1.0 firmada | 23 de 30 | 7 | 14 | 4 |
| S10 | 2026-10-12 → 2026-10-23 | G1 | Resto del código, vault aprobado y v0.2.0 | 20 de 28 | 8 | 28 | 4 |
| S11 | 2026-10-26 → 2026-11-06 | G2 | Stage real en AWS | 5 de 15 | 10 | 37 | 7 |
| S12 | 2026-11-09 → 2026-11-20 | G3 | Freeze de auditoría y v1.0.0-rc.1 | 0 de 1 | 1 | 3 | 1 |
| S13 | 2026-11-23 → 2026-12-04 | G4 | Auditoría en campo y aprobación legal | 0 de 3 | 3 | 4 | 0 |
| S14 | 2026-12-07 → 2026-12-18 | G4 | Informes externos y Nitro en Preview | 0 de 2 | 2 | 16 | 1 |
| S15 | 2027-01-04 → 2027-01-15 | G4 | Remediación, retest y v1.0.0-rc.2 | 0 de 2 | 2 | 16 | 2 |
| S16 | 2027-01-18 → 2027-01-29 | G5 | v1.0.0 firmada para despliegues controlados | 0 de 2 | 2 | 4 | 1 |
| Diferido | sin fecha | — | Después de v1.0: fuera del programa de cierre | 10 de 26 | 16 | 71 | 0 |

## P0 abiertas

| Tarea | Sprint | Estado | Depende de |
|---|---|---|---|
| [OPS-08](https://github.com/sedecim-com/nostr/issues/59) Separación de funciones en releases (quién construye vs quién publica) | S9 | Parcial | — |
| [NFR010-02](https://github.com/sedecim-com/nostr/issues/190) Firma de releases y provenance (SLSA/cosign) | S9 | Parcial | OPS-08 |
| [REL-01](https://github.com/sedecim-com/nostr/issues/196) Checklist de Definition of Done automatizado en el pipeline de release | S9 | Parcial | NFR010-02, NFR003-02, FR020-03, DEC-10, OPS-08 |
| [REL-02](https://github.com/sedecim-com/nostr/issues/197) Release notes con los cambios de trust model por release | S9 | Parcial | REL-01 |
| [NFR001-01](https://github.com/sedecim-com/nostr/issues/170) Infraestructura como código del SaaS (Helm/Terraform) | S10 | Parcial | OPS-02 |
| [NFR001-02](https://github.com/sedecim-com/nostr/issues/171) Monitorización de SLO (99,9 % mensual) y alertas | S10 | Parcial | NFR001-01 |
| [NFR001-03](https://github.com/sedecim-com/nostr/issues/172) Postgres de alta disponibilidad y backups gestionados | S10 | Parcial | NFR001-01 |
| [VAULT-07](https://github.com/sedecim-com/nostr/issues/239) Threat model y disclosure del Continuity Vault | S10 | Parcial | VAULT-01 |
| [NFR004-02](https://github.com/sedecim-com/nostr/issues/178) Dashboard de latencia y degradación sin ocultarla | S11 | Parcial | NFR004-01, NFR001-02 |
| [NFR005-02](https://github.com/sedecim-com/nostr/issues/180) Pruebas de carga del relay y el indexer | S11 | Parcial | NFR005-01, NFR001-01 |
| [OPS-12](https://github.com/sedecim-com/nostr/issues/220) Gobierno del repositorio: proteger main, activar private vulnerability reporting y nombrar un segundo mantenedor | S11 | Pendiente | — |
| [NFR003-03](https://github.com/sedecim-com/nostr/issues/251) Simulacro completo de RPO/RTO en stage | S11 | Pendiente | NFR001-03 |
| [FR026-04](https://github.com/sedecim-com/nostr/issues/253) Salida de la custodia, borrado verificable y derechos ARCO | S11 | Parcial | FR026-01, FR005-13 |
| [FR005-13](https://github.com/sedecim-com/nostr/issues/255) KMS y Secrets Manager validados en la cuenta y región reales | S11 | Pendiente | NFR001-01 |
| [SEC-12](https://github.com/sedecim-com/nostr/issues/258) Inventario de la superficie de ataque de Buzz desplegado | S11 | Parcial | NFR001-01, BUZZ-07 |
| [SEC-11](https://github.com/sedecim-com/nostr/issues/257) Tag de auditoría firmado y v1.0.0-rc.1 | S12 | Pendiente | SEC-06, SEC-07, SEC-13, FR025-11, VAULT-03, VAULT-04, FR026-04, FR005-13, OPS-18, DEC-10, REL-01 |
| [SEC-01](https://github.com/sedecim-com/nostr/issues/192) Revisión criptográfica independiente (NIP-44/49/59, MLS, key service) | S14 | Parcial | SEC-03, FR005-03, SEC-06, SEC-07, SEC-11 |
| [SEC-02](https://github.com/sedecim-com/nostr/issues/193) Pentest de API, relay, key service y cliente | S15 | Parcial | OPS-02, FR005-04, FR023-03, NFR001-01, SEC-11, SEC-12, SEC-08 |
| [SEC-08](https://github.com/sedecim-com/nostr/issues/275) Corregir los hallazgos críticos y altos de SEC-01 y SEC-02 | S15 | Pendiente | SEC-01 |
| [REL-03](https://github.com/sedecim-com/nostr/issues/277) v1.0.0 firmada con la Definition of Done completa y sin waiver | S16 | Pendiente | SEC-01, SEC-02, SEC-08, REL-01, OPS-20, NFR003-03, REL-04 |
