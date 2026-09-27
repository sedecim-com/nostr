# RPO y RTO por tier (NFR-003)

- **Estado:** Aprobada el 2026-09-27 · **Tarea:** NFR003-01 · **Fecha de la propuesta:** 2026-09-26
- **Depende de:** DEC-09 / [ADR 0009](adr/0009-custodia-managed-region-y-marco-legal.md) (custodia managed en
  `us-east-1`), [runbook de backup y restore](runbooks/restore.md), drill nocturno
  (`.github/workflows/restore-drill.yml`, NFR003-02).

**RPO** (Recovery Point Objective): cuántos datos, medidos en tiempo, se pueden perder como máximo.
**RTO** (Recovery Time Objective): cuánto puede tardar el servicio en volver a funcionar tras el incidente.

## Tiers

| Tier | Quién opera | Quién respalda | Base técnica |
|---|---|---|---|
| **Self-hosted** | El cliente (docker compose) | El cliente, con `scripts/backup.sh` / `scripts/restore.sh` | [Runbook](runbooks/restore.md), drill nocturno en CI |
| **SaaS** | Sedecim (Kubernetes en AWS `us-east-1`, [`deploy/`](../deploy/README.md)) | Sedecim | Volúmenes EBS + `pg_dump` al bucket `acceso-nostr-<env>-backups-*`. Postgres gestionado (RDS Multi-AZ, backups automáticos 14 días + PITR) definido como código en NFR001-03; rige desde su `terraform apply` ([runbook](runbooks/rds-postgres.md)) |
| **Institucional** | Sedecim o la institución, en infraestructura dedicada | Según contrato; mismas herramientas | Como SaaS + archivado continuo de WAL y copia de datos y WAL en una segunda región. Las llaves managed se quedan en `us-east-1` (ADR 0009) |

## Tabla aprobada

Valores **objetivo**. La columna "Hoy" dice qué se puede garantizar con lo que ya existe. En SaaS, las
bases de datos se comprometen a 24 h / 4 h mientras no haya PITR; el objetivo de 1 h / 1 h entra en vigor
cuando se complete NFR001-03 (Postgres gestionado con PITR).

| Componente | Dónde vive | Self-hosted RPO / RTO | SaaS RPO / RTO | Institucional RPO / RTO | Hoy |
|---|---|---|---|---|---|
| Eventos del relay (Buzz) | Postgres `buzz` | 24 h / 4 h | 24 h / 4 h; 1 h / 1 h con PITR (NFR001-03) | 15 min / 1 h | `pg_dump` con `backup.sh` (RPO = frecuencia del cron del operador). SaaS: RDS Multi-AZ con PITR ya definido como código (NFR001-03). Rige al aplicarse con `terraform apply`; hasta entonces, 24 h |
| Mirror e identidad | Postgres `sedecim` | 24 h / 4 h | 24 h / 4 h; 1 h / 1 h con PITR (NFR001-03) | 15 min / 1 h | `pg_dump` con `backup.sh`. SaaS: misma instancia RDS con PITR (NFR001-03), rige al aplicarse. El mirror además se reconstruye desde los relays |
| Media de canales (Buzz Blossom) | SeaweedFS (`seaweedfs-data`) | 24 h / 4 h | 24 h / 4 h | 1 h / 4 h | Archivo del volumen con `backup.sh` |
| Adjuntos cifrados | blob-store (`blob-data`) | 24 h / 4 h | 24 h / 4 h | 1 h / 4 h | Archivo del volumen con `backup.sh`. Son blobs cifrados en el cliente: el backup no expone contenido |
| Grupos Marmot (relay secundario) | SQLite (`secure-relay-data`) | 24 h / 4 h | 24 h / 4 h | 1 h / 4 h | Archivo del volumen con `backup.sh`. El estado MLS de cada miembro está además en su backup de cliente |
| Llaves de servicio (relay, mirror) | `.env` / Secrets Manager `k8s/<env>/acceso-nostr` | 0 / 1 h | 0 / 1 h | 0 / 1 h | Copia offline cifrada del `.env` (self-hosted); Secrets Manager con ventana de recuperación de 7 días (SaaS) |
| Llaves managed (custodia) | Secrets Manager + KMS (ADR 0009); registro en Postgres `sedecim` | n/a (vault local: 0 / 4 h con KEK separada) | 0 / 1 h | 0 / 1 h | Escritura síncrona en Secrets Manager (replicado dentro de `us-east-1`); llave KMS con 30 días de ventana de borrado. Sin réplica fuera de la región (ADR 0009) |
| Vault del cliente (llaves, relays, panel, estado MLS) | Dispositivo del usuario (almacenamiento cifrado local) | Último backup exportado por el usuario / minutos | Igual | Igual (la institución puede exigir exportación periódica) | Backup v2 cifrado (`sedecim-identity-backup`, NIP-49 para la llave). La plataforma no guarda copia: es soberano por diseño |
| Redis | Memoria + AOF | No aplica | No aplica | No aplica | Solo cachés y pub/sub de Buzz; se reconstruye al arrancar |

Notas:

- **PITR en SaaS (NFR001-03):** `deploy/terraform/modules/acceso-nostr/rds.tf` define RDS PostgreSQL 17
  Multi-AZ con backups automáticos (`rds_backup_retention_days`, 14 días por defecto), PITR, protección contra
  borrado y cifrado KMS. El overlay de stage ya apunta a RDS (`deploy/k8s/components/rds-postgres`). Los
  objetivos aprobados no cambian: el 1 h / 1 h de SaaS en bases de datos entra en vigor cuando RDS esté
  aplicado con `terraform apply` y los datos migrados, y el failover se haya probado en staging con
  `scripts/rds-failover-test.sh` ([runbook](runbooks/rds-postgres.md)). Mientras tanto rige 24 h / 4 h.
- **RPO 0 en llaves** significa que ninguna llave confirmada al usuario puede perderse: se escriben de
  forma síncrona antes de responder. Perder una llave es perder una identidad, a diferencia de los datos,
  que en Nostr suelen estar replicados en otros relays del usuario.
- **RPO del self-hosted (24 h)** es una recomendación al operador: se cumple programando `backup.sh` a
  diario y sacando la copia del host ([runbook, "Programar el backup"](runbooks/restore.md#programar-el-backup)).
- **RTO del self-hosted (4 h)** incluye conseguir un host limpio. La parte automatizable (restaurar y
  arrancar) la mide cada noche el drill (paso "Drill summary"): 40 s en la primera ejecución en verde
  (2026-09-27, [run](https://github.com/sedecim-com/nostr/actions/runs/36287681879)).
- **Vault del cliente:** la plataforma no puede recuperar lo que el usuario no exportó. El RPO real es el
  tiempo desde su último backup; el cliente debe recordarlo (FR-027) y el restore en un dispositivo limpio
  está probado (`identity.test.ts`, `groups.test.ts`).
- **Tier institucional y pérdida de región:** los datos y el WAL se copian a una segunda región, pero las
  llaves managed no salen de `us-east-1` (ADR 0009, sin cambios). Si se pierde la región, los datos se
  recuperan en la otra dentro del RTO; las cuentas con custodia managed no pueden firmar hasta que
  `us-east-1` vuelva. Las personas con llave propia (no managed) no dependen de la región.

## Cómo se verifica

| Qué | Cómo | Frecuencia |
|---|---|---|
| El restore funciona en un host limpio | `restore-drill.yml`: datos sembrados en Buzz, mirror, media, blob-store y secure relay → `backup.sh` → `docker compose down -v` sin `.env` → `restore.sh` → datos presentes → `npm run test:interop` | Cada noche; si falla, abre un issue |
| RTO de la parte automatizada | Tiempo de restore + arranque del drill, en el resumen del job | Cada noche |
| Failover de Postgres SaaS (NFR001-03) | `scripts/rds-failover-test.sh --yes` contra la instancia RDS de staging: failover forzado, caída medida, cambio de AZ ([runbook](runbooks/rds-postgres.md#prueba-de-failover)). En CI solo con un `aws` falso | Tras el primer `terraform apply` y en cada cambio de clase o versión mayor; pendiente |
| Backup del cliente | `identity.test.ts`, `groups.test.ts` (restauración en dispositivo limpio) | Cada PR |
| Integridad ante caídas del almacenamiento local | `encrypted-store/test/crash.test.ts` (kill -9 a mitad de escritura) | Cada PR |

## Aprobación

| Rol | Nombre | Fecha | Decisión / comentarios |
|---|---|---|---|
| Responsable de producto | Victor (@vic2099) | 2026-09-27 | Aprobada. SaaS: 24 h / 4 h en bases de datos hasta PITR (NFR001-03), luego 1 h / 1 h |
| Operaciones / SRE | Victor (@vic2099) | 2026-09-27 | Aprobada. Self-hosted: cron diario de ejemplo en el runbook |
| Seguridad y cumplimiento (tier institucional, llaves managed) | Victor (@vic2099) | 2026-09-27 | Aprobada. Institucional: copia de datos y WAL en otra región; llaves managed solo en `us-east-1` (ADR 0009) |
