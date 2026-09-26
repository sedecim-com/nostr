# RPO y RTO por tier (NFR-003)

- **Estado:** Propuesta pendiente de aprobación · **Tarea:** NFR003-01 · **Fecha de la propuesta:** 2026-09-26
- **Depende de:** DEC-09 / [ADR 0009](adr/0009-custodia-managed-region-y-marco-legal.md) (custodia managed en
  `us-east-1`), [runbook de backup y restore](runbooks/restore.md), drill nocturno
  (`.github/workflows/restore-drill.yml`, NFR003-02).

**RPO** (Recovery Point Objective): cuántos datos, medidos en tiempo, se pueden perder como máximo.
**RTO** (Recovery Time Objective): cuánto puede tardar el servicio en volver a funcionar tras el incidente.

## Tiers

| Tier | Quién opera | Quién respalda | Base técnica |
|---|---|---|---|
| **Self-hosted** | El cliente (docker compose) | El cliente, con `scripts/backup.sh` / `scripts/restore.sh` | [Runbook](runbooks/restore.md), drill nocturno en CI |
| **SaaS** | Sedecim (Kubernetes en AWS `us-east-1`, [`deploy/`](../deploy/README.md)) | Sedecim | Volúmenes EBS + `pg_dump` al bucket `acceso-nostr-<env>-backups-*`; Postgres gestionado con PITR en NFR001-03 |
| **Institucional** | Sedecim o la institución, en infraestructura dedicada | Según contrato; mismas herramientas | Como SaaS + archivado continuo de WAL y copia fuera de la región |

## Tabla propuesta

Valores **objetivo**. La columna "Hoy" dice qué se puede garantizar con lo que ya existe.

| Componente | Dónde vive | Self-hosted RPO / RTO | SaaS RPO / RTO | Institucional RPO / RTO | Hoy |
|---|---|---|---|---|---|
| Eventos del relay (Buzz) | Postgres `buzz` | 24 h / 4 h | 1 h / 1 h (15 min con PITR, NFR001-03) | 15 min / 1 h | `pg_dump` con `backup.sh` (RPO = frecuencia del cron del operador). En SaaS sin PITR todavía: 24 h |
| Mirror e identidad | Postgres `sedecim` | 24 h / 4 h | 1 h / 1 h | 15 min / 1 h | `pg_dump` con `backup.sh`. El mirror además se reconstruye desde los relays |
| Media de canales (Buzz Blossom) | SeaweedFS (`seaweedfs-data`) | 24 h / 4 h | 24 h / 4 h | 1 h / 4 h | Archivo del volumen con `backup.sh` |
| Adjuntos cifrados | blob-store (`blob-data`) | 24 h / 4 h | 24 h / 4 h | 1 h / 4 h | Archivo del volumen con `backup.sh`. Son blobs cifrados en el cliente: el backup no expone contenido |
| Grupos Marmot (relay secundario) | SQLite (`secure-relay-data`) | 24 h / 4 h | 24 h / 4 h | 1 h / 4 h | Archivo del volumen con `backup.sh`. El estado MLS de cada miembro está además en su backup de cliente |
| Llaves de servicio (relay, mirror) | `.env` / Secrets Manager `k8s/<env>/acceso-nostr` | 0 / 1 h | 0 / 1 h | 0 / 1 h | Copia offline cifrada del `.env` (self-hosted); Secrets Manager con ventana de recuperación de 7 días (SaaS) |
| Llaves managed (custodia) | Secrets Manager + KMS (ADR 0009); registro en Postgres `sedecim` | n/a (vault local: 0 / 4 h con KEK separada) | 0 / 1 h | 0 / 1 h | Escritura síncrona en Secrets Manager (replicado dentro de `us-east-1`); llave KMS con 30 días de ventana de borrado. Sin réplica fuera de la región (ADR 0009) |
| Vault del cliente (llaves, relays, panel, estado MLS) | Dispositivo del usuario (almacenamiento cifrado local) | Último backup exportado por el usuario / minutos | Igual | Igual (la institución puede exigir exportación periódica) | Backup v2 cifrado (`sedecim-identity-backup`, NIP-49 para la llave). La plataforma no guarda copia: es soberano por diseño |
| Redis | Memoria + AOF | No aplica | No aplica | No aplica | Solo cachés y pub/sub de Buzz; se reconstruye al arrancar |

Notas:

- **RPO 0 en llaves** significa que ninguna llave confirmada al usuario puede perderse: se escriben de
  forma síncrona antes de responder. Perder una llave es perder una identidad, a diferencia de los datos,
  que en Nostr suelen estar replicados en otros relays del usuario.
- **RTO del self-hosted (4 h)** incluye conseguir un host limpio. La parte automatizable (restaurar y
  arrancar) la mide cada noche el drill (paso "Drill summary"); debe quedar muy por debajo.
- **Vault del cliente:** la plataforma no puede recuperar lo que el usuario no exportó. El RPO real es el
  tiempo desde su último backup; el cliente debe recordarlo (FR-027) y el restore en un dispositivo limpio
  está probado (`identity.test.ts`, `groups.test.ts`).
- El tier institucional necesita, además, copia de backups fuera de `us-east-1`, lo que implica revisar
  ADR 0009 si incluye llaves managed.

## Cómo se verifica

| Qué | Cómo | Frecuencia |
|---|---|---|
| El restore funciona en un host limpio | `restore-drill.yml`: datos sembrados en Buzz, mirror, media, blob-store y secure relay → `backup.sh` → `docker compose down -v` sin `.env` → `restore.sh` → datos presentes → `npm run test:interop` | Cada noche; si falla, abre un issue |
| RTO de la parte automatizada | Tiempo de restore + arranque del drill, en el resumen del job | Cada noche |
| Backup del cliente | `identity.test.ts`, `groups.test.ts` (restauración en dispositivo limpio) | Cada PR |
| Integridad ante caídas del almacenamiento local | `encrypted-store/test/crash.test.ts` (kill -9 a mitad de escritura) | Cada PR |

## Aprobación

Pendiente. Esta tabla no compromete nada hasta que la firmen:

| Rol | Nombre | Fecha | Decisión / comentarios |
|---|---|---|---|
| Responsable de producto | | | |
| Operaciones / SRE | | | |
| Seguridad y cumplimiento (tier institucional, llaves managed) | | | |
