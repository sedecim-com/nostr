# Runbook: backup y restore

## Identidad (usuario)
1. Exportar: `npm run keygen -- --out backup.json` (nuevas llaves) o, en el cliente, "Descargar backup
   cifrado (NIP-49)". El archivo contiene solo `ncryptsec` (scrypt + XChaCha20-Poly1305).
2. Verificar offline: `npm run keygen -- verify backup.json`.
3. Restaurar en un dispositivo limpio: importar el archivo (web: modo "Importar"; CLI:
   `sovereign persona import --backup backup.json --label NOMBRE --relay URL`). Se valida que el
   `ncryptsec` descifre a una llave que derive el mismo npub antes de guardarla (`openKeyBackup`).
4. Backup completo de una persona (llave, relays, configuración del panel, estado MLS cifrado y
   outbox de entregas): `sovereign backup export --persona ID --out persona.json` y, en el dispositivo
   nuevo, `sovereign backup restore persona.json`. Todo va cifrado con la contraseña del backup (formato
   `sedecim-identity-backup` v2); los backups v1 siguen restaurándose.
5. Reconstruir el historial (FR-013): `sovereign history sync --persona ID` recupera canales NIP-29
   (descubiertos por la actividad propia y la lista kind 10009), DMs NIP-17 y concilia el outbox
   restaurado con lo que los relays ya guardan; los pendientes se reenvían con `sovereign resume`
   (mismo event id). Usa NIP-77 (Negentropy) si el relay lo soporta y, si no, REQ por ventanas.
6. Portabilidad (NFR-008): `sovereign history export --persona ID --out historial.jsonl` escribe un
   evento NIP-01 firmado por línea (orden `created_at`, luego `id`); `sovereign history import --persona
   ID historial.jsonl [--dry-run]` verifica firmas, informa líneas inválidas y republica los válidos.

7. Copia cifrada en la nube (FR027-03, si el despliegue define `backupVault` en `config.json`): en la
   web, "Guardar copia cifrada en la nube" sube el mismo archivo NIP-49 al identity-service
   (`POST /v1/backups`, NIP-98 de la persona; se guardan las últimas 5 versiones por cuenta). En un
   dispositivo nuevo, modo "Importar archivo de backup" → "Restaurar desde la nube": en SaaS basta el
   login de Acceso (debe estar vinculado a la cuenta de la persona) y en self-hosted firma una persona de
   la misma cuenta; después se descifra en el navegador con la contraseña del backup. El servidor
   rechaza lo que no sea un sobre cifrado conocido (`acceso-nostr-key-backup` v1 o
   `sedecim-identity-backup` v2 con lista cerrada de campos, sin `nsec1` ni hex de 32 bytes) y nunca
   recibe la contraseña. Límites: `BACKUP_VAULT_MAX_BYTES` (512 KiB) y `BACKUP_VAULT_KEEP` (5).
   API: `GET /v1/backups` (metadatos), `GET /v1/backups/:id|latest` (sobre + sha256),
   `DELETE /v1/backups[/:id]`; también con `Authorization: Bearer <token de Acceso>` en SaaS.

## Stack self-hosted (operador)
Objetivos de RPO/RTO por tier: [`docs/rpo-rto.md`](../rpo-rto.md) (aprobados el 2026-09-27).

| Dato | Dónde | Cómo respaldar (`scripts/backup.sh`) |
|---|---|---|
| Eventos del relay | Postgres `buzz` | `pg_dump -Fc` → `postgres-buzz.dump` (+ WAL si se requiere RPO bajo) |
| Mirror / identidad | Postgres `sedecim` | `pg_dump -Fc` → `postgres-platform.dump` (el mirror es reconstruible desde relays; incluye `backup_vault`, solo sobres cifrados) |
| Media Blossom (Buzz) | SeaweedFS, bucket `buzz-media` (volumen `seaweedfs-data`) | Archivo del volumen → `seaweedfs-data.tgz` |
| Continuity Vault (VAULT-06) | Filas en Postgres `sedecim` (`vault_*`); sobres sellados en SeaweedFS, bucket `continuity-vault` | Van en `postgres-platform.dump` y `seaweedfs-data.tgz`. El vault queda pausado desde antes de los dumps hasta copiar `seaweedfs-data`, así ninguna fila respaldada apunta a un sobre que falte |
| Adjuntos cifrados | blob-store (volumen `blob-data`) | Archivo del volumen → `blob-data.tgz`; son blobs cifrados, direccionados por hash |
| Repos git de Buzz | volumen `relay-git` | Archivo del volumen → `relay-git.tgz` |
| Grupos Marmot | secure-relay (volumen `secure-relay-data`, SQLite) | Archivo del volumen → `secure-relay-data.tgz` |
| Llave del relay y demás secretos | `.env` (`BUZZ_RELAY_PRIVATE_KEY`, `INDEXER_NSEC`, contraseñas) | Copia en el backup (`.env`, salvo `--no-env`) + copia offline cifrada |
| Vault managed | volumen `managed-vault` + KEK | `managed-vault.tgz` si corre el perfil `managed`; la KEK se guarda separada (HSM/KMS) |
| Onion service | volumen `tor-data` (`relay/hs_ed25519_secret_key`) | `tor-data.tgz` si corre el perfil `tor`: define la dirección .onion |
| Secure relay del onion | secure-relay-onion (volumen `secure-relay-onion-data`, SQLite) | `secure-relay-onion-data.tgz` si corre el perfil `tor` |
| Worker de rotaciones (FR024-05) | volumen `rotation-state`: su estado MLS, cifrado con `ROTATION_STATE_KEY` | `rotation-state.tgz` si corre el perfil `institutional`; la clave va en `.env`. Sin el volumen o sin la clave, el worker vuelve a empezar sin grupos |
| Redis | volumen `redis-data` | No se respalda: cachés y pub/sub de Buzz |

### Backup
```bash
sh scripts/backup.sh                 # → .data/backups/<fecha UTC>/ (o: sh scripts/backup.sh DIR)
```
Con el stack en marcha. Hace `pg_dump` de las dos bases, archiva cada volumen pausando su servicio unos
segundos (`docker compose pause`, copia consistente), copia `.env` y escribe `SHA256SUMS`. El Continuity
Vault se pausa durante los dumps y la copia de `seaweedfs-data`: sus subidas esperan ese rato y los clientes
reintentan (una copia `best-effort` no retrasa ningún envío; una `required-for-resilient` lo retiene hasta
entonces). El directorio
contiene todos los secretos del stack: cifrarlo y sacarlo del host (p. ej. al bucket de backups de
`deploy/terraform`). Programarlo con cron según el RPO del tier.

### Programar el backup
El RPO recomendado para self-hosted es 24 h: un backup diario, guardado fuera del host. Ejemplo con cron
(usuario con acceso a Docker, repo en `/opt/nostr`; conserva 7 días en el host):

```cron
# /etc/cron.d/sedecim-nostr-backup
15 3 * * * operador cd /opt/nostr && sh scripts/backup.sh >> /var/log/sedecim-nostr-backup.log 2>&1 && find .data/backups -mindepth 1 -maxdepth 1 -mtime +7 -exec rm -rf {} +
```

Después de cada backup, cifra el directorio y súbelo fuera del host. Por ejemplo, con
[age](https://age-encryption.org) y una llave pública cuya privada no esté en el servidor:
`tar -C .data/backups -cf - <dir> | age -r <age1…> > <dir>.tar.age`. El directorio contiene `.env` con
todos los secretos: nunca lo copies sin cifrar. Revisa el log y el `SHA256SUMS` de vez en cuando, y ensaya
el restore en otro host (como hace el drill).

### Restore en un host limpio
```bash
git clone … && cd nostr && npm ci && docker compose build
sh scripts/restore.sh /ruta/al/backup   # verifica SHA256SUMS, repone .env, volúmenes y bases, arranca
sh scripts/wait-stack.sh
npm run test:interop                    # con BUZZ_RELAY_URL etc., como en CI
```
`restore.sh` se niega si ya hay contenedores o volúmenes del stack (`docker compose down -v` antes) o si hay un `.env`
distinto del respaldado (la llave del relay debe ser la misma). Los perfiles opcionales se restauran si
están activos (`COMPOSE_PROFILES=managed sh scripts/restore.sh …`).

### Drill (NFR003-02)
`.github/workflows/restore-drill.yml`, cada noche: levanta el stack, siembra datos conocidos en Buzz, el
mirror, la media, el blob-store, el relay secundario y el Continuity Vault (un sobre sellado con una llave de
archivo de prueba; `scripts/drill-data.ts seed`), hace backup con
`backup.sh`, deja el host limpio (`docker compose down -v` y sin `.env`), restaura con `restore.sh`,
comprueba que los datos sembrados volvieron (`drill-data.ts verify`) y ejecuta `npm run test:interop`.
Si falla, abre (o comenta) el issue "Restore drill fallido". El tiempo de restore queda en el resumen del job.
