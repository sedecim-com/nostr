# Runbook: backup y restore

## Identidad (usuario)
1. Exportar: `npm run keygen -- --out backup.json` (nuevas llaves) o, en el cliente, "Descargar backup
   cifrado (NIP-49)". El archivo contiene solo `ncryptsec` (scrypt + XChaCha20-Poly1305).
2. Verificar offline: `npm run keygen -- verify backup.json`.
3. Restaurar en un dispositivo limpio: importar el archivo (web: modo "Importar"; CLI:
   `sovereign persona import --backup backup.json --label NOMBRE --relay URL`). Se valida que el
   `ncryptsec` descifre a una llave que derive el mismo npub antes de guardarla (`openKeyBackup`).
4. Backup completo de una persona (llave, relays, configuración del panel y estado MLS cifrado):
   `sovereign backup export --persona ID --out persona.json` y, en el dispositivo nuevo,
   `sovereign backup restore persona.json`. Todo va cifrado con la contraseña del backup (formato
   `sedecim-identity-backup` v2); los backups v1 siguen restaurándose.

## Stack self-hosted (operador)
| Dato | Dónde | Cómo respaldar |
|---|---|---|
| Eventos del relay | Postgres `buzz` | `pg_dump` diario + WAL si se requiere RPO bajo |
| Mirror / identidad | Postgres `sedecim` | `pg_dump` (el mirror es reconstruible desde relays) |
| Media Blossom (Buzz) | SeaweedFS, bucket `buzz-media` (volumen `seaweedfs-data`) | `weed backup` / `s3 sync` con cualquier cliente S3 hacia almacenamiento externo |
| Adjuntos cifrados | blob-store (volumen `blob-data`) | copia del volumen; son blobs cifrados, direccionados por hash |
| Llave del relay | `.env` `BUZZ_RELAY_PRIVATE_KEY` | Copia offline cifrada |
| Vault managed | volumen `managed-vault` + KEK | Volumen cifrado; la KEK se guarda separada (HSM/KMS) |
| Onion service | volumen `tor-data` (`relay/hs_ed25519_secret_key`) | Copia offline: define la dirección .onion |

Drill (NFR-003): restaurar en un host limpio, `docker compose up -d`, ejecutar `npm run test:interop` y
comprobar que el indexer reconstruye vistas (`GET /health` → recuento de eventos).
