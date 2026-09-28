# ADR 0011 · Continuity Vault: sobres de archivo sellados en el cliente

- **Estado:** Propuesto · **Tarea:** VAULT-01 (#237); cubre también VAULT-02 (#238) y VAULT-07 (#239) · **Fecha:** 2026-09-28
- **Aprobación:** pendiente (responsable de producto)

## Contexto
Hoy el historial se reconstruye desde los relays. Si todos pierden o podan los mismos eventos, no queda
ninguna copia independiente: es la brecha principal del PRD de cierre de brechas (epic B, GC-B01…B07).
- El backup de identidad (FR027-03, `identity-service /v1/backups`) guarda llaves y estado, no mensajes.
- El indexer copia eventos de los relays para servir consultas. No es un backup y no debe convertirse en
  uno: tendría que leer lo que guarda.

El PRD pide:
- un servicio separado del indexer que guarde sobres opacos;
- sellados en el cliente con una llave de respaldo distinta de la nsec;
- que el servidor reciba solo ciphertext;
- restaurar con relays vacíos;
- una política `off` / `best-effort` / `required-for-resilient`;
- retención y exportación;
- un backend self-hosted;
- una UI que diga qué metadatos ve el operador.

## Decisión

### Un servicio propio: `services/continuity-vault`
Tiene su propio proceso, su puerto (8088), su scope de migraciones (`continuity-vault`) y sus tablas.

No vive en el indexer, porque no debe poder leer ni indexar eventos.

Tampoco vive en identity-service, por dos razones:
- se puede desplegar solo (self-hosted, GC-B06);
- no necesita una cuenta de identidad, que ataría entre sí a las personas de un usuario.

| Método | Ruta | Qué hace |
|---|---|---|
| `PUT` | `/v1/archives/:id` | Guarda o reemplaza el sobre del id: 201 si es nuevo, 200 si reemplaza. Es idempotente, así que reintentar no duplica |
| `GET` | `/v1/archives?after=&limit=` | Metadatos por páginas, en orden de id (máximo 1000 por página) |
| `GET` | `/v1/archives/:id` | El texto exacto del sobre y sus metadatos |
| `DELETE` | `/v1/archives/:id` · `/v1/archives` | Borra uno, o todos junto con la cuenta |
| `GET` | `/v1/usage` | Uso de la cuenta y límites del vault |

De cada archivo el vault guarda solo seis datos: `id`, `key_id`, `size`, `sha256`, `created_at` y `updated_at`.

### La cuenta del vault
La cuenta es quien se autentica:
- **NIP-98 → `nostr:<pubkey>`.** El cliente firma con una llave derivada de la llave de archivo, no con la
  de la persona. Consecuencias:
  - el operador no puede ligar la cuenta del vault a la pubkey de la persona ni a otras personas del mismo
    usuario;
  - un signer remoto (NIP-46 o managed) nunca recibe peticiones de firma del vault;
  - para restaurar basta la llave de archivo.
- **Token de Acceso → `acceso:<issuer>#<sub>`** (SaaS). El operador sabe entonces qué usuario de Acceso
  guarda archivos. Es una cuenta distinta de cualquier cuenta NIP-98.

El operador elige la política con `VAULT_NIP98`:
- `open` (por defecto): cualquier llave abre cuenta. Cada cuenta tiene su cuota, pero el número de cuentas no
  tiene límite.
- `allowlist`: solo las pubkeys de `VAULT_ALLOWED_PUBKEYS`.
- `off`: solo Acceso.

Con `COGNITO_*` se aceptan logins de Acceso. Un SaaS que quiera acotar el almacenamiento total usa
`allowlist` u `off`.

### El sobre de archivo (v1)
El sobre es exactamente `{"format":"sedecim-archive-envelope","version":1,"key_id":…,"sealed":…}`.

`sealed` = nonce (24) ‖ XChaCha20-Poly1305(u32 longitud ‖ texto ‖ relleno de ceros), con su tag (16).
- **Relleno.** Sigue el esquema de NIP-44 con un mínimo de 256 bytes, con menos de un 25 % de sobrecarga.
  Los mensajes cortos miden todos lo mismo.
- **AAD.** Es `sedecim-archive-envelope:1:<key_id>:<id>`: el vault no puede servir un archivo en lugar de
  otro.

`validateArchiveEnvelope` (`packages/continuity`) lo comparten cliente y servidor, como el validador de
FR027-03. Rechaza:
- campos fuera de la lista;
- una nsec o 64 dígitos hex seguidos en el texto;
- un `sealed` corto o sin relleno;
- un ciphertext que parece texto: ≥ 75 % ASCII imprimible, o UTF-8 válido en conjunto.

El servidor no puede demostrar que unos bytes son ciphertext. Este filtro rechaza los errores probables de
un cliente: texto plano, base64 de texto plano o un sobre sin sellar. La garantía real es la prueba de
VAULT-02: ni la base ni el object store contienen texto, eventos ni llaves legibles.

### La llave de archivo
- Son 32 bytes aleatorios por persona. Nunca es la nsec (`assertDistinctFromNsec`).
- Con HKDF-SHA256 (salt `sedecim-archive-v1`) se derivan cuatro llaves, cada una para un solo uso:
  - `seal`: la llave AEAD de los sobres.
  - `id`: la llave HMAC que convierte una etiqueta (`ledger`, `event:<id>`…) en un id opaco. El vault no ve
    la etiqueta ni el id del evento.
  - `auth`: la llave secp256k1 que firma NIP-98 contra el vault.
  - `key-id`: la huella de 8 bytes que va en claro en cada sobre.
- Solo viaja dentro del backup de identidad, cifrada con la contraseña del backup:
  - en el CLI, en `BackupContents`;
  - en la web, como `archiveKey` (ncryptsec NIP-49) en el backup de la llave.

  El vault nunca la recibe. Restaurar un backup rechaza un logN de NIP-49 mayor que el máximo (VAULT-02).

### Almacenamiento
- **Dónde.** Los metadatos van en Postgres (`vault_owners`, `vault_archives`) y los sobres en un
  `ObjectStore`: memoria para desarrollo, sistema de archivos, y S3-compatible en VAULT-06. Las llaves de
  objeto son aleatorias: ni la ruta ni la llave dicen de quién es un sobre.
- **Orden de escritura.** Primero el objeto, después la fila. El objeto reemplazado o borrado se elimina
  tras el commit. Si el proceso cae en medio, queda un objeto huérfano (ninguna fila lo apunta), nunca una
  fila sin objeto. El barrido de huérfanos llega con la retención (VAULT-05).
- **Cuotas por cuenta.** Por defecto, 1 MiB por sobre, 100 000 archivos y 256 MiB; se cambian con
  `VAULT_MAX_*`.
  - Se comprueban con la fila de la cuenta bloqueada, así que las subidas simultáneas desde cualquier
    réplica no pueden pasarse.
  - Pasarse devuelve 507, sin efectos.
- **Límites de tasa.** Los de service-kit (`RATE_LIMIT_*`). Las descargas usan la clase `read`, no `auth`
  como `/v1/backups`:
  - un sobre está sellado con una llave aleatoria de 256 bits, así que no hay nada que adivinar offline;
  - lo que protege una contraseña es el backup de identidad, que sigue en identity-service con su límite
    estricto.

### Lo que ve el operador (VAULT-07)
- **Ve:**
  - la cuenta;
  - cuántos archivos tiene y su tamaño con relleno;
  - cuándo se escriben, reemplazan, leen o borran;
  - con Acceso, qué usuario de Acceso es;
  - la IP de cada petición, como en cualquier servicio HTTP.
- **No ve:** el contenido, los ids de evento, las etiquetas, con quién hablas, la pubkey de la persona ni la
  llave de archivo.
- **Borrar** elimina la fila y el objeto en el acto. Las copias de seguridad de la base del operador
  conservan los metadatos hasta que caduca su propia retención (se documenta en VAULT-05).

## Consecuencias
- VAULT-03 y VAULT-04 se construyen sobre este contrato. VAULT-03 es la restauración con relays vacíos;
  VAULT-04 es `CONTINUITY_BACKED_UP` en la máquina de estados. Se guarda un archivo por evento con id
  `event:<id>`, y los snapshots (ledger, estado MLS) por reemplazo.
- VAULT-06 añade:
  - el `ObjectStore` S3-compatible (SeaweedFS del compose);
  - el servicio en el compose y en Kubernetes;
  - la imagen de release;
  - el restore drill.

  Hasta entonces el vault se levanta a mano (`npx tsx services/continuity-vault/src/main.ts`) o con la
  imagen común (`--build-arg SERVICE=continuity-vault`).
- La frecuencia es visible. El cliente puede agrupar subidas (VAULT-04) para reducir la señal; v1 no
  disfraza los tiempos.
- Con NIP-98 `open`, cualquiera puede crear cuentas. Se acepta en self-hosted; el SaaS elige `allowlist` u
  `off`.

## Alternativas descartadas
- **Usar el indexer.** Lee e indexa eventos. Mezclar los papeles convertiría el mirror en backup y ampliaría
  lo que puede leer.
- **Meterlo en identity-service,** como `/v1/backups`. Ata el vault a las cuentas de identidad, que ligan
  personas, e impide un vault self-hosted independiente.
- **Cifrar con la nsec,** o con NIP-44 a uno mismo:
  - una nsec filtrada abriría todo el historial;
  - un signer remoto tendría que descifrar cada archivo;
  - el PRD pide una llave de respaldo separada.
- **Ids asignados por el servidor (`POST`).** Un reintento duplicaría. Los ids del cliente (HMAC) hacen la
  subida idempotente sin decirle al servidor qué contienen.
