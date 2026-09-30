# Arquitectura (v0.1)

Nostr es el contrato de interoperabilidad. Los clientes propios y Buzz leen/escriben los mismos eventos
firmados; las bases de datos son índices derivados.

```
        CLIENTES                      SERVICIOS PROPIOS (API solo para cuenta/políticas/custodia)
  web-saas · sovereign-client ─┐      identity-service (NIP-98) · policy-engine · managed-signer
                               │      notification-gateway (push opaco, opt-in, ADR 0010)
                               │      continuity-vault (sobres sellados en el cliente, ADR 0011)
  Buzz Desktop/Mobile          │                     │
                               ▼                     │
                     SDK (packages/*) ───────────────┘
   nostr-core · signer · relay-pool · delivery-engine · encrypted-store · identity
   messaging · blossom-client · tor-network · telemetry-policy · metrics · profiles · sync
                               │ WebSocket (NIP-01/29/42) — directo o vía Tor (socks5h)
             ┌─────────────────┼──────────────────┐
         Buzz relay       relay secundario     relay .onion
             └─────────────────┼──────────────────┘
                               ▼
                    indexer / mirror (ciphertext-first) ──► Postgres
                    Blossom: /media en Buzz (imágenes en claro) · blob-store (adjuntos cifrados)
```

## Paquetes (spec §17.1)
| Paquete | Responsabilidad |
|---|---|
| `nostr-core` | Eventos NIP-01, BIP-340, NIP-19, NIP-44 v2, NIP-49, NIP-98, filtros, head selection, interfaz `Signer` |
| `relay-pool` | WebSocket multi-relay, NIP-42, reconexión con backoff, dedupe, salud por relay |
| `signer` | `LocalSigner`, `Nip46Signer`/`Nip46Bunker`, `Nip07Signer`, `ManagedSignerClient` |
| `delivery-engine` | Máquina de estados DRAFT→…→READ, outbox persistente, quorum, reintentos idempotentes, reconciliación, y la copia en el Continuity Vault como pista propia (`CONTINUITY_BACKED_UP`, VAULT-04) |
| `encrypted-store` | Store local cifrado (XChaCha20-Poly1305, nombres HMAC), backends memoria/archivo atómico/IndexedDB; `Vault` con contraseña o llave del dispositivo (ADR 0007) |
| `identity` | Personas, compartimentos, vínculos con consentimiento, backup/restore NIP-49; vínculo público opcional firmado por ambas personas ([`public-link.md`](public-link.md)) |
| `messaging` | NIP-29, NIP-17/NIP-59, receipts (provisionales), feature flags, propiedades por tipo de conversación, DMs como operaciones de envío (FR011-05) |
| `marmot-adapter` | `GroupCryptoProvider`/`GroupSession`, proveedor marmot-ts (MLS), almacenamiento MLS cifrado, autoprueba de secreto post-expulsión, conformidad; los flujos que comparten el CLI y la web (dispositivos, propuestas y adjuntos MIP-04, FR025-14) |
| `blossom-client` | Saneamiento EXIF, cifrado AES-GCM compatible con kind 15, BUD-01/02, verificación de hash; lista de servidores del usuario (BUD-03, kind 10063) con subida al principal y descarga con alternativas; subida en espejo del cifrado de los archivos de grupo (`ciphertextUploader`) |
| `tor-network` | `NetworkGuard`: direct / tor-only, onion-only, allowlist, aislamiento de circuitos, fail closed |
| `telemetry-policy` | Redacción de secretos, niveles standard/minimal/none y trazador de los servicios: muestreo en la raíz, atributos acotados, log y OTLP opcional ([`slo.md`](slo.md#trazas-nfr007-02)) |
| `metrics` | Exportador Prometheus (latencia de ACK por relay y región, outbox) que respeta el nivel de telemetría del perfil ([`slo.md`](slo.md#latencia)) |
| `profiles` | Configuración del panel, presets (Apéndice B), validación, disclosures y matriz de notificaciones push (ADR 0010) |
| `policy-client` | Evaluador RBAC/ABAC + device trust |
| `qr` | Codificador QR propio (ISO/IEC 18004, modo byte) sin dependencias ni red, salida SVG (generador offline, `nostrconnect` en la web) |
| `rotation-worker` | Worker de revocación (FR-024): rotación MLS pendiente del policy-engine y propagación de revocaciones al managed-signer. Corre como servicio `services/rotation-worker` (FR024-05, compose perfil `institutional` y k8s) o desde el CLI (`sovereign group rotation-worker`) |
| `sync` | Reconstrucción de historial: NIP-77 (Negentropy) con detección NIP-11/sonda y fallback automático a REQ por ventanas; `rebuildHistory` (canales, DMs, evidencia para el outbox); export/import JSONL |
| `continuity` | Continuity Vault (ADR 0011): llave de archivo por persona distinta de la nsec, sobres XChaCha20-Poly1305 con relleno y AAD ligado al id, validador compartido que rechaza texto plano, cliente del vault, y archivo y restauración del historial de la persona (eventos, mensajes de grupo, ledger y estado MLS; VAULT-03), y su exportación portable (`sedecim-vault-export`, VAULT-05) |
| `service-kit` | HTTP mínimo con NIP-98/bearer, anti-replay NIP-98, límites de tasa, verificación de tokens de Acceso (Cognito), migraciones SQL y un span por petición y por consulta (apagado por defecto) |
| `test-relay` | Relay/Blossom/SOCKS en memoria para E2E con inyección de fallos |

## Decisiones (ADR resumidas; ver §25.1)
1. **Biblioteca base TS**: `@noble/*` + `@scure/base` directamente (auditadas, sin dependencias); `nostr-tools`
   como oráculo de interoperabilidad en los tests y, en runtime, solo para NIP-77 (Negentropy) en `packages/sync`. Rust/Flutter: rust-nostr + MDK y `flutter_rust_bridge` (ADR 0004), diferido hasta que haya app nativa.
2. **Storage local**: XChaCha20-Poly1305 con clave scrypt; nombres de entrada HMAC; escritura atómica.
3. **Receipts**: rumor gift-wrapped kind `16914`; lectura opt-in (ADR 0005).
4. **Marmot**: marmot-ts 0.5.1 + ts-mls rc.16 detrás de `GroupCryptoProvider`; tráfico por el relay secundario porque Buzz rechaza los kinds (ADR 0006).
5. **Licencia/nombre**: Apache-2.0 con scope `@sedecim` (ADR 0001); Buzz upstream sin fork (ADR 0002). Marca comercial pendiente.
6. **Notificaciones push**: opacas y opt-in por perfil, sin push en sovereign ni Tor (ADR 0010). **Custodia managed**:
   `us-east-1`, KMS + Secrets Manager y LFPDPPP (ADR 0009; términos pendientes de aprobación legal). Threat models por
   perfil en `docs/threat-models/`.

## Operaciones de envío del cliente (FR011-05)

El scope pide un identificador interno estable por operación, además del `event_id` (§11.1), para que un reintento de
la interfaz no duplique nada (§11.2). Cada envío de la web y del CLI es una operación con un id propio:

- **Web.** El id se mantiene mientras la persona reintenta el mismo mensaje (mismo destinatario o canal, texto y
  archivo) y cambia en cuanto edita algo o el envío sale (`SendOperation`, `apps/web-saas/src/lib/outbox.ts`).
- **CLI.** `dm send` y `channel send` imprimen el id antes de enviar, y `--op ID` reintenta ese envío, aunque se
  cortara a medias. Otro texto u otro destinatario con el mismo id se rechaza: sería un mensaje nuevo, no un
  reintento.
- **Canales y otros eventos.** `DeliveryEngine.submitOnce(opId, build)` guarda la operación (`LOCAL_PERSISTED`)
  antes de firmarla. Un reintento la vuelve a enviar y no construye nada: ni otro evento ni otra subida del adjunto.
  `submit` se serializa por id, así que un doble clic deja una sola operación.
- **DMs.** `DirectMessenger.sendDmOnce` y `sendFileOnce` guardan el rumor en el store cifrado de la persona
  (`dm-ops`) antes de crear ningún seal ni wrap. El wrap de cada destinatario, y la copia propia, va al outbox con
  el id `<operación>:<pubkey>`. Un reintento usa el mismo rumor, reenvía los wraps ya encolados y crea solo los que
  falten; si el firmante falló a mitad, el destinatario que ya tenía su wrap no recibe otro.

## Custodia gestionada: sesiones del navegador y recuperación (FR005-11)

**Sesión de dispositivo.** La web firma por una persona gestionada con una sesión de dispositivo de ese navegador, no
con el token de Acceso:
- la abre con el login de Acceso (`POST /v1/device-sessions`, 12 h) y la guarda en el almacén cifrado. El
  managed-signer nunca concede más que su vida configurada (`MANAGED_SIGNER_DEVICE_SESSION_TTL_S`), aunque el cliente
  pida más (IR-2026-10-11);
- su id de dispositivo es aleatorio (`web-…`) y es el mismo para todas las personas del navegador;
- si el managed-signer la rechaza (caducada o cerrada), la reabre con el login y repite la petición una vez. Un 401
  significa que no se hizo nada, así que repetirla no duplica nada.

La web funciona igual con `MANAGED_SIGNER_REQUIRE_DEVICE_SESSION=true`: el E2E corre así.

**Sesiones propias** (`services/managed-signer`). Nunca se muestra un token.
- `GET /v1/device-sessions` lista las del usuario: dispositivo, apertura y caducidad. Acepta el login o cualquiera de
  sus sesiones, y marca la de la llamada como `current`.
- `DELETE /v1/device-sessions/:id` cierra una. Con el login, cualquiera de las suyas; con una sesión, solo esa misma.
- `DELETE /v1/device-sessions?except=<id>` cierra todas menos una. Solo con un login reciente (ver abajo). Además deja
  fuera los demás logins de Acceso firmados antes de ese momento, salvo el de quien las cierra: aunque se refresquen
  (un token refrescado conserva su `auth_time`), no abren sesiones ni firman hasta que alguien vuelva a escribir la
  contraseña (IR-2026-10-11). El corte se guarda lo mismo que el log de uso (12 meses).
- Otro usuario no ve ni cierra las sesiones ajenas.
- El id público se deriva del hash del token: nombra la sesión, no sirve para abrirla.
- Cerrar una sesión no revoca el dispositivo: eso lo decide la organización (FR024-03). Si se cierra solo esa, un
  navegador que sigue con el login abierto abre otra en su siguiente firma; «cerrar las demás» se lo impide. Ante un
  dispositivo perdido hay que cambiar también la contraseña de Acceso.
- Con `organizationDevices` en la configuración, el navegador puede vincularse al dispositivo que la organización le
  registró: sus sesiones llevan ese id y revocarlo lo corta (docs/institutional.md, «Navegadores como dispositivos de
  la organización»).

**Operaciones que piden la contraseña otra vez** (IR-2026-10-03). Exportar la llave, confirmar su migración, borrarla,
cancelar la custodia y cerrar las demás sesiones solo se aceptan con un login de Acceso de los últimos minutos
(`auth_time`, `MANAGED_SIGNER_REAUTH_MAX_AGE_S`, 300 s por defecto), nunca con la sesión del navegador. Si no, el
managed-signer responde 401 con `WWW-Authenticate: Bearer error="insufficient_user_authentication"` (RFC 9470).
- La web pide la contraseña de Acceso, entra otra vez aparte y, si es correcta, ese login nuevo pasa a ser el del
  navegador. Con una contraseña incorrecta, la sesión actual sigue como estaba.
- Quien tenga el navegador abierto pero no la contraseña firma mientras dure su sesión, pero no puede sacar la llave
  ni destruirla.
- El log de uso de una llave sigue visible para su dueño después de borrarla o cancelarla, hasta que se destruye.

**Recuperación en otro navegador.**
1. Se entra con el mismo login de Acceso.
2. En «Nueva persona», «Recuperar mi persona gestionada» lista las llaves gestionadas que aún firman (`GET /v1/keys`,
   por la sesión del navegador) y no están ya en ese navegador.
3. Se abre la elegida: misma npub, ninguna llave nueva y el consentimiento registrado con la llave.

No se vuelve a publicar la lista de relays de DM (kind 10050), que es la del otro navegador. La llave de archivo del
Continuity Vault vuelve desde el archivo de backup, en su tarjeta.

**Registro de uso.** La tarjeta «Actividad de tu llave gestionada» muestra:
- las 20 operaciones más recientes (`GET /v1/keys/:id/usage`), con el dispositivo que las hizo. El registro se
  guarda 12 meses (DEC-09);
- las sesiones abiertas, con «Cerrar» y «Cerrar las demás sesiones».

**Pruebas.**
- `services/managed-signer/test/own-sessions.test.ts`;
- `registry.test.ts`, en memoria y Postgres;
- `tests/browser/web-saas.e2e.ts`: un segundo navegador recupera la persona, firma, ve las dos sesiones y cierra la
  del primero, que vuelve a firmar tras abrir otra.

## Grupos MLS sin red (FR025-12)

Los mensajes y commits de grupos Marmot tienen su propio outbox en el adaptador (`packages/marmot-adapter`), sellado
con el estado MLS. No van por el `DeliveryEngine`, porque un evento de grupo no es fijo:
- un mensaje se vuelve a cifrar si el grupo cambia de época antes de que salga;
- un commit se guarda con el estado al que lleva, para aplicarlo si un relay lo tomó sin que llegara el OK, o se
  vuelve a construir si otro commit ganó su época.

Nada adelanta a un commit pendiente. Detalle en `docs/marmot.md` («Sin red: mensajes y commits pendientes»).

## Grupos MLS completos en la web (FR025-14)

La web y el CLI hacen lo mismo con los grupos: multi-dispositivo, rotación, propuestas y archivos MIP-04. Las
decisiones viven en `packages/marmot-adapter/src/flows.ts`: quién hace commit y quién propone, qué lleva una propuesta
y cómo se abre un adjunto. La vista añade las confirmaciones y las reglas de la web: el aviso de reutilización entre
personas y la de no invitar ni proponer otra persona propia. Las operaciones MLS de una persona siguen en una sola
cola por sesión. La descarga de un archivo queda fuera de la cola; su subida, dentro, porque la época no puede cambiar
mientras se sube. Qué ve cada parte: `docs/threat-model.md`; detalle: `docs/marmot.md` («Uso (web…)»).

## Canales NIP-29: reacciones, hilos y borrado (FR015-04)
La vista de canales suscribe los mensajes (kind 9) de un canal y, con su propio límite, las reacciones y los borrados
de alrededor (7, 5 y 9005), y lee la lista de admins (39001) firmada por la llave que firma el 39000 del canal.
`channelView` (`packages/messaging/src/nip29.ts`) decide qué se muestra a partir de esos eventos, en cualquier orden:
- una respuesta va en el hilo que dicen sus marcadores NIP-10, leídos como Buzz (`threadOf`);
- cada reacción cuenta una vez por autor y contenido en el mensaje de su último `e`;
- un mensaje desaparece con un kind 5 o un 9005 de su autor, o con un 9005 de un admin en el mismo canal; una reacción,
  con un kind 5 de su autor.

Lo que la web envía (`apps/web-saas/src/lib/channels.ts`) pasa por el outbox como cualquier envío:
- responder publica un kind 9 en el hilo del padre (`replyMessage`);
- reaccionar, un kind 7, y quitar la reacción propia, un kind 5 de ella;
- borrar un mensaje propio o, como admin, uno ajeno, un 9005, después de un diálogo que dice lo que el borrado no hace
  (`CHANNEL_DELETION_TEXTS`).

Nada nuevo se guarda en el navegador aparte del outbox. Las reglas de Buzz y el gate contra el Buzz fijado están en
[`buzz-integration.md`](buzz-integration.md) («Reacciones, hilos y borrado en canales»). Pruebas:
- `packages/messaging/test/channels.test.ts`: la vista y los eventos;
- `apps/web-saas/test/channel-collab.test.ts`: la web contra un relay de prueba con las reglas de Buzz
  (`TestRelay` con `groupModeration`);
- `tests/interop/buzz.interop.test.ts`: contra Buzz, en CI.

## APIs: anti-replay NIP-98 y límites de tasa
Aplica a identity-service, policy-engine, indexer, notification-gateway, managed-signer y continuity-vault (todos sobre
`packages/service-kit`) y a blob-store (servidor propio que usa el mismo limitador). Corrige IR-2026-09-04 e
IR-2026-09-05 de la [revisión interna](security/internal-review-2026-09.md).

**NIP-98 (`Service.authenticate`).** Se exige kind 27235 con firma válida, `created_at` a ±60 s, `u` igual a
la URL pública exacta de la petición (`PUBLIC_BASE_URL` sin barra final + ruta + query tal como llegan; el
esquema y el host cuentan), `method` igual al de la petición y `payload` = SHA-256 del cuerpo cuando hay
cuerpo (sin cuerpo, un `payload` distinto del hash vacío se rechaza). Cada id de evento se acepta **una sola
vez** mientras está dentro de la ventana; un segundo uso da 401 `authorization already used`.

- **Almacén.** Con `DATABASE_URL`, identity-service, policy-engine e indexer usan `PgReplayStore`: tabla
  `nip98_replay` (id de evento como clave primaria y caducidad), creada por service-kit
  (`packages/service-kit/migrations`, ámbito `service-kit` de `schema_migrations`) y compartida por todas las
  réplicas y servicios de la misma base. `INSERT … ON CONFLICT DO NOTHING` decide de forma atómica qué
  petición gana; una limpieza cada minuto borra las filas caducadas hace más de 60 s. Sin base de datos
  (notification-gateway, o cualquier servicio sin `DATABASE_URL`) se usa `MemoryReplayStore`, **por
  proceso**: una cabecera capturada puede reutilizarse como mucho una vez en cada réplica distinta. Si la
  caché en memoria se llena (200 000 ids vivos) responde 503 en vez de olvidar ids.
- **Clientes.** `buildHttpAuthTemplate` añade un tag `nonce` aleatorio: dos peticiones idénticas en el mismo
  segundo, o un reintento, producen ids distintos. Ningún cliente del repositorio reutiliza una cabecera
  (web-saas, consola de administración, cliente de backups, `rotation-worker`, `nip98Fetch`): todos firman
  en cada petición. Un cliente externo que firme dos veces el mismo contenido en el mismo segundo sin tag
  extra obtendrá 401 en la segunda.
- **Fuera de alcance.** Los tokens Blossom de blob-store (kind 24242, BUD-02) siguen siendo reutilizables
  hasta su `expiration`, como permite la especificación; los limita la tasa por IP y por pubkey. La prueba
  de control de llave de identity-service (kind 27235 en el cuerpo) va siempre dentro de una petición NIP-98.

**Límites de tasa.** Token buckets en memoria (`HttpRateLimiter` de service-kit), primero por IP del cliente
(antes de leer el cuerpo o verificar firmas) y, tras autenticar, por principal (pubkey NIP-98, principal del
bearer de servicio o, en rutas con token Acceso, `cognito:<issuer>#<sub>`). Cada ruta tiene una clase:
`auth` (creación de cuentas, vincular login Acceso, descarga de un backup, apertura de sesiones de
dispositivo del signer; además, cada autenticación fallida gasta del bucket `auth` de su IP, y al agotarse
responde 429 en vez de 401), `mutating` (resto de POST/PUT/DELETE, y el GET de la attestation del enclave del
managed-signer, que hace firmar un documento al enclave, FR005-10), `read` (GET) y `service` (rutas bearer
servicio a servicio: solo por principal, no por IP). Los health checks no se limitan (salvo el del indexer,
que consulta la base). La respuesta es 429 con `Retry-After`; se registra una línea `rate limited` con
clase, ámbito y segundos (sin IP, pubkey ni token) y el contador `http_rate_limited_total{class,scope}` en
`METRICS_PORT` (sin etiquetas identificativas). La memoria está acotada: como mucho `RATE_LIMIT_MAX_KEYS`
buckets, se expulsa el menos usado (una expulsión solo perdona).

**Los límites son por réplica**: con N réplicas el límite efectivo es hasta N veces el configurado (el
balanceador reparte las peticiones). Lo mismo vale para el edge (por pod) y para el anti-replay en memoria.

| Variable | Por defecto | Uso |
|---|---|---|
| `RATE_LIMIT` | activo | `off` desactiva el limitador del servicio |
| `RATE_LIMIT_AUTH` | `20:10` | `porMinuto[:ráfaga]` de la clase `auth` (por IP y por principal) |
| `RATE_LIMIT_MUTATING` | `120:60` | Clase `mutating` |
| `RATE_LIMIT_READ` | `600:300` | Clase `read` (en compose, `INDEXER_RATE_LIMIT_READ` para el indexer) |
| `RATE_LIMIT_SERVICE` | `6000:1000` | Clase `service` (bearer), solo por principal |
| `RATE_LIMIT_TRUST_PROXY_HOPS` | `0` | Proxies delante del servicio cuyo `X-Forwarded-For` se cree. `0`: se ignora la cabecera (falsificable). k8s y `compose.tls.yml`: `1` |
| `RATE_LIMIT_MAX_KEYS` | `100000` | Buckets en memoria |
| `BLOB_MAX_CONCURRENT_UPLOADS_PER_IP` | `4` | Subidas simultáneas por IP en blob-store (cada una puede ocupar `BLOB_MAX_BYTES` en memoria) |
| `MANAGED_SIGNER_SCRYPT_PER_OWNER` | `10:5` | Import/export (scrypt) por dueño; también cuentan las contraseñas erróneas |
| `MANAGED_SIGNER_SCRYPT_CONCURRENCY` | `2` | scrypt simultáneos por réplica (hasta 256 MiB cada uno) |
| `MANAGED_SIGNER_SCRYPT_QUEUE` | `16` | Operaciones en espera; por encima, 429 |
| `MANAGED_SIGNER_SCRYPT_LIMITS` | activo | `off` desactiva la admisión de scrypt |

En managed-signer, además, un dueño solo puede tener una importación o exportación en curso; los límites de
firma por llave y por kind (`MANAGED_SIGNER_RATE_*`, FR005-06) siguen igual y son independientes.

**Trazas (NFR007-02).** El servidor de service-kit (y el de blob-store) abre un span por petición y
`createPgPool`, uno hijo por consulta, con el muestreo decidido en la raíz (`TRACE_SAMPLE_RATE`, 0 por defecto) y
solo atributos acotados: método, ruta como plantilla, estado, clase del error y operación de base de datos. Van al
log del servicio y, con `TRACE_EXPORT_URL`, al colector OTLP del operador. Con `TELEMETRY_LEVEL=none` no existen, y
una petición a un `.onion` nunca se traza. Detalle en [`slo.md`](slo.md#trazas-nfr007-02).

**Edge.** En Kubernetes, `deploy/k8s/base/files/edge-nginx.conf` resuelve la IP real (`set_real_ip_from`
rangos privados + `real_ip_recursive`), aplica `limit_req`/`limit_conn` por host y reenvía esa IP como único
`X-Forwarded-For`; también añade HSTS (solo tras TLS en el ALB), `X-Content-Type-Options` y
`X-Frame-Options` a todos los hosts (la web conserva su CSP con `frame-ancestors 'none'`). El nginx de la web
(`infra/web/nginx.conf`) limita los estáticos por IP. En compose con TLS, la imagen de Caddy no trae módulo de
límites: quedan los de cada servicio, que confían en el `X-Forwarded-For` de Caddy.

## Indexer / mirror: escalado horizontal (NFR005-01)
El indexer (`services/indexer`) corre con N réplicas sobre la misma base Postgres, sin duplicados ni pérdidas.
Las lecturas (`/v1/*`) no tienen estado: cualquier réplica las sirve detrás del Service de Kubernetes.

- **Shards.** Cada relay de `INDEXER_RELAYS` es un shard (suscripción base con los kinds espejados) y cada par
  relay + canal NIP-29 (`#h`) es otro (Buzz solo reparte el tráfico de canal a suscripciones `#h`). Todas las
  réplicas descubren los canales (kind 39000); cada una solo se suscribe a los shards que le tocan.
- **Asignación determinista.** Membresía por latido en `indexer_replicas` (reloj de la base, cada
  `INDEXER_HEARTBEAT_MS`, 5 s por defecto; una réplica sin latido durante `INDEXER_MEMBER_TTL_MS`, 3 latidos
  por defecto, se da por caída). El dueño de cada shard se elige por *rendezvous hashing* (HRW) sobre las
  réplicas vivas: todas calculan lo mismo y, al entrar o salir una réplica, solo se mueven sus shards.
- **Checkpoints por shard.** El dueño guarda en `indexer_checkpoints` hasta qué `created_at` está todo escrito:
  solo avanza con la suscripción conectada y tras su EOSE, nunca por delante de un evento en vuelo ni de una
  escritura fallida, y nunca retrocede. Quien toma un shard (réplica caída, rebalanceo, reinicio) se
  resuscribe desde `checkpoint − INDEXER_OVERLAP_SECONDS` (900 s por defecto); lo repetido se descarta.
  Un shard nunca sincronizado se reconstruye desde el principio. Tras una reconexión al relay la
  suscripción se reabre desde su checkpoint.
- **Escrituras idempotentes.** `event_id` es la clave primaria (`INSERT … ON CONFLICT DO NOTHING RETURNING`),
  así que cada evento se inserta una sola vez aunque dos réplicas lo reciban a la vez. Para eventos
  reemplazables y direccionables, los escritores de una misma dirección se serializan con
  `pg_advisory_xact_lock` y la nueva cabeza borra las versiones que reemplaza: tras cualquier carrera queda
  solo la cabeza NIP-01 (mayor `created_at`, empate por menor id). La columna `d_tag` (migración 003)
  permite elegir cabezas también en un espejo sellado. En modo institucional las versiones reemplazadas pasan a
  `events_superseded` en la misma transacción, y la retención borra las que no cubre un legal hold (FR023-12).
- **Trabajos únicos.** La retención institucional (FR023-08) se reclama de forma atómica en `indexer_jobs`:
  la ejecuta una sola réplica por `RETENTION_INTERVAL_MS`, y sus borrados son idempotentes de todos modos.
  El filtrado por políticas (FR023-05) se evalúa en cada lectura, en la réplica que la atiende.
- **Parada.** SIGTERM guarda los checkpoints y da de baja la réplica, así que sus shards se mueven en el
  siguiente latido de las demás y no hay que esperar al TTL.

Durante un cambio de membresía, las vistas pueden diferir un latido: dos réplicas espejan el mismo shard (inocuo)
o ninguna lo hace durante como mucho un TTL (lo cubre el checkpoint). **Límite:** un evento publicado
durante ese hueco con un `created_at` más de `INDEXER_OVERLAP_SECONDS` anterior al checkpoint no se recupera
hasta una reconstrucción completa. Por eso la ventana por defecto es amplia; los gift wraps con marca de
tiempo aleatoria no se espejan por defecto.

| Variable | Por defecto | Uso |
|---|---|---|
| `INDEXER_REPLICA_ID` | hostname | Identidad única de la réplica (en k8s, el nombre del pod vía `fieldRef`) |
| `INDEXER_HEARTBEAT_MS` | `5000` | Latido, volcado de checkpoints y rebalanceo |
| `INDEXER_MEMBER_TTL_MS` | 3 latidos | Tras cuánto tiempo sin latido se reparten los shards de una réplica |
| `INDEXER_OVERLAP_SECONDS` | `900` | Solape al resuscribirse desde un checkpoint |

Despliegue: `deploy/k8s/base/indexer.yaml` (anti-afinidad preferente por nodo, identidad por pod); el overlay
`stage` fija 2 réplicas. En compose, `docker compose --profile scale up -d` añade `indexer-2` (puerto
`INDEXER_2_PORT`, 8091). Sin `DATABASE_URL` el indexer usa memoria y es de una sola réplica. La prueba de
concurrencia (`services/indexer/test/sharding.test.ts`) levanta 3–4 réplicas contra dos relays de prueba
(uno como Buzz), con caída, alta y baja de réplicas y publicación concurrente. Comprueba que queda
indexado exactamente el conjunto publicado, que cada id se inserta una sola vez y que las direcciones
reemplazables quedan en su última versión. Corre en memoria y, con `TEST_DATABASE_URL`, sobre Postgres
con un pool por réplica (CI). Las cifras de carga están en [`load-testing.md`](load-testing.md).

## Indexer / mirror: membresía NIP-29 y moderación (FR014-05)
El espejo no sirve un canal a quien el relay no se lo serviría:
- **Solo miembros.** Los mensajes de un canal (`h`) y su estado NIP-29 (39000-39003, por su `d`) solo se
  devuelven a quien aparece en la lista de admins (39001) o de miembros (39002) del canal. Aplica a
  `/v1/events`, `/v1/events/:id`, el resumen, los no leídos, el cursor de lectura y la búsqueda, también sin
  nombrar un canal. Sin NIP-98 no se es miembro de nada. En modo institucional, además, decide el policy-engine
  (FR023-05).
- **Qué listas cuentan.** Solo las firmadas por la llave del relay que aloja el canal:
  - `INDEXER_GROUP_AUTHORITIES` (hex o npub, separadas por comas);
  - o, si está vacía, el campo `self` del NIP-11 de cada relay seguido. Buzz lo publica cuando tiene una llave
    estable (`BUZZ_RELAY_PRIVATE_KEY`, obligatoria en compose).

  Una lista firmada por otra llave no da acceso. Cuando el relay publica una lista nueva sin alguien, esa
  persona pierde el acceso. El indexer consulta las listas junto con los 39000 en cada refresco de canales
  (Buzz no las reparte en vivo).
- **Moderación.** Un 9005 (borrar un evento del grupo) oculta su objetivo, igual que en Buzz:
  - quien lo firma debe ser el autor del evento o un owner/admin de la 39001 del canal;
  - el objetivo debe estar en el mismo canal.

  Los 9005 llegan por la suscripción `#h` de cada canal. Se guardan en `moderation_deletions` hasta que se
  pueden aplicar, así que da igual qué llega antes: el 9005, su objetivo o la lista de admins que lo autoriza.
  Los borrados NIP-09 (kind 5) siguen ocultando solo eventos propios.

| Variable | Por defecto | Uso |
|---|---|---|
| `INDEXER_GROUP_AUTHORITIES` | vacía (NIP-11 `self`) | Llaves de relay cuyas listas NIP-29 dan acceso a un canal |

Pruebas en `services/indexer/test/membership.test.ts`, en memoria y en Postgres, en claro y sellado:
- quién lee qué y qué pasa al salir de un canal;
- la búsqueda;
- los 9005 en cualquier orden de llegada;
- un relay como Buzz que publica `self`.

`tests/interop/stack.interop.test.ts` lo comprueba contra el Buzz fijado.

## Indexer / mirror: no leídos y búsqueda en la web (FR014-04)
La vista de canales de la web pide al mirror los contadores de no leídos y la búsqueda: son consultas derivadas por la
API propia (spec §15.2), y los mensajes siguen llegando por WebSocket desde los relays. Cada consulta va firmada con la
llave de la persona (NIP-98), así que el indexer aplica sus reglas de siempre: la membresía NIP-29 (FR014-05) y, en
modo institucional, la política (FR023-05). Un canal que el mirror no responde no tiene contador.

- **Quién la usa.** `mirrorPolicy` (`packages/profiles`) lo decide por los controles de la persona:
  - con identidad vinculada o verificada (convenience, institutional), sí;
  - con identidad pseudónima (private-resilient, sovereign), no: cada consulta firmada le daría al operador el registro
    de qué canales lee la persona y qué busca;
  - en Tor-only, nunca, igual que los relays.

  La vista de canales lo dice con los textos de `CHANNEL_MIRROR_TEXTS`, que están en el catálogo revisado
  (`docs/disclosures.md`). Sin `mirror` en `config.json`, la vista no muestra contadores ni búsqueda.
- **Dónde vive el «leído hasta».** En el vault del navegador, cifrado, en la colección `chanread-<persona>`. Por canal
  guarda el `created_at` del mensaje más nuevo que la vista mostró; nunca retrocede ni pasa de la hora actual. No se
  envía: la web pide `GET /v1/unread/recent?h=…&kinds=9` y el mirror devuelve la hora de los mensajes más recientes de
  cada canal que la persona puede leer (hasta 100, sin los suyos ni los borrados). La web cuenta los posteriores a su
  cursor y muestra `100+` si toda la lista lo es. La web no usa `PUT /v1/read-cursor` (FR014-03), que sigue para otros
  clientes. El cursor no se sincroniza entre navegadores: un canal que este navegador nunca contó empieza como leído.
- **Búsqueda.** `GET /v1/search?q=…&kinds=9`: el operador ve el texto buscado. La web verifica la firma de cada
  resultado y descarta lo que no sea un mensaje de canal.
- **Cuándo consulta.** Al abrir la vista y cada 60 s mientras sigue abierta y visible, si la llave está en el navegador
  o en el managed-signer. Con NIP-07 o NIP-46, solo al pulsar «Actualizar», porque el signer puede pedir aprobar cada
  firma.
- **Despliegue.** El indexer responde al origen de la web (`CORS_ORIGINS`: `WEB_ORIGIN` en compose y k8s). `mirror`
  debe ser su `PUBLIC_BASE_URL`, porque la firma NIP-98 nombra esa URL (`tests/scripts/deploy-manifests.test.ts`).

Además de lo que ya ve el relay, el operador del mirror ve por qué canales pregunta la persona, cuándo, desde qué
dirección y qué busca. No ve hasta dónde leyó cada canal.

Pruebas:
- `apps/web-saas/test/mirror.test.ts`: la librería de la web contra el indexer real, con NIP-98, membresía y política;
  qué llega al mirror y qué queda en el vault;
- `services/indexer/test/indexer.test.ts`, `membership.test.ts` y `policy.test.ts`: la ruta nueva, en memoria y en
  Postgres, en claro y sellado;
- `packages/profiles/test/profiles.test.ts`: la política por perfil.
