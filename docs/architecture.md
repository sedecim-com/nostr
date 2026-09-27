# Arquitectura (v0.1)

Nostr es el contrato de interoperabilidad. Los clientes propios y Buzz leen/escriben los mismos eventos
firmados; las bases de datos son índices derivados.

```
        CLIENTES                      SERVICIOS PROPIOS (API solo para cuenta/políticas/custodia)
  web-saas · sovereign-client ─┐      identity-service (NIP-98) · policy-engine · managed-signer
                               │      notification-gateway (push opaco, opt-in, ADR 0010)
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
| `delivery-engine` | Máquina de estados DRAFT→…→READ, outbox persistente, quorum, reintentos idempotentes, reconciliación |
| `encrypted-store` | Store local cifrado (XChaCha20-Poly1305, nombres HMAC), backends memoria/archivo atómico/IndexedDB; `Vault` con contraseña o llave del dispositivo (ADR 0007) |
| `identity` | Personas, compartimentos, vínculos con consentimiento, backup/restore NIP-49; vínculo público opcional firmado por ambas personas ([`public-link.md`](public-link.md)) |
| `messaging` | NIP-29, NIP-17/NIP-59, receipts (provisionales), feature flags, propiedades por tipo de conversación |
| `marmot-adapter` | `GroupCryptoProvider`/`GroupSession`, proveedor marmot-ts (MLS), almacenamiento MLS cifrado, autoprueba de secreto post-expulsión, conformidad |
| `blossom-client` | Saneamiento EXIF, cifrado AES-GCM compatible con kind 15, BUD-01/02, verificación de hash; lista de servidores del usuario (BUD-03, kind 10063) con subida al principal y descarga con alternativas |
| `tor-network` | `NetworkGuard`: direct / tor-only, onion-only, allowlist, aislamiento de circuitos, fail closed |
| `telemetry-policy` | Redacción de secretos, niveles standard/minimal/none |
| `metrics` | Exportador Prometheus (latencia de ACK por relay y región, outbox) que respeta el nivel de telemetría del perfil ([`slo.md`](slo.md#latencia)) |
| `profiles` | Configuración del panel, presets (Apéndice B), validación, disclosures y matriz de notificaciones push (ADR 0010) |
| `policy-client` | Evaluador RBAC/ABAC + device trust |
| `sync` | Reconstrucción de historial: NIP-77 (Negentropy) con detección NIP-11/sonda y fallback automático a REQ por ventanas; `rebuildHistory` (canales, DMs, evidencia para el outbox); export/import JSONL |
| `service-kit` | HTTP mínimo con NIP-98/bearer y migraciones SQL |
| `test-relay` | Relay/Blossom/SOCKS en memoria para E2E con inyección de fallos |

## Decisiones (ADR resumidas; ver §25.1)
1. **Biblioteca base TS**: `@noble/*` + `@scure/base` directamente (auditadas, sin dependencias); `nostr-tools`
   solo como oráculo de interoperabilidad en tests. Rust/Flutter: rust-nostr + MDK y `flutter_rust_bridge` (ADR 0004), diferido hasta que haya app nativa.
2. **Storage local**: XChaCha20-Poly1305 con clave scrypt; nombres de entrada HMAC; escritura atómica.
3. **Receipts**: rumor gift-wrapped kind `16914`; lectura opt-in (ADR 0005).
4. **Marmot**: marmot-ts 0.5.1 + ts-mls rc.16 detrás de `GroupCryptoProvider`; tráfico por el relay secundario porque Buzz rechaza los kinds (ADR 0006).
5. **Licencia/nombre**: Apache-2.0 con scope `@sedecim` (ADR 0001); Buzz upstream sin fork (ADR 0002). Marca comercial pendiente.
6. **Notificaciones móviles**, **región cloud/legal para managed**: abiertas. Threat models por perfil en `docs/threat-models/`.

## APIs: anti-replay NIP-98 y límites de tasa
Aplica a identity-service, policy-engine, indexer, notification-gateway y managed-signer (todos sobre
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
responde 429 en vez de 401), `mutating` (resto de POST/PUT/DELETE), `read` (GET) y `service` (rutas bearer
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
  permite elegir cabezas también en un espejo sellado.
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
