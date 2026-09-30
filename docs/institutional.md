# Modo institucional: policy-engine, allowlist de relays, retención y dispositivos

El modo institucional (spec §16, FR-023/FR-024) añade a la identidad Nostr una capa de políticas que decide la
organización: roles y atributos por npub, dispositivos registrados o atestados, allowlist NIP-42 de los relays,
filtrado de las lecturas del mirror y retención con legal hold. La identidad sigue siendo la llave Nostr del
usuario; el policy-engine nunca guarda plaintext de mensajes.

| Pieza | Dónde | Qué hace |
|---|---|---|
| `services/policy-engine` | compose `policy-engine`, k8s `base/policy-engine.yaml` | API de políticas (admin NIP-98, servicios con bearer) |
| `relay-allowlist` | compose perfil `institutional`, k8s `components/institutional` | Sincroniza el allowlist NIP-42 de Buzz y del secure-relay |
| `services/indexer` | `POLICY_ENGINE_URL` + `POLICY_ENGINE_TOKEN` | Filtra lecturas por `evaluate()` y aplica la retención |
| `services/rotation-worker` | compose perfil `institutional`, k8s `components/institutional` | Saca de los grupos MLS a quien se revoca y lleva las revocaciones al managed-signer (FR024-05) |
| `@sedecim/policy-client` | paquete | Tipos, evaluador puro y cliente HTTP del engine |

## Persistencia (FR023-03)

Con `DATABASE_URL` el engine guarda sujetos, recursos, dispositivos, sesiones, rotaciones, auditoría, directorio,
retención y desafíos WebAuthn en tablas `policy_*` de la base de plataforma (la misma que identity-service); las
migraciones (`services/policy-engine/migrations`) se aplican al arrancar. Sin `DATABASE_URL` usa un repositorio
en memoria con el mismo comportamiento (se pierde al reiniciar; lo avisa en el log).

- **Auditoría append-only**: `policy_audit` rechaza `UPDATE`, `DELETE` y `TRUNCATE` con triggers. Registra lo que
  hacen los administradores: quién, qué acción, sobre qué y sus metadatos; nunca contenido de mensajes. No se poda.
- **Registro de accesos** (FR023-12): las decisiones de `POST /v1/evaluate` (quién pidió qué acción sobre qué recurso
  y qué se le respondió) van a `policy_access_log`, no a la auditoría, y tienen su propia retención (ver «Qué cubre y
  qué no»). Las anteriores a la migración 003 siguen en la auditoría, porque es append-only; la migración las copia
  al registro de accesos para que también se vean allí.
- **Sesiones**: el token se guarda como hash SHA-256; una fuga de la base no da tokens utilizables.
- **WebAuthn**: se guarda solo la llave pública de la credencial; la privada nunca sale del autenticador.

Pruebas: `services/policy-engine/test/policy-engine.test.ts` ejecuta la misma batería sobre memoria y Postgres,
más un test de reinicio (engine y pool nuevos sobre la misma base conservan todo el estado) y el de auditoría
append-only. Los tests de Postgres corren con `TEST_DATABASE_URL` (servicio postgres de CI) y se omiten sin él.

## API

Todas las rutas son JSON. "Admin" = NIP-98 firmado por una pubkey de `POLICY_ADMIN_PUBKEYS`. "Servicio" =
`Authorization: Bearer <token>` de `POLICY_SERVICE_TOKENS` (`token:principal`, separados por comas).

| Ruta | Auth | Respuesta |
|---|---|---|
| `GET /v1/subjects` · `PUT /v1/subjects/:pubkey` · `POST /v1/subjects/:pubkey/revoke` · `POST /v1/subjects/:pubkey/reactivate` | admin | `{subjects}` · `{ok}` · `{rotations}` · `{ok}` (404 si no existe, 409 si no está revocado) |
| `GET /v1/resources` · `PUT /v1/resources/:id` | admin | `{resources}` · `{ok}` |
| `GET /v1/devices?owner=<hex>` · `POST /v1/devices` · `POST /v1/devices/:id/revoke` | admin | `{devices}` · `Device` · `{rotations}` |
| `POST /v1/devices/:id/webauthn/options` · `POST /v1/devices/:id/webauthn/register` | dueño del dispositivo o admin | `PublicKeyCredentialCreationOptions` (base64url) · `Device` |
| `POST /v1/sessions` | NIP-98 del dueño | `{token}` |
| `POST /v1/evaluate` · `GET /v1/relay/allowlist` | servicio | `Decision` · `{pubkeys}` |
| `GET /v1/relay/grants` | servicio | `{grants}`: por cada recurso `channel` y `group`, `{resourceId, kind, pubkeys}` de quien puede publicar en él (FR023-10) |
| `GET /v1/rotations?status=pending\|done` | admin o servicio | `{rotations}` (cada una con `id` y `status`) |
| `POST /v1/rotations/:id/done` | admin o servicio | `Rotation` |
| `GET /v1/revocations?after=&limit=` | admin o servicio | `{revocations, latest, now}`: revocaciones de dispositivo (`{cursor, at, deviceId, reason}`, más antigua primero) con `cursor` mayor que `after`; `latest` = cursor de la última (FR024-04) |
| `GET /v1/audit?limit=&before=` | admin | `{audit}`, más nuevo primero; `before` = `id` de la última entrada recibida |
| `GET /v1/access-log?limit=&before=&resource=` | admin | `{access, retentionDays}`: decisiones de acceso, más nueva primero; `before` como en la auditoría; `resource` filtra por recurso (FR023-12) |
| `GET /v1/directory` · `PUT /v1/directory/:pubkey` · `DELETE /v1/directory/:pubkey` | admin | `{entries}` · entrada · `{ok}` |
| `GET /v1/retention` | admin o servicio | `{policies, notice}` |
| `PUT /v1/retention/:resourceId` `{days: number\|null, legalHold: boolean}` | admin | `{policy, notice}`; 409 si el recurso es un grupo MLS (FR023-12) |

`PUT /v1/subjects/:pubkey` cambia roles y atributos y nunca la revocación (FR023-09): editar a una persona
revocada la deja revocada, aunque el cuerpo traiga `suspended`. Levantarla es `POST …/reactivate`, con su propia
entrada `subject.reactivate` en la auditoría; los dispositivos revocados siguen revocados y las membresías no
vuelven, así que no entra en el allowlist hasta que se le registra un dispositivo nuevo.

`POST /v1/devices` no acepta `trust: 'attested'`: ese nivel solo se obtiene con WebAuthn. El navegador (consola
de administración, web) llama al engine directamente: `CORS_ORIGINS` = origen de la web.

## Allowlist NIP-42 de los relays (FR023-04)

`GET /v1/relay/allowlist` devuelve los sujetos activos con al menos un dispositivo no revocado. El servicio
`relay-allowlist` (`services/policy-engine/src/allowlist-sync-main.ts`) lo consulta cada
`ALLOWLIST_SYNC_INTERVAL_MS` (30 s) y lo aplica:

- **Buzz** (imagen upstream sin modificar): Buzz no tiene API de allowlist; con `BUZZ_PUBKEY_ALLOWLIST=true`
  consulta su tabla `pubkey_allowlist` (por comunidad) en cada AUTH NIP-42 de solo pubkey, y deniega si la
  consulta falla. El job escribe esa tabla en la base de Buzz (`BUZZ_DATABASE_URL`) para las comunidades de
  `BUZZ_ALLOWLIST_HOSTS` (vacío = todas las activas). Solo gestiona las filas con `note = 'policy-engine'`: las
  añadidas a mano se respetan. **No hace falta reiniciar Buzz**; una conexión ya autenticada sigue abierta hasta
  que se cierre (la revocación afecta a los AUTH siguientes). Los usuarios con API token de Buzz no pasan por el
  allowlist (comportamiento upstream).
- **secure-relay** (nostr-rs-relay 0.9.0): su `pubkey_whitelist` filtra por **autor** del evento y solo se lee
  al arrancar; no sirve porque los gift wraps (1059) y los mensajes MLS (445) van firmados con llaves efímeras.
  Se usa su admisión externa por gRPC (`[grpc] event_admission_server`): `relay-allowlist` sirve
  `nauthz.Authorization/EventAdmit` en el puerto 50051 y permite el evento solo si la sesión está autenticada
  (NIP-42) con una pubkey del allowlist. El cambio de lista es inmediato, sin reiniciar el relay. Para activarlo,
  el relay debe arrancar con `infra/secure-relay/config.institutional.toml` (`SECURE_RELAY_CONFIG` en compose;
  la componente k8s reemplaza el ConfigMap) y reiniciarse **una vez** tras cambiar la configuración.
- **Fichero** opcional (`ALLOWLIST_FILE`): una pubkey hex por línea, reescrito de forma atómica solo si cambia,
  para otros relays.

Comportamiento ante fallos: si el engine no responde se mantiene la última lista aplicada (nunca se vacía por un
error transitorio); antes de la primera sincronización el servidor gRPC deniega todo. `GET /health` del job
(puerto 8087) indica la última sincronización y el último error.

Identidades de servicio: el mirror (`INDEXER_NSEC`), el gateway de notificaciones y el worker de rotaciones
(`ROTATION_WORKER_NSEC`) también se autentican con NIP-42; sus pubkeys van en `ALLOWLIST_EXTRA_PUBKEYS` para que no
pierdan acceso. La de la sincronía de membresía (`BUZZ_MEMBERSHIP_NSEC`, FR023-10) se añade sola.

Activación en compose:

```sh
# .env: POLICY_SERVICE_TOKENS=<t1>:relay-allowlist,<t2>:indexer  RELAY_ALLOWLIST_POLICY_TOKEN=<t1>
#       BUZZ_PUBKEY_ALLOWLIST=true  SECURE_RELAY_CONFIG=./infra/secure-relay/config.institutional.toml
#       ALLOWLIST_EXTRA_PUBKEYS=<pubkey hex del indexer>
docker compose --profile institutional up -d
docker compose up -d --force-recreate relay secure-relay   # releen BUZZ_PUBKEY_ALLOWLIST y la config
```

En Kubernetes: `components: [../../components/institutional]` en el overlay y los secretos
`RELAY_ALLOWLIST_POLICY_TOKEN` e `INDEXER_POLICY_ENGINE_TOKEN` en `acceso-nostr-secrets`.

Pruebas:

- `services/policy-engine/test/allowlist-sync.test.ts`: gRPC real sobre HTTP/2 como el cliente tonic del relay,
  fichero, reconciliación de la tabla de Buzz sobre Postgres y fallo del engine.
- **En CI, de extremo a extremo (FR023-13).** El job `stack` levanta el perfil `institutional` y, tras el resto de
  comprobaciones, reinicia el relay seguro con `config.institutional.toml`. `tests/interop/institutional.interop.test.ts`
  comprueba contra ese relay, `relay-allowlist` y el policy-engine reales que:
  - una persona con dispositivo activo publica;
  - una llave que la organización no conoce recibe `blocked: restricted: …`;
  - al revocar a la persona, deja de poder publicar en la siguiente sincronización.
- El job `compose` valida todos los perfiles con esa configuración, y `deploy-config` y
  `tests/scripts/deploy-manifests.test.ts` renderizan la base con la componente `institutional`.

nostr-rs-relay antepone su propio `blocked:` a lo que responde el servidor de admisión. A un evento enviado antes
del AUTH le contesta `blocked: auth-required: …`. El cliente (`asksForAuth` de relay-pool) lo trata como petición de
NIP-42: se autentica y reenvía, y el outbox no lo cuenta como rechazo permanente.

**Riesgo residual**: nostr-rs-relay admite el evento (fail-open, solo registra un aviso) si no puede hablar con
el servidor gRPC. Vigilar la salud de `relay-allowlist`; el lado de Buzz es fail-closed.

## Publicar por recurso en los relays (FR023-10)

El allowlist decide quién entra en los relays. Además, en cada canal y grupo que la organización registra, solo
publica quien la política deja publicar ahí.

**Los permisos.** `GET /v1/relay/grants` (token de servicio) da, por cada recurso `channel` y `group`, las pubkeys que
pueden publicar en él:

- Personas del allowlist: activas y con un dispositivo sin revocar.
- Solo aquellas a las que `evaluate` deja publicar con alguno de sus dispositivos. El relay conoce la pubkey de la sesión
  NIP-42, no el dispositivo, así que cuenta el que más permite.
- Se calculan con `evaluate` sin registrar nada: no son decisiones de acceso y no aparecen en «Accesos».

`relay-allowlist` los lee en cada sincronización (`ALLOWLIST_SYNC_INTERVAL_MS`), como el allowlist. Si la lectura
falla, siguen en vigor los últimos.

**Relay seguro: admisión por `h`.** El servidor de admisión (gRPC) mira las etiquetas `h` de cada evento:

- Si una nombra un recurso registrado y la pubkey de la sesión no puede publicar en él, el relay responde
  `blocked: restricted: not allowed to publish in <h>`.
- Un `h` que nadie registró queda al allowlist, como hace Buzz con un canal no registrado.
- Hasta que se leen los permisos por primera vez, un evento con `h` se rechaza (fail closed).
- Las identidades de servicio (`ALLOWLIST_EXTRA_PUBKEYS`) no pasan por los permisos: el worker de rotaciones hace
  commits en los grupos que administra.

Un grupo Marmot se registra por el id que ven los relays: su `nostr_group_id`, el `h` de sus mensajes (kind 445).
`sovereign group list` lo muestra como `h=…`. El worker de rotaciones acepta ese id o el id MLS. Registrado por el id
MLS, el grupo tiene rotaciones, pero el relay seguro no puede aplicarle estos permisos.

**Buzz: membresía NIP-29.** Buzz admite un mensaje con `h` en un canal privado solo de sus miembros
(`restricted: not a channel member`). Con `BUZZ_MEMBERSHIP_NSEC`, `relay-allowlist` hace que los miembros de cada canal
registrado sean quienes pueden publicar en él:

- Añade con un kind 9000 a quien falta y quita con un kind 9001 a quien no tiene permiso.
- Los owners y admins del canal se quedan: la organización gestiona esos roles en Buzz.
- Lee el estado del canal que firma Buzz (39000–39002) y solo cuenta el firmado con su llave: NIP-11 `self` o
  `BUZZ_MEMBERSHIP_RELAY_KEY`.
- Conecta a `ws://relay:3000` presentando la URL pública (`RELAY_URL`), porque Buzz elige la comunidad por `Host`.

Requisitos de cada canal registrado:

- **Privado.** En un canal abierto Buzz admite a cualquiera: la membresía se sincroniza, pero no decide quién publica.
  La salud lo marca en `notEnforced`.
- **Con la identidad de `BUZZ_MEMBERSHIP_NSEC` como owner o admin.** Quien crea el canal la añade con un kind 9000 con
  `["role", "admin"]`. Sin ese rol (`withoutAuthority`), o si no puede leer el canal (`unreachable`), se informa y no
  se toca.
- La web crea canales abiertos. En modo institucional, créalos privados desde un cliente NIP-29 y añade la identidad
  como admin.

`scripts/init-env.sh` genera `BUZZ_MEMBERSHIP_NSEC`; en Kubernetes va en `acceso-nostr-secrets` y es opcional. Su pubkey
entra sola en el allowlist, para que Buzz acepte su NIP-42.

`GET /health` de `relay-allowlist` informa de `grants` (recursos con permisos) y `membership` (canales, altas, bajas y
los que no puede gestionar).

Pruebas:

- `services/policy-engine/test/policy-engine.test.ts`: los permisos (miembros, reglas, dispositivo revocado,
  sensibilidad y confianza del dispositivo) y que no quedan en el registro de accesos.
- `services/policy-engine/test/allowlist-sync.test.ts`: la admisión por `h` por gRPC, como la pide el relay.
- `services/policy-engine/test/membership-sync.test.ts`: la sincronía contra un Buzz simulado con sus reglas de
  autorización; una lista 39001 falsificada no protege a nadie.
- `tests/fuzz/nauthz-proto.test.ts`: el códec con etiquetas.
- **En CI (job `stack`)**, `tests/interop/institutional.interop.test.ts` contra el relay seguro, `relay-allowlist`, el
  policy-engine y Buzz reales:
  - el relay seguro deniega a quien no puede publicar en un grupo registrado;
  - en Buzz, la membresía de un canal privado registrado sigue a la política y Buzz rechaza al resto, también tras un
    cambio de la política.

**Riesgo residual:**

- Un canal o grupo sin registrar queda abierto a todo el allowlist.
- En Buzz, un cambio de la política llega en la siguiente sincronización. Hasta entonces sigue la membresía anterior.
- Los owners y admins de un canal de Buzz publican aunque la política no los incluya.
- El relay seguro admite los eventos si no puede hablar con `relay-allowlist` (fail-open, ver arriba).

## Lecturas del mirror filtradas por política (FR023-05)

Con `POLICY_ENGINE_URL` y `POLICY_ENGINE_TOKEN` el indexer exige NIP-98 en todas las lecturas y pregunta
`evaluate({pubkey: lector, resourceId, action: 'read'})` una vez por recurso y petición:

- El recurso de un evento es su canal (`h`, id del grupo NIP-29, que debe coincidir con el id del recurso en el
  engine) o, si no tiene canal, `INDEXER_POLICY_WORKSPACE` (por defecto `COMMUNITY_ID`). Sin recurso: denegado.
- Cabecera opcional `x-policy-device-id`: se evalúa con ese dispositivo (los recursos `confidential`/`secret`
  exigen uno registrado).
- `/v1/events` y `/v1/search` omiten lo no permitido; `/v1/events/:id` responde 404; `/v1/channels/:h/summary`
  y `PUT /v1/read-cursor` responden 403; `/v1/unread` omite los canales no permitidos.
- Denegación por defecto: un error del engine es un deny.

El filtrado ocurre después del `limit` de la consulta, así que una página puede traer menos resultados.
Pruebas: `services/indexer/test/policy.test.ts` y `tests/e2e/institutional-policy.test.ts` (engine real).

## Directorio organizacional (FR023-06)

Opcional: cargo (`title`) y unidad (`unit`) por npub. Solo lo leen y cambian admins por NIP-98; no se publica en
relays ni se expone sin autenticación de admin (ni siquiera con token de servicio). Los cambios quedan en la
auditoría sin copiar los valores.

## Dispositivos con passkeys (FR023-07)

Niveles de confianza: `unverified`, `registered` (alta por un admin) y `attested`, que solo se obtiene al
registrar una passkey WebAuthn en el dispositivo:

1. El dueño (NIP-98 con su pubkey) o un admin pide `POST /v1/devices/:id/webauthn/options`: desafío de un solo uso
   (5 minutos), RP = `WEBAUTHN_RP_ID` (por defecto el host de `WEB_ORIGIN`), ES256, `attestation: 'direct'` y las
   credenciales ya usadas del mismo dueño en `excludeCredentials`.
2. El navegador llama a `navigator.credentials.create()` y envía el resultado (JSON base64url) a
   `POST /v1/devices/:id/webauthn/register`.
3. El servidor verifica con `node:crypto`: tipo `webauthn.create`, desafío, origen (`WEBAUTHN_ORIGINS`), hash del
   RP id, presencia del usuario, id de credencial y llave COSE P-256; formato `packed` (firma con la llave de la
   credencial o con el certificado `x5c`) o `none`. El dispositivo pasa a `attested` con `credentialId` y
   `attestationFormat`.

`none` se acepta por defecto porque la mayoría de passkeys sincronizadas no dan attestation; con
`WEBAUTHN_REQUIRE_ATTESTATION=true` solo se acepta `packed`. La cadena `x5c` no se valida contra raíces de
fabricantes (sin FIDO MDS). Un dispositivo revocado no puede atestarse y una credencial no puede atestar dos
dispositivos. Pruebas: `services/policy-engine/test/webauthn.test.ts` (vectores generados en el test).

## Retención y legal hold (FR023-08)

`PUT /v1/retention/:resourceId` fija los días de retención (`null` = sin límite) y el legal hold de un espacio
de trabajo o canal registrado. El indexer en modo institucional lee las políticas (`GET /v1/retention` con su
token) cada `RETENTION_INTERVAL_MS` (1 h) y borra del mirror los eventos con `created_at` anterior al plazo:

- El `resourceId` se aplica como canal (`h`) y como espacio de trabajo (`COMMUNITY_ID` del mirror).
- Un canal con política propia se rige por ella, no por la de su espacio de trabajo.
- Legal hold gana: no se borra nada de un canal retenido ni de ningún canal de un espacio retenido.

> **Aviso (también en el campo `notice` de la API):** la retención y el borrado solo eliminan la copia del
> mirror/indexer de esta organización. No borran las copias ya replicadas en otros relays ni las que guardan los
> clientes y dispositivos de los participantes.

Tampoco borra los eventos del propio relay Buzz ni del secure-relay: su retención es la del relay. Pruebas: bloque
"Retention" de `services/indexer/test/indexer.test.ts` (memoria y Postgres) y `tests/e2e/institutional-policy.test.ts`.

### Qué cubre y qué no (FR023-12)

La retención y el legal hold actúan sobre lo que guarda la organización. Por eso:

- **Grupos MLS (Marmot): no aplica.**
  - `PUT /v1/retention/:id` sobre un recurso `group` responde 409. La organización no guarda copia de su contenido:
    va cifrado de extremo a extremo con secreto hacia adelante. Un legal hold sobre un grupo prometería una evidencia
    que nadie puede conservar.
  - Una política que quedara sobre un grupo (puesta antes, o sobre un recurso que después cambió de tipo) ni se aplica
    ni aparece en `GET /v1/retention`.
  - La consola muestra «No aplica» en esas filas.
- **Versiones reemplazadas.** Un evento reemplazable o direccionable sustituye a su versión anterior: un perfil
  (kind 0), la lista de miembros de un canal (39002)…
  - En modo institucional el indexer no la borra: la mueve a `events_superseded`, que las lecturas no ven. Lo mismo
    con una versión antigua que llega después de la nueva.
  - Cada pasada de retención borra las que no cubre ningún legal hold. La cubre un hold sobre su canal (`h`), sobre su
    espacio de trabajo o, en el estado de grupo NIP-29 (39000–39003), sobre su `d`.
  - Al levantar el hold, la siguiente pasada las borra.
  - Fuera del modo institucional se borran al llegar la versión nueva, como antes.
- **Decisiones de acceso.**
  - Se guardan `ACCESS_LOG_RETENTION_DAYS` días (90 por defecto). Cada réplica del engine poda cada
    `ACCESS_LOG_PRUNE_INTERVAL_MS` (1 h); el borrado es idempotente.
  - Las de un recurso con legal hold se guardan mientras dure.
  - Un hold sobre un espacio de trabajo cubre sus canales, y el engine no sabe cuáles son: mientras dure, no se poda
    nada.
- **Auditoría.** Guarda lo que hacen los administradores. Es append-only y no se poda.

Pruebas:
- `services/policy-engine/test/policy-engine.test.ts`, en memoria y Postgres;
- bloque "Retention" de `services/indexer/test/indexer.test.ts`, en memoria y Postgres;
- `tests/e2e/institutional-policy.test.ts`;
- `tests/browser/admin-console.e2e.ts`.

## Navegadores como dispositivos de la organización (FR024-03)

La persona gestionada de la web firma por una sesión de dispositivo del navegador (FR005-11). Por defecto su id es
aleatorio (`web-…`) y la organización no lo conoce, así que revocar un dispositivo en el policy-engine no la afecta.

Con `organizationDevices: true` en el `config.json` de la web, la tarjeta «Actividad de tu llave gestionada» ofrece
«Dispositivo de tu organización»:
1. El admin registra el dispositivo en la consola («Dispositivos») y le da su id a la persona.
2. La persona lo pega en «Vincular este navegador». El navegador cierra su sesión actual y abre las siguientes con ese
   id.
3. Si la organización revoca el dispositivo, el worker de rotaciones lleva la revocación al managed-signer:
   - la sesión abierta cae y el login no puede abrir otra;
   - la tarjeta dice que la organización revocó el dispositivo.

La vinculación la hace la persona: un id equivocado deja al navegador fuera de la revocación. Ante un dispositivo
perdido que no estaba vinculado, sigue valiendo cerrar su sesión y cambiar la contraseña de Acceso
(`docs/runbooks/device-loss.md`).

Pruebas:
- `apps/web-saas/test/managed-session.test.ts`, contra el managed-signer real;
- `tests/browser/web-saas.e2e.ts`: un navegador se vincula, firma con el id de la organización y, tras la revocación
  (policy-engine real y el feed del worker), no firma ni abre otra sesión. El otro navegador de la misma persona sigue
  firmando.

## Worker de rotaciones (FR024-05)

El servicio `rotation-worker` (`services/rotation-worker`) hace sin que nadie deje un CLI abierto lo que antes
pedía `sovereign group rotation-worker`: saca de los grupos MLS a quien la organización revoca (FR024-02) y lleva cada
revocación de dispositivo al managed-signer (FR024-03/04). En cada ciclo (`ROTATION_INTERVAL_MS`, 15 s):

1. acepta las invitaciones a grupos;
2. propaga las revocaciones de dispositivo, si tiene managed-signer;
3. hace el commit Remove de cada rotación pendiente y la marca como hecha.

Un paso que falla no detiene a los otros y se reintenta en el ciclo siguiente. `GET /health` (puerto 8089) dice si
el último ciclo terminó sin errores y cuál es el error de cada paso, sin contenido. Una rotación que espera su
reintento o una revocación sin propagar lo dejan en error hasta que se completan.

**Qué necesita cada grupo.** El worker solo rota los grupos que lo tienen como **admin** (MIP-03: solo los admins
hacen commit) y en los que entró:
- la web lo añade sola si `config.json` tiene `rotationWorker` (su npub). Al crear un grupo lo pone como admin y lo
  invita, y la lista de miembros lo muestra como «worker de rotaciones de la organización». Si no encuentra su key
  package, el grupo se crea igual y la web avisa. Se le puede invitar después con «Invitar»: el grupo ya lo lista
  como admin;
- en el policy-engine tiene que existir el recurso del grupo: id = id MLS del grupo, `kind: 'group'` y sus
  miembros (docs/marmot.md, «Revocación de dispositivos»).

**Confidencialidad.** El worker es un miembro más: mientras está en un grupo **puede descifrar** lo que se envía.
- No guarda los mensajes: los descarta al sincronizar.
- Su estado MLS está cifrado con `ROTATION_STATE_KEY` en su volumen. El secreto hacia adelante le afecta igual que a
  cualquier miembro.
- Quien controle el worker podría leer esos grupos. Es una decisión de la organización, y los miembros lo ven en la
  lista.

**Permisos.** No es admin del policy-engine: lee rotaciones y revocaciones con su token de servicio. Su llave Nostr
solo firma dentro de los grupos. En el managed-signer usa un token de revocación, que no sirve para nada más.

**Configuración.**

| Variable | Qué es |
|---|---|
| `ROTATION_WORKER_NSEC` | Identidad del worker (nsec o hex). La genera `scripts/init-env.sh`. |
| `ROTATION_STATE_KEY` | 32 bytes hex que cifran el estado MLS. La genera `init-env.sh`. Otra clave no abre el estado y el worker no arranca. |
| `ROTATION_STATE_DIR` | Volumen del estado (`/data`). Una sola réplica: el estado MLS tiene un único escritor. |
| `POLICY_ENGINE_URL`, `POLICY_ENGINE_TOKEN` | El engine y un token de `POLICY_SERVICE_TOKENS` (en compose, `ROTATION_WORKER_POLICY_TOKEN`). |
| `ROTATION_WORKER_RELAYS` | `pública=interna`: la URL del relay seguro que usan los clientes (`secureRelays` de la web) y dónde lo alcanza el worker. Por defecto `ws://localhost:7000=ws://secure-relay:8080`. |
| `ROTATION_MANAGED_SIGNER_URL`, `ROTATION_MANAGED_SIGNER_TOKEN` | El managed-signer y uno de sus `MANAGED_SIGNER_REVOCATION_TOKENS`. Los dos o ninguno. |
| `ROTATION_INTERVAL_MS` | Intervalo entre ciclos (15 000 ms). |

Con el relay seguro en modo institucional, la pubkey del worker va en `ALLOWLIST_EXTRA_PUBKEYS`.

**Despliegue.**
- compose: servicio `rotation-worker` del perfil `institutional`, con el volumen `rotation-state`;
- Kubernetes: `components/institutional` trae el Deployment (1 réplica, estrategia `Recreate`), su PVC y el
  Service. Secretos en `acceso-nostr-secrets`: `ROTATION_WORKER_NSEC`, `ROTATION_STATE_KEY`,
  `ROTATION_WORKER_POLICY_TOKEN` y, con el managed-signer, `ROTATION_MANAGED_SIGNER_TOKEN`
  (y `ROTATION_MANAGED_SIGNER_URL` en la configuración).

Si se pierden el volumen o la clave, el worker empieza sin grupos. En cada grupo, un admin tiene que sacarlo y volver
a invitarlo: sigue en la lista de admins, así que vuelve como admin. El procedimiento ante un dispositivo perdido
está en `docs/runbooks/device-loss.md`.

Pruebas:
- `services/rotation-worker/test/service.test.ts`, con un relay que exige NIP-42 y se conoce por una URL pública a la
  que el worker no se conecta, el policy-engine real (el worker no es admin) y el managed-signer:
  - entra en el grupo que lo tiene como admin, saca al miembro revocado y propaga la revocación;
  - lo que se envía después no llega al dispositivo revocado;
  - tras reiniciar sobre el mismo estado sigue en el grupo y rota la revocación siguiente;
  - otra clave no abre el estado.
- `packages/rotation-worker/test/service.test.ts`: un paso que falla no para a los demás, y la salud sigue en error
  hasta que la rotación está hecha.
- `tests/browser/web-groups.e2e.ts`: con `rotationWorker` en la configuración, el grupo nuevo lo tiene como admin, lo
  muestra como tal y el worker recibe la invitación.
- CI, job `stack`: el perfil `institutional` levanta el worker contra el relay seguro, el policy-engine y el
  managed-signer reales, y `scripts/wait-stack.sh` espera a que su primer ciclo termine sin errores.
