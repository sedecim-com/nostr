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
- **Sesiones**: el token se guarda como hash SHA-256; una fuga de la base no da tokens utilizables. Cada sesión guarda
  su dispositivo y, si se abrió con una passkey, la credencial que firmó (FR023-11).
- **WebAuthn**: se guarda solo la llave pública de la credencial y su contador de firmas; la privada nunca sale del
  autenticador.

Pruebas: `services/policy-engine/test/policy-engine.test.ts` ejecuta la misma batería sobre memoria y Postgres,
más un test de reinicio (engine y pool nuevos sobre la misma base conservan todo el estado) y el de auditoría
append-only. Los tests de Postgres corren con `TEST_DATABASE_URL` (servicio postgres de CI) y se omiten sin él.

## API

Todas las rutas son JSON. "Admin" = NIP-98 firmado por una pubkey de `POLICY_ADMIN_PUBKEYS`. "Servicio" =
`Authorization: Bearer <token>` de `POLICY_SERVICE_TOKENS` (`token:principal`, separados por comas).

Cada token de servicio solo llega a las rutas de su principal (IR-2026-10-01), para que el token de un servicio
expuesto no sirva para lo de otro:

| Principal | Ámbito | Rutas |
|---|---|---|
| `indexer` | `evaluate`, `retention` | `POST /v1/evaluate`, `GET /v1/retention` |
| `relay-allowlist` | `relay` | `GET /v1/relay/allowlist`, `GET /v1/relay/grants` |
| `rotation-worker` | `rotations` | `GET /v1/rotations`, `POST /v1/rotations/:id/done`, `GET /v1/revocations` |

Otro principal no llega a ninguna hasta que `POLICY_SERVICE_SCOPES` diga cuáles (`principal=ámbito+ámbito`, separados
por comas; por ejemplo `ops=rotations` para el worker del CLI soberano). Con un principal sin ámbito el engine avisa al
arrancar, y sus llamadas responden 403. El ámbito `events` (leer los eventos firmados, OPS-16) no lo tiene ningún
principal por defecto: una integración lo recibe así, por ejemplo `siem=events`.

| Ruta | Auth | Respuesta |
|---|---|---|
| `GET /v1/subjects` · `PUT /v1/subjects/:pubkey` · `POST /v1/subjects/:pubkey/revoke` · `POST /v1/subjects/:pubkey/reactivate` | admin | `{subjects}` · `{ok}` · `{rotations}` · `{ok}` (404 si no existe, 409 si no está revocado) |
| `GET /v1/resources` · `PUT /v1/resources/:id` | admin | `{resources}` · `{ok}` |
| `GET /v1/devices?owner=<hex>` | admin, o el propio dueño con su pubkey en `owner` (FR023-11) | `{devices}` |
| `POST /v1/devices` · `POST /v1/devices/:id/revoke` | admin | `Device` · `{rotations}` |
| `POST /v1/devices/:id/webauthn/options` · `POST /v1/devices/:id/webauthn/register` | admin, o el dueño del dispositivo hasta que registra su primera passkey (403 después); a cualquier otro, 404 | `PublicKeyCredentialCreationOptions` (base64url) · `Device` |
| `POST /v1/devices/:id/webauthn/assert/options` | NIP-98 del dueño; a cualquier otro, 404 | `PublicKeyCredentialRequestOptions` (base64url) con la passkey del dispositivo en `allowCredentials` (FR023-11) |
| `POST /v1/sessions` `{deviceId, assertion?}` | NIP-98 del dueño | `{token, deviceId, asserted}`; 403 sin `assertion` si el dueño registró una passkey (FR023-11) |
| `POST /v1/evaluate` · `GET /v1/relay/allowlist` | servicio | `Decision` · `{pubkeys}` |
| `GET /v1/relay/grants` | servicio | `{grants}`: por cada recurso `channel` y `group`, `{resourceId, kind, pubkeys}` de quien puede publicar en él (FR023-10) |
| `GET /v1/rotations?status=pending\|done` | admin o servicio | `{rotations}` (cada una con `id` y `status`) |
| `POST /v1/rotations/:id/done` | admin o servicio | `Rotation` |
| `GET /v1/revocations?after=&limit=` | admin o servicio | `{revocations, latest, now}`: revocaciones de dispositivo (`{cursor, at, deviceId, reason}`, más antigua primero) con `cursor` mayor que `after`; `latest` = cursor de la última (FR024-04) |
| `GET /v1/audit?limit=&before=` | admin | `{audit}`, más nuevo primero; `before` = `id` de la última entrada recibida |
| `GET /v1/access-log?limit=&before=&resource=` | admin | `{access, retentionDays}`: decisiones de acceso, más nueva primero; `before` como en la auditoría; `resource` filtra por recurso (FR023-12) |
| `GET /v1/events?after=&limit=` | admin, o servicio con el ámbito `events` | `{events, next}`: eventos firmados con `seq` mayor que `after`, más antiguo primero; `next` = el siguiente `after` (OPS-16) |
| `GET /v1/events/keys` | ninguna | `{issuer, current, keys}`: las llaves públicas Ed25519 (JWKS) que verifican los eventos (OPS-16) |
| `GET /v1/webhooks` · `POST /v1/webhooks` `{url, types?}` · `DELETE /v1/webhooks/:id` · `POST /v1/webhooks/:id/enable` | admin | `{webhooks}` · `{webhook, secret}`: el secreto, solo aquí; 400 si el destino no vale, 409 si ya hay `POLICY_WEBHOOKS_MAX` · `{ok}` · `{webhook}` (OPS-16) |
| `GET /v1/webhooks/:id/deliveries?limit=&before=` | admin | `{deliveries}`: registro de entregas, más nueva primero (OPS-16) |
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
- **secure-relay** (nostr-rs-relay 0.10.0): su `pubkey_whitelist` filtra por **autor** del evento y solo se lee
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
  y `PUT /v1/read-cursor` responden 403; `/v1/unread` y `/v1/unread/recent` (los contadores de la web, FR014-04)
  omiten los canales no permitidos.
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

1. Un admin, o el dueño (NIP-98 con su pubkey) para su primera passkey (ver FR023-11), pide
   `POST /v1/devices/:id/webauthn/options`: desafío de un solo uso (5 minutos), RP = `WEBAUTHN_RP_ID` (por defecto el
   host de `WEB_ORIGIN`), ES256, `attestation: 'direct'` y las credenciales ya usadas del mismo dueño en
   `excludeCredentials`.
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

## Passkey del propio usuario en cada sesión (FR023-11)

La persona registra la passkey en su dispositivo con su propia llave y, desde entonces, cada sesión de política que abre
pide una aserción WebAuthn de esa passkey.

**Registro.** En la consola (`/admin/`), una llave que no es de administración entra en «Mis dispositivos»: los
dispositivos que la organización registró a su nombre (`GET /v1/devices?owner=<su pubkey>`). «Registrar passkey» crea la
passkey en el navegador en el que está, con el flujo de FR023-07, firmado con su llave. El titular solo registra así la
primera. Cualquier otra la registra un administrador: para un dispositivo nuevo, para sustituir una o después de
revocar el dispositivo que la tenía. Así, quien solo tiene la llave Nostr de la persona no da de alta un autenticador
suyo.

**Cada sesión.**

1. `POST /v1/devices/:id/webauthn/assert/options` (NIP-98 del dueño) da un desafío de un solo uso para ese dispositivo
   (5 minutos; pedir otro sustituye al anterior), el `rpId` y la credencial del dispositivo, sola, en
   `allowCredentials`.
2. El navegador llama a `navigator.credentials.get()` y envía el resultado en `POST /v1/sessions` `{deviceId, assertion}`.
3. El servidor consume el desafío, salga bien o mal, y verifica con `node:crypto`:
   - tipo `webauthn.get`, desafío (en tiempo constante), origen de `WEBAUTHN_ORIGINS` y que no venga de un iframe de otro
     origen;
   - hash del RP id (`WEBAUTHN_RP_ID`), presencia del usuario y, con `WEBAUTHN_REQUIRE_UV=true`, su verificación;
   - que la credencial es la del dispositivo y que el user handle, si viene, es el del dueño;
   - la firma ES256 con la llave pública guardada al registrar la passkey;
   - que el contador de firmas sube. Si no sube, dos autenticadores tienen la misma llave (un posible clon) y se
     rechaza. Un autenticador sin contador (siempre 0, como muchas passkeys sincronizadas) no se compara.
4. La sesión queda ligada al dispositivo y a esa credencial: deja de valer si se revoca el dispositivo o se registra
   otra passkey en él.

Una aserción rechazada responde siempre `403 WebAuthn assertion rejected`, sin decir por qué. A quien no es el dueño se
le responde lo mismo que con un id que no existe: 404 en las opciones y `device not usable for a new session` al abrir
la sesión.

**Cuándo se exige.** Desde que el dueño registra una passkey en cualquiera de sus dispositivos, aunque después se revoque
ese dispositivo:
- una sesión sin aserción responde 403, también en un dispositivo sin passkey;
- las sesiones que abrió sin aserción dejan de valer, y registrar la passkey las borra.

Con `SESSION_REQUIRE_ASSERTION=true` se exige a todos: quien no tiene passkey no abre sesiones hasta registrar una. Sin
passkey y sin esa variable, la sesión se abre sin aserción, como antes.

**Qué se guarda.** Por sesión, el hash del token, el dispositivo, la credencial y la hora; por dispositivo, la llave
pública y el contador de firmas. La auditoría registra cada aserción rechazada (`session.assert`, con el motivo y, ante
un posible clon, el contador que traía), nunca el desafío, la credencial, la firma ni el token. Abrir una sesión no
deja entrada en la auditoría: cuándo se conecta una persona es un metadato de uso, y la auditoría no se poda (por lo
mismo, FR023-12 sacó de ella las decisiones de acceso).

**Al actualizar** (migración 004), las sesiones anteriores no tienen credencial: las de quien ya había registrado una
passkey con FR023-07 dejan de valer.

| Variable | Por defecto | Qué hace |
|---|---|---|
| `WEBAUTHN_REQUIRE_UV` | `false` | `true`: el registro y la aserción exigen la verificación del usuario (PIN o biometría), no solo su presencia |
| `SESSION_REQUIRE_ASSERTION` | `false` | `true`: toda sesión pide una aserción, también a quien aún no ha registrado una passkey |

En compose van en `.env`; en Kubernetes, en `acceso-nostr-config`.

Pruebas:
- `services/policy-engine/test/policy-engine.test.ts`, en memoria y Postgres: el alta por el dueño; la aserción en cada
  sesión; los rechazos (origen, RP id, desafío caducado, gastado o de otro dispositivo, otra credencial u otro dueño,
  sin presencia o sin verificación, firma inválida); el contador; la revocación, también la del dispositivo que tenía la
  passkey, y la migración 004.
- `services/policy-engine/test/webauthn.test.ts` y `tests/fuzz/webauthn.test.ts`: el verificador de aserciones.
- `apps/admin-console/test/passkey-session.test.ts`: el cliente y los helpers WebAuthn de la consola contra el
  policy-engine real.
- `tests/browser/admin-console.e2e.ts`: en Chromium, con su autenticador virtual, la persona registra la passkey desde
  «Mis dispositivos» y cada sesión le pide una aserción.

**Riesgo residual:**
- La primera passkey la registra quien tenga la llave Nostr de la persona. Si esa llave ya estaba robada, el ladrón
  puede adelantarse; para evitarlo, que la registre un administrador en el dispositivo.
- Ningún otro servicio comprueba todavía las sesiones de política, y no caducan: valen hasta que se revoca el
  dispositivo o se sustituye su passkey. `evaluate` confía en el dispositivo que le indica el servicio (en el indexer,
  la cabecera `x-policy-device-id`), sin pedir una sesión abierta con passkey.
- Si el proxy de borde restringe `/admin/`, la persona no llega a «Mis dispositivos»: su primera passkey la registra
  entonces un administrador.

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

## Eventos firmados y webhooks (OPS-16)

Para llevar la auditoría a otros sistemas (un SIEM, un gestor de incidencias) ya no hace falta sondear `GET /v1/audit`,
que pagina de la entrada más nueva a la más antigua y no tiene un cursor estable. El engine emite cada entrada de la
auditoría como un **evento firmado**, que se lee desde un cursor o llega por **webhook**.

**Activación.** Solo con `POLICY_EVENTS_SIGNING_KEY_FILE`, la ruta de un fichero con la llave privada Ed25519: PKCS#8
PEM, como la escribe `openssl genpkey -algorithm ed25519`, o su semilla de 32 bytes en hex. No hay llave por defecto.

- Sin la variable, eventos y webhooks quedan apagados: el log lo dice al arrancar y sus rutas responden 404.
- Con ella, el servicio no arranca si el fichero no se puede leer, está vacío o no tiene una llave Ed25519
  (`eventsConfigFromEnv`, lo primero que ejecuta `main.ts`). Tampoco sin emisor (`POLICY_EVENTS_ISSUER`, por defecto
  `PUBLIC_BASE_URL`) ni con la llave actual en `POLICY_EVENTS_REVOKED_KIDS`.
- Los webhooks necesitan además `POLICY_WEBHOOK_SECRETS_KEY_FILE` (32 bytes en hex). Sin ella el cursor funciona y las
  rutas de webhooks responden 404.
- Los eventos empiezan al activarlos. Las entradas anteriores, y las escritas con los eventos apagados, solo están en la
  auditoría.

### El evento

Cada entrada de la auditoría escrita con los eventos activos se guarda también como evento, en la misma transacción:

```json
{"created_at":1727700000000,"data":{"actor":"<pubkey del admin>","audit_id":42,"details":{"reason":"robado"},"target":"<id del dispositivo>"},"id":"<uuid>","issuer":"https://policy.example.org","kid":"<huella de la llave>","seq":17,"sig":"<firma>","type":"device.revoke"}
```

- `type` es la acción de la entrada (`device.revoke`, `subject.upsert`…) y `created_at`, su hora en ms.
- `data` es la entrada tal como la guarda la auditoría (`GET /v1/audit`), nunca más.
- `seq` es la posición en el flujo; `id`, un UUID que sirve de clave de idempotencia; `issuer`, quién lo emite.
- `sig` es la firma Ed25519 (base64url) del JSON canónico (RFC 8785) del evento sin `sig`, y `kid` la huella RFC 7638
  de la llave pública que firmó. La firma cubre también `issuer` y `kid`.

Se firma al emitirse y se guarda firmado, en `policy_events`, append-only como la auditoría: la firma sigue valiendo
aunque después cambie la llave.

**Qué no lleva.** Lo que la auditoría no guarda:

- las decisiones de acceso, que van al registro de accesos (FR023-12);
- la apertura de una sesión (FR023-11). Sí cada aserción rechazada (`session.assert`, con su motivo);
- desafíos, credenciales, firmas WebAuthn o tokens. Además, el evento quita a cualquier profundidad los nombres de esa
  lista (`FORBIDDEN_EVENT_KEYS`), por si una entrada futura los trajera.

Los tipos son las acciones de la auditoría más las de los webhooks: `webhook.create`, `webhook.delete`,
`webhook.enable` y `webhook.disable` (esta con `policy-engine` como actor). La auditoría de un webhook guarda el host
del destino, nunca la URL, que puede llevar un token.

**Verificar.** `GET /v1/events/keys`, sin autenticación, da `{issuer, current, keys}`: un JWKS con las llaves públicas.
Quien consume:

1. fija el `issuer` esperado y rechaza cualquier otro;
2. busca en `keys` la llave con el `kid` del evento (si no está, recarga la lista una vez);
3. quita `sig`, serializa el resto en JSON canónico (RFC 8785) y verifica la firma Ed25519.

`verifyPolicyEvent` (`services/policy-engine/src/events.ts`) es una implementación de referencia.

**Leer por cursor.** `GET /v1/events?after=<seq>&limit=<n>` (hasta 1000) da `{events, next}`, del más antiguo al más
nuevo; el siguiente `after` es `next`. Lo leen un admin o un token con el ámbito `events`. Un cursor no se salta ningún
evento: los escritores toman un advisory lock de Postgres antes de sacar su `seq` y lo sueltan al confirmar, así que
confirman en orden de `seq`. Puede haber huecos (una transacción que se deshizo), nunca uno que se llene después.

### Webhooks

Los gestiona un admin:

- `POST /v1/webhooks` `{url, types?}`. `types` son tipos de evento; sin ellos, todos. Responde `{webhook, secret}`:
  **el secreto solo aparece en esta respuesta**. Una suscripción a todos los tipos recibe primero su propio
  `webhook.create`.
- `GET /v1/webhooks` las lista, sin secreto. `DELETE /v1/webhooks/:id` borra la suscripción y sus entregas.
- Como mucho `POLICY_WEBHOOKS_MAX` suscripciones (10), contando las de todas las réplicas.

**El secreto no se guarda.** Para firmar cada entrega el servidor necesita el secreto, así que guardarlo con hash, como
los tokens de sesión, no sirve. Cifrado, dejaría en la base y en sus backups un texto que se abre con la llave. Se
deriva: `HMAC-SHA256(POLICY_WEBHOOK_SECRETS_KEY, id ‖ sal)`, con una sal aleatoria por suscripción, y la base solo
guarda la sal. Una copia de la base o de un backup no da ningún secreto sin esa llave, que vive en un secreto aparte.
Rotar la llave cambia todos los secretos a la vez ([runbook](runbooks/webhooks.md)).

**Cada entrega** es un `POST` cuyo cuerpo es el evento tal como se firmó, con estas cabeceras:

- `x-sedecim-signature: t=<segundos unix>,v1=<hex>`: HMAC-SHA256 de `t.cuerpo` con el secreto de la suscripción;
- `idempotency-key`: el `id` del evento;
- `content-type: application/json`.

Quien recibe compara la firma en tiempo constante y descarta una entrega cuyo `t` esté a más de 300 s de su reloj: una
entrega capturada no se puede repetir más tarde. Dentro de esa ventana, y con los reintentos, un evento puede llegar
más de una vez: se deduplica por `idempotency-key`. `verifyWebhookSignature` es una implementación de referencia.

**Reintentos.** Una entrega vale con una respuesta 2xx. Todo lo demás es un fallo: un 3xx (una redirección no se
sigue), un 4xx o 5xx, un error de DNS, de conexión o de TLS, una conexión que se cierra o pasar del límite de tiempo.

- El siguiente intento espera entre la mitad y el total de un tramo que empieza en 30 s y se dobla hasta 6 h.
- Tras `POLICY_WEBHOOK_MAX_ATTEMPTS` intentos (10) la entrega falla del todo. El evento sigue en el cursor.
- Tras `POLICY_WEBHOOK_DISABLE_AFTER` intentos fallidos seguidos (15), sumando todas sus entregas, la suscripción se
  desactiva: sus entregas pendientes fallan (`subscription_disabled`), no recibe eventos nuevos y el engine lo audita
  (`webhook.disable`). Una entrega que vale pone la cuenta a cero.
- `POST /v1/webhooks/:id/enable` la reactiva desde el evento siguiente. Lo intermedio se lee por el cursor.
- Cada petición tiene `POLICY_WEBHOOK_TIMEOUT_MS` (10 s), resolución DNS incluida. Un destino lento ocupa un hueco
  hasta su límite y no frena a los demás.
- Un evento de más de 64 KiB falla sin reintentos; se lee por el cursor.

**Varias réplicas y caídas.** Cada réplica busca entregas cada `POLICY_WEBHOOK_INTERVAL_MS` (2 s). Una entrega se
reclama con `FOR UPDATE SKIP LOCKED` y un plazo (el límite de tiempo más 30 s), así que dos réplicas nunca la envían a la
vez. Si el proceso muere a mitad, el plazo caduca y otra réplica la reintenta: al menos una vez. Si aquel era su último
intento, falla con `lease_expired`. Las entregas van en paralelo y sin un orden garantizado: el orden es el de `seq`.

**Registro de entregas.** `GET /v1/webhooks/:id/deliveries` da el estado, los intentos, el código HTTP y la clase del
último error (`http_5xx`, `timeout`, `connection_closed`, `redirect`, `blocked_destination`…). No guarda el cuerpo ni las
cabeceras de la respuesta. Las entregas terminadas se borran a los
`POLICY_WEBHOOK_DELIVERY_RETENTION_DAYS` días (30).

### Destinos (SSRF)

Un webhook es una petición que el servidor hace a una URL que escribe un admin. Al darla de alta y antes de cada
entrega se comprueba:

- Solo `https`, sin credenciales en la URL ni fragmento, hasta 2048 caracteres.
- Que el host no sea un nombre interno: sin punto, `localhost`, `.local`, `.internal`, `.onion`, `.home.arpa`…
- El nombre se resuelve una vez, como nombre absoluto (sin los dominios de búsqueda del pod o del host), y se rechaza si
  **alguna** de sus direcciones no es pública: loopback, redes privadas, CGNAT, link-local (con 169.254.169.254, los
  metadatos de AWS, GCP y Azure), las reservadas de IANA, multicast, las ULA de IPv6 (con fd00:ec2::254) y las formas de
  IPv6 que llevan una IPv4 dentro (mapeada, NAT64, 6to4, Teredo).
- La conexión va a la dirección ya comprobada, sin volver a resolver, así que un DNS que cambia de respuesta
  (rebinding) no sirve. Con https, `node:https` verifica el certificado para el nombre (`servername`); eso no lo prueba
  un test de aquí (ver «Sin probar aquí»).
- Las redirecciones no se siguen.

`POLICY_WEBHOOKS_ALLOW_PRIVATE=true` quita esas comprobaciones y permite `http`: es para pruebas y desarrollo con un
receptor local. Por defecto vale `false`. `release-gate config` la rechaza en cualquier manifiesto de producción
(`deploy/production-gates.json`, `testOnly`), y un test comprueba que ningún manifiesto la activa, tampoco el de stage.

### Configuración

| Variable | Por defecto | Qué hace |
|---|---|---|
| `POLICY_EVENTS_SIGNING_KEY_FILE` | vacía: apagado | Fichero con la llave Ed25519 que firma los eventos |
| `POLICY_EVENTS_ISSUER` | `PUBLIC_BASE_URL` | Emisor que nombra cada evento; quien verifica lo fija |
| `POLICY_EVENTS_REVOKED_KIDS` | vacía | `kid` que ya no se publican: una llave comprometida |
| `POLICY_WEBHOOK_SECRETS_KEY_FILE` | vacía: sin webhooks | Fichero con 32 bytes en hex de los que se derivan los secretos |
| `POLICY_WEBHOOKS_MAX` | 10 | Suscripciones de la organización |
| `POLICY_WEBHOOK_MAX_ATTEMPTS` | 10 | Intentos por entrega |
| `POLICY_WEBHOOK_DISABLE_AFTER` | 15 | Intentos fallidos seguidos que desactivan una suscripción |
| `POLICY_WEBHOOK_TIMEOUT_MS` | 10000 | Límite de cada petición |
| `POLICY_WEBHOOK_INTERVAL_MS` | 2000 | Cada cuánto busca entregas cada réplica |
| `POLICY_WEBHOOK_DELIVERY_RETENTION_DAYS` | 30 | Días que se guardan las entregas terminadas |
| `POLICY_WEBHOOKS_ALLOW_PRIVATE` | `false` | Solo pruebas: destinos locales y privados, también por `http` |

**Kubernetes.** Las llaves van en `acceso-nostr-secrets`, como `POLICY_EVENTS_SIGNING_KEY` y
`POLICY_WEBHOOK_SECRETS_KEY` (`generate-secret.sh` las copia de Secrets Manager si existen). El policy-engine las monta
como ficheros en `/run/secrets/policy-engine/`, un volumen opcional legible solo por el grupo del servicio. Para
activarlo, el overlay pone en `acceso-nostr-config`
`POLICY_EVENTS_SIGNING_KEY_FILE=/run/secrets/policy-engine/events-signing-key` y
`POLICY_WEBHOOK_SECRETS_KEY_FILE=/run/secrets/policy-engine/webhook-secrets-key`. Ningún manifiesto lleva el valor de
una llave.

**Compose.** Las variables están en `.env`, vacías. Las llaves se montan como secretos de compose, por ejemplo con un
`docker-compose.override.yml`:

```yaml
services:
  policy-engine:
    environment:
      POLICY_EVENTS_SIGNING_KEY_FILE: /run/secrets/policy_events_signing_key
      POLICY_WEBHOOK_SECRETS_KEY_FILE: /run/secrets/policy_webhook_secrets_key
    secrets: [policy_events_signing_key, policy_webhook_secrets_key]
secrets:
  policy_events_signing_key:
    file: ./.data/policy-events-signing-key
  policy_webhook_secrets_key:
    file: ./.data/policy-webhook-secrets-key
```

Sin Swarm, compose monta cada fichero con el dueño y los permisos que tiene en el host: el usuario del contenedor
tiene que poder leerlo. CI no ejecuta este ejemplo.

### Qué ve cada parte

- **El destino de un webhook**, que elige la organización y puede estar fuera de ella: los eventos de sus tipos, que
  llevan lo mismo que la auditoría. Qué admin hizo qué y cuándo, sobre qué persona, dispositivo o recurso, con los
  detalles: roles, motivo de una revocación, cada aserción rechazada con quién la intentó y por qué. También la
  dirección IP de salida del policy-engine. Para darle menos, se filtra por `types`.
- **La red y el DNS del camino**: con https, el host de destino (SNI), el tamaño y la hora de cada entrega, que delatan
  cuándo hay actividad de administración. El resolvedor ve el nombre.
- **Quien lee el cursor con un token `events`**: lo mismo que la auditoría. Ese token no sirve para nada más.
- **El operador, y quien tenga la base**: los eventos (lo mismo que la auditoría), las URL completas de las suscripciones
  y el registro de entregas. No los secretos: sin `POLICY_WEBHOOK_SECRETS_KEY` no se derivan.
- **Nadie** recibe contenido de mensajes, decisiones de acceso, aperturas de sesión, material WebAuthn ni tokens.

Pruebas:

- `services/policy-engine/test/events.test.ts`, en memoria y Postgres: el JSON canónico, la llave (PEM o semilla,
  `kid` RFC 7638), la verificación y sus rechazos (firma manipulada, `kid` desconocido, evento de otra organización), la
  configuración (apagado sin llave, no arranca con una llave mala), un evento por entrada y nunca más que ella, el
  cursor y quién lo lee, la rotación y la revocación de llaves, y la lista de nombres prohibidos tras registrar una
  passkey, abrir una sesión y rechazar dos aserciones. Sobre Postgres, seis escritores concurrentes y un lector por
  cursor que no pierde ni repite ningún evento, y la tabla append-only.
- `services/policy-engine/test/webhooks.test.ts`, en memoria y Postgres, contra servidores HTTP reales en 127.0.0.1 y con
  reloj inyectable: la firma y su ventana, `idempotency-key`, reintentos, tope de intentos, desactivación y
  reactivación, un 500, un destino que no responde y uno que cierra la conexión, redirecciones, eventos grandes, un
  despachador que muere con un reclamo, el secreto que solo sale en el alta, el límite de suscripciones y cada clase de
  destino rechazada, con el rebinding simulado por un resolvedor inyectable. Sobre Postgres, dos réplicas que no
  reclaman la misma entrega y altas concurrentes que no pasan del límite.
- `tests/scripts/release-gate.test.ts` y `tests/scripts/deploy-manifests.test.ts`: la variable de pruebas nunca en
  producción, y las llaves solo desde el Secret.

**Sin probar aquí**, se verifica en un despliegue real: la entrega por https a un destino real (la ruta TLS es la de
`node:https`), la resolución DNS real (los tests inyectan el resolvedor) y el montaje de las llaves en un clúster o en
compose. El stack de CI no activa los eventos.

**Riesgo residual:**

- Al menos una vez: un receptor que no deduplica por `idempotency-key` puede procesar un evento dos veces.
- Una suscripción desactivada no recibe lo que pasó mientras tanto: hay que leerlo por el cursor.
- La guarda conoce los rangos reservados de IANA. Si la red del clúster usa direcciones públicas, no las reconoce como
  internas: conviene además una NetworkPolicy de salida para el policy-engine.
- El registro de entregas da la clase del error de conexión, así que quien da de alta un webhook sabe si un puerto de
  un host público responde. Solo lo hace un admin, y el alta queda en la auditoría.
- Cada aserción rechazada es un evento: quien tenga la llave Nostr de una persona puede provocar entregas a las
  suscripciones de `session.assert`, dentro de los límites de peticiones del engine (IR-2026-09-05).
- Los plazos de los reclamos usan el reloj de cada réplica: con relojes muy desfasados (más que el margen de 30 s) una
  entrega puede enviarse dos veces, algo que el receptor ya debe tolerar.
