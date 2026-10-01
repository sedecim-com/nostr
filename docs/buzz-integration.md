# Integración con Block Buzz (early release, spec §6)

## Versión fijada
Ver `infra/buzz/PIN`: commit, fecha y digest vigentes. El mismo digest está en `docker-compose.yml` y en
`deploy/k8s/base/kustomization.yaml`. Cambia según ADR 0003, con el informe del gate de cada pin en `docs/interop/`
(el primero fue el commit `02c6309f`, 2026-09-25).
Buzz está bajo Apache-2.0 y se usa **sin modificar** (ADR 0002): no hay fork ni código de Buzz en este repositorio; `NOTICE` lo atribuye.

## Qué se reutiliza / qué no se delega
Reutilizamos el relay (NIP-01, NIP-29, NIP-42), su Postgres/Redis, búsqueda NIP-50, audit log y Blossom
(`/media`). **No** delegamos: custodia y abstracción de identidades, panel de soberanía, resiliencia
multi-relay y máquina de estados de entrega, Tor-only, mirror/vault cifrado, Marmot/MLS y políticas
institucionales. Todo eso vive en este repositorio y habla Nostr, no APIs internas de Buzz.

## Sin fork: pin y actualización
Usamos la imagen publicada por Block fijada por digest. Las divergencias se resuelven con adaptadores en el
SDK o servicios aparte, nunca modificando el relay. Para probar una imagen nueva: ejecutar el workflow `ci`
manualmente con el input `buzz_image`; los criterios de adopción y el rollback están en ADR 0003.

**Revisión mensual automática (BUZZ-05).** El workflow `buzz-upstream` se ejecuta el primer lunes de cada
mes, a mano con `workflow_dispatch` y al fusionar en `main` un cambio del workflow o del script. `scripts/buzz-upstream.sh check` resuelve de forma anónima el digest
de `ghcr.io/block/buzz:main` (token de GHCR + `HEAD` del manifiesto, que acepta índices OCI) y lo compara con
`BUZZ_IMAGE` de `infra/buzz/PIN`. Si cambió, reutiliza el job `stack` de `ci.yml` (`workflow_call` con
`buzz_image` y `stack_only`) contra la imagen candidata. Si el gate pasa, abre una PR en la rama
`buzz-upstream/<digest>` que actualiza el PIN, el digest por defecto de `docker-compose.yml` y de
`deploy/k8s/base/kustomization.yaml`, los flags de
despliegue (`infra/web/flags.json`, que llevan el commit del relay) y el informe en
`docs/interop/`. Solo ese job tiene `contents: write` y `pull-requests: write`. Requisitos y límites:
- Con la GitHub App de los bots configurada (OPS-12; la variable `BOT_APP_CLIENT_ID` y el secreto
  `BOT_APP_PRIVATE_KEY`, ver [docs/backlog/GITHUB.md](backlog/GITHUB.md)), la rama y la PR son de la App, y la PR
  lanza `ci`, CodeQL y dependency-review por sí sola.
- Sin ella, van con el `GITHUB_TOKEN`: hay que activar *Allow GitHub Actions to create and approve pull
  requests* en los ajustes del repositorio, y como esas PR no lanzan `ci` por sí solas, el job lo lanza con
  `workflow_dispatch` sobre la rama (necesita `actions: write`) y sus checks aparecen en la PR. CodeQL y
  dependency-review no corren.
- Si no se puede abrir la PR, el workflow deja la rama lista y abre un issue con el enlace para crearla a mano.
- Si falla el gate o la comprobación de flags, no se abre PR, la ejecución queda en rojo y se abre un issue
  "Buzz upstream: el gate falla con <digest>". Si ese issue ya existe, se comenta en él. La revisión es manual
  (ADR 0003).
- El commit upstream se lee de la etiqueta OCI `org.opencontainers.image.revision`. Si falta, la PR lo indica
  y `BUZZ_COMMIT` se actualiza a mano.

## Gate F0 → F0.5 (`npm run test:interop`)
```bash
docker compose up -d relay
BUZZ_RELAY_URL=ws://localhost:3000 npm run test:interop   # genera interop-report.json
```
Verifica NIP-11, NIP-42 + NIP-29 desde un cliente de terceros, aceptación de gift wraps con distintas
estrategias de timestamp, que las suscripciones a kind 1059 sin `#p` propio no filtren nada, y Blossom.
**NIP-17 solo se habilita en producción si `interop-report.json` → `nip17.enableFlag = true`**, y con el
`timestampJitterSeconds` recomendado configurado explícitamente (nunca en silencio).

## Resultado del gate (pin vigente; primera ejecución el 2026-09-26 contra `02c6309`, build local debug)
Evidencia: [`docs/interop/buzz-upstream-10343a68e68b-report.json`](interop/buzz-upstream-10343a68e68b-report.json)
(commit `8519db1`). Los informes anteriores (`buzz-upstream-ac4521f3e464-report.json`,
`buzz-upstream-8096413eb360-report.json` y `buzz-02c6309-report.json`) dan el mismo resultado; el job `stack` de CI
lo repite en cada PR.

| Verificación | Resultado |
|---|---|
| NIP-11 | ✅ `supported_nips` incluye 1, 17, 29, 42, 50 (versión relay 0.2.1) |
| NIP-42 + NIP-29 desde cliente de terceros (crear grupo, unirse, publicar, leer desde otro cliente) | ✅ |
| NIP-17 con timestamps NIP-59 estándar (hasta 2 días atrás) | ❌ 0/3 — `invalid: event timestamp too far from server time` (issue #4192; se re-evalúa en cada sync, ver "Seguimiento de #4192") |
| NIP-17 con jitter acotado ±5 min | ✅ 3/3 aceptados y recibidos/descifrados por el destinatario |
| Suscripción kind 1059 sin `#p` propio | ✅ 0 fugas |
| Blossom `/media` con blob cifrado en cliente | ❌ 415 `disallowed content type` (el media de Buzz solo acepta imágenes/vídeo detectados por magic bytes) |
| Blossom `/media` con imagen en claro | ✅ aceptada y descargada con verificación de hash (backend S3: SeaweedFS). Buzz exige autorización BUD-01 `get` también para leer; el cliente reintenta con ella ante un 401 |
| Cliente soberano E2E (canal + DM) contra Buzz | ✅ |
| Kinds Marmot 30443 / 445 / 10051 | ❌ `restricted: unknown event kind` → grupos MLS por `secure-relay` (`docs/marmot.md`) |
| Lista de relays de DM (kind 10050, FR017-06) | ❌ `restricted: unknown event kind` (job `tor-profile`, OPS-21; el gate lo registra en `interop-report.json` → `dmRelayList`). Sin esa lista, un DM a una persona cuyo relay es Buzz va a sus relays NIP-65 o, si no tiene, a los del emisor, con el aviso «la entrega es incierta» |

**Decisiones derivadas**
- `BUZZ_PINNED_ADAPTER` (`packages/messaging/src/adapters.ts`): jitter de gift wrap 300 s, explícito y
  declarado en la UI. El flag NIP-17 puede habilitarse para esta versión fijada con este adaptador.
- Adjuntos cifrados en cliente → `services/blob-store` (Blossom agnóstico al contenido); Buzz `/media`
  queda para imágenes en claro ya saneadas (Buzz además rechaza imágenes con metadatos).

**Seguimiento de #4192 (FR017-05).** El adaptador de 300 s es temporal y se retira solo cuando el gate lo
permite; nadie tiene que acordarse de revisarlo:

| Paso | Dónde | Qué hace |
|---|---|---|
| 1. Re-ejecutar el gate | `ci.yml` (cada PR/push) y `buzz-upstream.yml` (cada sync mensual con la imagen candidata) | `tests/interop/buzz.interop.test.ts` prueba siempre las tres estrategias (`nip59-default-2d`, `bounded-5m`, `none`) y guarda el resultado en `interop-report.json` |
| 2. Decidir | `nip17GateDecision` (`packages/messaging/src/flags.ts`) | Si Buzz acepta los 3 gift wraps con el jitter NIP-59 estándar → `recommendedJitterSeconds = 172800` (jitter estándar); si no, 300 s mientras el acotado pase; si ninguno pasa o no llega nada, NIP-17 queda deshabilitado |
| 3. Publicar | `scripts/interop-flags.ts` → `infra/web/flags.json` | Los clientes (web y soberano) usan el jitter de los flags por encima del adaptador fijado (`wrapOptionsFromFlags`); `--check` en CI impide que los flags diverjan del gate |
| 4. Avisar | PR de pin de `buzz-upstream` | `interop-flags.ts --change-from` compara con los flags anteriores y la PR lo dice: "#4192 resuelto upstream: se vuelve al jitter estándar…" (o "Regresión de #4192" si vuelve a fallar). Al fusionarla, retirar también el valor de reserva de `BUZZ_PINNED_ADAPTER.wrap` |

Pruebas: `packages/messaging/test/flags.test.ts` (172800 cuando la estrategia estándar pasa, 300 mientras no,
coherencia con el informe y los flags versionados, texto de la PR).

## Reacciones, hilos y borrado en canales (FR015-04)
Lo que envía la web y por qué, según el código del relay en `b0d6fb8` (el último commit de Buzz que se puede leer aquí; el
pin es posterior: `infra/buzz/PIN`) en `crates/buzz-relay/src/handlers/ingest.rs` y `side_effects.rs`,
`crates/buzz-core/src/nip10.rs` y `crates/buzz-db/src/store/event.rs`. Lo que vale para la imagen fijada lo dice el gate
de abajo, que corre contra ella:

| Acción | Evento de la web | Qué comprueba Buzz |
|---|---|---|
| Responder | kind 9 con `h`, `["e", raíz, "", "root"]`, `["e", padre, "", "reply"]` y `["q", padre, "", autor]` (NIP-C7) | El padre debe estar en el mismo canal y la `root` debe ser la raíz del hilo del padre; si no, `invalid: root tag does not match thread ancestry`. Buzz lee un `root` sin `reply` como mensaje de primer nivel, así que la web pone los dos marcadores también en una respuesta directa |
| Reaccionar | kind 7 con `h`, `e` (el mensaje), `p` y `k` (NIP-25) | El objetivo debe existir (`invalid: reaction target event not found`) y el canal sale de él. Una reacción repetida del mismo autor con el mismo contenido se rechaza (`duplicate: reaction already exists`): la web ofrece quitarla en vez de repetirla |
| Quitar mi reacción | kind 5 con `h`, `e` (la reacción) y `k` 7 | NIP-09 no está en el NIP-11 de Buzz, pero su ingest acepta un kind 5 del autor de su objetivo (un objetivo por evento) y es lo que usan sus clientes para quitar una reacción. El gate registra el resultado sin exigirlo |
| Borrar un mensaje | kind 9005 con `h` y `e` | El autor del mensaje o un owner/admin del canal, y el objetivo en ese canal; si no, `invalid: must be event author or channel owner/admin`. Buzz lo borra en blando: las lecturas (`query_events`) dejan de devolverlo |

La web no usa kind 5 para borrar mensajes: el 9005 es el borrado de NIP-29 y lo aceptan igual para el autor y para los
admins. La vista aplica un 9005 que le llega solo si lo firma el autor del mensaje o un admin de la lista 39001 firmada
por la misma llave que el 39000 del canal; y un kind 5 solo sobre eventos de quien lo firma. Un relay que aceptara
cualquier borrado no basta para ocultar mensajes ajenos.

**Qué ve cada parte.** Reacciones, respuestas y borrados son eventos firmados con la npub de quien los hace: los ven los
miembros del canal y el operador del relay, que sabe quién borró qué y cuándo. El borrado no retira las copias que ya
circularon: quien recibió el mensaje y otros clientes y relays pueden conservarlo. El mirror marca el mensaje como
borrado y deja de servirlo, pero conserva la fila. La web lo dice antes de borrar con los textos de
`CHANNEL_DELETION_TEXTS` (catálogo revisado, `docs/disclosures.md`).

**Gate.** `tests/interop/buzz.interop.test.ts` («FR015-04: …») crea un canal y, con las mismas plantillas que la web,
responde (directa y anidada), reacciona, quita la reacción y borra con 9005 como autor, como miembro sin permiso y como
owner. Exige lo que la web necesita (respuestas, reacción leída por `#h`, los dos borrados permitidos que dejan de
servirse y el rechazo del miembro) y guarda todo en `interop-report.json` → `nip29Collaboration`. Corre en el job
`stack` de CI y en cada sync de `buzz-upstream`; en `docs/interop/` aún no hay un informe con ese campo.

## Estado de presencia, kind 30315 (FR015-05)
Con lo que hay en este repositorio no se puede saber si el Buzz fijado acepta el estado NIP-38 que publica la web:
Buzz rechaza los kinds que no conoce (`restricted: unknown event kind`) y ningún informe de `docs/interop/` prueba un 30315.
En el código del relay en `b0d6fb8` (fuera de este repositorio; el pin es posterior), `required_scope_for_kind` admite
`KIND_USER_STATUS` con el scope `UsersWrite`. **Gate.** `tests/interop/buzz.interop.test.ts` («FR015-05: …») publica un
estado y su borrado como los construye la web, los lee desde otro cliente y lo guarda en `interop-report.json` →
`userStatus`, sin exigirlo: la presencia es opt-in y Experimental mientras tanto. Si Buzz aplica la expiración NIP-40
tampoco se sabe. Detalle y decisiones en [presence.md](presence.md#compatibilidad-con-los-relays).

## Revisión del pin 8519db1 (2026-09-30, ADR 0003)
De `b0d6fb8` a `8519db1`: 22 commits upstream. Se revisaron los del relay (`crates/buzz-relay`, `buzz-db`, `buzz-media`) y
su despliegue. El CI completo (job `stack` con la membresía NIP-29 de FR023-10, `tor-profile` con el DM por el
`.onion` de Buzz) pasa con la imagen nueva.

| Área | Qué cambia upstream | Efecto aquí |
|---|---|---|
| Kinds | NIP-AR: kinds 45010 (artefacto de canal) y 45011 (retirada, solo el relay); un REQ que pueda devolverlos no admite tags de varias letras | Ninguno: no usamos esos kinds ni tags de varias letras. 10050, 10051, 30443 y 445 siguen siendo desconocidos para Buzz |
| NIP-42 y tenant por `Host` | NIP-FI (JWT en el upgrade, emparejado con NIP-42, vida de la sesión), apagado si `BUZZ_NIP_FI_MODE` no está | Ninguno con NIP-FI apagado: el AUTH NIP-42, el tenant por `Host` y el tag `relay` no cambian. **`BUZZ_NIP_FI_MODE` debe seguir sin definirse**: en `enforce` los servicios internos, que solo hacen NIP-42, no entrarían |
| Entrega | Las lecturas `#e` tienen un límite de 20 s y, si una consulta agota su tiempo, el REQ recibe `CLOSED "error: query timed out"` en vez de EOSE, y se cierra también su parte en vivo | Ninguno hoy: no hacemos REQ `#e`, el pool cierra la suscripción con el `CLOSED` y el indexer reabre las suyas. Un cliente que dependa de una suscripción en vivo debe volver a suscribirse tras un `CLOSED` |
| Media | El verificador de la autorización kind 24242 se endurece solo con NIP-FI en `enforce` | Ninguno: el cliente Blossom firma `t`, `x` y `expiration` como antes |
| Timestamps | Sin cambios: ±900 s, también para kind 1059 | El adaptador de jitter de 300 s para #4192 sigue siendo necesario |
| NIP-29 | Sin cambios en 9000/9001/9007 ni en el estado 39000–39003 firmado por el relay | Ninguno para la membresía de FR023-10 ni para el mirror |
| Arranque y readiness | Falla al arrancar con `BUZZ_OPERATOR_LISTENERS` mal formado o sin Redis en 5 s. `/_readiness` solo dice que el proceso está arriba: Postgres y Redis pasan a `/_status` | No definimos esas variables, y compose espera a Redis. **La sonda de SLO pasa a `/_status`** (`http_buzz_status` en `deploy/monitoring/blackbox/blackbox.yml`, `docs/slo.md`); con `/_readiness` seguiría en verde con Postgres o Redis caídos |
| Borrado de comunidades | `POST /operator/communities/delete` y un drain automático, apagados sin `RELAY_OPERATOR_*` | Ninguno. Las rutas nuevas (`/operator/communities/delete`, `/operator/listener/pubkeys`, `/query` y `/count` de artefactos) fallan cerradas con nuestra configuración; entran en el inventario de SEC-12 ([`docs/security/buzz-attack-surface.md`](security/buzz-attack-surface.md)) |

**Rollback.** Las migraciones 0050–0053 son aditivas y se aplican al arrancar. Con `BUZZ_AUTO_MIGRATE` activo, la imagen
anterior no arranca sobre una base que ya las tiene: su migrador rechaza migraciones que no conoce. Para volver a
`ac4521f3e464` hay que arrancarla con `BUZZ_AUTO_MIGRATE=false` o restaurar el backup previo
(`docs/runbooks/restore.md`), como pide ADR 0003.

**Adaptadores del SDK: siguen todos justificados.**
- el jitter de 300 s en los gift wraps (#4192 sigue abierto);
- blob-store para blobs cifrados;
- el secure relay para los kinds de Marmot (y el 10050);
- la identidad de servicio del indexer, sus suscripciones `#h` y la URL pública como `Host` y tag `relay`;
- `#p` en los REQ de kind 1059;
- el reintento con autorización de las descargas de Blossom.

## Hallazgos del sprint S1 (2026-09-26)
- **MinIO ya no publica imágenes descargables** (Docker Hub y quay.io responden `unauthorized`); el compose upstream de Buzz también depende de ellas. El stack usa **SeaweedFS 4.47** (Apache-2.0, fijado por digest) como S3 compatible.
- Buzz rechaza las REQ **anónimas** con `NOTICE auth-required`: el indexer se autentica con una identidad de servicio (`INDEXER_NSEC`).
- El fan-out **en vivo** de Buzz separa las suscripciones globales de las de canal: los mensajes NIP-29 solo llegan a suscripciones con `#h`. El indexer descubre los canales y mantiene una suscripción `#h`.
- Buzz es multi-tenant por cabecera `Host`: un host no mapeado a una comunidad recibe **404**, y el tag `relay` del AUTH NIP-42 debe ser `ws(s)://<Host>`. Un servicio que conecta por la red interna (`ws://relay:3000`) debe presentar la URL pública: el indexer usa `INDEXER_RELAY_PUBLIC_URL` (por defecto `RELAY_URL`) para la cabecera `Host` y el tag `relay` (opción `authRelayUrl` del pool).
- Buzz exige autorización BUD-01 también para **descargar** media.

## Hallazgos conocidos
- Issues upstream #4677 (desktop no muestra ciertos kind 1059) y #4192 (rechazo de gift wraps con
  timestamps aleatorizados). El test `messaging.test.ts` reproduce este último contra un relay que emula
  la validación de frescura; `WrapOptions.timestampJitterSeconds` es el adaptador explícito, y el gate lo
  retira cuando upstream lo corrija (ver "Seguimiento de #4192").
- Buzz exige que las REQ que pueden devolver kinds 1059/44100/44101 incluyan `#p` = pubkey autenticada.
  El SDK (`dmInboxFilter`) y el indexer (`DEFAULT_MIRROR_KINDS`) respetan esta regla; el mirror nunca pide
  gift wraps ajenos.
- Con `BUZZ_REQUIRE_AUTH_TOKEN=false` los clientes de terceros se autentican solo con NIP-42; activar
  `BUZZ_PUBKEY_ALLOWLIST=true` para relays privados; en modo institucional el servicio `relay-allowlist`
  mantiene la tabla `pubkey_allowlist` desde el policy-engine (FR023-04, `docs/institutional.md`) y, con
  `BUZZ_MEMBERSHIP_NSEC`, la membresía NIP-29 de los canales privados registrados (kinds 9000/9001, FR023-10).
