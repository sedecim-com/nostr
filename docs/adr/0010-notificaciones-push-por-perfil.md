# ADR 0010 · Notificaciones push opacas por perfil

- **Estado:** Aceptado · **Tarea:** DEC-08 (#42), implementación OPS-06 (#57) · **Fecha:** 2026-09-26
- **Aprobación:** responsable de producto, 2026-09-26 (decisión: push opaco por perfil)

## Contexto
Sin push, un cliente solo se entera de los mensajes nuevos mientras está abierto. Con push, un tercero
participa en cada aviso. Ese tercero es el servicio push del navegador o del sistema: autopush de Mozilla,
FCM de Google para Chrome, Apple para Safari/iOS. También participa quien opera el gateway que decide cuándo
avisar. El panel ya tenía el control `notifications` (`push` · `privacy-push` · `none`), pero faltaba:
- fijar qué significa cada modo;
- fijar qué metadatos ve cada parte;
- fijar qué perfiles pueden usarlo.

## Decisión
**Todo push es opaco.** El aviso nunca lleva contenido, remitente ni número de mensajes. El cliente muestra
siempre el mismo texto genérico («Tienes actividad nueva») y no lee el payload.

| Perfil | Modo | Payload | Retardo aleatorio | Intervalo mínimo entre avisos | Tick de envío | TTL · Urgency |
|---|---|---|---|---|---|---|
| convenience | `push` (opaco) | constante `{"v":1}` cifrado (RFC 8291) | 10–60 s | 2 min | 15 s | 1 h · normal |
| institutional | `push` (opaco) | constante `{"v":1}` cifrado | 10–60 s | 2 min | 15 s | 1 h · normal |
| private-resilient | `privacy-push` (solo aviso) | vacío (push sin cuerpo) | 2–10 min | 15 min | 60 s | 4 h · low |
| sovereign | `none` | — | — | — | — | — |
| sovereign-tor (y cualquier configuración `tor-only`) | `none` | — | — | — | — | — |

Cómo se aplica la tabla:
- **Agrupación.** La primera actividad pendiente programa un aviso tras un retardo uniforme aleatorio. Lo que
  llegue mientras tanto se absorbe en ese mismo aviso. Además, nunca hay dos avisos al mismo dispositivo antes
  del intervalo mínimo. El instante de envío se redondea al siguiente *tick* del reloj, así que los avisos de
  todos los usuarios salen a la vez. Todos llevan el header `Topic: activity`, con lo que el servicio push
  sustituye un aviso pendiente por el siguiente en lugar de acumularlos.
- **Sin push en sovereign y Tor.** Registrar el dispositivo en un servicio push lo vincula a una identidad
  del sistema (cuenta de Google/Apple/Mozilla) y revela horarios de actividad. En estos perfiles el cliente
  consulta los relays solo mientras está abierto (polling local).
- **Validación.** `validateConfig` bloquea cualquier push en `tor-only` (`TOR_PUSH`). El gateway rechaza el
  registro con 403 si el perfil es `sovereign`/`sovereign-tor`, si la red es `tor-only` o si algún relay es
  `.onion`.
- **Código.** La matriz vive en `packages/profiles/src/notifications.ts`:
  - `NOTIFICATION_MODES`, con los parámetros y los metadatos expuestos por modo.
  - `notificationMatrix()`, que se deriva de los presets y por eso no puede divergir.
  - `notificationPolicy(config)` y `nextPushDelayMs`.
  - Los tests están en `packages/profiles/test`.
- **Transporte.** Hoy es Web Push:
  - Autenticación VAPID (RFC 8292).
  - Payload cifrado aes128gcm (RFC 8291), implementado con `node:crypto` y verificado byte a byte contra el
    ejemplo del RFC.
  - APNs, FCM nativo y UnifiedPush irán detrás de la misma interfaz (`WebPushSender` → `PushTransport`)
    cuando exista app nativa (ADR 0004). Se aplicarán las mismas reglas de payload constante y agrupación.

### Disparador en el relay
El cliente registra, con una petición firmada NIP-98, tres cosas:
- su suscripción Web Push (endpoint y claves);
- el perfil declarado;
- los relays donde recibe DMs (kind 10050).

El pubkey vigilado es **el que firmó la petición**, así que nadie puede suscribirse a los horarios de
actividad de otra persona. El gateway abre **un único REQ por relay** con todos los pubkeys registrados:
`{"kinds":[1059],"#p":[…],"limit":1}`. Cada gift wrap que llega programa el aviso opaco de los dispositivos
de ese pubkey.

Detalles del REQ:
- Descartar lo que llegue antes de EOSE hace que solo cuente lo nuevo. NIP-59 retrasa `created_at`, así que
  un `since` no sirve.
- `limit: 1` y no `0`: nostr-rs-relay nunca cierra con EOSE un REQ con `limit: 0`, así que el gateway no
  habría contado nada en él (medido con la imagen fijada, OPS-06). El único evento guardado que puede llegar
  antes de EOSE se descarta como el resto.
- Se descartó un «topic» aleatorio que el remitente tuviera que conocer. Obligaría a publicar la relación
  topic↔npub o a que el remitente hablara con el gateway, y eso expone más.

### Qué relays puede vigilar el gateway (OPS-06)
El REQ anterior solo sirve si el relay entrega al gateway los gift wraps dirigidos a otras personas. Muchos
relays no lo hacen, y con razón: los gift wraps solo se entregan a su destinatario autenticado. El gateway no
pide esa lectura y ninguna configuración se la da. Comprueba en cada relay si puede observar la actividad y
solo acepta registros donde puede.
- **Canario.** Al arrancar y cada `NOTIFY_PROBE_INTERVAL_MS` (6 h por defecto), para cada relay que sirve:
  - publica un gift wrap (kind 1059) entre dos claves desechables, con contenido aleatorio y `expiration` a
    10 minutos (NIP-40);
  - lo espera con un REQ de la misma forma que el de los registros, autenticado con su identidad NIP-42
    (`NOTIFY_NSEC`).

  El relay es observable solo si el canario llega. Si cierra el REQ, rechaza el canario o no lo entrega, no
  lo es.
- **El flag es por relay y lo pone el gateway.** Está apagado por defecto: un relay aún sin comprobar cuenta
  como no observable. No hay forma de forzarlo: encenderlo en un relay que no entrega gift wraps ajenos
  exigiría darle al gateway lectura de DMs.
- **Registros:**
  - solo sobre relays observables;
  - si no hay ninguno: 409 (503 mientras no se han comprobado);
  - si hay de los dos: 201, y la respuesta lista en `unwatched` los que no vigila.
- **Si un relay deja de ser observable,** los registros dejan de contar con él, y los que se quedan sin
  relays se borran.
- **La web pregunta antes de ofrecer el control.** Consulta `GET /v1/relays` (`relay`, `observable`,
  `checkedAt`), una consulta sin firmar que no dice qué persona pregunta:
  - si ningún relay de la persona es observable, no hay interruptor y se explica por qué
    (`#notifications-unobservable`);
  - mientras el gateway no los ha comprobado, dice que vuelva en unos minutos (`#notifications-checking`);
  - si solo lo son algunos, nombra los que no vigila.

#### Matriz real por relay
| Relay (versión fijada) | ¿Ve el gateway un gift wrap para otra persona? | Push web | Evidencia |
|---|---|---|---|
| Buzz (`ghcr.io/block/buzz@sha256:ac4521f3e464…`, commit `b0d6fb8`) | No. Cierra el REQ: `restricted: p-gated events require #p matching your pubkey` (`p_gated_filters_authorized`, `crates/buzz-relay/src/handlers/req.rs`). | No: 409 y la web no ofrece el control. | `tests/interop/notification-gateway.interop.test.ts`, job `stack` |
| Secure relay (nostr-rs-relay `03f54bfbffff…` con `nip42_auth` y `nip42_dms`) | No. Acepta el REQ y el canario, pero no entrega el gift wrap a quien no es su destinatario. | No: 409 y la web no ofrece el control. | El mismo test, job `stack` |
| nostr-rs-relay (la misma imagen) con `nip42_dms = false` | Sí. | Sí: un DM NIP-17 a un npub registrado produce un aviso opaco. | El mismo test, paso «Notification gateway on nostr-rs-relay without DM gating (OPS-06)» del job `stack` |
| Relays del cliente que el despliegue no sirve | No se vigilan. | 400 si ninguno de los pedidos es del despliegue. | `services/notification-gateway/test/gateway.test.ts` |

Con el stack de referencia (Buzz y el secure relay) no hay push web. Buzz trae su propio mecanismo, NIP-PL
(*push leases*, `docs/nips/NIP-PL.md` del commit fijado):
- el relay guarda un filtro firmado y es él quien despierta la instalación;
- en v1 solo es conforme el perfil APNs, con App Attest (FCM y UnifiedPush aún no); no hay Web Push;
- cada aviso es una señal constante de «reconectar».

Encaja con la app nativa (ADR 0004), no con la web.

### Qué ve cada parte

| Parte | `push` (convenience, institutional) | `privacy-push` (private-resilient) | `none` (sovereign, Tor) |
|---|---|---|---|
| **Servicio push** (Mozilla / Google / Apple) | Que el dispositivo tiene suscripción y la IP del gateway. Cuándo se entrega cada aviso (hora desplazada 10–60 s y agrupada). Tamaño constante del cifrado. Headers TTL/Urgency/Topic. **No** ve contenido, remitente, npub ni recuento. | Lo mismo, con avisos vacíos y horas desplazadas 2–10 min y agrupadas cada ≥15 min. | Nada: no hay suscripción. |
| **Operador del gateway** | npub ↔ endpoint push del dispositivo, perfil declarado, IP del cliente al registrarse, relays vigilados. Cuándo llega un gift wrap a ese npub. **No** ve contenido ni remitente real (van cifrados en el gift wrap). Solo en memoria: sin base de datos. | Igual. | Nada: el registro se rechaza. |
| **Relay** | Que el gateway (su IP y su identidad NIP-42 de servicio) pide los gift wraps de un conjunto de npubs. El relay ya veía antes la llegada de gift wraps a cada npub. También recibe el canario (OPS-06): cada 6 h, un gift wrap entre dos claves desechables que caduca a los 10 minutos. | Igual. | Nada nuevo. |

## Riesgos residuales y mitigaciones

| Riesgo | Mitigación | Residual |
|---|---|---|
| **Correlación temporal.** Quien vea a la vez el relay (gift wrap para X a las t) y el servicio push (aviso a un dispositivo a las t+δ) puede enlazar npub y dispositivo. | Retardo aleatorio por perfil. Agrupación e intervalo mínimo. Envío alineado a ticks comunes para todos los dispositivos. `Topic` para coalescer. Con `privacy-push`, ventanas de minutos. | Con muchos mensajes y poca población de usuarios la correlación estadística sigue siendo posible. Por eso Tor y sovereign no tienen push. |
| **IP del gateway.** El servicio push ve siempre la misma IP de origen para todos los avisos del despliegue. | Es la IP del operador, no la del usuario, y es común a todos los usuarios. El gateway no reenvía nada del cliente. | Identifica que el dispositivo usa este despliegue de Acceso Nostr. |
| **Vinculación por token de dispositivo.** El endpoint push identifica el navegador o dispositivo; varias personas con el mismo endpoint quedarían vinculadas ante el gateway. | La web registra cada persona con **su propio scope de service worker** (`./push/<persona>/`), es decir, con endpoints distintos. Los logs solo guardan un HMAC truncado con clave efímera por proceso, nunca el endpoint ni el npub. | El registro sale desde la misma IP del cliente. El servicio push sabe qué endpoints pertenecen al mismo navegador. |
| **El gateway conoce npub ↔ dispositivo.** | Sin persistencia (en memoria). DELETE `/v1/subscriptions` firmado. Baja automática ante 404/410 del servicio push. Límite de dispositivos por npub. Rate limit de registros. | Un operador malicioso puede registrar esa relación mientras el usuario tenga push activo. Por eso es opt-in y el panel lo declara. |
| **SSRF y abuso del gateway.** | Solo se aceptan endpoints `https` de servicios push conocidos (`NOTIFY_PUSH_HOSTS`). Relays restringidos a los que sirve el gateway. Cuerpo ≤ 16 KiB. | — |
| **Relays que solo sirven kind 1059 a su destinatario.** Buzz y el secure relay con `nip42_dms` lo hacen. | El gateway no pide esa lectura: darla sería darle acceso a los DMs. Su canario (OPS-06) detecta esos relays y el gateway no acepta registros en ellos. La web no ofrece el control y explica por qué. | Con el stack de referencia no hay push web. Solo hay aviso en relays DM que entregan gift wraps ajenos, como nostr-rs-relay sin `nip42_dms`. En Buzz el camino es NIP-PL con la app nativa. |

## Consecuencias
- `institutional` pasa de `privacy-push` a `push` (opaco). Los textos de disclosure de `push`,
  `privacy-push` y `none` cambian. Por eso `DISCLOSURE_VERSION` sube a 1.1.0 y `docs/disclosures.md` queda
  pendiente de revisión legal/UX (FR028-02).
- Nuevo servicio `services/notification-gateway`:
  - En compose va en el perfil `push`.
  - En Kubernetes es el componente opcional `deploy/k8s/components/notification-gateway`.
- La web muestra el control opt-in «Notificaciones» solo si `config.json` define `notificationGateway`. En
  personas sovereign/Tor muestra por qué no hay push. El service worker (`sw.js`, mismo origen, permitido por
  `script-src 'self'`) muestra siempre el texto genérico.
- Las suscripciones viven en memoria. Tras reiniciar el gateway, cada cliente se vuelve a registrar al abrir
  la persona. Hasta entonces no recibe avisos.
- OPS-06:
  - el gateway comprueba sus relays con el canario y expone el resultado en `GET /v1/relays`;
  - la web solo ofrece el control donde algún relay de la persona es observable;
  - el job `stack` de CI mide la matriz por relay contra las imágenes fijadas.
