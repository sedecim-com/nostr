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
`{"kinds":[1059],"#p":[…],"limit":0}`. Cada gift wrap que llega programa el aviso opaco de los dispositivos
de ese pubkey.

Detalles del REQ:
- `limit: 0` y descartar lo que llegue antes de EOSE hacen que solo cuente lo nuevo. NIP-59 retrasa
  `created_at`, así que un `since` no sirve.
- Se descartó un «topic» aleatorio que el remitente tuviera que conocer. Obligaría a publicar la relación
  topic↔npub o a que el remitente hablara con el gateway, y eso expone más.

### Qué ve cada parte

| Parte | `push` (convenience, institutional) | `privacy-push` (private-resilient) | `none` (sovereign, Tor) |
|---|---|---|---|
| **Servicio push** (Mozilla / Google / Apple) | Que el dispositivo tiene suscripción y la IP del gateway. Cuándo se entrega cada aviso (hora desplazada 10–60 s y agrupada). Tamaño constante del cifrado. Headers TTL/Urgency/Topic. **No** ve contenido, remitente, npub ni recuento. | Lo mismo, con avisos vacíos y horas desplazadas 2–10 min y agrupadas cada ≥15 min. | Nada: no hay suscripción. |
| **Operador del gateway** | npub ↔ endpoint push del dispositivo, perfil declarado, IP del cliente al registrarse, relays vigilados. Cuándo llega un gift wrap a ese npub. **No** ve contenido ni remitente real (van cifrados en el gift wrap). Solo en memoria: sin base de datos. | Igual. | Nada: el registro se rechaza. |
| **Relay** | Que el gateway (su IP y su identidad NIP-42 de servicio) pide los gift wraps de un conjunto de npubs. El relay ya veía antes la llegada de gift wraps a cada npub. | Igual. | Nada nuevo. |

## Riesgos residuales y mitigaciones

| Riesgo | Mitigación | Residual |
|---|---|---|
| **Correlación temporal.** Quien vea a la vez el relay (gift wrap para X a las t) y el servicio push (aviso a un dispositivo a las t+δ) puede enlazar npub y dispositivo. | Retardo aleatorio por perfil. Agrupación e intervalo mínimo. Envío alineado a ticks comunes para todos los dispositivos. `Topic` para coalescer. Con `privacy-push`, ventanas de minutos. | Con muchos mensajes y poca población de usuarios la correlación estadística sigue siendo posible. Por eso Tor y sovereign no tienen push. |
| **IP del gateway.** El servicio push ve siempre la misma IP de origen para todos los avisos del despliegue. | Es la IP del operador, no la del usuario, y es común a todos los usuarios. El gateway no reenvía nada del cliente. | Identifica que el dispositivo usa este despliegue de Acceso Nostr. |
| **Vinculación por token de dispositivo.** El endpoint push identifica el navegador o dispositivo; varias personas con el mismo endpoint quedarían vinculadas ante el gateway. | La web registra cada persona con **su propio scope de service worker** (`./push/<persona>/`), es decir, con endpoints distintos. Los logs solo guardan un HMAC truncado con clave efímera por proceso, nunca el endpoint ni el npub. | El registro sale desde la misma IP del cliente. El servicio push sabe qué endpoints pertenecen al mismo navegador. |
| **El gateway conoce npub ↔ dispositivo.** | Sin persistencia (en memoria). DELETE `/v1/subscriptions` firmado. Baja automática ante 404/410 del servicio push. Límite de dispositivos por npub. Rate limit de registros. | Un operador malicioso puede registrar esa relación mientras el usuario tenga push activo. Por eso es opt-in y el panel lo declara. |
| **SSRF y abuso del gateway.** | Solo se aceptan endpoints `https` de servicios push conocidos (`NOTIFY_PUSH_HOSTS`). Relays restringidos a los que sirve el gateway. Cuerpo ≤ 16 KiB. | — |
| **Relays que solo sirven kind 1059 a su destinatario.** Buzz y el relay secundario con `nip42_dms` lo hacen. | El gateway se autentica con NIP-42 (`NOTIFY_NSEC`). En esos relays hace falta conceder lectura a esa identidad de servicio. | Con las versiones fijadas de Buzz y nostr-rs-relay no hay excepción configurable. En el stack de referencia el aviso solo funciona con relays DM que permitan `#p` sobre kind 1059 a la identidad del gateway. |

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
