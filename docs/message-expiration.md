# Caducidad y borrado de mensajes directos (PANEL-06)

Requisito §12.2. Una persona puede pedir que sus mensajes directos (NIP-17) caduquen, y puede borrar los suyos. Las dos
cosas son peticiones a terceros: relays y clientes de los contactos. Lo que este cliente controla es lo que muestra y lo
que guarda. Este documento dice qué hace cada parte, qué ve cada una y qué es petición y qué es garantía.

Los textos que ve el usuario están en el catálogo revisado (`MESSAGE_EXPIRATION_TEXTS` y `DM_DELETION_TEXTS` en
`packages/profiles/src/expiration.ts`, [`disclosures.md`](disclosures.md) desde la versión 1.13.0).

## Configuración

Hay tres niveles. El más específico gana:

1. **Perfil.** El valor por defecto del preset (`messageExpiration` en `packages/profiles/src/presets.ts`). Hoy todos los
   presets dicen `off`: la caducidad borra historial en el dispositivo y en el vault, y su efecto en relays y contactos
   no depende del cliente. La elige la persona o la conversación.
2. **Persona.** Su configuración del panel (`SovereigntyConfig.messageExpiration`), guardada donde ya se guarda esa
   configuración: en la web, en el registro de la persona del almacén cifrado del navegador; en el CLI, en
   `settings/sovereignty` del almacén cifrado de la persona. Una configuración guardada antes de PANEL-06 no tiene valor
   y toma el del perfil.
3. **Conversación.** Un DM con un contacto, por su pubkey. Se guarda cifrado junto a los datos de la persona: colección
   `conv-<persona>` en la web y `conversations` en el CLI. `off` también es una elección: una conversación en `off` no
   caduca aunque la persona tenga plazo. Sin valor propio, sigue a la persona.

En el CLI, `dm send --expire` fija la caducidad de un solo mensaje, por encima de los tres niveles.

Los plazos son días enteros: `off`, `1d`, `7d`, `30d` y `90d`. Son días enteros porque la fecha se redondea al día (abajo).

**No se reescribe el pasado.** La caducidad se calcula una vez, cuando se crea el mensaje (la operación de FR011-05
guarda la fecha en `DmOperation.expiration`), y un reintento conserva la misma. Cambiar el ajuste solo afecta a los
mensajes nuevos: los enviados conservan la caducidad que tenían, o ninguna.

## Lo que se envía

- **Dónde va la etiqueta.** Cada gift wrap (kind 1059) de un mensaje con caducidad lleva `["expiration", T]` (NIP-40),
  también la copia propia del remitente. El seal (kind 13) lleva la misma, como pide NIP-17 por si el seal se filtra.
  El rumor no la lleva. Cada capa conserva su `created_at` aleatorio propio (NIP-59).
- **Redondeo.** `T` es la primera medianoche UTC igual o posterior a `ahora + días` (`roundedExpiration`,
  `packages/messaging/src/expiration.ts`). El relay lee `T` en el wrap. Un `ahora + días` exacto, con `días` de una
  lista corta, le daría la hora exacta de envío, que NIP-59 esconde al retrasar `created_at` hasta dos días. Redondeado,
  solo le dice el día: todos los mensajes con el mismo plazo enviados el mismo día (UTC) llevan el mismo valor. El precio
  es que un mensaje puede durar hasta un día más de lo elegido.
- **Límite del redondeo.** Con el adaptador de Buzz (jitter de ±5 minutos, FR017-05), `created_at` ya da la hora de envío
  con ±5 minutos, y `T − created_at` da el plazo elegido. Ahí el redondeo no esconde nada más.
- **Lo que hereda la caducidad.** El acuse de entrega o de lectura de un mensaje con caducidad lleva la misma. También
  la petición de borrado de ese mensaje: pasada la fecha no queda nada que borrar.
- **NIP-11.** NIP-40 dice que un cliente no debería enviar eventos con caducidad a relays que no anuncian NIP-40. Este
  cliente no lo comprueba: el mensaje va a los relays de DM del destinatario, que son los suyos, y entregarlo pesa más.
  Un relay sin NIP-40 lo sigue sirviendo, y este cliente lo ignora al leerlo. Comprobarlo exigiría otra petición a cada
  relay.

## Lo que se recibe y lo que se guarda

- **Al leer.** `DmInbox` no muestra un mensaje cuya caducidad pasó (la del wrap o la del seal, la que llegue antes),
  aunque el relay lo siga sirviendo. Tampoco lo responde con acuses ni lo guarda. Si caduca mientras está en pantalla,
  `purgeExpired()` lo quita.
- **Copias locales.** `purgeExpiredCopies` borra la operación enviada (`dm-ops`, que guarda el rumor) y cada registro
  del outbox cuyo evento caducó: los wraps del mensaje y los acuses o borrados que caducan con él. Lo hace aunque ningún
  relay los aceptara. `DeliveryEngine.forget` los saca del outbox, y una ronda en curso no los vuelve a escribir.
- **Cuándo.** No espera al remitente ni al contacto:
  - en la web, al abrir la persona y, mientras está abierta, al llegar la siguiente caducidad que conoce (y en todo caso
    cada hora);
  - en el CLI, al abrir la persona en cualquier orden, y en `dm watch` mientras escucha;
  - si el dispositivo está apagado, al volver a abrir la persona.
- **Historial.** `rebuildHistory` (`packages/sync`) deja fuera lo caducado: cada evento por su etiqueta y, al abrirlo,
  un gift wrap también por la de su seal. Así `history sync`, `history export` y el push al vault no lo llevan.
  Restaurar desde el vault (`restoreHistory`) ignora eventos y operaciones del ledger caducados, y la exportación del
  vault también.
- **Caché de eventos del CLI** ([`event-cache.md`](event-cache.md), FR013-05). Guarda los gift wraps cifrados y ya no
  devuelve uno caducado. Del disco sale con la siguiente escritura de la caché (`history sync`, o `dm inbox` y
  `channel read` con conexión), o en la purga si el proceso ya la tiene abierta para escribir (`EventCache.prune`).
  `dm inbox --offline` tampoco muestra un mensaje caducado por la fecha de su seal.

## Borrar un mensaje propio

- **Cómo se hace.** Los gift wraps los firma una llave efímera que el remitente ya no tiene, así que un kind 5 del
  remitente no puede borrarlos de los relays. Se hace como dice NIP-17: un rumor kind 5 (`e` = id del mensaje, `k` = 14 o
  15 y los `p` de sus destinatarios) envuelto en un gift wrap para cada destinatario y para la propia persona, que lo
  reciben sus otros dispositivos. El relay no lo distingue de un mensaje. Sale por el outbox como una operación
  (`delete:<id>`): repetir el borrado reintenta la misma petición.
- **Solo lo tuyo.** Un mensaje que escribió otra persona se rechaza antes de firmar nada (`NotYourMessageError`). El
  cliente que recibe la petición solo la aplica si quien firma el seal es el autor del mensaje. Un borrado falso, de
  otra persona, no oculta nada.
- **El aviso, antes de confirmar.** La web abre un diálogo y el CLI no hace nada sin `--yes`. Los dos dicen qué se pide,
  qué hace este dispositivo y que las copias replicadas pueden seguir existiendo. El texto de las copias empieza igual
  que el de borrar en un canal (FR015-04): «Borrar no retira las copias que ya circularon».
- **Lo que borra este dispositivo.** Quita el mensaje de la conversación, borra su operación y sus registros del outbox
  y borra sus archivos del vault (abajo). En el CLI, la caché de eventos olvida sus wraps (`EventCache.forget`): los
  borra y no los vuelve a guardar si un relay los sirve. `history sync` y `history export` tampoco los incluyen. Además deja una lápida en el almacén cifrado de la persona (`dmdel-<persona>`
  en la web, `dm-deleted` en el CLI): el id del mensaje con su autor y los ids de sus wraps. Así un relay que lo siga
  sirviendo no lo devuelve, llegue antes la petición o el mensaje, y un push al vault no vuelve a subirlo. Las lápidas
  no llevan contenido.
- **Lo que no puede garantizar.**
  - Los wraps siguen en los relays, cifrados, salvo que caduquen y el relay respete NIP-40.
  - El cliente del contacto puede no aplicar la petición (NIP-17 la deja como opcional).
  - El contacto pudo guardar o capturar el mensaje.
  - Un archivo adjunto (kind 15) sigue cifrado en su servidor Blossom: borrar el mensaje no borra el blob.
- **Por qué no un kind 5 firmado.** NIP-59 permite que el destinatario de un wrap (`p`) pida a los relays que lo
  borren con un kind 5 firmado con su llave. El cliente no lo publica. Sería un evento público, firmado con la npub, que
  liga una petición de borrado a un mensaje concreto y a su hora. Además, que Buzz o el relay seguro lo apliquen no está
  probado aquí.

## Coherencia con el Continuity Vault

El vault (ADR 0011, VAULT-05) guarda los archivos con su plazo, contado desde la última escritura. Sus archivos no saben
de caducidades: el formato no cambia y los borrados van por id. La regla:

1. **Al guardar en el vault** un evento con caducidad (la copia automática de cada envío, VAULT-04, o un push), el
   cliente lo apunta con su fecha en una cola cifrada (`vdel-<persona>` en la web, `vault-forget` en el CLI). Así lo
   borra al caducar aunque para entonces ningún relay lo sirva.
2. **Al caducar**, borra los archivos `event:<wrap>` de la cola que vencen y, si tiene el vault a mano, también los de
   los wraps caducados que conocía (outbox, pantalla). Si el vault no responde, o en esa ejecución no hay vault (el CLI
   sin `--vault`), los de la cola siguen en ella y se borran en la siguiente purga que llegue al vault. Un mensaje que
   nunca llegó al vault no entra en la cola, que no crece con cada caducidad.
3. **Al borrar**, borra los archivos de los wraps del mensaje que conoce (los del outbox y el que leyó) o, si no puede,
   los encola. La web no encola nada si el despliegue no tiene vault o la persona no tiene llave de archivo en ese
   navegador: no puede tener archivos allí.
4. **Cada push** deja fuera lo caducado y lo borrado (lápidas) y borra sus archivos si siguen ahí. El snapshot del
   ledger se reescribe sin sus operaciones.
5. **Al restaurar** se ignoran los eventos y las operaciones caducados, y no se vuelven a publicar ni a poner en el outbox
   los wraps que este dispositivo sabe borrados.
6. **Aviso.** Cuando el plazo del vault es mayor que la caducidad más corta de la persona o de una conversación, o es
   «hasta que lo borres», el panel, la conversación, la tarjeta del vault y el CLI lo dicen (`vaultExpirationNotice`). Si
   la web no conoce el plazo, lo dice sin cifras. Solo pregunta el plazo al vault cuando el usuario cambia la caducidad
   de una conversación o usa el vault.

**Peor caso.** Un archivo que este dispositivo no llega a borrar (no vuelve a abrirse, o era de un push desde otro
dispositivo que no lo sabe) dura en el vault hasta su plazo: `effective_days` desde que se subió (un evento se sube una
sola vez). Después, las copias de seguridad del operador lo conservan cifrado hasta su propia retención. En el módulo de
Terraform de referencia son 14 días de RDS y 35 días del bucket de backups; en el compose, lo que conserve el operador.
Sin plazo en el vault, dura hasta que la persona lo borra o borra el vault. El snapshot del ledger guardado antes del
borrado dura hasta el siguiente push, que lo reemplaza, o hasta el plazo del vault.

## Qué ve cada parte

| Parte | Caducidad | Borrado |
|---|---|---|
| Relay | La fecha de caducidad de cada wrap (el día UTC), además del destinatario (`p`) y el `created_at` aleatorio. Con el jitter de Buzz deduce el plazo | Un wrap más, igual que un mensaje |
| Operador del vault | Peticiones de borrado de archivos: cuándo y cuántas, no de qué | Lo mismo |
| Contacto | La fecha (en el seal); su cliente decide si la respeta | Qué mensaje pediste borrar y cuándo; su cliente decide |
| Tus otros dispositivos | La copia propia con la misma fecha | La petición, que este cliente aplica |
| Quien abra el almacén local | La cola de borrados del vault (ids y fechas de lo que espera borrarse) y, hasta su siguiente escritura, los wraps caducados que la caché del CLI aún tenga en disco | Las lápidas (ids de mensajes, autores y wraps), la cola de borrados del vault (ids) y, en la caché del CLI, los ids de los wraps olvidados |

## Petición y garantía

Lo que este cliente hace, con prueba:

- no muestra ni responde lo caducado;
- borra sus copias locales al caducar o al borrar;
- no sube lo caducado o borrado al vault y borra los archivos que conoce, o los encola;
- no restaura lo caducado ni vuelve a publicar lo borrado;
- solo aplica borrados del autor del mensaje.

Lo que depende de otros:

- que un relay deje de servir o borre un wrap caducado (NIP-40);
- que el cliente de un contacto respete la caducidad o el borrado;
- lo que el contacto guardó;
- las copias de seguridad del operador del vault;
- el blob de un adjunto en Blossom.

## Quién conserva qué

| Copia | Tras caducar | Tras borrar |
|---|---|---|
| La conversación en este dispositivo | Fuera (al caducar o al abrir la persona) | Fuera en el momento |
| Mensaje enviado (`dm-ops`) y su entrega (outbox) | Se borran | Se borran |
| Caché de eventos del CLI (wraps cifrados) | Fuera de las lecturas; del disco, en la siguiente escritura | Se olvidan sus wraps (si otro proceso escribe la caché, en la siguiente `history sync`) |
| Acuses enviados (`receipts-*`, solo ids) | Quedan los ids | Quedan los ids |
| Lápidas | — | Quedan los ids |
| Archivos del vault que el cliente conoce | Se borran (o se encolan) | Se borran (o se encolan) |
| Otros archivos del vault | Hasta el plazo del vault | Hasta el plazo del vault |
| Copias de seguridad del operador del vault | Su retención | Su retención |
| Relays con NIP-40 | Dejan de servirlo; pueden guardarlo | Lo siguen sirviendo, cifrado |
| Relays sin NIP-40 | Lo siguen sirviendo, cifrado | Lo siguen sirviendo, cifrado |
| Contacto con este cliente | Deja de mostrarlo y no lo guarda | Lo quita |
| Contacto con otro cliente | Depende de ese cliente | Depende de ese cliente |
| Capturas y reenvíos | Quedan | Quedan |

## Dónde se usa

- **Web.**
  - Panel: control `messageExpiration`, con el aviso de que solo afecta a los mensajes nuevos.
  - Mensajes directos: la caducidad de la conversación (con la de la persona como opción), «caduca el …» en cada mensaje
    y «Borrar» en los propios, con el diálogo.
  - Tarjeta del vault: el aviso de plazo.
- **CLI.**
  - `persona expiration --persona ID <plazo>` y `dm expiration --persona ID --to NPUB <plazo|persona>`.
  - `dm send --expire <plazo>`.
  - `dm delete --persona ID --id ID --yes`: sin `--yes` solo muestra el aviso.
  - `dm inbox` y `dm watch` muestran el id y la caducidad de cada mensaje.
  - `vault retention` avisa si el plazo es mayor que la caducidad.

## Fuera de alcance

- **Grupos seguros (Marmot/MLS).** Una caducidad de grupo tendría que acordarse en el estado del grupo, para todos sus
  miembros, y no en un dispositivo.
- **Canales NIP-29.** Son colaboración en claro y no caducan. Su borrado sigue siendo el de FR015-04, con el mismo aviso
  de copias.
- **Relays y clientes reales.** Está probado con el relay de pruebas, que no respeta NIP-40, y con este cliente en los
  dos extremos. Que Buzz, el relay seguro u otros clientes respeten la caducidad o apliquen la petición de borrado no
  está verificado aquí.

## Pruebas

- `packages/profiles/test/expiration.test.ts`: precedencia, presets, aviso del vault, textos y lint de afirmaciones.
- `packages/messaging/test/expiration.test.ts`:
  - redondeo y etiquetas en wraps y seals, ausentes sin caducidad;
  - reintentos;
  - purga con reloj inyectable y control negativo;
  - inbox con el relay de pruebas: no muestra lo caducado ni lo responde, y aplica el borrado en el contacto y en el
    otro dispositivo, en cualquier orden;
  - un borrado ajeno se rechaza o se ignora.
- `packages/delivery-engine/test/forget.test.ts`: `forget` con una ronda en curso.
- `packages/sync/test/expiration.test.ts`: la reconstrucción del historial deja fuera lo caducado (por el wrap, por el
  seal y en canales) con el relay de pruebas, que lo sigue sirviendo; la caché olvida los wraps borrados y saca del
  disco lo caducado (`forget`, `prune`); controles negativos.
- `services/continuity-vault/test/expiration.test.ts`: push, restauración y cola de borrados contra el vault de pruebas,
  y que la cola no crece con los mensajes que nunca llegaron al vault.
- `apps/web-saas/test/expiration.test.ts`:
  - ajustes cifrados;
  - purga del almacén, el outbox y el vault;
  - el aviso antes de confirmar y el borrado aplicado por el contacto;
  - un borrado ajeno se rechaza.
- `apps/sovereign-client/test/expiration.test.ts`: API del CLI y procesos reales (`persona expiration`,
  `dm expiration`, `dm send --expire`, `dm delete` con y sin `--yes`), y la caché de eventos: el wrap borrado sale y
  no vuelve con `history sync`, y `dm inbox --offline` no muestra lo borrado ni lo caducado.
