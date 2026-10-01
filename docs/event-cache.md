# Caché local de eventos (FR013-05)

Copia cifrada, en el dispositivo, de los eventos Nostr de una persona (spec §7 y §12). Sirve para tres cosas:

- leer sin conexión;
- reanudar la sincronización por `since` desde el último punto completo de cada relay;
- que NIP-77 (Negentropy) parta de lo que ya hay y solo descargue lo que falta.

La usa el cliente soberano (CLI). La web todavía no.

Código: `packages/sync/src/cache.ts` (`EventCache`), `packages/sync/src/resume.ts` (`syncWithCache`),
`packages/sync/src/eose.ts`. Integración: `apps/sovereign-client/src/app.ts`. Pruebas:
`packages/sync/test/cache.test.ts`, `packages/sync/test/resume.test.ts`,
`packages/sync/test/negentropy-protocol.test.ts`, `apps/sovereign-client/test/event-cache.test.ts` y
`packages/encrypted-store/test/store.test.ts`.

## Qué guarda

Eventos firmados tal como los sirven los relays (NIP-01, verificables por cualquier cliente):

- **Canales NIP-29:** mensajes, reacciones y borrados (kinds 9, 7, 5 y 9005 con `h`).
- **Actividad propia:** entradas y salidas de canales, lista de grupos (kind 10009), etc.
- **Gift wraps (kind 1059) dirigidos a la persona:** siguen cifrados con NIP-44, igual que en el relay.

**No guarda:** DMs abiertos (el rumor), mensajes de grupos Marmot (esos van en `group-history`, VAULT-03) ni
eventos efímeros.

**Por qué el gift wrap y no el mensaje abierto:**
1. NIP-77 reconcilia los ids que tienen los relays: el id de un DM abierto no está en ningún relay.
2. En el disco, el wrap sigue cifrado para la llave de la persona. Si esa llave está en un signer NIP-46, un DM
   de la caché no se lee ni con la passphrase.
3. La caché no añade texto en claro que los relays no tengan ya: los canales NIP-29 ya los leen el relay y los
   miembros.

`dm inbox --offline` abre los wraps con la llave del dispositivo cada vez que se ejecuta.

## Formato en disco

Dos colecciones del almacén cifrado de la persona (el mismo mecanismo que su outbox y su llave):

- **`evcache`:** los eventos, cada uno con los relays que lo sirvieron, repartidos en 64 cubos por el primer byte
  del id.
- **`evcache-meta`:** la lista de relays, los cursores, el suelo de expulsión y los registros de borrado.

Cifrado: XChaCha20-Poly1305 con la llave que sale de la passphrase (scrypt). Los nombres de entrada son HMAC.
En el CLI viven en el directorio de la persona (`personas/<id>`): un archivo por entrada, con escritura atómica.
Los índices por kind, autor y created_at se construyen en memoria al abrir la caché; no se escriben.

**Una copia del disco sin la passphrase** muestra como mucho 65 archivos de tamaño variable y sus fechas de
modificación, es decir, el volumen aproximado de la caché y cuándo cambió. Mientras un proceso del CLI la escribe,
también `evcache.lock`, con el pid de ese proceso. No muestra ids, autores, canales, relays ni cuántos eventos hay.

**Con la passphrase** se lee todo lo guardado:
- los mensajes de canal;
- los metadatos de los gift wraps (destinataria: la persona; created_at aleatorio; tamaño);
- qué relay sirvió cada evento;
- los cursores: cuándo se sincronizó por última vez cada filtro, con los ids de canal.

Con custodia local, la passphrase abre también la llave, y con ella los DMs.

Una llave equivocada no lee nada: la caché no se abre y no se toca ningún archivo.

## Tope y expulsión

- Por defecto, 5000 eventos y 16 MiB (JSON serializado). Se puede fijar además una antigüedad máxima por
  created_at. En el CLI: `SOVEREIGN_CACHE_MAX_EVENTS`, `SOVEREIGN_CACHE_MAX_DAYS` y `SOVEREIGN_CACHE=off` (no
  guarda nada; `history sync` reconstruye como antes).
- Al pasar un tope sale el evento más antiguo (created_at, luego id), y sube el **suelo**: lo anterior puede
  faltar. Una sincronización reanudada no pide nada por debajo del suelo, porque lo volvería a expulsar.
- Un tope más bajo se aplica la próxima vez que se abre la caché.
- `history export` pide todo a los relays: una exportación no depende de lo que conserve la caché.

## Reglas que aplica

- **NIP-40.** No guarda ni devuelve eventos con `expiration` vencida. Los que vencen después se quitan: una lectura
  ya no los devuelve, y salen del disco con la siguiente escritura (`history sync`, o `channel read` y `dm inbox` con
  conexión). PANEL-06: si el proceso ya tiene la caché abierta para escribir, la purga de lo caducado la limpia
  también en disco (`EventCache.prune`).
- **NIP-09.** Un kind 5 borra los eventos de su mismo autor que nombra con `e`, también los que lleguen después:
  el registro dura mientras el kind 5 siga en la caché. No aplica las coordenadas `a`.
- **NIP-29.** Un 9005 borra los eventos de su mismo canal (`h`) que nombra. La caché sigue al relay del grupo,
  que es quien decide quién puede borrar: Buzz solo acepta el 9005 del autor o de un admin del canal. Un relay
  que no aplique NIP-29 podría hacer que la caché oculte mensajes que ese relay sigue sirviendo.
- **Reemplazables y direccionables:** guarda solo la versión más nueva.
- **Borrado de mensajes directos (PANEL-06).** La petición de borrado de un DM va dentro de un gift wrap, y la caché
  no la puede leer. Cuando el cliente aplica una (la suya o la de un contacto, al leer los DMs), la caché olvida los
  wraps de ese mensaje: los borra y los rechaza si un relay los vuelve a servir. Ese registro dura hasta
  `cache clear`. Si otro proceso escribe la caché en ese momento, lo hace la siguiente `history sync`; mientras
  tanto, `dm inbox --offline` tampoco lo muestra. Ver [`message-expiration.md`](message-expiration.md).
- Límite: si un relay conserva eventos expirados o borrados, NIP-77 los vuelve a pedir en cada sincronización y
  la caché los rechaza cada vez.

## Reanudación por `since`

- **Cursor por relay y filtro:** el momento en que empezó la última sincronización completa de ese filtro con ese
  relay. El filtro se identifica sin `since`, `until` ni `limit`.
- **Desde dónde pide:** desde el cursor menos 600 s (desfase de relojes y tiempo de llegada al relay). Para los
  gift wraps, `dmInboxFilter` resta además los 2 días de NIP-59. Nunca por debajo del suelo.
- **Cuándo avanza el cursor:** solo cuando una estrategia terminó contra ese relay:
  - NIP-77 reconcilió y cada lote de ids terminó con EOSE;
  - o cada página REQ terminó con EOSE.

  Si ninguna estrategia termina (un timeout, un CLOSED, una conexión caída, una sesión NIP-77 abortada sin un REQ
  que la complete), el cursor queda donde estaba. Lo que llegó antes del corte sí se guarda.
- **Varios relays:** cada uno con su cursor.
- **Reloj adelantado:** un cursor por delante de la hora actual más el solape (escrito con el reloj adelantado) no
  se usa. Esa sincronización pide todo y, si termina, lo reemplaza.
- **Actividad propia:** se sincroniza siempre entera (con NIP-77 solo baja lo que falta), porque de ella salen
  los canales de la persona.
- Límite: un evento que llega al relay más de 10 minutos después de su created_at no entra en la ventana de una
  sincronización reanudada, ni por REQ ni por NIP-77. Pasa, por ejemplo, con un mensaje firmado sin conexión que
  sale horas después. `history sync --full` sí lo trae.

## NIP-77 con el conjunto local

- La estrategia parte de los eventos de la caché que casan con el filtro **y que ese mismo relay sirvió**. La
  caché recuerda qué relay sirvió cada evento, así que un relay no se entera de lo que llegó por otro.
- Lo que el relay tiene y la caché ya guarda (llegado por otro relay) no se descarga otra vez: se anota como
  visto en ese relay.
- Un relay sin NIP-77 pasa a REQ por ventanas desde el cursor.
- Si una estrategia se corta a mitad, pasa la siguiente, y lo ya recibido se queda.

## Conformidad con Negentropy V1

`packages/sync/test/negentropy-protocol.test.ts` compara los mensajes del cliente con el apéndice de NIP-77
(Negentropy Protocol V1). Los compara con un lector escrito desde ese texto, no desde ninguna implementación.
Comprueba:

- el byte de versión `0x61` e ids de 32 bytes;
- los varints (base 128, el dígito más significativo primero, sin ceros a la izquierda);
- los timestamps como desplazamiento desde el anterior, reiniciado en cada mensaje (infinito = 0);
- las cotas con el prefijo de id mínimo;
- los rangos ascendentes, con huellas según el algoritmo de la especificación y Skips contiguos agrupados;
- `NEG-OPEN` con un id nuevo por sesión, y `NEG-CLOSE` al terminar;
- que ante otra versión se detiene y pasa a la siguiente estrategia;
- el límite de tamaño de fotograma.

Los vectores fijos salen de la gramática. Por ejemplo, `6100000200` es un conjunto vacío: versión, cota
infinita, modo IdList y 0 ids.

**Hallazgo.** Con límite de fotograma, un mensaje cortado termina en un rango Fingerprint hasta infinito. Su
huella no es la de todo el rango, como dice el texto, sino la de los elementos que hay después del rango donde se
cortó. El código de las implementaciones de referencia de hoytech/negentropy (C++ y JavaScript) la calcula así
(`fingerprint(upper, storageSize)`), y nostr-tools porta la de JavaScript. El receptor ve una huella distinta y
divide ese rango, así que la diferencia se reconcilia en una ronda posterior. La prueba fija ese comportamiento.

El cliente usa el `frameSizeLimit` por defecto de nostr-tools (60 000 bytes). Un `NEG-MSG`, que va en
hexadecimal, queda por debajo de los 131 072 bytes por fotograma WebSocket que acepta el `strfry.conf` por
defecto.

## Interoperabilidad con strfry: no probada en CI

El relay de pruebas del repositorio responde NIP-77 con su propia implementación
(`packages/test-relay/src/negentropy.ts`). Eso no prueba la interoperabilidad con strfry.

`tests/interop/strfry-negentropy.interop.test.ts` corre contra un strfry real solo si `STRFRY_URL` apunta a uno;
si no, se omite:

```bash
STRFRY_URL=ws://127.0.0.1:7777 npx vitest run tests/interop/strfry-negentropy.interop.test.ts
```

Requisitos:
- strfry con `relay.negentropy.enabled = true` (su valor por defecto), alcanzable desde la máquina de la prueba
  (`bind` distinto de `127.0.0.1` si corre en un contenedor);
- que acepte eventos de la última hora de una llave nueva.

La prueba publica 300 eventos con una etiqueta `t` propia de esa ejecución.

No hay job de CI con strfry. La política del repositorio (docs/building.md) exige fijar cada imagen de terceros
por digest y con su versión en la etiqueta o en un comentario. La imagen que publica el proyecto
(`ghcr.io/hoytech/strfry`) solo tenía la etiqueta `latest` el 30 de septiembre de 2026. Hasta fijar una versión
verificada, la prueba es opt-in.

## Lectura sin conexión (CLI)

- `sovereign channel read --persona ID --group G --offline`
- `sovereign dm inbox --persona ID --offline`

No abren la persona: ninguna conexión (tampoco al proxy de Tor), ninguna consulta NIP-11, ningún reintento del
outbox y ningún acuse. Los DMs se abren con la llave del dispositivo. Si la llave está en un signer NIP-46, la
orden falla, porque solo el signer puede abrirlos, y está en la red. Cualquier otra orden con `--offline` falla
antes de abrir nada: nunca se ignora. PANEL-06: `dm inbox --offline` deja fuera, como con conexión, lo caducado
(también por la fecha del seal) y lo que su autor borró (una petición de borrado guardada en la caché o recordada
por la persona).

Qué llena la caché: `history sync`, y `channel read` y `dm inbox` con conexión. `dm watch` no la llena.

**Un solo proceso escribe a la vez.** Cada proceso tiene la caché en memoria y reescribe enteros los cubos que
cambia, así que solo la escribe el que tiene `evcache.lock` en el directorio de la persona (un archivo con su pid).
Los demás procesos la leen, pero no la escriben:
- `channel read` y `dm inbox` no guardan lo que leen;
- `history sync` reconstruye como con la caché apagada, y lo avisa;
- `cache clear` se niega.

El candado de un proceso que ya no existe (matado, caído) lo toma el siguiente. Un cliente lo suelta al cerrar. El
aviso y el error dicen qué archivo borrar si ningún otro proceso la usa: el pid de otro espacio de procesos (otro
contenedor) puede coincidir con uno vivo de este.

## Borrado

- `sovereign cache clear --persona ID` borra las dos colecciones entrada a entrada, sin descifrarlas, así que
  también se va lo que ya no abre con la llave actual. El resto de la persona sigue igual.
- El CLI no tiene «eliminar persona» ni borrado de emergencia. Borrar el directorio `personas/<id>` elimina la
  persona entera, caché incluida.
- La caché no va en los backups ni en el Continuity Vault.
- Es un borrado lógico: no garantiza que el disco no conserve bloques antiguos.

## Qué ve cada parte

- **Relays:** las mismas consultas que antes, con un `since` que sale del cursor. Ese `since` revela,
  aproximadamente, cuándo sincronizó este dispositivo por última vez (el relay ya ve cuándo se conecta). En NIP-77
  solo recibe ids que ese mismo relay sirvió antes.
- **Nadie fuera del dispositivo:** la caché no sale de él.
- **Quien tenga el disco:** ver «Formato en disco».

## La web

La web no usa todavía la caché: los mensajes de una sesión viven en memoria, y su vault guarda el outbox y las
operaciones de envío. «Olvidar este navegador» borra toda la base IndexedDB.
