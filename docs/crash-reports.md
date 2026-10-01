# Informes de fallo (NFR007-03)

Requisito §18 y FR-028. Cuando la app falla, puede preparar un informe del fallo **limpio** que sirva para
arreglarlo. Ningún modo lo envía ni hace una petición de red: lo que sale del dispositivo lo saca la persona a mano,
como un archivo que guarda y comparte ella. El control es `crashReports` de cada persona (panel de soberanía en la
web, `sovereign persona crash-reports` en el CLI).

Implementación: el núcleo, compartido por la web y el CLI, está en `packages/telemetry-policy/src/crash-report.ts`
(sin dependencias y sin módulos de Node, importable desde el navegador como `@sedecim/telemetry-policy/crash-report`);
la web, en `apps/web-saas/src/lib/crash.ts` y `apps/web-saas/src/views/CrashReports.tsx`; el CLI, en
`apps/sovereign-client/src/crash.ts`. Pruebas al final.

## Qué hace cada modo

| Modo | Web | CLI | Qué queda en el dispositivo |
|---|---|---|---|
| `off` | No hay ningún listener de errores. Si una vista falla, se detiene sola y lo dice, pero no se lee ni se recuerda nada del fallo. | Solo la línea de error en stderr (ver «CLI»). | Nada. |
| `manual-export` | El informe limpio del **último** fallo se queda en la memoria de la pestaña hasta que se cierra, se bloquea el almacén o se cambia de persona. En el panel se ve entero y se puede guardar en un archivo. | Si el comando falla y se ejecutó con `--crash-report ARCHIVO`, el informe se escribe en ese archivo; sin la opción, solo se dice cómo obtenerlo. | Nada. |
| `opt-in` | Lo mismo, y además cada informe se guarda cifrado en el almacén local del navegador. | Lo mismo, y además cada informe se guarda cifrado en el almacén de la persona. | Como mucho 20 informes, cada uno 30 días desde la última vez que se produjo, hasta que se borran. |

Sin persona activa (el almacén de la web bloqueado, o un comando del CLI sin `--persona` o con una persona que no se
puede leer) no hay informe: es `off`. En la web, como mucho se capturan diez fallos por minuto, para que un fallo en
bucle no llene el almacén; el mismo fallo repetido cuenta una vez más en lugar de ocupar otro sitio.

## Por perfil

| Perfil | Apéndice B | Aquí |
|---|---|---|
| convenience | `opt-in` | `manual-export` |
| private-resilient | `off` | `off` |
| institutional | `opt-in` | `manual-export` |
| sovereign | `manual-export` | `manual-export` |
| sovereign-tor | `off` | `off` |

En este diseño `opt-in` significa **guardar informes en el dispositivo**, y eso solo lo decide la persona: ningún
perfil de referencia lo enciende, y los que en el Apéndice B traían `opt-in` traen `manual-export`, que no guarda
nada. Una persona que ya existía conserva su configuración guardada (desde PANEL-05, `off`); las nuevas reciben estos
valores. En el CLI, el modo de cada persona es el que se guardó al crearla o con `persona crash-reports`.

### Sovereign-tor: `manual-export` sí, `opt-in` no

El [threat model del perfil](threat-models/sovereign-tor.md) protege el anonimato de red, la no vinculación entre
identidades, el contenido y las fuentes, frente a la red, al operador del relay, a quien correlaciona identidades y a
quien compromete el dispositivo más tarde. `manual-export` no cambia nada frente a ninguno: no hay red, y en el CLI
(el único cliente de este perfil) solo existe un archivo si la persona lo pide con `--crash-report` en ese comando.
El informe no lleva hosts, `.onion`, IPs, llaves ni rutas; si la persona lo comparte, dice la versión, el perfil
`sovereign-tor`, el sistema y la versión mayor de Node, y el error limpio, y lo ve antes de compartirlo.

`opt-in` dejaría en el dispositivo un registro de fallos con su fecha: un rastro de cuándo se usó la persona para
quien abra el almacén más tarde, en un perfil que busca dejar el mínimo. Por eso `validateConfig` lo rechaza en
Tor-only (`TOR_CRASH_REPORTS`, bloqueante), `sovereign persona crash-reports … opt-in` falla en una persona Tor, y
el CLI trata como `off` un `opt-in` guardado en una persona Tor por cualquier otra vía. El perfil sigue en `off`.

## Qué lleva un informe

Una lista cerrada de campos, como los spans de las trazas ([NFR007-02](slo.md#trazas-nfr007-02)): cada campo se
construye a partir de un valor que pasa su regla; nada del error se copia tal cual. Ejemplo (de un CLI):

```json
{
  "format": "acceso-nostr-crash-report",
  "version": 1,
  "app": { "name": "sovereign-cli", "version": "0.1.0" },
  "profile": "sovereign",
  "environment": { "os": "linux", "runtime": "node", "runtimeMajor": 22 },
  "source": "fatal",
  "error": {
    "name": "Error",
    "message": "ENOENT: no such file or directory, open '[ruta]'",
    "stack": ["at Object.openSync (node:fs:573:18)", "at readGroupFile (sovereign-client/cli.ts:174:14)"]
  }
}
```

| Campo | Regla |
|---|---|
| `app` | `acceso-nostr-web` o `sovereign-cli`, y la versión `x.y.z` del `package.json` de esa app. |
| `profile` | El preset de la persona activa (`convenience` … `sovereign-tor`) o `custom`; nunca la persona. |
| `environment` | Familia del sistema (`linux`, `macos`, `windows`, `android`, `ios`, `chromeos`, `other`) y del navegador o Node (`chrome`, `edge`, `firefox`, `safari`, `node`, `other`) con su versión mayor. El user agent se lee para eso y no se guarda: ni modelo de dispositivo ni versiones menores. |
| `source` | `error` (error global), `unhandledrejection`, `component` (una vista de React) o `fatal` (CLI). |
| `error.name` | La clase (`TypeError`, `DOMException`): palabras con mayúscula inicial y sin dígitos, la misma regla que `error.type` en las trazas. Otra cosa es `_OTHER`. |
| `error.message` | El mensaje después de la limpieza (abajo), en una línea de 300 caracteres como mucho. |
| `error.stack` | Hasta 30 frames (10 en las causas) con la forma `at función (archivo:línea:columna)`. |
| `error.cause`, `error.errors` | La causa y los errores de un `AggregateError`, con las mismas reglas: hasta 4 niveles, 8 errores y 12 nodos en total. |
| `componentStack` | Los componentes por los que pasó un fallo de la web, como frames. |

Un valor lanzado que no es un error (un texto, un objeto sin mensaje) se registra solo por su tipo: `_NonError` con
mensaje `[string]`, `[object]`… No hay campo para la hora, la persona, el grupo ni ninguna pubkey, ni siquiera con
hash. El almacén guarda junto a cada informe la hora de la última vez que se produjo y cuántas veces, para la
retención; eso no se exporta.

## Limpieza

Reutiliza la maquinaria de NFR007-02: las reglas de forma de valor y de nombre de clase (`packages/telemetry-policy/src/rules.ts`,
movidas allí desde el trazador para usarlas también en el navegador) y `redactString`.

**Mensaje** (`cleanCrashText`), por orden, cada forma por un marcador:

1. nsec, ncryptsec, el secreto de una URL `bunker://` y la cabecera `Authorization` (`redactString`);
2. el comienzo de un texto que `JSON.parse` no pudo leer, que V8 y Safari citan: puede ser el texto de un mensaje;
3. JWT → `[token]`; URLs → solo el esquema (`wss://[url]`); `data:` → `data:[url]`; direcciones `.onion` → `[onion]`;
   correos → `[email]`; entidades NIP-19 (npub, nsec, nprofile, nevent, naddr, note, nrelay, ncryptsec) → `[npub]`,
   `[nevent]`…; UUID → `[uuid]`;
4. rutas absolutas (Linux, macOS, Windows, UNC y `~/`) → `[ruta]`, entera: el nombre de usuario va en ellas y el resto
   puede decir qué guarda la persona;
5. IPv4 e IPv6 (con su puerto) → `[ip]`;
6. pares `token=`, `password:`, `secret=`, `sig=`… y cabeceras `Cookie` → el valor por `[…]`;
7. hex: 16 caracteres o más → `[hex]` (llaves, pubkeys, ids de evento, de persona y de grupo, firmas), y de 8 a 15
   si mezcla dígitos y letras (el comienzo de una pubkey); secuencias de 20 o más letras y dígitos → `[token]`;
8. nombres de host fuera de una URL → `[host]`: los que terminan en un dominio conocido (una lista de genéricos y
   todos los de país de dos letras), llevan un guion o un puerto, o siguen a un error de red (`ENOTFOUND`,
   `ECONNREFUSED`…). `this.store.get` o `index.js` no son hosts;
9. números de 6 cifras o más → `[n]` (horas, teléfonos, ids);
10. el texto entre comillas (`"…"`, `'…'`, `` `…` ``, `«…»`, `“…”`) → `[texto]`, salvo un marcador o el nombre de una
    propiedad donde los motores de JavaScript lo citan (`(reading 'foo')`, `property "foo"`). Si una pareja no se
    conserva, se sustituye todo desde ella hasta la última comilla, para que una comilla dentro del contenido no deje
    parte fuera, y una comilla sin cerrar se lleva el resto del mensaje.

La limpieza se repite hasta que no cambia nada (recortar el texto puede dejar un valor que solo reconoce otra
pasada), así que es idempotente. Un informe leído del almacén pasa otra vez por la lista de campos y por estas reglas
(`parseCrashReport`) antes de mostrarse o exportarse.

**Pila** (`cleanStack`): solo se quedan las líneas que son frames de V8, SpiderMonkey o JavaScriptCore; la cabecera
(`TypeError: mensaje`) nunca, y un frame de V8 tiene que ir sangrado, así que una línea del mensaje que empiece por
«at» no pasa por frame. El archivo se recorta a `paquete/archivo` cuando la ruta pasa por `node_modules` o por
`packages/`, `apps/` o `services/` del monorepo (`sovereign-client/cli.ts`, `@noble/hashes/scrypt.js`), y al nombre
del archivo en otro caso (el bundle de la web, `index-B5t3Xk2a.js`): fuera el host, los directorios (y el usuario en
ellos), la consulta y el fragmento. Un nombre de función con forma de valor (8 hex o 4 dígitos seguidos, una entidad
NIP-19), o de archivo o de paquete con 16 hex seguidos o una entidad NIP-19, no se guarda: el frame se queda sin él o
desaparece.

**Lo que no se puede reconocer.** Palabras normales fuera de comillas no se distinguen de las del programa: un error
construido con el texto de un mensaje sin comillas lo conservaría, y lo mismo un nombre de host interno sin dominio
(`relay`). Por eso la persona ve el informe entero antes de guardarlo, y por eso los informes no salen solos.

## Web

- **Captura.** Mientras el modo de la persona activa no es `off`, la página escucha `error` y `unhandledrejection`
  en `window`; con `off`, bloqueada o sin persona, no hay ningún listener. Cada sección (Personas, Canales…) tiene un
  error boundary de React (`CrashBoundary`): una vista que falla se detiene sola, el resto de la app sigue, y el fallo
  se captura con su `componentStack`. La tarjeta de informes tiene su propio boundary, para que un fallo del panel no la oculte.
- **Panel → «Informes de fallo»** (`#crash-reports`): el texto revisado del modo de la persona; el último fallo de la
  pestaña con «Ver el informe»; la vista previa (`#crash-preview`) muestra exactamente el JSON que tendrá el archivo, y
  solo desde ahí se puede «Guardar en un archivo», con la descarga del propio navegador desde un `Blob` (sin
  petición). Los informes guardados se ven en cualquier modo, con «Ver» y «Borrar» cada uno y «Borrar todos los
  informes guardados», para que se puedan borrar también los de cuando la persona tenía `opt-in`.
- **Dónde se guardan** (`opt-in`): en la colección `crash-reports` del vault del navegador (IndexedDB), sellados con
  su llave maestra como el resto de registros (XChaCha20-Poly1305, con el nombre de cada entrada bajo HMAC).

## CLI

- **Un fallo fatal** (el comando falla, una excepción no capturada o una promesa rechazada sin manejar) imprime una
  sola línea, `error: <mensaje>`, y sale con código 1: nunca la pila, la causa ni los campos del error. El mensaje
  pasa por `redactFreeText`: nsec, ncryptsec, el secreto de un bunker, `Authorization`, usuario y contraseña de una
  URL y su consulta, claves de 64 hex o más, JWT y tokens, pares `token=`, cookies y el nombre de usuario de un
  directorio personal (el propio, `~`). Las IPs se enmascaran como en el resto del CLI (`ip-<8 hex>`); los hosts, los
  `.onion` y las demás rutas se quedan, porque en la terminal de la persona dicen qué falló.
- **`--crash-report ARCHIVO`** en cualquier comando con `--persona`: si falla y el modo de la persona lo permite
  (`manual-export` u `opt-in`), escribe ahí el informe limpio (permisos `0600`, sin sobrescribir un archivo que ya
  exista). Con `off` dice que no hay informe y no escribe nada.
- **`sovereign persona crash-reports --persona ID off|manual-export|opt-in`**: cambia el modo, muestra su texto y, si
  quedan informes guardados de antes, cuántos y cómo borrarlos. En Tor-only rechaza `opt-in`.
- **`sovereign crash-report list|show|export|clear --persona ID [--id ID] [--out FILE]`**: los informes guardados en
  el almacén de la persona (colección `crash-reports`, sellada con la passphrase): listarlos, ver uno (el último sin
  `--id`), exportarlo a un archivo (`0600`) y borrar uno o todos.

## Retención y borrado

Como mucho 20 informes, y cada uno como mucho 30 días desde la última vez que se produjo (`CRASH_RETENTION`). Se
aplica cada vez que se lee o se escribe el almacén (al abrir el panel, al guardar un informe, en cada comando
`crash-report`): lo que pasa de cualquiera de los dos límites se borra del almacén, igual que un registro que no es
un informe o que está fechado en el futuro. Borrar quita la entrada del almacén (en la web, del IndexedDB; en el CLI,
el archivo, con `fsync` del directorio). El sistema de archivos o el motor de IndexedDB pueden conservar esos bytes,
cifrados con la llave del almacén, hasta que los reutilicen.

## Qué ve cada parte

- **El operador, los relays y cualquier servidor:** nada; no hay ninguna petición.
- **Quien tenga el dispositivo con el almacén abierto:** los informes guardados (`opt-in`) y cuándo se produjo cada
  uno.
- **Quien reciba un archivo exportado:** lo que la persona vio en la vista previa o en el archivo.

## Riesgo residual

- Texto que la limpieza no reconoce por su forma (palabras sin comillas, un host sin dominio): la persona lo ve antes
  de compartir el informe.
- En `opt-in`, las fechas de los fallos en el almacén, para quien lo abra.
- En el CLI, la línea de error en la terminal conserva hosts, `.onion` y rutas fuera del directorio personal; si la
  salida del CLI se recoge en un log (por ejemplo, el del servicio de Compose), esos datos también.

## Pruebas

- `packages/telemetry-policy/test/crash-report.test.ts`: valores canario (pubkeys, npub, nsec, ncryptsec, nprofile,
  nevent, URL con usuario, contraseña y token, host, `.onion`, IPv4 e IPv6, ruta `/home/<usuario>/…`, el texto de un
  mensaje, ids de persona y de grupo, bearer, JWT, correo y la etiqueta de una persona) sembrados en el mensaje, la
  pila, causas anidadas, un `AggregateError`, campos del error y el `componentStack`: ninguno llega al JSON exportado.
  El control negativo comprueba que la misma búsqueda los encuentra todos en el error serializado tal cual. Además:
  propiedades (fuzz) de lista blanca, límites y gramática para cualquier valor lanzado, de idempotencia, y de que un
  canario entre separadores nunca sobrevive; valores hostiles (proxies, getters que lanzan, ciclos, cadenas enormes);
  lo que captura cada modo (`off` ni siquiera lee el valor); el límite por minuto; la retención por número y por edad
  con borrado del almacén; la relectura de un registro manipulado; y que el código no usa ninguna primitiva de red ni
  la llama al capturar, guardar o exportar.
- `apps/web-saas/test/crash.test.ts`: sin listeners en `off`, la captura de `error`, `unhandledrejection` y de una
  vista, que bloquear quita los listeners y olvida; nada en el vault con `manual-export`, el informe sellado en el
  vault con `opt-in` y su borrado; el archivo descargado es exactamente el JSON de la vista previa, sin peticiones.
- `apps/sovereign-client/test/crash-reports.test.ts` (procesos reales del CLI): una sola línea en stderr sin pila ni
  secretos; `--crash-report` con `manual-export` y nada guardado; `opt-in` sellado en el almacén de la persona, con
  `list`, `show`, `export` y `clear` y borrado real de los archivos; Tor-only sin informes por defecto, rechazo de
  `opt-in` y `manual-export` permitido.
- `packages/profiles/test/profiles.test.ts`: los modos por perfil, la validación en Tor-only y que cada texto del
  catálogo dice lo que hace el código (sin envío, la retención de `CRASH_RETENTION`).
