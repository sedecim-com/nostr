# Sovereign Tor Mode (spec §14)

```bash
docker compose --profile tor up -d           # Tor SOCKS en 127.0.0.1:9050 + onion services de los relays
docker compose logs tor | grep "onion"         # direcciones ws://<56 chars>.onion (relay y secure relay)
export SOVEREIGN_PASSPHRASE='…'
npm run sovereign -- persona create --label Fuente --relay ws://<onion>.onion --high-risk
npm run sovereign -- channel send --persona <id> --group <h> "texto"
```

**Buzz por `.onion`: una comunidad para el host onion.** Buzz asigna cada conexión a la comunidad de su
cabecera `Host` y rechaza los hosts sin comunidad, así que el `.onion` del relay necesita la suya. Se crea una
vez, con una llave de operador listada en `RELAY_OPERATOR_PUBKEYS` y con `RELAY_OPERATOR_API_ORIGIN` igual a la URL
HTTP del relay que llama el script (p. ej. `http://localhost:3000`), ambos en `.env`:

```bash
BUZZ_OPERATOR_SECRET=<hex|nsec> npx tsx scripts/buzz-provision-community.ts <56 chars>.onion
```

Es otro tenant: sus canales y mensajes no se mezclan con los de la comunidad clearnet (`RELAY_URL`).

**Secure relay por `.onion`: una instancia propia (FR025-11).** nostr-rs-relay solo acepta un AUTH NIP-42 cuyo
tag `relay` tenga el host de su `relay_url`, y un cliente que entra por el onion firma para el onion. Por eso
el onion del secure relay apunta a `secure-relay-onion`, que solo existe en el perfil `tor` y no publica
puertos en el host.
- Arranca con la misma configuración, pero con `relay_url = "ws://<onion>/"`
  (`infra/secure-relay/onion-entrypoint.sh`).
- El contenedor de Tor publica el hostname del onion en el volumen `onion-names`; las llaves siguen en
  `tor-data`.
- Como la comunidad onion de Buzz, tiene sus propios datos: no se mezcla con el secure relay clearnet.
- Sin ese ajuste, los clientes no se autentican por el onion. El relay descarta los gift wraps sin avisar,
  y ni las invitaciones a grupos ni los DM NIP-17 llegan.

Garantías verificadas por tests (`packages/tor-network/test`, `apps/sovereign-client/test`, `scripts/leak-test.sh`):
- Con Tor caído, **no** se abre ninguna conexión: el mensaje queda en outbox con
  "No enviado: red de privacidad no disponible" y se reenvía (mismo event id) en cuanto cualquier comando
  vuelve a abrir la persona, o con `sovereign resume` (FR011-04).
- **Un solo mensaje de fallo (FR021-03).** Cualquier fallo en la capa SOCKS es el mismo fallo retenido,
  "No enviado: red de privacidad no disponible":
  - el proxy caído o que rechaza la conexión;
  - un circuito que no se construye;
  - un `.onion` inalcanzable.

  El mensaje espera en el outbox en lugar de fallar, y el error del proxy (que puede nombrar direcciones) no
  llega al registro.
- Resolución DNS dentro de Tor (`socks5h`): ningún `dns.lookup` local de destinos.
- Cada persona usa credenciales SOCKS distintas → circuitos separados (`IsolateSOCKSAuth`). FR006-06 lo
  comprueba de dos formas:
  - contra un servidor SOCKS que exige usuario y contraseña y registra el usuario de cada CONNECT;
  - en el arnés de fugas, donde cada CONNECT del CLI real debe llevar el id de su persona.
- Solo se permiten los hosts de relay configurados para la persona.
- **`--onion-only` (FR021-03)** en `persona create` o `persona import`:
  - la persona sale por Tor y solo acepta relays `.onion`: crearla con uno clearnet falla;
  - el guard bloquea cualquier destino clearnet, también los relays de DM que publique un destinatario.
- **Sin IPs en los logs (FR021-03).** Lo que el CLI registra sobre la red no lleva IPs: errores, estado de
  entrega por relay (`outbox`) y resultados de `history sync`. Una IP se muestra como `ip-<8 hex>`, estable,
  así que dos relays se siguen distinguiendo. Los nombres de host y los `.onion` se mantienen; el contenido de
  los mensajes y la configuración propia (`persona list`) no se tocan.
- **Antes de cada envío (FR007-05),** el CLI muestra quién envía: identidad, custodia, red y nivel de vínculo
  (también con `sovereign whoami`).
- **Lectura sin conexión (FR013-05).** `channel read --offline` y `dm inbox --offline` leen la caché cifrada de la
  persona sin abrir ninguna conexión, tampoco al proxy SOCKS. La caché está activa por defecto;
  `SOVEREIGN_CACHE=off` no guarda nada y `cache clear` la borra ([event-cache.md](event-cache.md)).
- Telemetría `none`: cero llamadas externas.

## Custodia: llave en el dispositivo o signer NIP-46 (FR004-08)

La especificación (§14) pide para este modo una llave offline o un signer. El CLI declara la custodia de la llave
real, nunca el `offline` del preset, que describiría una llave air-gapped:

| Cómo se crea la persona | Custodia declarada | Dónde está la llave |
|---|---|---|
| `persona create`, `persona import --backup`, `persona import --key-file` | `local` | En este dispositivo, cifrada (NIP-49) dentro del almacén de la persona, que abre `SOVEREIGN_PASSPHRASE` |
| `persona connect` (`bunker://` o `nostrconnect://`) | `external` | En el signer NIP-46; este dispositivo solo guarda una llave de cliente que el signer autorizó |

`whoami`, el aviso antes de cada envío y `disclose` muestran esa custodia. En Tor-only, una llave `local` añade el
aviso `TOR_DEVICE_KEY`: quien comprometa el dispositivo y consiga la passphrase puede firmar como tú.

```bash
# Una llave que ya tienes: nsec o ncryptsec (NIP-49) en un archivo, nunca en la línea de comandos
npm run sovereign -- persona import --key-file llave.txt --npub npub1… --label Fuente --relay ws://<onion>.onion --tor
#   (ncryptsec: su contraseña con --password-file FILE o SOVEREIGN_BACKUP_PASSWORD)
# Un signer NIP-46: la URL bunker:// en un archivo, porque puede llevar el secreto del signer
npm run sovereign -- persona connect --bunker-file bunker.txt --label Fuente --relay ws://<onion>.onion --tor --npub npub1…
# ... o una oferta nostrconnect:// que el CLI imprime para pegarla o escanearla en el signer
npm run sovereign -- persona connect --nostrconnect --signer-relay ws://<onion>.onion --label Fuente --relay ws://<onion>.onion --tor
# Emparejar de nuevo este dispositivo: tras `backup restore` o si el signer lo revocó
npm run sovereign -- persona connect --persona <id> --bunker-file bunker.txt
```

- **La llave importada debe ser la de `--npub`**, o no se crea nada. Una ncryptsec que pide un coste de scrypt
  mayor que 2^20 se rechaza antes de ejecutar scrypt.
- **Permisos mínimos.** Antes de conectar, el CLI lista lo que pide al signer: NIP-44 y firmar solo los kinds que
  firma (`SOVEREIGN_NIP46_PERMISSIONS`: 9, 13, 9021, 10050, 22242, 24242, 27235 y 30443). Un test recorre los caminos
  de firma del CLI (canales, DMs, grupos Marmot con key package, invitaciones y mensajes, media, NIP-42 y NIP-98)
  contra un bunker que solo permite esos kinds, y comprueba la lista en los dos sentidos. Con `--npub`, un signer que
  tenga otra llave se rechaza; al emparejar de nuevo, siempre.
- **El tráfico del signer, por Tor.** Las peticiones NIP-46 (kind 24133) solo van a los relays del signer, por SOCKS
  con las credenciales de la persona, como el resto de su tráfico. Durante `persona connect` la persona aún no
  existe: ese intercambio usa credenciales propias que ninguna persona usa. Con `--onion-only`, los relays del signer
  también tienen que ser `.onion`, y se comprueba antes de conectar. En esos relays, NIP-42 autentica la llave de
  cliente, nunca la de la persona.
- **Falla cerrado.** Sin Tor no se conecta con el signer ni se firma nada: `persona connect` no crea la persona y un
  envío falla con «No enviado: red de privacidad no disponible». Un mensaje de canal queda guardado y, con Tor de
  vuelta, se firma y se publica en el siguiente comando que abra la persona (también `sovereign resume`). Un DM se
  reintenta con `--op`, que el CLI imprime antes de enviar.
- **Qué ve cada parte.** El signer ve lo que firma y los DMs que descifra por la persona (NIP-44). El relay del signer
  ve eventos cifrados entre la llave de cliente y el signer, y cuándo; por Tor, no la IP. Si el signer pide aprobación
  en una página (auth_url), el CLI la muestra sin abrirla: en una persona Tor, ábrela en Tor Browser.
- **El emparejamiento no viaja en el backup.** La llave de cliente y la dirección del signer (nunca el secreto del
  bunker) se guardan cifradas en el almacén de la persona. Una persona restaurada no firma hasta emparejarla otra vez,
  y solo con un signer que tenga su npub.

Tests: `apps/sovereign-client/test/nip46.test.ts` (Tor con un SOCKS que exige credenciales, bunker y
`nostrconnect://`, Tor caído, onion-only, importación, restauración y el CLI real), `packages/signer/test/signer.test.ts`
y `packages/profiles/test/profiles.test.ts`.

## Tests de fugas con captura de red real (FR020-03, FR020-05, FR022-02)

```bash
npm ci && sudo apt-get install -y tcpdump     # Linux, root (el script se relanza con sudo)
npm run test:leak                             # = bash scripts/leak-test.sh; resultados en ./leak-results
```

Qué hace `scripts/leak-test.sh` (job `leak-tests` en CI):
1. Crea un network namespace cuya única interfaz es un veth hacia el host, con ruta por defecto por él
   (el host no reenvía: `FORWARD` descartado para esa interfaz), `resolv.conf` apuntando al host y
   `nsswitch.conf` con `hosts: files dns` (así una resolución de nombres sale al cable y no se cuela por el
   socket de systemd-resolved/avahi del host). IPv6 con dirección ULA y ruta por defecto (en CI es
   obligatorio: `LEAK_REQUIRE_IPV6=1`).
2. Captura con `tcpdump` todo lo que cruza ese veth mientras el **CLI soberano real** trabaja:
   `persona create`, `channel send`, `channel read`, `history sync`, `persona list`.
   **Grupos por Tor** (FR020-05), en una captura aparte. Dos personas Tor, cada una con su propio
   directorio de datos, como dos usuarios, trabajan juntas solo a través del proxy:
   - **MLS:** key package, `group create`, invitación (Welcome), `group accept`, mensaje y `group read`;
   - **media del grupo (MIP-04):** `group send-file` cifra y sube a un Blossom `.onion`; la otra persona
     lo descarga y descifra con `group fetch-file`, y el archivo debe salir idéntico;
   - **DM NIP-17:** `dm send` a los relays de DM de la otra persona y `dm inbox`;
   - **worker de rotaciones:** la organización revoca un dispositivo de la otra persona en un
     policy-engine detrás de su propio `.onion`. `group rotation-worker --once`, con NIP-98, la saca del
     grupo con un commit MLS y marca la rotación como hecha.
3. Analiza el pcap (`tests/leak/pcap.ts`, `tests/leak/analyze.ts`, sin dependencias):
   - **Perfil Tor** (`--tor --high-risk`, relay `.onion`): cero paquetes DNS (UDP/TCP 53, DoT 853, mDNS,
     LLMNR), cero HTTPS a resolvers DoH conocidos, cero paquetes IPv6 (salvo ND/MLD del kernel en el
     enlace), y ningún paquete a otro destino que `IP:puerto` del proxy SOCKS. Además cada CONNECT SOCKS
     nombra por **nombre** (socks5h) un relay de la allowlist de la persona.
   - **Perfil directo** (`sovereign`): todos los destinos están en la allowlist de la persona (sus relays,
     leída de `persona list`, es decir, de la configuración que guardó el CLI) y el proxy no se usa.
   - Se exige tráfico real (≥ 10 paquetes salientes, `REPLICATED` y el mensaje leído de vuelta): una
     captura vacía no pasa.
   - **Grupos por Tor:**
     - la misma política Tor, con cada CONNECT juzgado contra la persona que nombra su usuario SOCKS
       (`--all-personas`);
     - los destinos permitidos son sus relays y los `.onion` del Blossom y del policy-engine
       (`--socks-allow`), lo mismo que el CLI añade a su allowlist para esos comandos;
     - se exige que cada paso haya hecho su trabajo (mensaje leído, archivo idéntico, DM recibido,
       `removed`) y que el log SOCKS tenga CONNECT a los tres `.onion` y de las dos personas.
4. **Controles negativos** (el test puede fallar): comandos deliberadamente filtrantes que el análisis
   debe detectar: resolución por getaddrinfo y por c-ares, conexión a un resolver DoH, TCP directo al relay
   saltándose el proxy, un destino fuera de la allowlist del perfil directo, TCP por IPv6, y el tráfico
   real del perfil directo juzgado con la política Tor.

Elección del lado "Tor": un stub SOCKS5 local (`tests/leak/stub.ts`, sobre `TestSocksServer`) que mapea
nombres `.onion` fijos al relay en memoria, a un servidor Blossom y a un policy-engine. Es determinista y
no depende del arranque de Tor. El policy-engine se prepara desde el host con un endpoint de control
(`127.0.0.1`, fuera del namespace y de la captura): hace admin a una persona y revoca un dispositivo. La propiedad
probada, "el cliente no emite nada salvo hacia el proxy", no depende de lo que haya detrás del proxy; la
conexión real a Tor se prueba aparte (abajo). Las capturas y veredictos quedan como artefacto de CI.

Hallazgo: la primera ejecución detectó una fuga real. `history sync` consultaba el NIP-11 del relay
(soporte NIP-77) con el `fetch` global: resolvía el `.onion` con el DNS local y, con un relay clearnet,
habría conectado directo. Ahora usa `NetworkGuard.fetchApi()` (Tor/allowlist), con test unitario.

Tests unitarios del arnés (se ejecutan en `npm test`, sin root): `tests/leak/leak.test.ts`, con capturas
reales de tcpdump en `tests/leak/fixtures/` y paquetes sintéticos (IPv6, DoH, mDNS...).

El mismo job ejecuta después el **control negativo de ts-mls rc.10** (`scripts/mls-negative-control.sh`,
FR020-05). Instala la versión vulnerable, exige que la autoprueba MLS falle cerrada y restaura la instalada
(docs/marmot.md).

## Perfil `tor` del compose de punta a punta (FR021-02)

```bash
bash scripts/tor-profile-check.sh                    # levanta relay, secure-relay, secure-relay-onion y tor (--build)
TOR_CHECK_SKIP_UP=1 bash scripts/tor-profile-check.sh   # con el stack ya arriba
```

Espera los hostnames de los onion services en el volumen `tor-data` (`relay/hostname`,
`secure-relay/hostname`), `Bootstrapped 100%` y que cada `.onion` responda NIP-11 por el puerto SOCKS del
compose (hasta `TOR_CHECK_TIMEOUT`, 420 s por etapa). Después, con el CLI en perfil Tor:
- En el `.onion` del secure-relay, publica y relee un mensaje de canal y envía un DM NIP-17 que el
  destinatario relee.
- En el `.onion` del relay (Buzz), envía un DM NIP-17 entre dos personas Tor, que el destinatario relee.

Ambos DM exigen NIP-42 a través del onion service. Antes crea la comunidad del
host onion con una llave de operador desechable (o `BUZZ_OPERATOR_SECRET`). Si falla, imprime el log
de Tor y dice qué etapa falló. Job `tor-profile` en CI.

Un circuito lento no debe hacerlo fallar (OPS-21):

- Antes de cada DM, el script vuelve a publicar la lista de relays de DM del destinatario (kind 10050)
  mientras siga `QUEUED`. Si no, el DM saldría hacia los relays del emisor.
  - El secure relay tiene que aceptarla.
  - Buzz no acepta el kind 10050 (`restricted: unknown event kind`). El CLI muestra `FAILED` con la respuesta
    del relay, y el gate de interoperabilidad la registra en `interop-report.json` (`dmRelayList`). Ese DM va a
    los relays del emisor, que en esta prueba son el mismo onion.
- Relee el inbox hasta 8 veces, con esperas crecientes. Guarda la salida de cada intento
  (`secure.inbox.log.N`, `buzz.inbox.log.N`) y lo que tardó.
- En Tor, el CLI da 30 s a cada lectura.
- Si el challenge NIP-42 llega después de pedir los gift wraps, el relay-pool se autentica y vuelve a pedirlos.

## Web: WebRTC y previews remotas (SEC-05)

La web elimina los constructores WebRTC (`RTCPeerConnection` y afines) antes de arrancar, en todos los
perfiles: no usa WebRTC y así ningún código de la página puede reunir candidatos ICE. En los perfiles
sensibles del navegador (`private-resilient`, `sovereign`; `tor-only` está bloqueado en la web) los enlaces
no generan previews y las imágenes remotas esperan a un clic. `tests/browser/web-leaks.e2e.ts` lo verifica
interceptando todas las peticiones del contexto, con controles negativos (el clic sí genera la petición;
una página sin la app sí reúne candidatos ICE).

Limitaciones: el navegador estándar no puede garantizar Tor-only (el panel lo bloquea); el lado Tor de los
tests de fugas es un stub; no se ha realizado una auditoría independiente de fugas.
