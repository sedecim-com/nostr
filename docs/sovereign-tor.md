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
- Telemetría `none`: cero llamadas externas.

## Tests de fugas con captura de red real (FR020-03, FR022-02)

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
3. Analiza el pcap (`tests/leak/pcap.ts`, `tests/leak/analyze.ts`, sin dependencias):
   - **Perfil Tor** (`--tor --high-risk`, relay `.onion`): cero paquetes DNS (UDP/TCP 53, DoT 853, mDNS,
     LLMNR), cero HTTPS a resolvers DoH conocidos, cero paquetes IPv6 (salvo ND/MLD del kernel en el
     enlace), y ningún paquete a otro destino que `IP:puerto` del proxy SOCKS. Además cada CONNECT SOCKS
     nombra por **nombre** (socks5h) un relay de la allowlist de la persona.
   - **Perfil directo** (`sovereign`): todos los destinos están en la allowlist de la persona (sus relays,
     leída de `persona list`, es decir, de la configuración que guardó el CLI) y el proxy no se usa.
   - Se exige tráfico real (≥ 10 paquetes salientes, `REPLICATED` y el mensaje leído de vuelta): una
     captura vacía no pasa.
4. **Controles negativos** (el test puede fallar): comandos deliberadamente filtrantes que el análisis
   debe detectar: resolución por getaddrinfo y por c-ares, conexión a un resolver DoH, TCP directo al relay
   saltándose el proxy, un destino fuera de la allowlist del perfil directo, TCP por IPv6, y el tráfico
   real del perfil directo juzgado con la política Tor.

Elección del lado "Tor": un stub SOCKS5 local (`tests/leak/stub.ts`, sobre `TestSocksServer`) que mapea un
nombre `.onion` fijo al relay en memoria. Es determinista y no depende del arranque de Tor. La propiedad
probada, "el cliente no emite nada salvo hacia el proxy", no depende de lo que haya detrás del proxy; la
conexión real a Tor se prueba aparte (abajo). Las capturas y veredictos quedan como artefacto de CI.

Hallazgo: la primera ejecución detectó una fuga real. `history sync` consultaba el NIP-11 del relay
(soporte NIP-77) con el `fetch` global: resolvía el `.onion` con el DNS local y, con un relay clearnet,
habría conectado directo. Ahora usa `NetworkGuard.fetchApi()` (Tor/allowlist), con test unitario.

Tests unitarios del arnés (se ejecutan en `npm test`, sin root): `tests/leak/leak.test.ts`, con capturas
reales de tcpdump en `tests/leak/fixtures/` y paquetes sintéticos (IPv6, DoH, mDNS...).

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

- Antes de cada DM, el script vuelve a publicar la lista de relays de DM del destinatario (kind 10050) hasta
  que un relay la acepte. Si no, el DM saldría hacia los relays del emisor.
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
