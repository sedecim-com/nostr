# Grupos high-security: Marmot / MLS (spec §10.3, FR-025)

## Proveedor
`packages/marmot-adapter` expone `GroupCryptoProvider` → `GroupSession` (sesión por identidad y
dispositivo). La implementación por defecto es `MarmotTsProvider`:

| Componente | Versión fijada | Licencia | Nota |
|---|---|---|---|
| `@internet-privacy/marmot-ts` | 0.5.1 | MIT | Implementación TS del proyecto Marmot (MIP-00…04). Upstream: **alpha** |
| `ts-mls` | **2.0.0-rc.16** (override) | MIT | RFC 9420. marmot-ts 0.5.1 pide rc.10, que es vulnerable (ver abajo) |

Kinds: key package `30443` (lee también el legado `443`), Welcome `444` dentro de gift wrap `1059`,
mensajes de grupo `445` (firmante efímero por mensaje, tag `h` = id Nostr del grupo), lista de relays
`10051`. Ciphersuite por defecto `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`.

## Garantías verificadas por tests
`runConformance` (en `packages/marmot-adapter` y `apps/sovereign-client`), contra relay en memoria,
relay autenticado con compuerta `#p` y relay `.onion` vía SOCKS:
- alta de miembros por key package + Welcome, mensajes descifrables por los miembros;
- **expulsión**: el expulsado no descifra mensajes posteriores (secreto post-expulsión);
- **self-update** (`rotate`): avanza la época → post-compromise security; el grupo sigue operativo;
- relays solo ven ciphertext; el estado MLS (claves privadas, árbol) se guarda **cifrado** en el
  `encrypted-store` de la persona (XChaCha20-Poly1305, nombres HMAC) y sobrevive reinicios;
- compartimentación: no se puede invitar a otra identidad high-risk propia.

## Vulnerabilidad encontrada y mitigada (ts-mls ≤ 2.0.0-rc.10)
`ts-mls` rc.10 solo exigía `UpdatePath` en commits con **más de una** propuesta Update/Remove.
Un commit con un único Remove salía sin path, `commit_secret` = 0 y el miembro expulsado podía derivar
la época siguiente y leer mensajes posteriores (viola RFC 9420 §12.4). Corregido upstream en rc.11.
Mitigación en este repo:
1. `overrides` en `package.json` fuerza `ts-mls@2.0.0-rc.16` (la corrección llegó en rc.11) para marmot-ts;
2. **autoprueba de comportamiento** (`assertRemovalSecrecy`) al abrir la primera sesión del proceso:
   crea un grupo en memoria, expulsa a un miembro y comprueba que no descifra. Si falla, el proveedor
   **falla cerrado** (`UnsafeMlsImplementationError`). Verificado: falla con rc.10, pasa con rc.11.

## Multi-dispositivo (FR025-06)
En MLS cada dispositivo es **su propia hoja**: una persona (misma pubkey Nostr, misma credencial `basic`)
con dos dispositivos tiene dos hojas en el árbol. Implementación (`ExtendedGroupSession`, que implementan las
sesiones de `MarmotTsProvider`; `GroupSession` no cambia):
- **Key package por dispositivo**: kind `30443` direccionable con `d` = id del dispositivo
  (`SessionOptions.deviceId`). `findKeyPackages(pubkey)` devuelve el más reciente de cada `d` (el legado
  `443` solo si no hay ninguno direccionable).
- **Invitar a una persona añade todos sus dispositivos** en un único commit (`invitePersona` /
  `inviteMany`; `sovereign group invite` ya lo hace). Se envía **un** Welcome por persona: el mismo Welcome
  lleva los secretos de todas sus hojas nuevas y cada dispositivo solo se une si tiene uno de los key
  packages referenciados (los demás lo ignoran).
- **Dispositivo nuevo de un miembro existente**: `missingDeviceKeyPackages` detecta los dispositivos que
  aún no están (por el roster o por la clave de firma de la hoja) y `group add-device` los añade: el admin
  hace commit directamente; un miembro no admin (p. ej. otro dispositivo de la misma persona) envía una
  propuesta Add que el admin compromete. marmot-ts 0.5.1 no admite *external commits* (su política de
  admins rechaza todo commit sin hoja emisora), así que el autoalta pasa por propuesta.
- **Roster de dispositivos**: tras unirse, cada dispositivo anuncia dentro del grupo (mensaje de aplicación
  MLS con kind interno `9443`, nunca publicado en claro) su `d` y una etiqueta opcional, ligados a la clave
  de firma de su hoja; el admin lo reenvía tras cada alta para que los recién llegados lo conozcan. Las
  etiquetas solo las ven los miembros. Una entrada solo la acepta el propio dispositivo o un admin, y solo
  para hojas vivas.
- Los mensajes de un dispositivo los ven los demás dispositivos de la persona (son hojas distintas);
  `GroupMessage` incluye `senderLeaf` y `epoch`. Un miembro no puede hablar en nombre de otra pubkey: el
  rumor se descarta si su `pubkey` no coincide con la credencial de la hoja emisora.
- **Expulsar a una persona elimina todas sus hojas**; `removeDevice` (`group remove-device --leaf N`)
  elimina solo una (dispositivo perdido).

### Hallazgo: ts-mls rc.16 impedía el multi-dispositivo
La política por defecto de ts-mls 2.0.0-rc.16 (`defaultKeyPackageEqualityConfig`) considera "ya en el grupo"
un Add cuya **credencial** ya tiene una hoja, y marmot-ts 0.5.1 no pasa `ClientConfig`, así que se aplica al
crear y al validar commits/propuestas. Con credenciales = pubkey Nostr eso prohíbe el segundo dispositivo que
MIP-00 permite. `allowMultiDeviceCredentials()` (se aplica al importar el adaptador, en las dos copias de
ts-mls) reduce la comparación a la clave de firma, que es lo que exige RFC 9420 (claves de firma y HPKE
únicas, que ts-mls sigue comprobando aparte).

### Backup y restauración: nunca clonar una hoja
El backup v2 (`packages/identity`) incluye el estado MLS, es decir, las claves privadas de la hoja del
dispositivo origen. Usar esa copia en otro dispositivo clonaría la hoja: dos dispositivos con el mismo
secret tree y la misma posición en el árbol rompen el secreto hacia adelante (reutilización de generaciones)
y bifurcan épocas. Por eso:
1. El **id de dispositivo** vive fuera de las colecciones `mls-*` (colección `device` del almacén de la
   persona) y no viaja en el backup; `restoreBackup` crea uno nuevo aleatorio y marca la restauración.
2. El adaptador guarda el dispositivo dueño del estado (`mls-device`). Si al abrir la sesión no coincide (o no
   existe y `clonedState` está activo), todos los grupos quedan **restaurados**: se borran los key packages
   privados copiados (son del `d` del origen) y `send`, `rotate`, `invite`, `commit`… fallan con
   `RestoredGroupStateError`. Leer (`sync`) sí está permitido.
3. `group rejoin` (`rejoin`) hace que el dispositivo entre como **hoja nueva** con un key package propio y
   elimina la hoja clonada: si la persona es admin, la hoja clonada añade la nueva, el dispositivo se une por
   Welcome (sustituyendo la copia local) y la hoja nueva elimina la clonada (un committer no puede eliminarse a
   sí mismo, de ahí los dos commits); si no es admin, la hoja clonada propone Add(hoja nueva) + Remove(sí
   misma), el admin compromete y un segundo `rejoin` (o `group accept`) completa la entrada.
4. El dispositivo origen, si seguía vivo, queda fuera del grupo. Para tener **dos dispositivos a la vez** no
   se restaura un backup completo: se exporta sin MLS (`backup export --no-mls`) y se usa `group add-device`.

## Propuestas de miembros y commit del admin (FR025-09)
- Cualquier miembro propone Add/Remove como mensaje de grupo kind `445` (`proposeAdd`, `proposeRemove`,
  `group propose`); el admin (lista `adminPubkeys` de `NostrGroupData`, MIP-01) las ve con `pendingProposals`
  y las compromete con `commitProposals` (`group commit`, todas las admisibles o `--ref`).
- **Los no admin no pueden hacer commit**: marmot-ts se niega a construirlo y, al recibir, la política MIP-03
  rechaza cualquier commit de un no admin que no sea un self-update (probado forjando uno con ts-mls:
  `rejectedCommits = 1`, la época no avanza).
- Política de admisión (el adaptador filtra `unappliedProposals` antes de cada commit, porque ts-mls incluye
  siempre todas las pendientes): Add y Update de cualquiera; Remove de hojas propias o de no admins; cualquier
  cosa propuesta por un admin. Una propuesta de expulsar a un admin o de cambiar la extensión del grupo
  enviada por un no admin nunca se compromete. En commits "incidentales" (invitar, expulsar) solo entran Add,
  Update y autoexpulsiones; expulsar a otro exige `commitProposals` explícito.
- **Propuestas obsoletas**: las propuestas pertenecen a su época. Si la época avanza sin comprometerlas
  (otro commit, `rotate`), se descartan y `commitProposals` responde que no hay pendientes; el miembro debe
  volver a proponer (probado).

## Media cifrada en grupos: MIP-04 (FR025-05)
Versión `mip04-v2`, la que implementa marmot-ts 0.5.1 (se usan sus primitivas AEAD y el parser de `imeta`):
- `media_secret = MLS-Exporter("marmot", "encrypted-media", 32)` de la **época del mensaje** que lleva el
  adjunto; `file_key = HKDF-Expand-SHA256(media_secret, "mip04-v2"‖0‖sha256(plano)‖0‖mime‖0‖filename‖0‖"key", 32)`;
  ChaCha20-Poly1305 con nonce aleatorio de 12 bytes y AAD `"mip04-v2"‖0‖sha256‖0‖mime‖0‖filename`; al
  descifrar se verifica el tag y el SHA-256 del plano.
- `imeta`: `url m x filename n v size` (+ `dim`, `blurhash`, `alt`). Las etiquetas `mip04-v1` o mal formadas
  se ignoran.
- El receptor necesita el secreto de la época de envío, no el de su época actual: el adaptador guarda el
  `media_secret` de cada época (cifrado en `mls-mediakeys`, retención 128 épocas) y las referencias recibidas
  (`mls-mediarefs`). Un miembro expulsado no tiene el secreto de las épocas posteriores y no descifra la media
  nueva (`MediaKeyUnavailableError`, probado); los miembros restantes siguen descifrando media antigua.
- Cliente soberano (`group send-file` / `group fetch-file`): EXIF saneado antes de cifrar → subida del
  ciphertext a la lista Blossom del usuario (kind `10063`, con espejo) o, sin lista, al blob-store
  (`SOVEREIGN_BLOB_STORE`) → mensaje kind 9 con `imeta`. La descarga prueba la URL compartida y luego los
  servidores de la lista del emisor, verifica el hash del blob antes de descifrar y pasa por la política de
  red de la persona (Tor-only, allowlist ampliada solo con esos servidores).

## Integración con Buzz: no soportado por el relay fijado
El Buzz fijado (`02c6309`) tiene una lista cerrada de kinds y responde
`restricted: unknown event kind` a 30443, 445 y 10051 (`docs/interop/`). Por eso los grupos Marmot
van por el **relay secundario** del stack (`secure-relay`: nostr-rs-relay 0.9.0 fijado por digest,
NIP-42 obligatorio, gift wraps solo al destinatario, también publicado como onion service).
Incluye su URL en los relays de la persona (`--relay ws://localhost:7000`); la política de red de la
persona (Tor-only, allowlist) se aplica también al tráfico MLS.

Ruta decidida en ADR 0006: los grupos MLS viven en el `secure-relay`. Parchear Buzz para aceptar
30443/445/10051 queda descartado (no hay fork, ADR 0002); se reevalúa si upstream acepta esos kinds o
añade un allowlist configurable.

## Interoperabilidad con un relay real
La suite de conformidad pasa contra **nostr-rs-relay 0.9.0** (el `secure-relay` del stack) con NIP-42
obligatorio: [`docs/interop/marmot-nostr-rs-relay-0.9.0-report.json`](interop/marmot-nostr-rs-relay-0.9.0-report.json).
Hallazgos corregidos en el SDK: ese relay no envía `OK` tras un `AUTH` correcto (el pool acepta un AUTH
silencioso tras `authTimeoutMs`) y confirma antes de persistir (la verificación del key package reintenta).
Reproducir: `MARMOT_RELAY_URL=ws://localhost:7000 npm run test:interop`.

## Interoperabilidad con MDK (FR025-04)
Grupo mixto marmot-ts ↔ **MDK** (Marmot Development Kit en Rust, el de whitenoise) verificado con
mensajes en ambos sentidos y con el creador en cada lado:
[`docs/interop/marmot-mdk-0.8.0-report.json`](interop/marmot-mdk-0.8.0-report.json).

- Lado MDK: `interop/mdk-harness` (Rust; `mdk-core` / `mdk-memory-storage` **0.8.0**, la última versión
  publicada en crates.io, y `nostr-sdk` 0.44.1, todo fijado en `Cargo.lock`; toolchain en
  `rust-toolchain.toml`). Es un proceso que el test maneja por stdin/stdout (JSON por línea): publica key
  package, acepta Welcomes (gift wrap 1059 → 444), sincroniza y envía kind 445, crea grupos.
- Test: `tests/interop/marmot-mdk.interop.test.ts`, contra `packages/test-relay` (NIP-42, 1059 solo
  para su destinatario, como el secure-relay) o el relay de `MDK_RELAY_URL`. Se salta si el binario no
  está compilado; en CI (job `marmot-mdk`) falla (`MDK_INTEROP_REQUIRED=1`).

```bash
(cd interop/mdk-harness && cargo build --release --locked)
npx vitest run tests/interop/marmot-mdk.interop.test.ts     # escribe interop-mdk-report.json
MDK_RELAY_URL=ws://localhost:7000 npx vitest run tests/interop/marmot-mdk.interop.test.ts  # secure-relay
```

Coinciden en ambos lados: ciphersuite `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (**0x0001**, el
único que usan los dos), extensión Nostr Group Data `0xf2ee` (MDK lee nombre, admins y relays del grupo
creado por marmot-ts y viceversa), `last_resort`, kinds 30443 / 444 en 1059 / 445 (`h` = id Nostr del
grupo, cifrado MIP-03 con `MLS-Exporter("marmot", "group-event")` + ChaCha20-Poly1305) / 10051. Es normal
que quien entra por Welcome no descifre el commit que lo añadió (época anterior): MDK lo informa como
error de ese evento y sigue.

Incompatibilidades encontradas (marmot-ts 0.5.1 / ts-mls 2.0.0-rc.16 frente a MDK 0.8.0):

| Hallazgo | Estado |
|---|---|
| **`mls_proposals`**: MDK ≥ 0.7 rechaza key packages kind 30443 sin la etiqueta `mls_proposals` = `0x000a` (propuesta SelfRemove, MIP-00): `Missing required tag: mls_proposals`. ts-mls rc.16 no implementa SelfRemove, así que marmot-ts ni anuncia la capacidad ni la etiqueta. **Un cliente MDK no puede añadir a un miembro marmot-ts por su key package actual** (la dirección marmot-ts crea → MDK entra sí funciona). | **Abierta, upstream.** No se arregla aquí: poner la etiqueta sin soportar la propuesta sería anunciar algo falso. El test lo afirma y, para cubrir el resto de la dirección MDK crea → marmot-ts entra (Welcome, mensajes), vuelve a publicar el mismo key package como kind 443 legado, que MDK 0.8.0 aún acepta sin `mls_proposals`. El producto no publica 443 (legado desde el 31-05-2026). |
| **Lifetime**: marmot-ts pone `not_before` = segundo actual, sin margen; OpenMLS exige `not_before < ahora` (estricto). Un Welcome o key package procesado por MDK en el mismo segundo falla con `Lifetime is not acceptable`. | **Mitigada en el adaptador**: `createGroup` y `publishKeyPackage` esperan al segundo siguiente (≤ 1 s). Queda: si el reloj de quien recibe va por detrás del del creador, lo rechaza hasta alcanzarlo (upstream debería retrasar `not_before`, OpenMLS usa 1 h). Además marmot-ts usa 90 días de vida y OpenMLS define 84 días + 1 h como máximo (aún no lo aplica en 0.8.1). |
| **`d` del key package**: MDK exige 64 hex (32 bytes aleatorios, MIP-00). El adaptador usaba el `deviceId` (en el CLI soberano, el id de la persona, visible en relays). | **Corregida**: slot aleatorio de 32 bytes por dispositivo, guardado cifrado con el estado MLS. |

MDK `main` (0.10.x, reescritura sobre `cgka-engine`, sin publicar en crates.io) no se probó: según su
código exige además una prueba de identidad de cuenta en cada hoja (componente `0x8009` / extensión
legada `0xf2f1`), que marmot-ts 0.5.1 no genera; se evaluará cuando se publique.

## Seguimiento de versiones estables (FR025-08)
Hoy no hay versiones estables: ts-mls solo tiene 2.0.0-rc.x (su `latest` es 1.6.4, la major anterior)
y marmot-ts `latest` es 0.5.1 (`next` 0.5.2-next…). El workflow `.github/workflows/marmot-upstream.yml`
(mensual y a mano) ejecuta `scripts/marmot-upstream.sh check`, que consulta el registro de npm por
ts-mls ≥ 2.0.0 estable y `@internet-privacy/marmot-ts` ≥ 1.0.0 (incluye v2). Si aparece alguna, abre
(o comenta) la issue **“Marmot upstream: versiones estables disponibles”** con las versiones y la lista de
comprobación (`sh scripts/marmot-upstream.sh body TS_MLS MARMOT_TS`): subir dependencia y `overrides`,
`npx vitest run packages/marmot-adapter tests/fuzz`, autoprueba `assertRemovalSecrecy`, job `marmot-mdk`
y el gate del secure-relay. No migra solo: la subida es una PR revisada.

```bash
sh scripts/marmot-upstream.sh check     # ts_mls=, marmot_ts=, pinned_*=, available=true|false
```

## Uso (CLI soberano)
```bash
sovereign group keypackage --persona B                 # B publica su key package
sovereign group create --persona A --name "Redacción"
sovereign group invite --persona A --group <gid> --to <npub-B>
sovereign group accept --persona B
sovereign group send   --persona A --group <gid> "texto"
sovereign group read   --persona B --group <gid>
sovereign group remove --persona A --group <gid> --member <npub-B>
sovereign group rotate --persona A --group <gid>

# Multi-dispositivo: segundo dispositivo de B (backup solo de llave) y alta de sus dispositivos
sovereign backup export --persona B --out b.json --no-mls          # en el dispositivo 1
sovereign backup restore b.json && sovereign group device --persona B --label "Portátil"   # dispositivo 2
sovereign group keypackage --persona B                             # en el dispositivo 2 (key package propio, otro `d`)
sovereign group add-device --persona A --group <gid> --member <npub-B>   # admin: commit
sovereign group add-device --persona B --group <gid>               # miembro no admin: propuesta
sovereign group proposals --persona A --group <gid>
sovereign group commit    --persona A --group <gid>                # el admin compromete las propuestas
sovereign group devices   --persona A --group <gid>
sovereign group propose   --persona B --group <gid> --remove <npub-C>
sovereign group remove-device --persona A --group <gid> --leaf 3   # dispositivo perdido

# Tras restaurar un backup completo en un dispositivo nuevo
sovereign group rejoin --persona A                                 # hoja nueva; la clonada se elimina

# MIP-04
sovereign group send-file  --persona A --group <gid> --file foto.jpg "pie de foto"
sovereign group read       --persona B --group <gid>                # muestra [archivo … --sha <x>]
sovereign group fetch-file --persona B --group <gid> --sha <x> --out foto.jpg
```

## Uso (web, FR025-07)
La vista **Grupos seguros** de la web (`apps/web-saas/src/views/GroupsView.tsx`, carga diferida junto con
marmot-ts/ts-mls) usa la misma API pública (`MarmotTsProvider` → `GroupSession`):
- **Relay**: la clave `secureRelays` de `config.json` apunta al `secure-relay` (ADR 0006). Sin ella se usan
  los relays de la persona y la vista avisa de que Buzz rechaza los kinds de Marmot. El tráfico sale por el
  pool de la persona (NIP-42 bajo demanda).
- **Flujo**: publicar key package, crear grupo (nombre, descripción), invitar por npub (busca el key package
  en el relay de grupos; avisa de las npubs sin key package y rechaza invitar a otra persona propia), aceptar
  invitaciones (Welcome en gift wrap), chatear (kind 445, sondeo cada 4 s), expulsar (solo admin) y salir.
  Muestra época, miembros/admins y la insignia «cifrado de extremo a extremo (MLS)».
- **Estado**: el estado MLS va al vault cifrado del navegador (IndexedDB, `EncryptedGroupStorage`) en
  colecciones por persona (`mls-<persona>-groups|keypackages|invites`); el historial descifrado, también
  sellado, en `mlsmsg-<persona>` (las claves de épocas pasadas se borran, así que no se puede volver a
  descifrar tras recargar). Nada en `localStorage`. Las operaciones MLS se serializan por sesión.
- **Perfiles**: una persona Tor-only no abre sesión MLS en el navegador (mismo bloqueo que el resto de vistas).
- **Verificación**: `tests/browser/web-groups.e2e.ts` (en `npm run test:browser`): Alice y Bob en dos
  contextos, invitación, chat en ambos sentidos, recarga con estado restaurado, expulsión (Bob no lee lo
  posterior), comprobación de IndexedDB/localStorage y axe.
- **Límites**: una misma persona abierta en dos pestañas o dispositivos con el mismo vault puede bifurcar el
  estado MLS (no hay bloqueo entre pestañas); la descripción del grupo no se muestra (`GroupHandle` no la
  expone); la recepción es por sondeo, no por suscripción.

## Límites
- marmot-ts es alpha: no apto para producción high-risk sin revisión independiente (spec §20.3).
- Solo los admins de `NostrGroupData` hacen commits (salvo self-update); los miembros proponen.
- Mientras haya propuestas pendientes nadie puede enviar mensajes de aplicación (ts-mls, RFC 9420): el admin
  debe comprometerlas (o un `rotate` las descarta y quedan obsoletas).
- Multi-dispositivo requiere que **todos** los miembros relajen la política de igualdad de ts-mls
  (`allowMultiDeviceCredentials`, ver arriba); clientes Marmot sin ese ajuste rechazan el commit que añade un
  segundo dispositivo de una persona ya presente.
- El roster de dispositivos (kind interno `9443`) es una convención de este repo; otros clientes lo ignoran y
  para ellos los dispositivos aparecen sin etiqueta.
- MIP-04 se implementa como `mip04-v2` (la versión de marmot-ts 0.5.1). La especificación nueva
  (`encrypted-media-v2`: etiquetas y campos `imeta` distintos, `ciphertext_sha256`, `locator`) no es
  compatible byte a byte; migrar cuando marmot-ts la publique. La rama Marmot v2 de marmot-ts no se integra.
- Backups antiguos (sin registro de dueño en el estado MLS) solo se detectan como restaurados porque el
  cliente soberano marca la restauración (`clonedState`); otra integración debe pasar esa pista.
- Con MDK/whitenoise: un cliente MDK no puede invitar a un miembro marmot-ts hasta que marmot-ts/ts-mls
  soporten SelfRemove (`mls_proposals`, ver arriba); al revés sí funciona. El multi-dispositivo y MIP-04 no se
  han probado contra MDK.
