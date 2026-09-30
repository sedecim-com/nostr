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
- compartimentación: no se puede invitar a otra identidad high-risk propia, e invitar a alguien que otra persona del
  dispositivo ya invitó o a quien ya escribió, o enviar un archivo que ya envió, exige confirmación explícita
  (`--confirm-reuse`; FR006-07, `apps/sovereign-client/test/compartment.test.ts`).

## Vulnerabilidad encontrada y mitigada (ts-mls ≤ 2.0.0-rc.10)
`ts-mls` rc.10 solo exigía `UpdatePath` en commits con **más de una** propuesta Update/Remove.
Un commit con un único Remove salía sin path, `commit_secret` = 0 y el miembro expulsado podía derivar
la época siguiente y leer mensajes posteriores (viola RFC 9420 §12.4). Corregido upstream en rc.11.
Mitigación en este repo:
1. `overrides` en `package.json` fuerza `ts-mls@2.0.0-rc.16` (la corrección llegó en rc.11) para marmot-ts;
2. **autoprueba de comportamiento** (`assertRemovalSecrecy`) al abrir la primera sesión del proceso:
   crea un grupo en memoria, expulsa a un miembro y comprueba que no descifra. Si falla, el proveedor
   **falla cerrado** (`UnsafeMlsImplementationError`). Verificado: falla con rc.10, pasa con rc.11.
3. **Control negativo en CI** (FR020-05, job `leak-tests`): `scripts/mls-negative-control.sh`
   - cambia cada copia instalada de ts-mls por rc.10, con el tarball de npm fijado por su integridad;
   - exige que la autoprueba falle cerrada;
   - restaura las copias y exige que vuelva a pasar.

   Si un cambio desactiva o debilita la autoprueba y deja de detectar rc.10, CI falla. Las copias se
   restauran aunque un paso falle.

## Multi-dispositivo (FR025-06)
En MLS cada dispositivo es **su propia hoja**: una persona (misma pubkey Nostr, misma credencial `basic`)
con dos dispositivos tiene dos hojas en el árbol. Implementación (`ExtendedGroupSession`, que implementan las
sesiones de `MarmotTsProvider`; `GroupSession` no cambia):
- **Key package por dispositivo**: kind `30443` direccionable con `d` = un slot aleatorio de 32 bytes por
  dispositivo, guardado con el estado MLS (no el `SessionOptions.deviceId`, que no debe verse en los relays).
  El relay guarda uno por `d`: el más reciente por `created_at` y, en el mismo segundo, el de id menor
  (NIP-01). Por eso el adaptador firma cada key package de un slot en un segundo posterior al del anterior:
  en el mismo segundo, el relay descartaba el nuevo la mitad de las veces, respondiendo OK.
  `findKeyPackages(pubkey)` devuelve el más reciente de cada `d` (el legado `443` solo si no hay ninguno
  direccionable).
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
  elimina solo una (dispositivo perdido). La revocación institucional (FR-024, abajo) expulsa todas.
- **Las mismas decisiones en el CLI y en la web** (FR025-14): `addDevices` (el admin hace commit, un miembro propone),
  `proposeMemberChange` (alta con todos los dispositivos fuera del grupo, o baja) y `fetchGroupMedia` (buscar,
  descargar por el hash del cifrado y descifrar un adjunto) viven en `src/flows.ts`, y la subida del cifrado en
  `ciphertextUploader` de `packages/blossom-client`. En lo pendiente, una baja de dispositivos lleva `leaves` y no se
  confunde con una expulsión.

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

## Revocación de dispositivos: rotación automática y firmantes (FR-024)
Flujo completo de un dispositivo perdido o robado, probado de punta a punta en
`tests/security/device-loss.test.ts` (SEC-04):

1. **Policy-engine** (fuente de verdad). El admin revoca el dispositivo (`POST /v1/devices/:id/revoke`,
   NIP-98 de admin): las sesiones abiertas quedan inválidas, no se abren nuevas y `evaluate` deniega con
   `device revoked`. Por cada recurso de tipo `group` del que el dueño es miembro se registra una rotación
   `{id, at, resourceId, reason, removedPubkey, status: 'pending'}`.
   - **Convención**: el `id` de un recurso `group` es el **id MLS del grupo** (hex, el que muestra
     `sovereign group list`): `PUT /v1/resources/<groupId>` con `{kind: 'group', members: [...]}`. Sin esa
     convención el worker no sabe qué grupo rotar (falla y reintenta; nunca marca la rotación como hecha).
2. **Worker de rotación** (`packages/rotation-worker`, FR024-02). Lo ejecuta una identidad que es **admin del
   grupo** (MIP-03: solo los admins hacen commit). En modo institucional corre como servicio `rotation-worker`
   (FR024-05, docs/institutional.md «Worker de rotaciones»): entra solo en los grupos que lo invitan y lee el
   policy-engine con su token de servicio, sin ser admin de él. También se puede ejecutar desde el CLI, con un
   token de servicio o como admin del policy-engine (NIP-98):
   ```bash
   SOVEREIGN_POLICY_BEARER=… SOVEREIGN_REVOCATION_TOKEN=… \
   sovereign group rotation-worker --persona ADMIN --policy https://policy.example \
     --managed-signer https://signer.example [--interval 15] [--once]
   ```
   Cada ciclo lee `GET /v1/rotations?status=pending`, sincroniza el grupo y, si la pubkey sigue dentro, hace
   `removeMember` (un Remove por **cada hoja** de esa pubkey en un único commit → época nueva). Solo cuando el
   commit fue aceptado por algún relay y la pubkey ya no está en el roster llama a
   `POST /v1/rotations/:id/done` (bearer `SOVEREIGN_POLICY_BEARER` o NIP-98). Propiedades:
   - **idempotente**: si el miembro ya no está (lo expulsó otro admin, rotación duplicada) se marca hecha sin
     commit; si falla el `done` después del commit, el ciclo siguiente la encuentra expulsada y la marca;
   - **reintentos** con backoff exponencial por rotación (5 s → 10 min); un fallo (relays caídos, grupo que
     esta identidad no tiene, intento de expulsarse a sí misma) **nunca** marca la rotación como hecha;
   - **logs** solo con id de rotación, prefijo del grupo, época y resultado; nunca texto de mensajes. Usa un
     dispositivo (o una persona admin) dedicado: el worker sincroniza los grupos y descarta lo que descifra.
3. **Firmantes** (FR024-03). Con `--managed-signer` el worker también propaga cada revocación de dispositivo
   del policy-engine a `POST /v1/devices/:id/revoke` del managed-signer, autenticado con un token de
   revocación (`MANAGED_SIGNER_REVOCATION_TOKENS`, que no sirve para nada más). Es idempotente y se reintenta
   hasta que todos los destinos lo aceptan.
   - **Sin pérdidas** (FR024-04). El worker lee `GET /v1/revocations?after=<cursor>`: solo las entradas
     `device.revoke` de la auditoría, de la más antigua a la más nueva y por páginas. Así, ningún volumen de
     otras entradas de la auditoría desplaza una revocación fuera de la página, como pasaba al leer las últimas
     100 de `GET /v1/audit`.
     - Una revocación que falla no deja pasar el cursor y se reintenta en cada ciclo. Las siguientes se
       propagan igual.
     - El cursor tampoco pasa una revocación con menos de 60 s según el reloj del policy-engine. El id de
       auditoría se asigna antes del commit, así que un id menor puede aparecer después que uno mayor.
     - El cursor se guarda, por policy-engine, en el almacén cifrado de la persona. Al reiniciar se sigue
       desde ahí. Si el cursor es mayor que la última revocación (otra base, o una reconstruida), empieza de
       cero.
   - **Managed-signer**: los clientes abren **sesiones ligadas al dispositivo** (`POST /v1/device-sessions`
     con su token de Acceso → token `sds_…`, 12 h por defecto; solo se guarda su SHA-256). Al revocar el
     dispositivo sus sesiones se borran, no se abren nuevas y cualquier petición con `x-device-id` de ese
     dispositivo se rechaza; la revocación se comprueba en cada uso (también si llegó mientras se abría la
     sesión). `MANAGED_SIGNER_REQUIRE_DEVICE_SESSION=true` obliga a usar sesiones de dispositivo para toda
     operación con llaves. El log de uso registra qué dispositivo firmó (`device_id`).
   - **Bunker NIP-46** (`Nip46Bunker`): las sesiones de cliente viven en el propio bunker (clave pública
     efímera del cliente → dispositivo). `bindDevice(clientPubkey, deviceId)` liga cada cliente a su
     dispositivo y `revokeDevice(deviceId)` las elimina, bloquea esas claves de cliente (ni con el secreto
     vuelven a conectar) y rota el secreto de conexión. Un bunker delante del vault managed se engancha con
     `ManagedSigner.onDeviceRevoked`; uno independiente debe recibir la misma llamada de su operador.

### Límites de la revocación
- **Revocar no borra**: lo que el dispositivo ya descifró (mensajes, media, estado MLS de épocas anteriores)
  sigue en él. La rotación solo protege lo que se envía **después** del commit del worker.
- **Ventana**: entre la revocación y el commit pasan el intervalo de sondeo (15 s por defecto) y los
  reintentos; si el dispositivo sigue conectado a los relays en ese tiempo, puede leer lo que se envíe.
- **Se expulsan todas las hojas de la pubkey**, también los otros dispositivos legítimos de esa persona
  (la rotación del policy-engine nombra una pubkey, no una hoja). El admin los vuelve a invitar con un key
  package **nuevo** publicado desde cada dispositivo legítimo; no usar `invitePersona`/`group add-device` a
  ciegas, porque puede recoger un key package publicado por el dispositivo robado.
- **Si el dispositivo tenía la llave Nostr** (custodia local), quien lo tiene puede firmar como la persona y
  publicar key packages nuevos: revocar el dispositivo no basta. Hay que revocar el sujeto
  (`POST /v1/subjects/:pubkey/revoke`) y migrar a una identidad nueva. La revocación de dispositivo es
  suficiente cuando la llave no está en él (NIP-46 o managed).
- **Managed-signer**: no verifica que el `device_id` de una sesión esté registrado en el policy-engine (las
  cuentas de Acceso y las pubkeys no están enlazadas allí). Quien tenga las credenciales de Acceso del
  usuario puede abrir una sesión con otro id: el runbook de pérdida incluye cerrar las sesiones de Acceso
  (cierre global en Cognito).
- **Bunker**: las revocaciones y el secreto rotado viven en la memoria del proceso; el operador debe
  persistir el secreto nuevo (`bunker.secret`) si reinicia el bunker.
- La propagación lee la auditoría del policy-engine (`GET /v1/audit`) hasta que este emita eventos propios.

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
- **Rechazar**: no hay un mensaje de rechazo en MLS. El admin rechaza dejando la propuesta fuera de su commit:
  `commitProposals({ refs })` aplica solo las elegidas y descarta el resto, y sin ninguna elegida la web hace un
  `rotate`, un commit sin propuestas que las descarta todas (FR025-14). Un `rotate` de cualquier miembro las descarta
  igual.

## Sin red: mensajes y commits pendientes (FR025-12)
Con Tor caído o sin red, un mensaje o un commit de grupo que ningún relay toma queda pendiente en lugar de fallar.
Se guarda con el estado MLS, sellado igual (`mls-outbox`), y se reenvía en la siguiente sincronización del grupo o
con `retryPending`. `GroupMessage.pending` y `GroupHandle.pending` lo dicen; `pendingOperations` lo lista.

- **Mensajes.** Se guarda el cifrado con su época y se reenvía ese mismo cifrado: no gasta otra generación del
  ratchet ni duplica el mensaje. Si el grupo pasa a otra época antes de que salga, se vuelve a cifrar para la nueva.
  marmot-ts cifra la capa externa del kind 445 con el exporter de la época, así que quien ya está en la nueva no
  podría leer el cifrado anterior. Un mensaje con archivo (MIP-04) no se vuelve a cifrar, porque la clave del archivo
  es la de la época en que se subió: queda rechazado y hay que enviar el archivo otra vez.
- **Commits.** El adaptador construye los commits (invitar, expulsar, rotar, comprometer propuestas) en lugar de
  `commit` y `selfUpdate` de marmot-ts. Así guarda, antes de publicarlos, el evento, el estado al que llevan y sus
  Welcomes. marmot-ts descarta ese estado cuando no llega el OK, aunque un relay lo haya guardado y los miembros lo
  apliquen, y el dispositivo quedaría en otra rama del grupo. La sincronización siguiente decide:
  - si el commit está en un relay y es el primero de su época entre los que los miembros aplicarían (MIP-03: por
    `created_at` y después por id), se aplica, después de leer los mensajes pendientes de la época anterior;
  - si otro commit ganó la época, el nuestro se vuelve a construir sobre el estado nuevo, y se olvida si ya no queda
    nada que hacer (el miembro ya no está, la clave ya se añadió);
  - si no está en ningún relay y nadie más hizo commit en esa época, se vuelve a publicar el mismo.
- **Orden.** Las operaciones de un grupo salen en el orden en que se hicieron y nada adelanta a un commit pendiente.
  Un mensaje escrito después de una expulsión que aún espera sale detrás de ella, así que el expulsado no lo lee.
  Los commits solo se publican justo después de sincronizar.
- **Repeticiones.** Una petición repetida mientras espera no se guarda dos veces, por ejemplo cuando el admin o el
  rotation-worker vuelven a expulsar al mismo miembro.
- **Welcomes.** Salen cuando su commit ya está aplicado (MIP-02). Si no llegan a ningún relay, esperan como
  operación propia.
- **Rechazos definitivos.** Lo que todos los relays rechazan para siempre (`invalid:`, `restricted:`…) no se guarda:
  falla en el momento. Si pasa en un reintento, queda como rechazado, visible y sin más intentos, hasta que se
  descarta (`discardPending`).
- **Dónde se reintenta.**
  - CLI: en cada `group` que sincroniza y al final de cualquier comando de la persona, como los DMs de FR011-04.
    `group pending`, `group retry` y `group discard` lo muestran, lo fuerzan y lo olvidan.
  - Web: en cada sondeo del grupo abierto, al abrir la vista y al volver la conexión (`online`). La vista lista lo
    pendiente y marca los mensajes «pendiente de enviar».
- **Verificación.**
  - `packages/marmot-adapter/test/group-outbox.test.ts`, con MLS real entre tres y cuatro miembros:
    - mensaje sin red y reenvío del mismo cifrado;
    - cambio de época mientras espera;
    - expulsión sin red, con un mensaje posterior que espera detrás;
    - OK perdido aplicado tras reiniciar;
    - carrera entre ese commit y otro;
    - Welcome reenviado;
    - rechazo definitivo.
  - `apps/sovereign-client/test/groups.test.ts`: persona Tor-only con el proxy SOCKS caído; el mensaje y la
    rotación salen al final del siguiente comando.
  - `tests/browser/web-groups.e2e.ts`: el navegador sin red y de vuelta.
- **Límites.**
  - Las propuestas (`proposeAdd`, `proposeRemove`, `leave`, la petición de `rejoin` de un no admin) siguen fallando
    sin red, como en marmot-ts: hay que repetirlas.
  - Si un commit guardado sin OK solo sigue en relays que este dispositivo ya no alcanza, y en los que alcanza otro
    commit ocupa la época, este dispositivo aplica el otro. MIP-03 no ordena más allá de lo que se ve.
  - Los Welcomes de un commit propio se guardan justo después de aplicarlo. Si el proceso muere en ese instante, el
    invitado queda en el árbol sin invitación: hay que expulsarlo e invitarlo otra vez.
  - No va por el `DeliveryEngine`, el outbox de DMs y canales. Un evento de grupo no es fijo, porque se vuelve a
    cifrar al cambiar de época. Tampoco sirve su copia en el Continuity Vault: VAULT-03 guarda los mensajes descifrados.

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
- **Nombre del archivo**: de 1 a 255 bytes UTF-8, sin NUL ni saltos de línea. Los parsers de `imeta` de marmot-ts y
  applesauce leen `filename <valor>` con una expresión regular cuyo `.` se detiene en cualquier fin de línea de
  JavaScript (LF, CR, U+2028 y U+2029). Con U+2028 o U+2029 en el nombre, el emisor lo aceptaba y los receptores
  descartaban el adjunto sin avisar: ahora se rechaza al cifrar (`isValidMediaFilename`, encontrado por
  `tests/fuzz/group-inputs.test.ts`).
- Cliente soberano (`group send-file` / `group fetch-file`): EXIF saneado antes de cifrar; una imagen que no se
  puede sanear (HEIC, TIFF/RAW, un formato de imagen desconocido) se rechaza antes de subir nada → subida del
  ciphertext a la lista Blossom del usuario (kind `10063`, con espejo) o, sin lista, al blob-store
  (`SOVEREIGN_BLOB_STORE`) → mensaje kind 9 con `imeta`. La descarga prueba la URL compartida y luego los
  servidores de la lista del emisor, verifica el hash del blob antes de descifrar y pasa por la política de
  red de la persona (Tor-only, allowlist ampliada solo con esos servidores).

## Integración con Buzz: no soportado por el relay fijado
El Buzz fijado (`infra/buzz/PIN`) tiene una lista cerrada de kinds y responde
`restricted: unknown event kind` a 30443, 445 y 10051 (`docs/interop/`). Por eso los grupos Marmot
van por el **relay secundario** del stack (`secure-relay`: nostr-rs-relay 0.10.0 fijado por digest,
NIP-42, gift wraps solo al destinatario; en el perfil `tor`, una instancia propia detrás del onion service,
ver `docs/sovereign-tor.md`).
- Ese relay descarta sin avisar los gift wraps (y los DM de kind 4 y 44) de una conexión no autenticada:
  no manda CLOSED ni NOTICE.
- Por eso el relay-pool se autentica antes de cualquier suscripción que pida esos kinds, también en modo
  `on-demand` (FR025-11). Así llegan las invitaciones (Welcome dentro del gift wrap) y los DM NIP-17.
- Si el challenge tarda más que esa espera, como pasa por un circuito Tor lento, el REQ sale sin autenticar y el
  relay lo contesta con un EOSE vacío que llega después del challenge. Al recibir un challenge tardío, el
  relay-pool se autentica y repite esas suscripciones con otro id, y descarta lo que el relay conteste al id
  anterior (OPS-21). En Tor, el CLI da además 30 s a cada lectura, en vez de 10 s.
- El E2E de grupos de la web y el del CLI (`tests/interop/sovereign-secure-relay.interop.test.ts`) corren en
  CI contra el nostr-rs-relay real del stack.
Incluye su URL en los relays de la persona (`--relay ws://localhost:7000`); la política de red de la
persona (Tor-only, allowlist) se aplica también al tráfico MLS.

Ruta decidida en ADR 0006: los grupos MLS viven en el `secure-relay`. Parchear Buzz para aceptar
30443/445/10051 queda descartado (no hay fork, ADR 0002); se reevalúa si upstream acepta esos kinds o
añade un allowlist configurable.

## Interoperabilidad con un relay real
La suite de conformidad pasa contra **nostr-rs-relay 0.10.0** (el `secure-relay` del stack) con NIP-42
obligatorio: el job `stack` de CI la corre en cada PR y en main. El informe inicial, con 0.9.0, está en
[`docs/interop/marmot-nostr-rs-relay-0.9.0-report.json`](interop/marmot-nostr-rs-relay-0.9.0-report.json).
Hallazgos corregidos en el SDK: 0.9.0 no envía `OK` tras un `AUTH` correcto (el pool acepta un AUTH
silencioso tras `authTimeoutMs`; 0.10.0 ya lo confirma) y el relay confirma antes de persistir (la
verificación del key package reintenta).
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
sovereign group pending --persona A                    # sin red: lo que espera un relay (FR025-12)
sovereign group retry   --persona A                    # reintentarlo ya (también sale al final de cualquier comando)
sovereign group discard --persona A --op <id>          # olvidar uno rechazado

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
sovereign group rotation-worker --persona A --policy <url>         # rotación automática tras revocar (FR-024)

# Tras restaurar un backup completo en un dispositivo nuevo
sovereign group rejoin --persona A                                 # hoja nueva; la clonada se elimina

# MIP-04
sovereign group send-file  --persona A --group <gid> --file foto.jpg "pie de foto"
sovereign group read       --persona B --group <gid>                # muestra [archivo … --sha <x>]
sovereign group fetch-file --persona B --group <gid> --sha <x> --out foto.jpg
```

## Uso (web, FR025-07 y FR025-14)
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
- **Lo que antes solo hacía el CLI (FR025-14)**, con los flujos compartidos de `src/flows.ts` desde
  `apps/web-saas/src/lib/groups.ts` y los componentes `GroupDevices.tsx`, `GroupProposals.tsx` y `GroupAttachment.tsx`:
  - *Multi-dispositivo*: invitar añade todos los dispositivos de la persona en un commit (`inviteMembers`, como
    `group invite`). La lista «Dispositivos» muestra cada hoja con el nombre que anuncia. Cada navegador es un
    dispositivo propio: su `deviceId` es `web-<id de la persona en ese navegador>` y su slot de key package es
    aleatorio. Su nombre («Nombre de este navegador en los grupos») se guarda en la colección `groupdevice-<persona>`
    del vault, fuera de `mls-*`; los demás lo guardan como lo anunció, en su roster. «Añadir dispositivos»
    (admin, commit) o «Proponer dispositivos» (miembro, propuesta) busca los key packages de dispositivos que faltan
    (`missingDeviceKeyPackages`) y deja marcar cuáles entran; el dispositivo nuevo entra con «Aceptar invitaciones
    pendientes». El admin quita un dispositivo con confirmación (`removeDevice`). El navegador al que le quitan su
    hoja lo ve (`membership`: sin hoja propia aunque su persona siga) y deja de tener composer.
  - *Rotación*: «Rotar mis claves» (`rotate`, como `group rotate`), con una confirmación que dice que descarta las
    propuestas pendientes; sin relay queda pendiente como cualquier commit (FR025-12).
  - *Propuestas*: todos ven las pendientes (`pendingProposals`); el admin confirma las marcadas o rechaza todas (ver
    «Rechazar» arriba); un miembro propone altas y bajas (`proposeMemberChange`, como `group propose`), con el aviso
    de reutilización entre personas (FR006-07) para las altas y la regla de no proponer otra persona propia. Mientras
    haya propuestas la vista no deja escribir, y el admin no puede invitar, expulsar ni cambiar dispositivos, porque
    ese commit aplicaría también las altas propuestas (`incidental`).
  - *Archivos (MIP-04)*: «Adjuntar archivo cifrado» sigue el orden del CLI y de los adjuntos de DM:
    - aviso de reutilización con el hash del archivo tal como se eligió;
    - metadatos fuera (`prepareBlob`; con `stripFileMetadata`, una imagen que no se puede limpiar se rechaza);
    - registro del uso;
    - cifrado con la época actual y subida del cifrado, en espejo como el CLI, a la lista Blossom de la persona
      (sin el servidor de medios de Buzz) y al blob-store del despliegue.
    El historial (`mlsmsg-<persona>`) guarda los adjuntos de cada mensaje, enviado o recibido, y sus tags, que el
    vault archiva y restaura. «Descargar y verificar» pide el cifrado a la URL compartida y, si falla, a los servidores
    de la lista del emisor. Comprueba su hash, lo descifra con el secreto de su época y lo guarda como archivo. La
    descarga va fuera de la cola MLS; buscar el adjunto y descifrarlo, dentro.
  - Lo pendiente distingue «Baja de dispositivo» y tiene «Reintentar ahora» (`group retry`). Los errores del
    adaptador se muestran en español (`groupErrorMessage`).
  - Qué ve cada parte y el riesgo residual: [threat model](threat-model.md#grupos-seguros-en-la-web-dispositivos-rotación-propuestas-y-archivos-fr025-14).
    Los textos de la vista salen de `SECURE_GROUP_TEXTS` (catálogo revisado).
- **Verificación**: `tests/browser/web-groups.e2e.ts` (en `npm run test:browser`): Alice y Bob en dos
  contextos, invitación, chat en ambos sentidos, recarga con estado restaurado, expulsión (Bob no lee lo
  posterior), comprobación de IndexedDB/localStorage y axe. FR025-14, en el mismo E2E: Eva en dos navegadores con la
  misma llave (propuesta del segundo desde el primero, confirmación de Dana, rotación, foto sin metadatos descargada
  con el hash comprobado y baja del segundo navegador). Sin navegador, con el adaptador real y relays y Blossom en
  proceso: `apps/web-saas/test/secure-groups.test.ts`. Por ejemplo, una copia de las claves de un dispositivo
  anterior a su rotación no lee lo que se envía después, y lo pendiente sobrevive a un reinicio de la sesión.
- **Límites**: una misma persona abierta en dos pestañas o dispositivos con el mismo vault puede bifurcar el
  estado MLS (no hay bloqueo entre pestañas); la descripción del grupo no se muestra (`GroupHandle` no la
  expone); la recepción es por sondeo, no por suscripción. Además (FR025-14):
  - un nombre de dispositivo cambiado solo llega a los grupos en los que ya está el navegador cuando se vuelve a
    anunciar (al entrar en un grupo, o como admin al añadir a alguien);
  - la subida de un archivo ocupa la cola MLS mientras dura;
  - la web no propone Updates ni la baja de un solo dispositivo, igual que el CLI.

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
