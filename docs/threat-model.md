# Threat model — v0.1 (versionado por release, spec §20)

## Activos
nsec / material de llave · contenido de mensajes · grafo social y vínculos entre personas · metadatos de
red (IP, horarios) · outbox local · backups · credenciales de servicio (KEK, tokens).

## Adversarios (§20.1) y mitigaciones implementadas

| Adversario | Mitigaciones en código | Riesgo residual |
|---|---|---|
| Relay curioso o comprometido | Gift wrap NIP-59 (remitente oculto, timestamps aleatorios), NIP-44, verificación de firmas en cliente, multi-relay con quorum, suscripciones `#p` acotadas | Ve destinatario (tag `p`), IP sin Tor, tamaños (padding NIP-44 parcial), canales NIP-29 en claro |
| Operador SaaS comprometido | Llaves locales/NIP-46 por defecto; backups NIP-49 con clave del usuario; mirror ciphertext-first y sellado opcional en reposo, ligado al `event_id` de cada fila (SEC-06); indexer nunca descifra | En modo managed puede firmar y ve en claro los DMs NIP-44 que descifra el managed-signer (custodial, declarado); ve metadatos de canales, y las columnas de índice del mirror van en claro |
| Atacante de red / ISP | TLS (wss), Tor-only con socks5h y fail-closed, allowlist de hosts por persona; tests de fugas con captura real (netns + tcpdump) del CLI soberano: cero DNS, cero IPv6 y cero conexiones fuera del proxy SOCKS en perfil Tor, también con dos personas en grupos MLS, media cifrada en un Blossom `.onion`, DMs y el worker de rotaciones contra un policy-engine `.onion` (FR020-05); egress solo a los relays de la persona en perfil directo, con controles negativos (`scripts/leak-test.sh`, FR020-03/FR022-02); perfil `tor` del compose probado de punta a punta contra los .onion de relay y secure-relay (`scripts/tor-profile-check.sh`, FR021-02) | Correlación temporal; fingerprint de tráfico; el lado Tor de los tests de fugas es un stub SOCKS local (la propiedad probada es qué emite el cliente, no la calidad de Tor); la captura cubre el CLI, no la web ni el worker como servicio |
| Fugas desde el navegador (WebRTC, previews) | La web elimina `RTCPeerConnection` y el resto de constructores WebRTC antes de arrancar (sin candidatos ICE en ningún perfil); en perfiles sensibles (`private-resilient`, `sovereign`) enlaces, imágenes remotas y avatares de otros perfiles ([FR006-04](#perfil-público-por-persona-fr006-04)) no generan peticiones hasta un clic explícito; E2E con interceptación de todas las peticiones y controles negativos (`tests/browser/web-leaks.e2e.ts`, SEC-05) | Un iframe same-origin creado por script tendría WebRTC (lo impide `script-src 'self'`); el navegador estándar no garantiza Tor-only |
| Malware en endpoint | Stores cifrados (XChaCha20-Poly1305 + scrypt), wipe de llaves en memoria best-effort | Un endpoint comprometido controla la sesión: fuera de alcance |
| Robo físico del dispositivo | Passphrase + scrypt en stores y NIP-49; revocación de dispositivo (policy-engine) | Passphrase débil |
| Persona de la organización que publica donde la política no la deja | Modo institucional: el relay seguro admite por `h` solo a quien puede publicar en el canal o grupo registrado; en Buzz, la membresía NIP-29 de los canales privados registrados sigue a la política (FR023-10); lecturas del mirror filtradas (FR023-05) | Canales y grupos sin registrar quedan abiertos a todo el allowlist; un cambio de la política llega en la siguiente sincronización; los owners y admins de un canal de Buzz publican aunque la política no los incluya |
| Compromiso de cuenta cloud | El backup cloud solo contiene ciphertext (vault `/v1/backups`: el servidor valida que el sobre sea NIP-49/XChaCha20 y rechaza nsec o hex en claro; la contraseña del backup no sale del cliente); NIP-98 en APIs (sin contraseñas de servidor). El Continuity Vault (ADR 0011) guarda solo sobres sellados en el cliente con la llave de archivo (256 bits, que el servidor no recibe) y rechaza texto plano ([threat model](threat-models/continuity-vault.md)) | Disponibilidad; quien obtenga el login de Acceso vinculado o el volcado de la base puede descargar el ciphertext e intentar fuerza bruta offline (scrypt): depende de la fortaleza de la contraseña del backup. El operador ve npub, tamaño y fechas de las copias; en el vault, la cuenta, cuántos archivos, su tamaño aproximado y cuándo cambian |
| Correlación entre identidades | Personas sin vínculo por defecto, compartimentos con store/relays/circuito Tor separados (IsolateSOCKSAuth), aviso con confirmación explícita antes de usar desde una persona un contacto o un archivo que ya usó otra, en la web y en el CLI ([más abajo](#compartimentación-aviso-antes-de-reutilizar-un-contacto-o-un-archivo-fr006-07), FR006-07), banner "Enviando como…" | Estilo de escritura, horarios, errores humanos; un contacto o un archivo que otra persona usó desde otro dispositivo, o antes de restaurar un backup, no se detecta |
| Insider organizacional | RBAC/ABAC default-deny, auditoría sin plaintext, dispositivos registrados para recursos sensibles | Admins con privilegios amplios |
| Bug en biblioteca criptográfica | Autoprueba de secreto post-expulsión al abrir sesiones MLS (fail closed), con control negativo en CI que instala ts-mls rc.10 y exige que falle (`scripts/mls-negative-control.sh`, FR020-05); override de ts-mls (hoy 2.0.0-rc.16; la corrección llegó en rc.11) tras hallar que rc.10 omitía UpdatePath en un Remove (RFC 9420 §12.4); tests de propiedades/fuzz con fast-check (`tests/fuzz`, SEC-03: eventos NIP-01, NIP-44, NIP-49, TLV NIP-19, codecs MLS y parsers de backup, con pruebas diferenciales contra nostr-tools; `FUZZ_RUNS=2000 npx vitest run tests/fuzz --testTimeout=0` para una campaña larga) | Otros fallos no cubiertos por la autoprueba; revisión independiente pendiente |
| Supply chain | Dependencias fijadas (versiones exactas + lockfile), noble/scure auditadas, keygen sin dependencias en runtime y bundle reproducible, SBOM, gitleaks, Dependabot, CodeQL y dependency review en CI, imágenes reproducibles bit a bit (NFR010-03), releases firmados con cosign keyless + provenance SLSA desde un entorno protegido (`release.yml`, docs/building.md) | Primer release firmado pendiente y entorno `release` sin aprobador distinto del autor del tag (OPS-08); `main` sin protección hasta OPS-12, prevista para noviembre |
| Servicio push / operador del gateway de notificaciones (ADR 0010) | Push opt-in y opaco (payload constante cifrado RFC 8291 o vacío; sin contenido, remitente ni recuento), retardo aleatorio + agrupación + ticks comunes por perfil, registro NIP-98 (solo el propio npub), un scope de service worker por persona, registros solo en memoria, baja ante 404/410, logs con HMAC truncado; sin push en sovereign y Tor (validación + 403 en el gateway) | El servicio push ve cuándo llega un aviso al dispositivo y la IP del gateway; el gateway conoce npub ↔ endpoint mientras el push esté activo; correlación temporal relay↔push posible con poco tráfico |
| Usuario de la plataforma fuera de un canal | El espejo solo sirve un canal (mensajes, estado NIP-29, no leídos y búsqueda) a quien figura en sus listas 39001/39002 firmadas por el relay (NIP-11 `self` o `INDEXER_GROUP_AUTHORITIES`), y aplica los 9005 de moderación como Buzz: autor o admin del canal (FR014-05) | Las listas se consultan en cada refresco de canales (`INDEXER_CHANNEL_REFRESH_MS`, 30 s por defecto): quien sale de un canal puede seguir leyéndolo por el espejo hasta el siguiente refresco |
| Error humano | Advertencia antes de mostrar nsec, confirmación explícita para vínculos, no sobrescribir backups, disclosures por opción | — |

## Compartimentación: aviso antes de reutilizar un contacto o un archivo (FR006-07)

Spec §14.1: la aplicación advierte antes de reutilizar una identidad, un archivo o un contacto entre compartimentos.
Implementación en `packages/identity/src/usage.ts` (compartida por la web y el CLI); pruebas en
`packages/identity/test/usage.test.ts`, `apps/sovereign-client/test/compartment.test.ts`,
`apps/web-saas/test/compartment.test.ts` y `tests/browser/web-saas.e2e.ts`.

**Qué cuenta como uso.** Lo que la persona hace hacia un contacto o con un archivo: escribirle un DM, invitarlo a un
grupo seguro, proponer que entre o añadir sus dispositivos, y enviar un archivo (adjunto de DM, imagen de canal o
media de grupo). Lo que la persona recibe no cuenta.

**Cuándo avisa.** Antes de cualquier petición de red, cuando la persona activa va a usar un contacto o un archivo que
otra persona de este dispositivo ya usó y ella todavía no, sean cuales sean los compartimentos o perfiles. El aviso
nombra la otra persona y quién podría relacionarlas (el contacto, quien vea el tráfico de las dos, quien reciba las
dos copias del archivo). Sin confirmación explícita no sale nada: en la web, un diálogo con «Cancelar» y «Entiendo el
riesgo, seguir con …»; en el CLI, la orden termina con error y hay que repetirla con `--confirm-reuse` (`dm send`,
`group invite`, `group propose --add`, `group add-device --member`, `group send-file`). Cuando el envío sigue adelante,
el uso queda registrado antes de su primera petición de red (un archivo, después de pasar el saneador de metadatos) y
ese mismo cruce no se vuelve a preguntar. Escribir a otra de tus propias identidades también avisa, cada vez, cuando
una de las dos es de alto riesgo; invitarla a un grupo sigue prohibido (todos los miembros verían a las dos), también
en la web, que no admite personas de alto riesgo y rechaza invitar a cualquier otra persona propia.

**Qué se guarda para detectarlo.** Un registro por persona, dentro de su propio almacén cifrado (en el CLI, el
directorio de la persona; en la web, la colección `usage-<id>` del almacén del navegador, junto a su outbox), nunca
en una lista común a todas: una llave aleatoria de 32 bytes de esa persona y, por cada contacto o archivo usado, una
etiqueta HMAC-SHA256(llave, `contact:<pubkey>` o `file:<sha256 del archivo tal como se eligió>`). No se guarda la
npub, ni el hash del archivo, ni su nombre, ni la conversación, ni cuándo se usó (en el CLI cada entrada es un
archivo, y el sistema de archivos conserva su fecha de modificación, como la de cada operación del outbox). Para
comprobar un uso se calcula la etiqueta con la llave de cada una de las otras personas; lo que la persona activa ya
usó ni siquiera abre las demás. El registro no sale del dispositivo: no va en los backups ni en el Continuity Vault.
Lo que el CLI guardaba antes (las npubs y los hashes de todas las personas, juntos en una lista del almacén de la
cuenta) se pasa al registro de cada persona y se borra la primera vez que se usa.

**Qué ve cada parte.** Nadie fuera del dispositivo: la comprobación es local y no añade ninguna petición. Quien abra
el almacén local tiene también las llaves: puede comprobar si una npub o un archivo concretos están en el registro de
una persona, pero no listarlos, y las etiquetas de dos personas no se pueden cruzar sin las dos llaves.

**Riesgo residual.** El registro es de cada dispositivo: lo usado desde otro dispositivo, o antes de restaurar un
backup, no se detecta. Un archivo con los mismos píxeles y otros bytes (por ejemplo, reexportado) cuenta como otro.
Confirmar el aviso no borra el riesgo: solo deja constancia de que el usuario lo aceptó.

## Propiedades por modo (§20.2)

| Propiedad | Standard SaaS | Zero-knowledge | Tor high-risk |
|---|---|---|---|
| Servidor asocia cuenta↔npub | Sí (si el usuario registra la persona) | Opcional | No (no se registra) |
| Servidor obtiene nsec | Solo managed | No | No (validación rechaza managed) |
| Servidor ve plaintext de DMs | Solo managed (el managed-signer descifra NIP-44) | No | No |
| Relay ve IP | Sí | Sí | Mitigado por Tor |
| Relay ve plaintext de canal | Canales NIP-29 sí | No si cifrado cliente | No si cifrado cliente |
| Forward secrecy | Solo Marmot/MLS | Solo Marmot/MLS | Solo Marmot/MLS (marmot-ts alpha, vía relay secundario) |
| Cloud recovery | Sí | Solo ciphertext | Off por defecto |

## Gates de seguridad (§20.3) — estado

- [ ] Revisión criptográfica independiente.
- [ ] Pentest de API, relay, key service y cliente.
- [x] Tests automatizados de Tor/DNS: DNS remoto verificado y ausencia de fallback clearnet; captura de red real (pcap) sin DNS, IPv6 ni conexiones fuera del proxy (job `leak-tests`). [x] WebRTC y previews remotas en la web (SEC-05). WebRTC en móvil: no aplica (sin app móvil propia).
- [x] Revocación en el policy-engine y rotación MLS con el worker del CLI (FR024-01/02/04). [x] Revocación efectiva en la web managed y worker como servicio (FR024-03, FR024-05). [x] Rotación MLS (self-update) y expulsión con secreto post-expulsión (tests de conformidad + autoprueba en runtime).
- [x] Restore completo de identidad en dispositivo limpio (test). [x] Drill de restore del stack self-hosted, nocturno en CI (`restore-drill.yml`, NFR003-02). [ ] Simulacro de RPO/RTO en stage (NFR003-03).
- [x] Fuzz/property tests con fast-check de serialización, criptografía y parsers propios (`tests/fuzz`, SEC-03).
- [x] Dependency scanning (Dependabot, dependency review), CodeQL, SBOM, gitleaks. [ ] Firma de releases: `release.yml` firma con cosign keyless y provenance SLSA, pero aún no hay ningún release (NFR010-02).
- [ ] Threat models versionados (v0.1) pero en estado Propuesto: falta la aprobación de alguien distinto del autor y ligarlos a un release (DEC-10).

## Perfil público por persona (FR006-04)

Implementación: `packages/messaging/src/profile.ts` (kind 0: construirlo, leerlo con cuidado y la caché de cada
persona), `apps/web-saas/src/lib/profiles.ts` y `apps/web-saas/src/views/Profile.tsx`; los textos de consecuencias
están en el catálogo revisado (`PUBLIC_PROFILE_TEXTS`, [disclosures](disclosures.md)). Pruebas:
`packages/messaging/test/profile.test.ts`, `apps/web-saas/test/profile.test.ts`, `packages/profiles/test/profiles.test.ts`
y los E2E de navegador `tests/browser/web-saas.e2e.ts`, `tests/browser/web-leaks.e2e.ts` y `tests/browser/web-groups.e2e.ts`.

**Qué se publica y cuándo.** Solo cuando el usuario pulsa «Publicar perfil» en la tarjeta «Perfil público» de la
persona: un kind 0 con nombre, descripción y dirección del avatar, firmado por el signer de esa persona, sea cual sea
su custodia (a un signer NIP-46 la web le pide permiso para firmar kind 0; la llave gestionada firma en el
managed-signer), y enviado por su outbox a sus relays. El nombre que la persona tiene en este navegador («Nombre visible solo para ti») nunca se publica. En una
persona seudónima (`identity: pseudonymous`, como `private-resilient` y `sovereign`) la tarjeta muestra el aviso de
vinculabilidad y el botón no se activa sin marcar «Entiendo que el perfil es público…»: sin esa elección no se publica
nada, tampoco al crear la persona. «Retirar perfil» publica uno vacío que sustituye al anterior. Una configuración
Tor-only no publica ni sube nada desde el navegador. El cliente soberano (CLI) no publica perfiles.

**El avatar propio.** Se sube sin cifrar al primer servidor de la lista Blossom de la persona (kind 10063) o al de
media del despliegue, siempre sin metadatos (EXIF…), diga lo que diga el panel, y solo JPEG, PNG o WebP de hasta 1 MB.

**Qué perfiles se buscan y dónde.** Siempre en los relays de la persona, y solo cuando no les dice nada nuevo: los
autores de los mensajes de un canal que esos mismos relays le sirvieron, la propia persona y sus contactos (a quienes
escribió: buscar sus relays de DM ya los preguntaba). No se busca a quien escribe sin ser contacto (el gift wrap oculta
al remitente) ni a los miembros de un grupo seguro (revelaría quién está en el grupo), salvo que el usuario pulse
«Buscar sus perfiles públicos» en el grupo, que avisa de lo que implica; si no, se muestran los perfiles que la persona
ya conocía por los canales o los mensajes directos. La caché es de cada persona, en memoria y con una vigencia de 10
minutos (spec §14.1: cada persona mantiene su caché); no se guarda en el almacén.

**Cómo se muestran.** Siempre «nombre · npub»: cualquiera puede publicar cualquier nombre. De los perfiles ajenos se
quitan los caracteres de control, de ancho cero y de dirección (que podrían reordenar lo que se ve junto al nombre) y se
recortan nombre y descripción; solo se aceptan avatares http(s).

**Avatares ajenos.** Con las previews remotas bloqueadas (todos los perfiles salvo `convenience`) no se descarga ninguno
hasta que el usuario pulsa «Mostrar avatares». La descarga va sin cookies, sin referrer y sin seguir redirecciones, se
comprueba contra el hash cuando la dirección es de Blossom (`…/<sha256>`), solo acepta JPEG, PNG o WebP de hasta 1 MB y
se muestra desde un `blob:` (la CSP no admite imágenes remotas). Solo el servidor de media del propio despliegue, del
mismo operador que los relays donde la persona ya se autentica (NIP-42), puede recibir un token BUD-01 de lectura;
ningún otro servidor sabe quién pide el avatar.

**Qué ve cada parte.** Los relays de la persona: el kind 0 que publique, que es público, y los perfiles que pide (los
de autores y contactos que ya conocían, y los de un grupo solo si el usuario lo pide). El servidor del avatar propio: la
imagen y la IP de quien la sube, y la IP de quien la descarga. El servidor de un avatar ajeno: la IP de quien lo mira y
cuándo, solo tras «Mostrar avatares» o con las previews remotas activadas.

**Riesgo residual.** Un perfil publicado se copia y se conserva fuera de tu control: retirarlo no borra esas copias.
Un nombre o una foto pueden identificar a una persona seudónima; por eso hace falta la elección explícita, que es del
usuario y no se puede deshacer una vez publicado.

## Estado de presencia por persona (FR015-05)

Implementación: `packages/profiles/src/presence.ts` (quién puede), `packages/messaging/src/presence.ts` (kind 30315:
construirlo, validarlo, leerlo con cuidado y la caché de cada persona), `apps/web-saas/src/lib/presence.ts` y
`apps/web-saas/src/views/Presence.tsx`; los textos están en el catálogo revisado (`PRESENCE_TEXTS`,
[disclosures](disclosures.md)). Diseño y decisiones en [presence.md](presence.md). Pruebas:
`packages/profiles/test/profiles.test.ts`, `packages/messaging/test/presence.test.ts`,
`apps/web-saas/test/presence.test.ts` y `apps/web-saas/test/nip46-permissions.test.ts`.

**Dónde existe.** En ningún preset. La persona lo activa en el panel (`presence: status`) y solo vale donde el perfil lo
permite: Tor-only (`TOR_PRESENCE`) y una identidad verificada por una organización (`PRESENCE_ORGANIZATION`) son errores
bloqueantes; una persona pseudónima recibe el aviso `PRESENCE_PSEUDONYMOUS`. Sin presencia, la web no publica ni pide
nada de kind 30315, lo que comprueba un test contra el relay de pruebas, que registra cada EVENT y cada REQ.

**Qué se publica y cuándo.** Solo cuando el usuario pulsa «Publicar estado»: el texto que escribió, tal como lo ve en la
vista previa (100 caracteres como mucho, sin caracteres de control, saltos de línea, enlaces ni menciones), en la ranura
`general`, con una expiración NIP-40 de 24 h como mucho y ninguna otra etiqueta. Nada se deriva de la actividad.
«Borrar estado» publica uno vacío que caduca en una hora. Sale firmado por el signer de la persona, por su outbox, a sus
relays y por su conexión, nunca por la de otra persona del navegador.

**Qué se lee.** Los estados de otras personas viajan en la misma consulta que los perfiles que la web ya busca: el mismo
REQ lleva un segundo filtro para las mismas llaves. No hay consulta propia, suscripción con la lista de contactos ni
sondeo. El estado propio se pide a los relays de la persona. Todo vive en memoria, por persona, y un estado ajeno se
muestra como texto hasta que caduca y nunca más de 24 horas.

**Qué ve cada parte.** Los relays de la persona, y quien pueda leerlos: el estado, la npub, cuándo se publicó y cuándo
caduca, la IP (sin Tor) y que esa persona lee estados. El mirror del operador no copia el kind 30315 por defecto. El
Continuity Vault recibe una copia sellada más si la persona copia sus envíos.

**Riesgo residual.** Un estado publicado se puede copiar y conservar fuera de tu control, y los relays que ignoran NIP-40
pueden seguir sirviéndolo; las horas a las que lo cambias dicen cuándo estabas activa. No está probado contra el Buzz
fijado (el gate lo registra sin exigirlo). En modo institucional, `relay-allowlist` no filtra por kind: el bloqueo es de
esta web, no de un cliente de terceros con una llave del allowlist.

## Grupos seguros en la web: dispositivos, rotación, propuestas y archivos (FR025-14)

Implementación: los flujos que comparten el CLI y la web están en `packages/marmot-adapter/src/flows.ts` (quién hace
commit y quién propone un dispositivo, qué lleva una propuesta, cómo se busca, descarga y abre un archivo) y la subida
del cifrado en `packages/blossom-client/src/ciphertext.ts`. La web los usa desde `apps/web-saas/src/lib/groups.ts` y
las vistas `GroupsView.tsx`, `GroupDevices.tsx`, `GroupProposals.tsx` y `GroupAttachment.tsx`. Los textos de
consecuencias están en el catálogo revisado (`SECURE_GROUP_TEXTS`, [disclosures](disclosures.md)). Pruebas:
`apps/web-saas/test/secure-groups.test.ts`, `tests/fuzz/group-inputs.test.ts`, `apps/web-saas/test/nip46-permissions.test.ts`
y el E2E de navegador `tests/browser/web-groups.e2e.ts`. Detalle del protocolo en [marmot.md](marmot.md).

**Qué hace cada acción.**
- *Dispositivos.* Invitar a alguien añade todos sus dispositivos con key package en un solo commit, como el CLI.
  «Añadir dispositivos» (admin) o «Proponer dispositivos» (miembro) busca los key packages de dispositivos de una
  persona que aún no están y deja marcar cuáles entran. El admin los añade con un commit; un miembro envía una propuesta.
  El admin quita un dispositivo con confirmación, y ese navegador ve que está fuera aunque su persona siga en el grupo.
  El nombre de cada navegador se guarda en su vault, fuera del estado MLS, y se anuncia cifrado dentro de cada grupo.
- *Rotación.* «Rotar mis claves», con confirmación, publica un commit de self-update. Antes lee lo que el relay ya
  tiene de esa época, así que no pierde los mensajes enviados antes de rotar. Las propuestas pendientes quedan
  descartadas.
- *Propuestas.* Un miembro propone altas y bajas. Todos ven las pendientes. El admin confirma las que marca: un commit
  las aplica y descarta el resto. O rechaza todas con una rotación de sus claves. Mientras haya propuestas, la vista no
  deja escribir, porque MLS no lo permite, ni hacer otros commits del admin, que aplicarían también algunas de ellas.
- *Archivos (MIP-04).* Primero, el aviso de reutilización entre personas (FR006-07) con el archivo tal como se eligió.
  Después se quitan los metadatos de JPEG, PNG y WebP. Con `stripFileMetadata`, una imagen que no se puede limpiar se
  rechaza antes de subir nada, la regla de los demás adjuntos. El archivo se cifra con la clave de la época y solo se
  sube el cifrado. La descarga comprueba el hash del cifrado antes de descifrar y se hace fuera de la cola MLS.

**Qué ve cada parte.**
- *Los miembros del grupo:* cada dispositivo de cada persona, con su identificador y el nombre que anuncie; quién
  propone qué; el nombre, el tipo y el tamaño de cada archivo.
- *El relay de grupos:* eventos kind 445 cifrados, firmados con una llave de un solo uso, y un key package firmado con
  la npub por cada dispositivo.
- *Los servidores Blossom del emisor y el blob-store del despliegue:* el archivo cifrado (tamaño y hash), la npub que
  firma la subida y la IP. Al descargar, el servidor donde está el archivo ve la IP de quien lo pide, y su npub si exige
  autorización. Si la dirección compartida falla, los relays de la persona ven que busca la lista de servidores del
  emisor.

**Riesgo residual.**
- Un miembro puede bloquear el grupo proponiendo cambios: nadie escribe hasta que un admin decide.
- Quien sale o es expulsado conserva lo que ya descifró. Puede abrir los archivos de las épocas en que era miembro si
  consigue el cifrado.
- Un nombre de dispositivo cambiado no llega a los grupos en los que ya está el navegador hasta que se anuncia otra vez.
  Se anuncia al entrar en un grupo y, si es admin, al añadir a alguien.
- La subida de un archivo ocupa la cola MLS de la persona mientras dura. Un servidor Blossom que no responde retrasa
  las demás operaciones de sus grupos en ese navegador.
- Tras revocar un dispositivo, un key package publicado por el dispositivo perdido aparece entre los candidatos: por
  eso se marcan uno a uno.

## Trazas de los servicios (NFR007-02)

Las trazas son la telemetría del operador sobre sus propios servicios; el detalle está en
[`slo.md`](slo.md#trazas-nfr007-02). Implementación en `packages/telemetry-policy/src/tracing.ts` y
`packages/service-kit/src/tracing.ts`; pruebas en `packages/telemetry-policy/test/tracing.test.ts`,
`packages/service-kit/test/tracing.test.ts` y `services/blob-store/test/tracing.test.ts`.

**Cuándo existen.** Solo si el operador fija `TRACE_SAMPLE_RATE` por encima de 0 con `TELEMETRY_LEVEL=standard`
(el nivel por defecto). Con `none`, el nivel de los despliegues sovereign y Tor, el servicio no tiene
trazador y ninguna variable lo cambia. Una petición dirigida a un `.onion` nunca se traza. Los clientes (web, CLI y
consola) no trazan.

**Qué se guarda.** Por cada petición muestreada: el servicio, el método, la ruta como plantilla (`/v1/keys/:id`),
el estado, la hora, la duración, la clase del error en los 5xx y la operación (`SELECT`…) de cada consulta. Nada
más cabe en un span: sus atributos son una lista cerrada con reglas por valor, así que no hay IPs, pubkeys, ids de
la ruta, cabeceras, cuerpos, tokens ni mensajes de error.

**Qué ve cada parte.** El operador, en el log del servicio y, si lo configura, en su colector OTLP: lo anterior,
que es parte de lo que ya recibe con cada petición (ruta, hora, estado), sin la IP ni la pubkey de quien pide. El
colector es suyo (una sola URL, sin redirecciones): ningún exportador sale por defecto hacia fuera. Los servicios no
leen ni envían `traceparent`, así que una traza no une peticiones de servicios distintos. Quien usa el servicio no
ve nada nuevo y no envía nada nuevo.

**Riesgo residual.** Las horas y las duraciones de las trazas, junto con los logs de acceso del operador, permiten
las mismas correlaciones temporales que esos logs por sí solos. Una persona Tor que llega por un nodo de salida al
nombre clearnet de un servicio con trazas activas se muestrea como cualquiera; con `--onion-only` solo alcanza
`.onion`, que no se trazan. Una ruta o un nombre de span que el código construyera con datos solo pasarían si
tuvieran forma de palabras en minúsculas (sin hex ni cuatro dígitos seguidos, sin `@`, `:`, `?` ni `=`, y sin puntos
en una ruta): las rutas de los servicios son plantillas fijas.

## Informes de fallo (NFR007-03)

Detalle en [`crash-reports.md`](crash-reports.md). Implementación en `packages/telemetry-policy/src/crash-report.ts`,
`apps/web-saas/src/lib/crash.ts`, `apps/web-saas/src/views/CrashReports.tsx` y `apps/sovereign-client/src/crash.ts`;
pruebas en `packages/telemetry-policy/test/crash-report.test.ts`, `apps/web-saas/test/crash.test.ts`,
`apps/sovereign-client/test/crash-reports.test.ts` y `packages/profiles/test/profiles.test.ts`.

**Cuándo existen.** Según el control `crashReports` de la persona activa: con `off` no se captura nada, ni en memoria;
con `manual-export`, el informe del último fallo queda en memoria (la web) o se escribe en un archivo si se pide con
`--crash-report` (el CLI); con `opt-in`, además, cada informe se guarda cifrado en el almacén local. Ningún perfil
de referencia trae `opt-in`, y Tor-only lo rechaza. Ningún modo hace una petición de red.

**Qué se guarda.** Un informe es una lista cerrada de campos (la versión de la app, el preset, el sistema y el
navegador o Node por familia y versión mayor, el origen del fallo y el error con su clase, su mensaje limpio, sus
frames y sus causas). El mensaje pierde llaves, entidades NIP-19, URLs, hosts, `.onion`, IPs, rutas, tokens, correos
y el texto entre comillas; la pila se queda en `paquete/archivo:línea:columna`. No hay ids de persona ni de grupo,
pubkeys, user agent ni hora en el informe. En `opt-in`, el almacén guarda además cuándo se produjo cada uno y cuántas
veces, para la retención (20 informes, 30 días), y no lo exporta.

**Qué ve cada parte.** El operador, los relays y cualquier servidor: nada nuevo, porque no se envía nada. Quien abra
el almacén local (con la contraseña o la llave del dispositivo): los informes guardados y sus fechas. Quien reciba un
archivo exportado: lo que la persona vio en la vista previa o en el archivo.

**Riesgo residual.** Palabras normales sin comillas (por ejemplo, un error construido con el texto de un mensaje) y
nombres de host internos sin dominio no se reconocen por su forma: por eso la persona ve el informe entero antes de
guardarlo y nada sale solo. La línea de error del CLI en la terminal conserva hosts, `.onion` y rutas fuera del
directorio personal (sin secretos ni IPs), como el resto de su salida (FR021-03). El borrado quita la entrada del
almacén; el sistema de archivos o IndexedDB pueden conservar esos bytes cifrados hasta reutilizarlos.
