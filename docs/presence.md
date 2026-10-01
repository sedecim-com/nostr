# Estado de presencia (NIP-38) por perfil (FR015-05)

Spec §15.1. Criterio de hecho: el estado de presencia solo existe en los perfiles que lo permiten. Estado de madurez:
**Experimental** (`packages/profiles/src/maturity.ts`): solo en la web, apagado salvo que la persona lo active y sin
probar todavía contra el Buzz fijado ([más abajo](#compatibilidad-con-los-relays)).

## Qué es y por qué no viene encendido

Un estado NIP-38 es un evento direccionable de kind 30315: un texto corto en una ranura (`d`), aquí solo `general`.
Es **metadato público**: va firmado con la npub de la persona, y los relays donde se publica, y quien pueda leerlos,
ven lo que dice y cuándo se publicó, es decir, cuándo estaba activa la persona. El producto promete no filtrar
metadatos ([arquitectura](architecture.md), [threat models](threat-models/README.md)), así que la presencia:

- está apagada en **todos** los presets (`presence: 'off'` en `packages/profiles/src/presets.ts`);
- se enciende solo en el panel de soberanía, por persona, con el control `presence` (`off` | `status`), que muestra su
  consecuencia (catálogo revisado, [docs/disclosures.md](disclosures.md)) y la madurez Experimental;
- y solo donde el perfil lo permite: `presencePolicy` (`packages/profiles/src/presence.ts`) lo deriva de los controles
  de la persona, como `mirrorPolicy`, y `validateConfig` bloquea las combinaciones que no lo permiten.

Una configuración guardada antes de esta tarea no tiene el control: vale `off` (`presenceOption`).

## Qué perfiles lo permiten

| Perfil | ¿Lo permite? | Por qué (threat model del perfil) | `validateConfig` con `presence: 'status'` |
|---|---|---|---|
| convenience | Sí, si la persona lo activa | Identidad vinculada y red directa: los relays ya ven su IP y cuándo se conecta. El estado añade lo que escribe y cuándo lo cambia, y el panel lo dice | Nada más que el texto del panel |
| private-resilient | Sí, con aviso | Protege el «anonimato relativo» de una persona pseudónima frente a relays que correlacionan: lo que escribe y las horas a las que cambia el estado pueden relacionarla con otras identidades. Lo decide la persona con el aviso delante. Con varios relays, cada uno recibe el estado | Aviso `PRESENCE_PSEUDONYMOUS` |
| institutional | **No** | El modelo institucional deniega por defecto (RBAC/ABAC): lo que la política no gobierna queda denegado, y el policy-engine no tiene un recurso para la presencia. Con identidad verificada, el estado aparecería junto al cargo del directorio ante el operador y los miembros del relay, que verían patrones de trabajo. Que lo gobierne la política exige un recurso nuevo en el policy-engine y que los relays lo apliquen: queda fuera de esta tarea | Error bloqueante `PRESENCE_ORGANIZATION` |
| sovereign | Sí, con aviso | Persona pseudónima en un relay propio o privado: el mismo riesgo de vinculación que private-resilient, ante menos observadores | Aviso `PRESENCE_PSEUDONYMOUS` |
| sovereign-tor | **No** | Sus activos son el anonimato de red y la no vinculación. Tor oculta desde dónde se publica, no cuándo ni qué: cada estado sería un oráculo de actividad firmado con la npub. Además, la web no abre ninguna conexión para una persona Tor-only (PANEL-05) | Error bloqueante `TOR_PRESENCE` |

La regla, sobre los controles y no sobre el nombre del preset: con `network: 'tor-only'` nunca; con `identity: 'verified'`
nunca; en lo demás, cuando la persona lo activa, con aviso si su identidad es pseudónima. El panel no guarda una
configuración con un error bloqueante, y aunque una configuración lo tuviera activado, la web no publica ni pide nada
mientras `presencePolicy` no lo permita.

## Qué publica la web

Desde la tarjeta «Estado de presencia» de Personas (`apps/web-saas/src/views/Presence.tsx`), que solo aparece con la
presencia activada:

- **Solo lo que la persona escribe y confirma.** `buildStatus` (`packages/messaging/src/presence.ts`) recibe el texto; la
  vista previa enseña el texto exactamente como saldrá y solo «Publicar estado» lo publica. Nada se deriva de la
  actividad: ni «en línea», ni «escribiendo», ni «visto por última vez». Abrir la persona, leer o buscar perfiles no
  publica ningún estado (lo comprueba el test de la web).
- **Ranura `general` y expiración NIP-40 obligatoria**: la tarjeta ofrece 30 minutos, 1, 4, 8 o 24 horas; el constructor
  acepta de 60 s a 24 h y rechaza lo demás en vez de recortarlo. Un estado viejo desaparece solo en los relays que
  respetan NIP-40, y la web deja de mostrarlo al caducar.
- **Sin etiquetas `p`, `e`, `a` ni `r`**: enlazarían el estado con otras personas o lugares. `statusTemplateProblem`
  comprueba antes de enviar que las únicas etiquetas son la ranura y una expiración.
- **Texto de hasta 100 caracteres, saneado y sin enlaces.** Los caracteres de control, de ancho cero y de dirección y los
  saltos de línea pasan a espacios, y los espacios se colapsan. Se rechaza, nunca se recorta, un texto más largo o con un
  enlace o una mención: `esquema://`, `www.`, `nostr:`, `mailto:`, `tel:`, `geo:`, `lightning:`, `bitcoin:`, `magnet:` o
  una entidad bech32 de Nostr (`npub1…`, `nprofile1…`, `note1…`, `nevent1…`, `naddr1…`, `nrelay1…`). Por qué: un
  cliente que lea el estado puede cargar la vista previa de un enlace, y ese servidor vería la IP de quien lee; un
  enlace a un sitio puede decir dónde está la persona, y una mención la relaciona con otra. Un dominio sin esquema
  (`ejemplo.com`) no se detecta, y algunos clientes lo convierten en enlace.
- **Borrar** publica en su lugar un estado vacío que caduca en una hora (`buildStatusClear`): los relays que respetan los
  eventos reemplazables dejan de servir el anterior; las copias que otros guardaron no desaparecen. Un cambio en el
  mismo segundo que el anterior se fecha un segundo después, para que lo sustituya (NIP-01).
- **Por dónde sale**: por el outbox de la persona, firmado por su propio signer (llave local, NIP-07, NIP-46 o
  gestionada), en sus relays (`persona.relays`) y por su propia conexión: cada persona abre su pool, y ninguna publica
  por la conexión de otra (test). Para un signer NIP-46, la web pide desde ahora `sign_event:30315`
  (`WEB_NIP46_PERMISSIONS`); un signer conectado antes puede pedir aprobarlo o rechazarlo. Una persona Tor-only no
  tiene presencia, y la web no abre conexiones para ella.
- Como cualquier envío, el estado sigue la política del Continuity Vault de la persona: si copia sus envíos, también
  este (sellado); con `required-for-resilient`, espera a su copia. Un estado que se queda en la cola sin conexión sale
  cuando un relay lo acepte; si ya caducó, un relay que respete NIP-40 puede rechazarlo o descartarlo.

## Qué lee la web: los estados de otras personas

Una suscripción por autores con la lista de contactos le daría a los relays esa lista y un registro en vivo de a quién
sigue la persona; una consulta por persona les diría a quién mira y cuándo; sondear cada cierto tiempo, cuándo está
abierta la app. Nada de eso se hace. En su lugar:

- **Los estados viajan en la misma consulta que los perfiles públicos que la web ya busca** (las reglas de FR006-04: los
  autores de los canales, en los relays que sirvieron sus mensajes; los contactos de mensajes directos; los miembros de
  un grupo seguro cuando la persona pide sus nombres). `ProfileCache` añade al mismo REQ un segundo filtro,
  `{"kinds":[30315],"authors":<las mismas llaves>,"#d":["general"]}`. Los relays no reciben ninguna llave, consulta ni
  momento nuevo: solo saben que esta persona lee estados.
- Solo mientras la presencia de la persona esté activada y su perfil la permita: si no, el filtro no está (test negativo
  contra el relay de pruebas, que registra cada REQ).
- El estado propio: la tarjeta pide a los relays de la persona su propio estado (`authors: [su npub]`), lo que no dice
  nada de nadie más.
- Lo que se muestra: solo la ranura `general`, como texto sin enlaces, saneado y con 100 caracteres como mucho, hasta que
  caduca y nunca más de 24 horas después de publicarse, ni si viene fechado más de 15 minutos en el futuro. Sus
  etiquetas se ignoran.
- Frescura: un estado se actualiza cuando se vuelve a buscar el perfil de esa llave (`ProfileCache` no repite una llave
  antes de 10 minutos, y solo cuando una vista la busca). Una llave sin estado en la respuesta deja de tener estado aquí.
  Los estados viven en memoria, por persona (`StatusCache`); no se guardan.

## Qué ve cada parte

| Parte | Qué ve |
|---|---|
| Relays de la persona, y quien pueda leerlos (en un relay público, cualquiera; en uno privado NIP-42, sus miembros) | El estado, la npub que lo firma, cuándo se publicó y cuándo caduca, la IP de la conexión (sin Tor) y que la persona lee estados (el segundo filtro) |
| Operador del Continuity Vault | Si la persona copia sus envíos: una copia sellada más, con su tamaño y su hora, como cualquier envío |
| Mirror del operador (indexer) | Nada: el kind 30315 no está entre los que copia por defecto (`DEFAULT_MIRROR_KINDS`, test) |
| Otras personas del mismo navegador | Nada: cada una tiene su conexión y sus estados en memoria |
| Signer NIP-46 | El estado que firma, como cualquier evento |
| Managed-signer (custodia gestionada) | Firma el estado y anota la firma en su log de uso, con el kind, el id del evento y la hora, como cualquier firma |

## Compatibilidad con los relays

- **Buzz fijado: no se puede saber con lo que hay en el repositorio.** Buzz rechaza los kinds que no conoce
  (`restricted: unknown event kind`, como el 10050 y el 30443, [buzz-integration.md](buzz-integration.md)), y ningún test
  ni informe de `docs/interop/` publica un 30315. Leído en el código de Buzz en `b0d6fb8`, fuera de este repositorio (la
  misma lectura que FR015-04; el pin es posterior): `required_scope_for_kind`
  (`crates/buzz-relay/src/handlers/ingest.rs`) admite `KIND_USER_STATUS` (30315, `crates/buzz-core/src/kind.rs`) con el
  scope `UsersWrite` y lo guarda como evento global, no de canal; sus tests e2e
  (`crates/buzz-test-client/tests/e2e_user_status.rs`, marcados `#[ignore]` porque necesitan un relay en marcha) lo
  publican, lo leen y lo reemplazan. No se afirma para la imagen fijada hasta que lo diga el gate: `tests/interop/buzz.interop.test.ts` («FR015-05: …») publica un
  estado y su borrado como los construye la web, los vuelve a leer desde otro cliente y lo guarda en
  `interop-report.json` → `userStatus`, sin exigirlo. Corre en el job `stack` de CI; en `docs/interop/` aún no hay un
  informe con ese campo. Tampoco se sabe si Buzz aplica la expiración NIP-40.
- **Edge de SEC-12**: es una lista de rutas, no de kinds. Reenvía el WebSocket de `/` sea cual sea el kind
  ([buzz-attack-surface.md](security/buzz-attack-surface.md)).
- **Secure relay** (nostr-rs-relay): su configuración (`infra/secure-relay/config.toml`) no restringe kinds, pero ningún
  test publica un 30315 en él. La web lo usa para los grupos seguros; el estado va a los relays de la persona.
- **relay-allowlist** (modo institucional): admite por la npub autenticada (NIP-42) y por los permisos de la etiqueta
  `h`, no por kind, así que un 30315 de una llave del allowlist entraría. La web lo bloquea en institucional; un cliente
  de terceros con una llave del allowlist no lo tiene bloqueado.
- **NIP-40 en los relays**: ningún relay de este repositorio está probado aplicándola; el relay de pruebas no la aplica.
  La web oculta por su cuenta los estados caducados.

## Lo que no hace, y por qué

- **El CLI** (`apps/sovereign-client`) no tiene presencia. Su perfil de referencia es sovereign-tor, donde está bloqueada;
  y para firmarla, `SOVEREIGN_NIP46_PERMISSIONS` tendría que pedir `sign_event:30315` a los signers de todas sus personas,
  también las Tor, para un kind que no podrían usar (permisos mínimos, spec §8.3).
  `apps/sovereign-client/test/nip46.test.ts` contrasta en los dos sentidos lo que firma el CLI con
  `SOVEREIGN_SIGNED_KINDS`, que no incluye el 30315.
- Ni la ranura `music`, ni enlaces `r`, ni estados automáticos, ni presencia gobernada por la política de una
  organización (ver la fila institutional).

## Pruebas

- `packages/profiles/test/profiles.test.ts`: ningún preset la activa, la matriz por perfil, la validación (bloqueos y
  avisos) y los textos revisados; `packages/profiles/test/maturity.test.ts`: la etiqueta Experimental.
- `packages/messaging/test/presence.test.ts`: el constructor, el validador, el lector, la caché y el filtro que viaja con
  los perfiles.
- `apps/web-saas/test/presence.test.ts`: contra el relay de pruebas (`TestRelay`, que registra cada REQ en `requests`),
  sin presencia no sale ni se pide nada de kind 30315 en ningún perfil que la web abre; con ella, los estados viajan con
  los perfiles, solo sale lo que la persona publica y por sus relays y su conexión; donde el perfil no la permite, nada.
- `apps/web-saas/test/nip46-permissions.test.ts`: el estado y su borrado entre los kinds que firma la web.
- `tests/interop/buzz.interop.test.ts`: el registro contra el Buzz fijado, en CI.
