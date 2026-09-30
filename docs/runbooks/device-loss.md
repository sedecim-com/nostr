# Runbook: dispositivo perdido o robado

Qué hacer cuando se pierde o roban un teléfono, un portátil o un navegador con una persona abierta. El flujo completo
está probado de punta a punta en `tests/security/device-loss.test.ts` (SEC-04) y el servicio de rotaciones en
`services/rotation-worker/test/service.test.ts` (FR024-05).

**Qué protege y qué no.**
- Revocar protege lo que se envía **después**: sesiones cerradas, firmas rechazadas y grupos en una época nueva.
- Lo que el dispositivo ya descifró sigue en él: mensajes, media y claves de épocas anteriores. Revocar no borra.
- Hay una **ventana**: entre la revocación y el commit que saca al dispositivo de cada grupo pasan hasta
  `ROTATION_INTERVAL_MS` (15 s) más los reintentos. Si el dispositivo sigue conectado, puede leer lo que se envíe en
  ese tiempo.

Primero, identifica qué custodia tenía la persona de ese dispositivo; los pasos cambian.

## 1. Persona gestionada (custodia managed, web SaaS)

La llave no está en el dispositivo: vive en el managed-signer (KMS). El navegador perdido solo tiene una sesión de
dispositivo (`sds_…`, 12 h como mucho), que se puede cerrar desde otro navegador. Con ella se puede firmar mientras
siga abierta, pero no exportar la llave, migrarla, borrarla ni cancelar la custodia: eso pide la contraseña de Acceso
de los últimos minutos (IR-2026-10-03).

1. En otro navegador, entra con el mismo login de Acceso y abre la persona: «Nueva persona» → «Recuperar mi persona
   gestionada».
2. En la tarjeta «Actividad de tu llave gestionada», revisa las operaciones recientes. Cada una nombra el
   dispositivo que la hizo. Busca firmas que no reconozcas, y cualquier exportación, migración o borrado: siguen en
   el log aunque la llave ya no esté.
3. Escribe tu contraseña de Acceso y pulsa «Cerrar las demás sesiones». Cierra la sesión del dispositivo perdido y
   deja fuera su login: aunque lo refresque, no abre otra sesión ni firma hasta que alguien vuelva a escribir la
   contraseña (IR-2026-10-11). «Cerrar» en esa sola sesión no deja fuera su login.
4. **Cambia la contraseña de Acceso.** El corte del paso 3 dura hasta que alguien entre otra vez con la contraseña:
   si el dispositivo la tenía guardada o alguien la conoce, podría volver a entrar. Tus otros navegadores también
   te la pedirán una vez.
5. En modo institucional, además, sigue la sección 3. Si ese navegador estaba vinculado al dispositivo de la
   organización («Dispositivo de tu organización» en la misma tarjeta), revocarlo hace que el managed-signer lo rechace
   para siempre, aunque tenga el login. Si no lo estaba, la revocación no le llega: los pasos 3 y 4 son los que
   cuentan.

## 2. Persona local (la llave estaba en el dispositivo)

La nsec estaba en el almacén cifrado del dispositivo, protegida por la contraseña local (scrypt). Si esa contraseña
era débil o se conoce, **da la llave por comprometida**.

1. En los grupos MLS, un admin saca solo esa hoja y deja los otros dispositivos de la persona:
   ```bash
   sovereign group devices --persona ADMIN --group GID            # una hoja por dispositivo, con su etiqueta
   sovereign group remove-device --persona ADMIN --group GID --leaf N
   ```
   En la web, «Expulsar» saca a la persona entera (todas sus hojas). Después hay que invitar de nuevo a sus otros
   dispositivos.
2. Si la llave está comprometida, crea una persona nueva, pide a tus contactos que la usen y deja de usar la
   anterior. Una llave Nostr no se puede revocar: quien la tenga puede firmar y leer los DMs que se le envíen.
3. Restaura en un dispositivo nuevo desde tu backup (`docs/runbooks/restore.md`).

## 3. Modo institucional (admin de la organización)

La organización revoca el dispositivo en el policy-engine, y desde ahí todo lo demás ocurre solo.

1. **Revocar.** En la consola de administración, «Dispositivos» → busca al titular → «Revocar», con un motivo
   («robado», «perdido»). Al momento:
   - se invalidan sus sesiones de política, no se abren nuevas y `evaluate` responde `device revoked`;
   - si la persona no tiene otro dispositivo activo, sale del allowlist NIP-42 de los relays en la siguiente
     sincronización (`ALLOWLIST_SYNC_INTERVAL_MS`);
   - queda una rotación pendiente por cada recurso de tipo `group` del que la persona es miembro.
2. **Rotaciones.** El worker de rotaciones (`rotation-worker`, docs/institutional.md) las aplica en su ciclo
   siguiente: un commit Remove por grupo, con todas las hojas de la persona.
   - En la consola, «Rotaciones pendientes» debe quedar vacía en unos segundos.
   - Salud del worker: `GET /health` (puerto 8089) con `"ok": true` y `rotations.removed` incrementado.
3. **Firmantes.** El worker lleva la revocación al managed-signer: se borran las sesiones de ese dispositivo y se
   rechazan las nuevas, también con el login de Acceso. Un bunker NIP-46 conectado a él suelta la sesión del
   dispositivo y rota su secreto.
   - En la web, esto alcanza al navegador que la persona vinculó al dispositivo de la organización (FR024-03). Ese
     navegador ya no firma, y la tarjeta «Actividad de tu llave gestionada» explica que la organización lo revocó.
   - Un navegador sin vincular firma con un id propio (`web-…`) que la organización no conoce. Para cortarlo, la
     persona cierra su sesión desde otro navegador y cambia su contraseña de Acceso (sección 1).
4. **Comprobar.**
   - «Auditoría»: la entrada `device.revoke` con el motivo.
   - «Accesos»: las peticiones posteriores de ese dispositivo aparecen como «Denegado».
   - En cada grupo afectado, la época avanzó y la persona ya no está en la lista de miembros.
5. **Sus otros dispositivos.** El worker saca todas las hojas de la persona, así que sus dispositivos legítimos
   también salen. La persona abre «Grupos seguros» en cada uno (publica su key package) y un admin del grupo la
   invita de nuevo.

### Si una rotación no se hace

La rotación sigue pendiente, el worker reintenta con backoff (5 s → 10 min) y su salud está en error con el motivo:

| Error en `/health` | Qué pasa | Qué hacer |
|---|---|---|
| `group not held by the worker identity` | El worker no está en ese grupo | Un admin del grupo expulsa a la persona a mano («Expulsar» en la web o `sovereign group remove`) y marca la rotación como hecha en la consola; después invita al worker |
| `only group admins can …` (grupo en `groupsWithoutAdmin`) | El grupo no tiene al worker como admin | Igual: expulsión manual. Los grupos nuevos lo incluyen si la web tiene `rotationWorker` |
| `resource is not a Marmot group id (hex)` | El recurso de la política no usa el id MLS del grupo | Corrige el recurso en «Recursos y políticas» (id = id MLS del grupo) |
| `remove commit pending: no relay took it yet` | El relay de grupos no responde | Revisa el relay seguro; el commit sale solo cuando vuelva |
| `device revocation(s) not propagated yet` | El managed-signer no aceptó la revocación | Revisa su salud y `ROTATION_MANAGED_SIGNER_TOKEN` (uno de `MANAGED_SIGNER_REVOCATION_TOKENS`) |

## 4. Después

- Si el dispositivo aparece, no lo reactives: regístralo como dispositivo nuevo. Un dispositivo revocado sigue
  revocado, y reactivar a una persona (`POST /v1/subjects/:pubkey/reactivate`) no devuelve sus dispositivos.
- Revisa en «Accesos» y en la actividad de la llave gestionada lo que hizo el dispositivo antes de la revocación.
- Los DMs (NIP-17) no tienen épocas. Con custodia managed, el dispositivo revocado ya no puede descifrar los nuevos
  porque necesita al signer. Con la llave en el dispositivo (sección 2), sí puede: cambia de persona.
