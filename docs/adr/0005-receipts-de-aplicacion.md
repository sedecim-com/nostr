# ADR 0005 · Receipts de aplicación y read receipts

- **Estado:** Aceptado · **Tarea:** DEC-06 (P1) · **Fecha:** 2026-09-26
- **Aprobación:** responsable de producto (vic2099), 2026-09-26

## Contexto
La máquina de estados distingue `REPLICATED` (OK del relay), `RECIPIENT_ACKED` y `READ` (§11). No hay un
NIP estándar de receipts para NIP-17. El código usa un rumor provisional de kind `16914`
(`packages/messaging/src/receipts.ts`), que esta decisión adopta como definitivo. Un receipt revela actividad (cuándo se recibe y cuándo se
lee), así que es un dato sensible.

## Decisión
1. **Formato:** el receipt es un **rumor NIP-59 con gift wrap**, de kind `16914` (específico de la
   aplicación, nunca publicado sin envolver), con los tags `["e", <rumor-id>]`, `["p", <destinatario>]`
   y `["receipt", "delivered" | "read"]`. Usa el mismo gift wrap que el mensaje, así que el relay no
   puede distinguir un receipt de un mensaje. Otros clientes NIP-17 lo ignoran, porque el kind es
   desconocido y el rumor va cifrado, y la interoperabilidad no se rompe.
2. **Política por perfil:**

| Perfil | Delivered | Read |
|---|---|---|
| convenience | activado | desactivado (opt-in) |
| private-resilient | activado | desactivado (opt-in) |
| institutional | activado | desactivado (opt-in; la organización no puede forzarlo) |
| sovereign | desactivado | desactivado |
| sovereign-tor | desactivado | desactivado; el panel lo advierte si se activa |

3. **Grupos Marmot:** fuera de este ADR. Los receipts de grupo filtran metadatos a todo el grupo.
4. Si se propone un NIP de receipts en la comunidad y se acepta, este ADR se reemplaza y el kind se
   migra.

## Consecuencias
- `profiles` añade `deliveryReceipts` a la configuración, con disclosures y validación. Implementado en
  este sprint: `receiptPolicy()`.
- FR009-02 conecta los receipts entrantes con `RECIPIENT_ACKED`/`READ`.
- FR009-03: el receipt se enruta como un DM, a los relays de DM (kind 10050) de quien envió el mensaje, y no se queda
  solo en los relays de quien lo recibió. Cada cliente lee sus propios relays de DM y aplica los receipts:
  - la web lo hace en segundo plano mientras NIP-17 está activo, salvo con NIP-07, cuya extensión puede pedir
    permiso para cada descifrado;
  - el CLI lo hace con `sovereign dm inbox`, o con `sovereign dm watch` mientras escucha.

  El read receipt solo sale cuando el usuario ve el mensaje y el perfil lo permite (`DmInbox` en
  `packages/messaging/src/inbox.ts`).
- IR-2026-10-09: los receipts solo van a **contactos**, es decir, a quien esta persona ya escribió un DM (lo que
  registra su outbox, `outboxContacts`). Un desconocido que escribe primero no recibe ninguno hasta que la persona le
  contesta:
  - no sabe cuándo está conectado el dispositivo;
  - no consigue que se conecte, y firme un AUTH NIP-42, en los relays que él elija.

  Con un contacto, el receipt va a los mismos relays de DM a los que la persona ya le escribe, y firma el mismo AUTH.
  Los relays de referencia exigen NIP-42 para publicar, así que sin AUTH el receipt no llegaría.
