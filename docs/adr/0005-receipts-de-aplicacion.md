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
