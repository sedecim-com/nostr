# ADR 0006 · Proveedor Marmot y ruta de relay

- **Estado:** Propuesto · **Tarea:** DEC-07 (P1) · **Fecha:** 2026-09-26
- **Aprobación:** pendiente

## Contexto
FR-025 está implementado con `@internet-privacy/marmot-ts` 0.5.1 sobre `ts-mls`, forzado a
`2.0.0-rc.11` tras encontrar que `rc.10` permite a un miembro expulsado derivar la época siguiente
(`docs/marmot.md`). El Buzz fijado rechaza los kinds 30443, 445 y 10051 con
`restricted: unknown event kind`. La conformidad pasa contra nostr-rs-relay 0.9.0 real
(`docs/interop/marmot-nostr-rs-relay-0.9.0-report.json`).

## Opciones de ruta
| Opción | A favor | En contra |
|---|---|---|
| A · **secure-relay** (nostr-rs-relay fijado, NIP-42, onion) | Sin parches a Buzz (cumple §6.3); ya implementado y probado; es el mismo relay que usa el perfil Tor | Un servicio más que operar; los grupos MLS no viven en el workspace Buzz |
| B · Parche en el fork de Buzz para aceptar los kinds | Un solo relay | Contradice "minimizar parches"; Buzz interpreta `h` como canal NIP-29 y el `h` de 445 es el id Nostr del grupo, lo que obliga a revisar el scoping; el parche no puede enviarse a upstream sin un diseño previo |

## Decisión propuesta
- **Proveedor:** marmot-ts 0.5.1 + ts-mls 2.0.0-rc.11 (override) con la autoprueba de secreto
  post-expulsión obligatoria. Se migra a versiones estables en cuanto se publiquen (FR025-08).
- **Ruta: opción A (secure-relay).** Se reevalúa la opción B solo si upstream Buzz acepta los kinds
  Marmot o ofrece un allowlist de kinds configurable. En ese caso, FR025-10 deja de ser un parche propio.

## Consecuencias
- FR025-10 queda en el backlog como P3, condicionado a este ADR.
- Documentación de usuario: las personas que usen grupos MLS incluyen `secure-relay` en su lista de
  relays.
