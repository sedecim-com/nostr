# Architecture Decision Records

Cada ADR resuelve una decisión abierta del scope (§25.1). Estados: **Propuesto** (redactado, pendiente de
aprobación) · **Aceptado** (aprobado por el responsable de producto) · **Reemplazado**.

Para aprobar un ADR: cambiar su estado a *Aceptado*, anotar quién y cuándo en "Aprobación" y marcar la
tarea correspondiente del backlog como `Hecho` (`docs/backlog/backlog.json`, luego `npm run backlog`).

| ADR | Decisión | Tarea | Estado |
|---|---|---|---|
| [0001](0001-nombre-y-licencia.md) | Nombre y licencia del proyecto | DEC-01 | Aceptado |
| [0002](0002-subset-y-pin-de-buzz.md) | Buzz upstream sin fork y versión fijada | DEC-02 | Aceptado |
| [0003](0003-compatibilidad-con-upstream-buzz.md) | Política de pin y actualización de Buzz | DEC-03 | Aceptado |
| [0004](0004-bibliotecas-nostr-rust-flutter.md) | Bibliotecas Nostr para Rust y Flutter | DEC-04 | Aceptado (diferido) |
| [0005](0005-receipts-de-aplicacion.md) | Receipts de aplicación y read receipts | DEC-06 | Aceptado |
| [0006](0006-marmot-proveedor-y-ruta-de-relay.md) | Proveedor Marmot y ruta de relay | DEC-07 | Aceptado |

Los threat models por perfil (DEC-10) están en [`../threat-models/`](../threat-models/README.md).
