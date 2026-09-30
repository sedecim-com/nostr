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
| [0007](0007-almacenamiento-local-cifrado.md) | Almacenamiento local cifrado por plataforma y perfil | DEC-05 | Aceptado |
| [0008](0008-login-acceso-en-saas.md) | Login de Acceso (Cognito) obligatorio en SaaS | — | Aceptado |
| [0009](0009-custodia-managed-region-y-marco-legal.md) | Región (us-east-1) y marco legal (LFPDPPP) de la custodia managed | DEC-09 | Aceptado (términos pendientes de legal) |
| [0010](0010-notificaciones-push-por-perfil.md) | Notificaciones push opacas por perfil | DEC-08 | Aceptado |
| [0011](0011-continuity-vault.md) | Continuity Vault: sobres de archivo sellados en el cliente | VAULT-01 | Propuesto |
| [0012](0012-estructura-de-repositorios.md) | Un monorepo en lugar de los seis repositorios del scope | DEC-15 | Propuesto |
| [0013](0013-distribucion-del-sdk.md) | El SDK de cliente se publica en npm (`@sedecim`) con provenance desde el release | OPS-14 | Propuesto |

Los threat models por perfil (DEC-10) están en [`../threat-models/`](../threat-models/README.md).
