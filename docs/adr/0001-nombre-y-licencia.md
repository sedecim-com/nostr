# ADR 0001 · Nombre y licencia del proyecto open source

- **Estado:** Aceptado · **Tarea:** DEC-01 (P0) · **Fecha:** 2026-09-26
- **Aprobación:** responsable de producto (vic2099), 2026-09-26

## Contexto
El repositorio se creó con licencia **MIT** y paquetes bajo el scope `@sedecim`. El relay y el cliente de
early release proceden de Block Buzz, con licencia **Apache-2.0** (`infra/buzz/PIN`). La plataforma
maneja criptografía y custodia de llaves, un área con historial de patentes, y se ofrecerá como
self-hosted y como SaaS.

## Opciones de licencia
| Opción | A favor | En contra |
|---|---|---|
| **MIT** (actual) | Máxima adopción; es compatible con dependencias MIT (noble, marmot-ts, ts-mls, MDK) | No incluye concesión explícita de patentes |
| **Apache-2.0** | Concesión y retorsión de patentes; misma licencia que Buzz; compatible con dependencias MIT | Requiere NOTICE y marcar los cambios; algo más de fricción para contribuidores |
| **AGPL-3.0** | Obliga a publicar las modificaciones de quien opere un SaaS derivado | Frena la adopción institucional; es incompatible con parte del ecosistema; choca con la estrategia de SaaS propio |

## Decisión
1. **Licencia: Apache-2.0** para el código de este repositorio, por la concesión de patentes en un
   producto criptográfico. El historial de git solo contiene commits del titular (sedecim) y
   generados con Claude Code para él, sin aportaciones de terceros, así que el relicenciamiento desde MIT
   no requiere cesiones adicionales (comprobado el 2026-09-26).
2. **Nombre:** mantener el identificador técnico `sedecim-nostr` y el scope npm `@sedecim` hasta
   elegir la marca comercial. El nombre de marca queda **fuera de este ADR**: requiere una búsqueda
   de marcas y una decisión de producto.

## Consecuencias
- `LICENSE` pasa a Apache-2.0, el campo `license` de todos los `package.json` a `Apache-2.0` y se añade
  `NOTICE`.
- Buzz se usa sin modificar como imagen upstream (ADR 0002), así que no hay un segundo repositorio con
  obligaciones propias; `NOTICE` lo atribuye.
- Los contribuidores externos futuros aportan bajo Apache-2.0 (cláusula 5); no se exige CLA por ahora.
