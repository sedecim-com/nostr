# ADR 0001 · Nombre y licencia del proyecto open source

- **Estado:** Propuesto · **Tarea:** DEC-01 (P0) · **Fecha:** 2026-09-26
- **Aprobación:** pendiente (responsable de producto y asesoría legal)

## Contexto
El repositorio se creó con licencia **MIT** y paquetes bajo el scope `@sedecim`. El relay y el cliente de
early release proceden de Block Buzz, con licencia **Apache-2.0** (`infra/buzz/PIN`). La plataforma
maneja criptografía y custodia de llaves, un área con historial de patentes, y se ofrecerá como
self-hosted y como SaaS.

## Opciones de licencia
| Opción | A favor | En contra |
|---|---|---|
| **MIT** (actual) | Máxima adopción; es compatible con dependencias MIT (noble, marmot-ts, ts-mls, MDK) | No incluye concesión explícita de patentes; hay que gestionar dos licencias con el fork Apache |
| **Apache-2.0** | Concesión y retorsión de patentes; misma licencia que el fork de Buzz, un único régimen de NOTICE; compatible con dependencias MIT | Requiere NOTICE y marcar los cambios; algo más de fricción para contribuidores |
| **AGPL-3.0** | Obliga a publicar las modificaciones de quien opere un SaaS derivado | Frena la adopción institucional; es incompatible con parte del ecosistema; choca con la estrategia de SaaS propio |

## Decisión propuesta
1. **Licencia: Apache-2.0** para el código de este repositorio, por la concesión de patentes en un
   producto criptográfico y por tener un solo régimen legal con el fork de Buzz. El titular del copyright
   (`LICENSE`: sedecim) puede relicenciar el código publicado bajo MIT, siempre que no haya aportaciones
   de terceros sin cesión de derechos. Hay que confirmarlo sobre el historial antes del cambio.
2. **Nombre:** mantener el identificador técnico `sedecim-nostr` y el scope npm `@sedecim` hasta
   elegir la marca comercial. El nombre de marca queda **fuera de este ADR**: requiere una búsqueda
   de marcas y una decisión de producto.

## Consecuencias
- Sustituir `LICENSE`, el campo `license` de todos los `package.json` y añadir `NOTICE`.
- La compatibilidad con Apache-2.0 del fork queda resuelta por construcción (misma licencia).
- Si se mantiene MIT, el fork sigue en Apache-2.0 como repositorio separado con su propio `NOTICE`
  (ver `docs/buzz-fork/legal-checklist.md`), y la combinación sigue siendo válida.
