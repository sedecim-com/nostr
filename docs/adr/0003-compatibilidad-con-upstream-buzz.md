# ADR 0003 · Política de compatibilidad con upstream Buzz

- **Estado:** Propuesto · **Tarea:** DEC-03 (P1) · **Depende de:** ADR 0002 · **Fecha:** 2026-09-26
- **Aprobación:** pendiente

## Contexto
Buzz evoluciona rápido: más de 200 tags y varios cambios de protocolo por mes. El scope pide pin, suite E2E y
capa de adaptadores (§6.3, §25). El gate ya detectó divergencias reales: timestamps de NIP-59, media
que no acepta blobs cifrados y kinds de Marmot rechazados.

## Decisión propuesta
**Cadencia**
- Sync ordinario **mensual** (primera semana del mes) desde `vendor/upstream`.
- Sync **extraordinario en 72 h** ante un aviso de seguridad upstream que afecte al subset incluido.

**Criterios de adopción** (todos obligatorios):
1. `npm run test:interop` en verde contra la imagen nueva: gate de Buzz, stack completo y Marmot en el
   secure-relay.
2. Revisión del changelog upstream buscando cambios en: registro de kinds, NIP-42/auth, fan-out y
   scoping de canales, validación de media, límites de timestamps.
3. Revisión de seguridad del diff en `buzz-auth`, `buzz-media`, `buzz-relay/src/handlers/ingest.rs` y
   `admission.rs`.
4. Los adaptadores del SDK siguen justificados. Si upstream corrige un comportamiento, se retira el
   adaptador en el mismo ciclo (p. ej. FR017-05 con el issue #4192).

**Parches propios**
- Solo en `product/main`. Cada parche lleva un issue o PR abierto upstream, o una justificación escrita
  de por qué no se envía.
- Límite: **como máximo 5 parches vivos**. Por encima de ese número, se prioriza upstreamear o sustituir
  el parche por un adaptador.

**Rollback**
- `infra/buzz/PIN` conserva el historial en git. Volver atrás es revertir el commit del PIN y el digest
  del compose. Tiempo objetivo: menos de 30 minutos.
- Las migraciones de Postgres de Buzz no siempre son reversibles: antes de cada sync se hace un backup
  (`docs/runbooks/restore.md`) y se prueba el rollback en staging.

## Consecuencias
- BUZZ-05 automatiza la PR mensual con el gate.
- El pin de desktop sigue la misma política con su propio tag.
