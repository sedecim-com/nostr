# ADR 0003 · Política de pin y actualización de Buzz upstream

- **Estado:** Aceptado · **Tarea:** DEC-03 (P1) · **Depende de:** ADR 0002 · **Fecha:** 2026-09-26
- **Aprobación:** responsable de producto (vic2099), 2026-09-26

## Contexto
Buzz evoluciona rápido: más de 200 tags y varios cambios de protocolo por mes. El scope pide pin, suite E2E y
capa de adaptadores (§6.3, §25). El gate ya detectó divergencias reales: timestamps de NIP-59, media
que no acepta blobs cifrados, kinds de Marmot rechazados, REQ anónimas rechazadas y tenant por `Host`.
Sin fork (ADR 0002), actualizar Buzz es cambiar un digest.

## Decisión
**Cadencia**
- Revisión ordinaria **mensual** (primera semana del mes) de la última imagen upstream.
- Actualización **extraordinaria en 72 h** ante un aviso de seguridad upstream que afecte al relay.

**Cómo se prueba un candidato**
- Workflow `ci` en modo manual (`workflow_dispatch`) con el input `buzz_image` = digest candidato: levanta
  el stack completo con esa imagen y ejecuta el gate (`tests/interop`) y la comprobación de flags.

**Criterios de adopción** (todos obligatorios):
1. Gate en verde contra el candidato: Buzz, stack completo y Marmot en el secure-relay.
2. `interop-flags --check` sin deriva, o `infra/web/flags.json` regenerado y revisado en la misma PR.
3. Revisión del changelog upstream buscando cambios en: registro de kinds, NIP-42/auth y tenant por
   `Host`, fan-out y scoping de canales, validación de media, límites de timestamps.
4. Los adaptadores del SDK siguen justificados. Si upstream corrige un comportamiento, se retira el
   adaptador en el mismo ciclo (p. ej. FR017-05 con el issue #4192).

**Cómo se adopta**
- Una PR que cambia a la vez `infra/buzz/PIN` (commit, fecha, digest), el digest por defecto de
  `docker-compose.yml` y de `deploy/k8s/base/kustomization.yaml`, el informe en `docs/interop/` y, si cambian,
  los flags.

**Cambios que necesitemos en el relay**
- Se proponen upstream (issue o PR). Mientras tanto se resuelven con un adaptador o un servicio aparte.
  Si no hay alternativa, se reabre ADR 0002.

**Rollback**
- Revertir la PR del pin. Tiempo objetivo: menos de 30 minutos.
- Las migraciones de Postgres de Buzz no siempre son reversibles: antes de cada actualización se hace un
  backup (`docs/runbooks/restore.md`) y se prueba el rollback en staging.

## Consecuencias
- BUZZ-05 automatiza la revisión mensual: detectar una imagen nueva y lanzar el gate contra ella.
