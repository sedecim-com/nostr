# ADR 0002 · Buzz upstream sin fork y versión fijada para F0

- **Estado:** Aceptado · **Tarea:** DEC-02 (P0) · **Fecha:** 2026-09-26
- **Aprobación:** responsable de producto (vic2099), 2026-09-26
- **Cambio de scope:** el scope (§6.3) preveía un fork controlado de Buzz. Esta decisión lo sustituye por
  Buzz upstream sin modificar, fijado por digest.

## Contexto
El plan original era mantener un fork (`vendor/upstream` + `product/main`) con parches mínimos. Tras el
sprint S1 el fork tendría **cero parches**: cada divergencia encontrada por el gate se resolvió fuera del
relay:

| Divergencia de Buzz | Resolución sin tocar el relay |
|---|---|
| Gift wraps con jitter de 2 días rechazados | Adaptador de jitter acotado en el SDK (flags del gate) |
| `/media` no acepta blobs cifrados | `blob-store` propio para adjuntos cifrados |
| Kinds Marmot rechazados | `secure-relay` (ADR 0006) |
| REQ anónimas rechazadas, fan-out por canal, tenant por `Host` | Identidad de servicio, suscripción `#h` y URL pública en el indexer |

Además, el early release usa solo clientes propios (web SaaS y CLI); no se rebrandean desktop ni mobile de
Buzz, que siguen funcionando contra nuestro relay porque hablan el mismo protocolo.

## Decisión
- **Sin fork.** Se usa la imagen publicada por Block, fijada por digest en `infra/buzz/PIN`, en
  `docker-compose.yml` (`BUZZ_IMAGE`) y en `deploy/k8s/base/kustomization.yaml`.
- **Pin de F0:** relay en el commit `02c6309f` (2026-09-25), imagen
  `ghcr.io/block/buzz@sha256:da30acf8…`. Evidencia: `docs/interop/buzz-02c6309-report.json`. El pin vigente vive
  en `infra/buzz/PIN` y cambia según ADR 0003, con su informe del gate en `docs/interop/`.
- **Superficie:** solo se despliega el relay. Los componentes de Buzz que no usamos (agentes, desktop,
  mobile, admin-web) no se ejecutan. Dentro del relay, push se desactiva explícitamente
  (`BUZZ_PUSH_ENABLED=false`) y el resto de funciones opcionales quedan en sus valores por defecto; git
  mantiene la configuración mínima que el relay exige para arrancar. No se compila una imagen reducida.
- **Cuándo se reabre:** solo si hace falta un cambio en el relay que upstream no acepte y que no pueda
  resolverse con un adaptador o un servicio aparte. Entonces se crea un ADR nuevo que reemplace a este.

## Consecuencias
- Se eliminan `scripts/buzz-fork.sh`, `docs/buzz-fork/` y el workflow de build de la imagen. Las tareas
  BUZZ-01/02/03 (fork, obligaciones Apache del fork, build propio) y BUZZ-04/06 (rebrand de desktop y
  mobile) se descartan.
- No hay código de Buzz en este repositorio ni se redistribuye una imagen modificada: la única
  obligación es la atribución en `NOTICE`.
- Dependemos del ritmo de upstream para correcciones del relay; la política de pin y actualización está
  en ADR 0003. Todo el código del relay sigue en la imagen: la revisión de seguridad (SEC-02) debe
  inventariar qué rutas opcionales quedan alcanzables y desactivarlas por configuración.
