# ADR 0002 · Subset de Buzz y versión fijada para F0

- **Estado:** Propuesto · **Tarea:** DEC-02 (P0) · **Fecha:** 2026-09-26
- **Aprobación:** pendiente

## Contexto
Buzz es un monorepo con 33 crates Rust más desktop (Tauri/React), mobile (Flutter), admin-web y web.
Gran parte no corresponde al alcance de la plataforma: agentes de IA, mesh inter-relay, voz y
workflows. Cada componente que se compila y se despliega amplía la superficie de ataque y el trabajo
de sincronizar con upstream.

## Versión fijada
| Componente | Pin | Evidencia |
|---|---|---|
| Relay | commit `02c6309f` (2026-09-25), relay 0.2.1 | `infra/buzz/PIN`, `docs/interop/buzz-02c6309-report.json` |
| Imagen | `ghcr.io/block/buzz@sha256:da30acf8…` (tag `main` a esa fecha) | `docker-compose.yml`; se reemplazará por la imagen propia de `buzz-image.yml` |
| Desktop | release `desktop-v0.5.24` (`3befaf16`, 2026-09-22) | tag upstream |

## Subset propuesto
**Se incluye** (se compila, se despliega y se da soporte):
`buzz-relay`, `buzz-core`, `buzz-db`, `buzz-auth`, `buzz-pubsub`, `buzz-media`, `buzz-search`,
`buzz-audit`, `buzz-deletion`, `buzz-feature-flags`, `buzz-admin` (operación), `buzz-sdk` y
`buzz-test-client` (solo pruebas), `desktop/` (early release) y `admin-web/`.

**Se excluye o se deshabilita por configuración:**
| Componente | Motivo |
|---|---|
| `buzz-acp`, `buzz-agent`, `sprig`, `buzz-dev-mcp`, `buzz-persona`, `buzz-cli`, `buzz-backend-kubernetes` | Agentes de IA y agentes remotos: fuera del alcance y con superficie de ataque alta |
| `buzz-workflow` (kinds de workflow/approval) | Fuera de alcance en F0 |
| `buzz-relay-mesh`, `buzz-mesh-smoke` | Mesh QUIC inter-relay: la resiliencia multi-relay está en nuestro SDK |
| `buzz-voice`, huddles | Fuera de alcance |
| `buzz-push-gateway` | Pendiente de DEC-08 (notificaciones); `BUZZ_PUSH_ENABLED=false` |
| Servidor git (`git-*`, `BUZZ_GIT_*`) | Fuera de alcance; se mantiene la configuración mínima que el relay exige para arrancar |
| `buzz-pair-relay`, `buzz-pairing-cli` (NIP-AB) | Se reevalúa en F4 para el multi-dispositivo |
| `mobile/` (Flutter) | Integración progresiva en S6 (BUZZ-06); ver ADR 0004 |

## Decisión propuesta
Fijar el relay en `02c6309` y el desktop en `desktop-v0.5.24`. El fork construye y publica solo el
subset incluido. Lo excluido se deshabilita por configuración, sin borrar código, para no complicar
el rebase con upstream (ADR 0003).

## Consecuencias
- `buzz-image.yml` construye el target `runtime` del relay. El desktop requiere su propio pipeline
  (BUZZ-04).
- Deshabilitar sin borrar mantiene el diff con upstream pequeño, pero ese código sigue en la imagen. La
  revisión de seguridad (SEC-02) debe confirmar que las rutas deshabilitadas no son alcanzables.
