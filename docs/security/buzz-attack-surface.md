# Superficie de ataque de Buzz (SEC-12)

- **Estado:** Parcial · **Tarea:** SEC-12 (#258) · **Fecha:** 2026-09-30
- **Pin revisado:** `infra/buzz/PIN` (commit `0ee6093`). Las rutas se leyeron del router upstream en el commit `12dbb11`
  (2026-09-29), el más reciente que se puede leer aquí, un día anterior al pin.
- **Para quién:** el pentest de SEC-02 (alcance en [`audit-scope.md`](audit-scope.md)) y quien despliegue el relay.

## Resumen

- Buzz registra **unas 40 rutas HTTP y WebSocket**, no solo el relay Nostr: API de operador, git, invitaciones, puente
  HTTP, moderación, workflows, audio de huddles y una API de administración opcional.
- Nuestro producto usa **dos cosas**: el WebSocket con el documento NIP-11 en `/` y la media Blossom en `/media/*`.
- Hasta esta tarea el edge (nginx en Kubernetes, Caddy en compose con TLS) reenviaba **todo** el host del relay a
  Buzz. Ahora ese host reenvía solo esas dos y contesta con su propio 404 a lo demás, también a las variantes que
  solo *parecen* una ruta permitida (`/media/../operator/…`, `%2e%2e`, `//`, mayúsculas).
- La configuración del stack deja apagado lo opcional que Buzz deja apagar. Lo que no se puede apagar por variable
  (el git HTTP, el audio) se niega en el edge.
- Lo que queda alcanzable, y por tanto es lo que el pentest debe atacar, está en [«Lo que sigue alcanzable»](#lo-que-sigue-alcanzable).

## Cómo se comprueba

| Qué | Cómo | Dónde corre |
|---|---|---|
| El edge reenvía solo `/` y `/media/*` | `bash scripts/edge-check.sh`: la config real de nginx, en la imagen fijada, delante de un upstream de pega que contesta `UPSTREAM-HIT` a cualquier ruta; cada ruta denegada y cada variante debe dar el 404 del edge | CI, job `deploy-config` |
| Caddy hace lo mismo | `caddy validate` (job `compose`) y `tests/scripts/buzz-surface.test.ts` (el bloque del relay) | CI |
| Buzz no contesta sin credenciales lo que las exige | `npx tsx scripts/buzz-surface.ts --relay http://localhost:3000`: una petición por ruta, sin credenciales; ninguna ruta que las exija puede dar 2xx o 3xx y ninguna puede dar 5xx | CI, job `stack`, contra la imagen fijada |
| Este documento y el código dicen lo mismo | la tabla de rutas se genera de `scripts/buzz-surface-routes.ts` y `tests/scripts/buzz-surface.test.ts` la compara | CI |

## Quién llega a qué

| Puerto | Qué sirve | Quién llega |
|---|---|---|
| 3000 | Todas las rutas de la tabla de abajo | El edge (solo reenvía `/` y `/media/*`); en compose sin TLS se publica entero en `localhost` (desarrollo); el servicio oculto `.onion` del perfil tor apunta aquí sin edge (`infra/tor/torrc`) |
| 8080 | Puerto de salud: `/_liveness`, `/_readiness`, `/_status`, `/_mesh` | Solo dentro de la red: sondas de compose y de Kubernetes, blackbox y Prometheus. Compose no lo publica; el Service de Kubernetes lo expone dentro del cluster |
| 9102 | Métricas de Prometheus | Igual que el 8080 |

## Rutas

Tabla generada de `scripts/buzz-surface-routes.ts` (`npx tsx scripts/buzz-surface.ts --table`). «Qué pide sin
credenciales» es lo que Buzz exige en esta configuración; lo comprueba la sonda en cada pin.

<!-- routes:start -->
| Ruta | Grupo | Qué pide sin credenciales | ¿La reenvía el edge? | Nota |
|---|---|---|---|---|
| `GET /` | websocket | nada (pública) | sí | WebSocket (NIP-01, NIP-42) y documento NIP-11 |
| `GET /info` | websocket | nada (pública) | no (404 del edge) | información del relay |
| `GET /.well-known/nostr.json` | websocket | nada (pública) | no (404 del edge) | nombres NIP-05 |
| `GET /health` | health | nada (pública) | no (404 del edge) | sonda; el stack sondea el puerto de salud |
| `GET /_liveness` | health | nada (pública) | no (404 del edge) | sonda |
| `GET /_readiness` | health | nada (pública) | no (404 del edge) | sonda |
| `POST /events` | bridge | credenciales (NIP-98, BUD-01 o un secreto) | no (404 del edge) | puente HTTP para publicar (NIP-98); los clientes usan el WebSocket |
| `POST /query` | bridge | credenciales (NIP-98, BUD-01 o un secreto) | no (404 del edge) | puente HTTP para leer (NIP-98) |
| `POST /count` | bridge | credenciales (NIP-98, BUD-01 o un secreto) | no (404 del edge) | puente HTTP para contar (NIP-98) |
| `POST /gifs/search` | gifs | credenciales (NIP-98, BUD-01 o un secreto) | no (404 del edge) | proxy a un proveedor de GIF de terceros (NIP-98); necesita su clave de API, que no ponemos |
| `POST /gifs/share` | gifs | credenciales (NIP-98, BUD-01 o un secreto) | no (404 del edge) | el mismo proxy |
| `GET /workflows/{workflow_id}/runs` | workflows | credenciales (NIP-98, BUD-01 o un secreto) | no (404 del edge) | ejecuciones de un workflow |
| `GET /workflows/{workflow_id}/runs/{run_id}/approvals` | workflows | credenciales (NIP-98, BUD-01 o un secreto) | no (404 del edge) | aprobaciones de una ejecución |
| `POST /hooks/{id}` | workflows | credenciales (NIP-98, BUD-01 o un secreto) | no (404 del edge) | webhook de workflow, autenticado por un secreto y no por NIP-98 |
| `GET /operator/communities` | operator | clave de operador | no (404 del edge) | lista las comunidades de la clave de operador (NIP-98); exige RELAY_OPERATOR_PUBKEYS |
| `POST /operator/communities` | operator | clave de operador | no (404 del edge) | provisiona una comunidad (scripts/buzz-provision-community.ts) |
| `POST /operator/listener/pubkeys` | operator | clave de operador | no (404 del edge) | registra las claves que sigue un listener de operador |
| `DELETE /operator/listener/pubkeys` | operator | clave de operador | no (404 del edge) | las retira |
| `POST /operator/communities/archive` | operator | clave de operador | no (404 del edge) | archiva una comunidad |
| `POST /operator/communities/unarchive` | operator | clave de operador | no (404 del edge) | la desarchiva |
| `POST /operator/communities/delete` | operator | clave de operador | no (404 del edge) | la borra |
| `GET /operator/communities/availability` | operator | clave de operador | no (404 del edge) | comprueba si un host está libre |
| `POST /operator/communities/transfer` | operator | clave de operador | no (404 del edge) | transfiere la propiedad |
| `POST /api/invites` | invites | credenciales (NIP-98, BUD-01 o un secreto) | no (404 del edge) | crea una invitación (dueño o admin) |
| `GET /api/join-policy` | invites | nada (pública) | no (404 del edge) | política que debe aceptar quien se une |
| `GET /api/join-policy/terms` | invites | nada (pública) | no (404 del edge) | página de términos de servicio |
| `GET /api/join-policy/privacy` | invites | nada (pública) | no (404 del edge) | página de política de privacidad |
| `POST /api/invites/accept-policy` | invites | credenciales (NIP-98, BUD-01 o un secreto) | no (404 del edge) | acepta la política |
| `POST /api/invites/claim` | invites | nada (pública) | no (404 del edge) | canjea una invitación (fuera de la puerta de membresía; exige una invitación válida) |
| `GET /moderation/reports` | moderation | credenciales (NIP-98, BUD-01 o un secreto) | no (404 del edge) | cola de moderación (NIP-98 y autorización de moderador) |
| `GET /moderation/audit` | moderation | credenciales (NIP-98, BUD-01 o un secreto) | no (404 del edge) | auditoría de moderación |
| `GET /moderation/restricted` | moderation | credenciales (NIP-98, BUD-01 o un secreto) | no (404 del edge) | contenido restringido |
| `POST /_mesh/demo/echo` | mesh | apagada por configuración | no (404 del edge) | solo de banco de pruebas: 404 salvo con BUZZ_MESH y BUZZ_MESH_DEMO_ECHO |
| `GET /huddle/{channel_id}/audio` | huddle | credenciales (NIP-98, BUD-01 o un secreto) | no (404 del edge) | WebSocket de audio de los huddles |
| `PUT /upload` | media | credenciales (NIP-98, BUD-01 o un secreto) | no (404 del edge) | subida Blossom en la raíz (BUD-02); los clientes usan /media/upload |
| `PUT /media/upload` | media | credenciales (NIP-98, BUD-01 o un secreto) | sí | subida Blossom |
| `GET /media/{sha256_ext}` | media | credenciales (NIP-98, BUD-01 o un secreto) | sí | descarga Blossom; Buzz pide autorización BUD-01 también para descargar |
| `HEAD /media/{sha256_ext}` | media | credenciales (NIP-98, BUD-01 o un secreto) | sí | comprobación de existencia Blossom |
| `GET /git/{owner}/{repo}/info/refs` | git | credenciales (NIP-98, BUD-01 o un secreto) | no (404 del edge) | git smart HTTP (Buzz aloja repositorios); nuestro producto no lo usa |
| `POST /git/{owner}/{repo}/git-upload-pack` | git | credenciales (NIP-98, BUD-01 o un secreto) | no (404 del edge) | git fetch |
| `POST /git/{owner}/{repo}/git-receive-pack` | git | credenciales (NIP-98, BUD-01 o un secreto) | no (404 del edge) | git push |
| `POST /internal/git/policy` | git | solo localhost | no (404 del edge) | comprobación de política del hook pre-receive, solo desde localhost |
| `GET /api/admin/v1/communities` | admin | apagada por configuración | no (404 del edge) | API de administración, montada solo con BUZZ_ADMIN_HOST, que no ponemos |
<!-- routes:end -->

## Configuración de Buzz que abre o cierra superficie

| Variable | Qué abre | Aquí |
|---|---|---|
| `BUZZ_ADMIN_HOST` | monta `/api/admin/v1` y su web | sin definir (`docker-compose.yml`, `deploy/k8s`) |
| `BUZZ_MESH`, `BUZZ_MESH_DEMO_ECHO` | malla entre relays y su eco de prueba | sin definir: apagadas |
| `BUZZ_KLIPY_API_KEY` | el proxy de GIF llama a un tercero | sin definir |
| `BUZZ_PUSH_ENABLED` | push del propio Buzz (NIP-PL) | `false` |
| `BUZZ_NIP_FI_MODE` | JWT en el upgrade del WebSocket (NIP-FI) | **debe seguir sin definir**: en `enforce` los servicios internos, que solo hacen NIP-42, no entrarían (`docs/buzz-integration.md`) |
| `RELAY_OPERATOR_PUBKEYS`, `RELAY_OPERATOR_API_ORIGIN` | las rutas `/operator/*` aceptan claves de operador | vacías por defecto (`docker-compose.yml`): sin aprovisionamiento. Se ponen solo para aprovisionar la comunidad del `.onion` (`scripts/buzz-provision-community.ts`), contra el puerto 3000 por `localhost` o por la red interna, no por el host público, que ya no reenvía `/operator/*` |
| `BUZZ_OPERATOR_LISTENERS` | entrega a listeners de operador | sin definir |
| `BUZZ_GIT_REPO_PATH`, `BUZZ_GIT_HOOK_HMAC_SECRET` | dónde guarda Buzz sus repositorios git. En el código revisado el git HTTP no tiene una variable que lo apague: sus rutas siempre están montadas | puestas (`/data/git`, volumen `relay-git`): las rutas `/git/*` existen y el edge las niega |
| `BUZZ_HUDDLE_AUDIO_AVAILABLE` | WebSocket de audio de los huddles | activo por defecto en Buzz; el edge niega la ruta |
| `BUZZ_WEB_DIR`, `BUZZ_ADMIN_WEB_DIR`, `BUZZ_SERVE_GIT_WEB_GUI` | Buzz sirve páginas estáticas | sin definir |
| `BUZZ_REQUIRE_AUTH_TOKEN`, `BUZZ_PUBKEY_ALLOWLIST`, `BUZZ_REQUIRE_RELAY_MEMBERSHIP` | puertas de acceso al relay | `false` en el stack de referencia (los clientes de terceros se autentican solo con NIP-42). El componente institucional pone `BUZZ_PUBKEY_ALLOWLIST=true` |
| `BUZZ_CORS_ORIGINS` | orígenes permitidos por CORS | el origen de la web (`WEB_ORIGIN`) |

## El edge

| Edge | Dónde | Qué reenvía al relay |
|---|---|---|
| nginx (Kubernetes) | `deploy/k8s/base/files/core-server.conf`, el `server` de `*-relay.` | `location = /` y `location /media/`. `location = /media` y `location /` devuelven 404 sin pasar por Buzz |
| Caddy (compose con TLS) | `infra/caddy/Caddyfile`, `relay.{$DOMAIN}` | `path /` y `path /media/*`; el resto, `respond "not found" 404` |

Las dos coinciden a propósito: el WebSocket de NIP-42 y NIP-11 van por `/`, y el cliente Blossom sube a `/media/upload`
y baja de `/media/<hash>`. El 404 del edge no lleva cuerpo de Buzz, y eso es lo que distingue en la sonda («not found»)
una ruta negada por el edge de una ruta a la que Buzz contesta 404.

## Lo que sigue alcanzable

1. **`/` y `/media/*`** son la superficie legítima y la que debe atacar el pentest: el WebSocket (NIP-01, NIP-42,
   límites de marcos y de suscripciones, tasas) y la media (autorización BUD-01, tipos y tamaños, subidas
   concurrentes).
2. **El `.onion`.** El servicio oculto del perfil tor apunta directo a `relay:3000` (`infra/tor/torrc`): no hay edge, así
   que por el onion son alcanzables todas las rutas de la tabla. Las protege la autenticación propia de Buzz
   (NIP-98, BUD-01, clave de operador), que es lo que la sonda verifica en el puerto 3000. Un proxy delante del onion
   que aplique la misma lista queda como deuda.
3. **Compose sin TLS** (`docker compose up`) publica el puerto 3000 entero en `localhost`. Es el modo de desarrollo.
4. **Los puertos 8080 y 9102** están en el Service de Kubernetes y cualquier pod del cluster los alcanza
   (`/_status`, `/_mesh`, métricas). Hoy no hay una NetworkPolicy que los limite a Prometheus y al blackbox exporter.
5. **Rutas nuevas en un pin nuevo.** El edge niega por defecto, y la sonda detecta una ruta conocida que deje de exigir
   credenciales. Una ruta añadida después del commit `12dbb11` no está en la tabla: hay que releer el router en cada
   revisión de pin (`docs/buzz-integration.md`, ADR 0003).

## Cómo repetirlo

```bash
bash scripts/edge-check.sh                                          # el edge real, en docker
npx tsx scripts/buzz-surface.ts --relay http://localhost:3000       # el relay, sin credenciales
npx tsx scripts/buzz-surface.ts --edge https://<host del relay>     # a través del edge público (stage, producción)
npx tsx scripts/buzz-surface.ts --table                             # la tabla de este documento
```

## Qué falta (por eso es Parcial)

- Ejecutar la sonda con `--edge` y `--relay` contra el stage real de AWS y anotar el resultado aquí (depende de
  NFR001-01).
- Leer el router del commit exacto del pin cuando se pueda.
- Un proxy delante del `.onion` y una NetworkPolicy para los puertos 8080 y 9102.
- La revisión del pentest (SEC-02).
