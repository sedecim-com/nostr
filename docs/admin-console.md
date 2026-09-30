# Consola de administración (OPS-07)

Consola web para el modo institucional: gestiona sobre el **policy-engine** las personas (sujetos),
los recursos y sus políticas, los dispositivos, las rotaciones de clave MLS, el directorio
organizacional, la retención y la auditoría. Del **identity-service** solo usa la consulta de vínculos
visibles, porque ese servicio no tiene rutas de administración: nunca lista cuentas.

Código: `apps/admin-console` (React 19 + MUI 9 + Vite). Cliente tipado del API: `apps/admin-console/src/api.ts`.

## Autenticación

- El administrador entra con un signer Nostr: **extensión NIP-07** o **bunker NIP-46** (solo se piden
  los permisos `get_public_key` y `sign_event:27235`).
- **Llave local (nsec)**: solo para desarrollo, marcada como tal en la pantalla y en la cabecera. Solo
  aparece si `config.json` tiene `"devLocalKey": true`. En `infra/web/admin-config.json` y en stage está
  desactivada (un test de despliegue lo comprueba).
- Cada petición lleva `Authorization: Nostr <evento kind 27235>` (NIP-98) firmado para la URL exacta
  (con la query), el método y el hash del cuerpo. El policy-engine solo acepta las claves de
  `POLICY_ADMIN_PUBKEYS`. La sesión solo se abre si una petición de administración con esa llave
  tiene éxito.
- La consola no guarda nada: la llave o la conexión viven en la memoria de la pestaña; al recargar
  o al cerrar sesión hay que volver a entrar.

## Pantallas

| Pantalla | Qué hace | API |
| --- | --- | --- |
| Personas | Alta y edición de roles y atributos (editar a una persona revocada no la reactiva); revocación con diálogo que explica la rotación MLS; muestra las rotaciones devueltas; **Reactivar** explícito y auditado, avisando de que los dispositivos siguen revocados | `GET /v1/subjects`, `PUT /v1/subjects/:pubkey`, `POST /v1/subjects/:pubkey/revoke`, `POST /v1/subjects/:pubkey/reactivate` |
| Recursos y políticas | Tipo, sensibilidad, reglas (JSON validado en el cliente) y miembros explícitos | `GET /v1/resources`, `PUT /v1/resources/:id` |
| Dispositivos | Lista por titular, registro, revocación (muestra rotaciones), nivel de confianza (registrado / atestiguado) y **Registrar passkey** | `GET /v1/devices?owner=`, `POST /v1/devices`, `POST /v1/devices/:id/revoke`, `POST /v1/devices/:id/webauthn/options` → `navigator.credentials.create` → `POST /v1/devices/:id/webauthn/register` |
| Rotaciones pendientes | Grupos MLS en los que hay que publicar un commit que quite al miembro; marcar como hecha | `GET /v1/rotations?status=pending`, `POST /v1/rotations/:id/done` |
| Directorio | Cargo y unidad ↔ npub, con el aviso de que nunca se publica | `GET/PUT/DELETE /v1/directory[/:pubkey]` |
| Retención | Días por recurso (vacío = sin borrado automático) y retención legal; muestra el texto `notice` del API de forma destacada. Los grupos MLS muestran «No aplica» y no se editan (FR023-12) | `GET /v1/retention`, `PUT /v1/retention/:resourceId` |
| Auditoría | Lo que hacen los administradores. Tabla paginada en el servidor (`limit`, `before` = `id` de la última fila) y filtros por actor y acción sobre la página cargada | `GET /v1/audit?limit=&before=` |
| Accesos | Decisiones de acceso del policy-engine (persona, dispositivo, recurso, acción, permitido o denegado). Paginada como la auditoría; el filtro por recurso lo aplica el servidor. Indica cuántos días se guardan (FR023-12) | `GET /v1/access-log?limit=&before=&resource=` |
| Vínculos de identidad | Vínculos públicos, o selectivos con el administrador en la audiencia | identity-service `GET /v1/links/visible/:pubkey` |

Las opciones de WebAuthn y la credencial viajan en JSON con los campos binarios en base64url. La
verificación de la atestación es del policy-engine.

## Configuración y despliegue

`config.json` junto a la app:

```json
{ "policyEngineUrl": "http://localhost:8083", "identityServiceUrl": "http://localhost:8082", "devLocalKey": false }
```

- **Imagen web**: el `Dockerfile` construye la consola (`npm run build:admin`) y nginx la sirve en
  `/admin/` con la misma CSP estricta que la web (sin scripts inline; estilos con nonce por petición).
- **Compose**: monta `infra/web/admin-config.json` (o `WEB_ADMIN_CONFIG`) en
  `/usr/share/nginx/html/admin/config.json`. El policy-engine recibe `CORS_ORIGINS=${WEB_ORIGIN}` para
  aceptar las llamadas del navegador. Consola: http://localhost:8080/admin/
- **Kubernetes**: ConfigMap `web-admin-config` (`deploy/k8s/base/files/admin-config.json`, copia de
  `infra/web/admin-config.json`; stage la reemplaza con sus URLs) montado en el Deployment `web`, y
  `CORS_ORIGINS=$(WEB_ORIGIN)` en `policy-engine`.
- `/admin/` es público como el resto de la web; la protección real es NIP-98 más la lista de
  administradores. Si la red lo permite, restringe también `/admin/` en el proxy de borde.

## Desarrollo y pruebas

```bash
npm run dev:admin        # http://localhost:5174 (static/config.json permite la llave local)
npm run build:admin      # apps/admin-console/dist
npx vitest run apps/admin-console
npm run test:browser     # incluye tests/browser/admin-console.e2e.ts
```

El E2E levanta el policy-engine real en el mismo proceso (su API y su motor, con repositorio en memoria y la
verificación WebAuthn incluida; FR023-13), el identity-service real y un relay de prueba para el bunker NIP-46. Lo
que guarda cada acción se comprueba leyendo el propio motor, nunca a través de la consola. Recorre el alta, la edición, la revocación y la reactivación, las rotaciones, la
paginación de la auditoría, el aviso de retención y el alta de una passkey con el autenticador virtual
de Chromium (CDP `WebAuthn.addVirtualAuthenticator`). También pasa axe sin violaciones graves o
críticas y comprueba que no haya ids duplicados, violaciones de CSP ni errores de página.
