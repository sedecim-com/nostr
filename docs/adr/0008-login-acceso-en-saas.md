# ADR 0008 · Login de Acceso (Cognito) obligatorio en el modo SaaS

- **Estado:** Aceptado · **Fecha:** 2026-09-26
- **Aprobación:** responsable de producto (vic2099), 2026-09-26

## Contexto
Acceso Nostr se ofrece como SaaS de Sedecim y como despliegue self-hosted. Los usuarios de Sedecim ya
tienen cuenta en Acceso, que usa AWS Cognito User Pools vía Amplify y cookies en `.acce.so`. El scope
exige que la centralización sea opcional y que la identidad Nostr no dependa del operador.

## Decisión
- **SaaS** (`config.json` → `"mode": "saas"` con la sección `cognito`):
  - Hay que entrar con la cuenta de Acceso antes de abrir cualquier identidad.
  - Se usa el mismo user pool y la misma configuración de Amplify que `acceso-frontend`.
  - Con `cookieDomain`, la sesión se comparte por cookies igual que en Acceso.
  - Si `saas` no trae configuración de Cognito, el arranque falla: nunca se entra sin login.
- **Self-hosted**: no hay Cognito; el SDK de Amplify ni siquiera se descarga, porque se carga de forma diferida.
- **La identidad sigue siendo la npub**: el login de Acceso autoriza el uso del servicio pero no custodia llaves. La nsec no sale del vault local (ADR 0007).
- **Vinculación opcional y explícita**:
  - El usuario puede asociar una persona a su cuenta de Acceso marcando el consentimiento.
  - La web envía el ID token al identity-service con autenticación NIP-98.
  - El servicio verifica el token con RS256 contra el JWKS del pool y comprueba issuer, `token_use`, audiencia/cliente y expiración, igual que `authentication-server-api`.
  - El servicio solo guarda `issuer` y `sub` (tabla `external_logins`). Un login de Acceso no puede quedar vinculado a dos cuentas.
- **Cierre de sesión**: salir de Acceso en una pestaña bloquea el vault en todas (`BroadcastChannel('auth')`).

## Consecuencias
- En SaaS, el operador sabe qué usuario de Acceso usa el servicio. Solo sabe qué npub es suya si el usuario la vincula.
- Las cookies de Amplify son legibles por JS, como en Acceso: un XSS podría robar la sesión de Acceso. Mitigaciones:
  - CSP estricta con nonce por petición, sin `unsafe-inline`.
  - La sesión de Acceso no da acceso a las llaves Nostr.
- El login en el SaaS no controla el acceso al relay. Si se quiere restringir el relay a usuarios de Acceso, se hace con el allowlist NIP-42 del modo institucional (FR023-04).
