# Runbook: eventos firmados y webhooks del policy-engine

Qué hacer cuando las entregas fallan, cuando una suscripción se desactiva, cuando se filtra un secreto y cuando toca
rotar una llave. Cómo funciona todo: `docs/institutional.md`, «Eventos firmados y webhooks» (OPS-16). Las rutas son de
admin (NIP-98), salvo `GET /v1/events/keys`.

## Entregas que fallan

1. `GET /v1/webhooks`: el `status` de cada suscripción y sus `consecutiveFailures` (intentos fallidos seguidos).
2. `GET /v1/webhooks/<id>/deliveries`: `lastError` y `lastStatus` de las últimas entregas, más nueva primero.
3. En los logs del policy-engine, `webhook delivery failed` con la suscripción, la entrega, el intento y la clase del
   error. Nunca llevan la URL, el cuerpo ni el secreto.

| `lastError` | Qué suele ser | Qué hacer |
|---|---|---|
| `http_4xx` | El receptor rechaza la firma (otro secreto, o su reloj a más de 300 s) o no conoce la ruta | Revisar el secreto y el reloj del receptor |
| `http_5xx` | Un error del receptor | Es suyo; los reintentos siguen |
| `timeout` | El receptor tarda más que `POLICY_WEBHOOK_TIMEOUT_MS` (10 s) | Que responda 2xx en cuanto guarde el evento y lo procese después |
| `connect`, `connection_closed`, `tls`, `dns` | La red, el certificado o el nombre del receptor | Probarlo desde fuera, p. ej. `curl -v https://…` |
| `redirect` | La URL redirige, y las redirecciones no se siguen | Dar de alta la URL final |
| `blocked_destination` | El nombre resuelve ahora a una dirección que no es pública | Si es legítimo, que resuelva a una pública; si no, es un intento de SSRF: darla de baja y revisar la auditoría |
| `invalid_destination` | La URL ya no pasa las comprobaciones (p. ej. se quitó `POLICY_WEBHOOKS_ALLOW_PRIVATE`) | Darla de baja y de alta con una URL válida |
| `payload_too_large` | Un evento de más de 64 KiB: no hay reintentos | Leerlo por el cursor |
| `lease_expired` | El proceso murió durante el último intento permitido | Leerlo por el cursor |
| `subscription_disabled` | La suscripción se desactivó con la entrega pendiente | Ver la sección siguiente |

Una entrega que falla del todo no se reintenta más, pero el evento sigue en `GET /v1/events`.

## Suscripción desactivada

Tras `POLICY_WEBHOOK_DISABLE_AFTER` intentos fallidos seguidos (15 por defecto) la suscripción pasa a `disabled`, sus
entregas pendientes fallan y no recibe eventos nuevos. La auditoría lo registra (`webhook.disable`, actor
`policy-engine`) y las suscripciones a ese tipo lo reciben.

1. Arregla la causa (tabla de arriba).
2. `POST /v1/webhooks/<id>/enable`: vuelve a `active`, con la cuenta de fallos a cero, desde el evento siguiente.
3. Lo que pasó mientras estaba desactivada se lee por el cursor: `GET /v1/events?after=<seq del último evento que
   recibió>`, página a página con el `next` de cada respuesta, hasta que `events` venga vacío. El receptor deduplica
   por `id`.

## Se filtró el secreto de una suscripción

El secreto no se guarda ni se puede volver a leer: se deriva de `POLICY_WEBHOOK_SECRETS_KEY`, el id y una sal.

1. Da de alta una suscripción nueva con la misma URL y tipos (`POST /v1/webhooks`): trae otro id y otro secreto.
2. Configura el receptor con el secreto nuevo y da de baja la vieja (`DELETE /v1/webhooks/<id>`).
3. Mientras tanto, quien tenga el secreto viejo puede falsificar entregas para ese receptor: que el receptor verifique
   también la firma Ed25519 del evento (`GET /v1/events/keys`), que no depende del secreto.

## Rotar la llave que firma los eventos

1. Genera la nueva: `openssl genpkey -algorithm ed25519 -out nueva.pem`, o su semilla en hex:
   `od -An -tx1 -N32 /dev/urandom | tr -d ' \n'`.
2. Sustitúyela:
   - Kubernetes: `POLICY_EVENTS_SIGNING_KEY` en Secrets Manager, `deploy/k8s/scripts/generate-secret.sh --yes`, aplica
     el Secret y `kubectl -n acceso-nostr rollout restart deployment/policy-engine`;
   - compose: el fichero del secreto y `docker compose up -d policy-engine`.
3. Al arrancar, el engine registra la llave pública nueva. `GET /v1/events/keys` da la nueva como `current` y sigue
   dando las anteriores, así que los eventos que firmaron se verifican igual. Durante un reinicio escalonado conviven
   réplicas con las dos llaves: las dos están publicadas.
4. Los consumidores que guardan una copia del JWKS la recargan al ver un `kid` que no conocen.

**Si la llave se comprometió**, además:

1. Añade su `kid` a `POLICY_EVENTS_REVOKED_KIDS` y reinicia. Deja de publicarse: los eventos que firmó ya no se
   verifican, porque quien tenga la llave podría falsificarlos. El engine no arranca si la llave actual está en esa
   lista, así que primero rota (pasos 1-3).
2. Pide a los consumidores que la quiten de su copia del JWKS.
3. Lo firmado con ella se coteja con `GET /v1/audit`.

## Rotar la llave de los secretos de webhook

Cambia todos los secretos de suscripción a la vez, y la API solo da un secreto en el alta.

1. Avisa a los receptores: sus entregas fallarán con la firma vieja hasta que tengan la nueva.
2. Genera la llave (`od -An -tx1 -N32 /dev/urandom | tr -d ' \n'`) y sustituye `POLICY_WEBHOOK_SECRETS_KEY` como en el
   paso 2 anterior.
3. Da de alta cada suscripción otra vez y lleva cada secreto nuevo a su receptor; da de baja las anteriores. Lo que
   se perdiera mientras tanto se lee por el cursor.
