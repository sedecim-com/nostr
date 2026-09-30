# SLO de disponibilidad del SaaS (NFR-001)

- **Objetivo:** 99,9 % de disponibilidad mensual (ventana móvil de 30 días) **por servicio**.
- **Presupuesto de error:** 0,1 % de 30 días = **43,2 minutos** de indisponibilidad al mes por servicio.
- **Latencia:** P95/P99 de ACK por relay y región, ver [Latencia](#latencia) (NFR-004).
- **Implementación:** [`deploy/monitoring`](../deploy/monitoring) (Prometheus, blackbox exporter,
  Alertmanager, Grafana), incluida en el overlay de stage. Reglas probadas con
  `promtool test rules deploy/monitoring/prometheus/tests/slo-availability.test.yml` (CI, job `deploy-config`).

## SLI

**Disponibilidad = fracción de sondas exitosas.** El blackbox exporter consulta cada 30 s el mismo
endpoint de salud que usan los healthchecks de compose y las probes de Kubernetes. Una sonda es exitosa si
responde 200 en menos de 5 s (y, para relays, si el documento NIP-11 tiene `name`). Buzz es la excepción:
compose y Kubernetes miran `/_readiness`, que desde el pin 8519db1 solo dice que el proceso está arriba, y la
sonda mira `/_status`. Esta exige que Postgres y Redis respondan según la última muestra del relay y que esa
muestra sea reciente (`"sample":"fresh"`).

| Servicio (`service`) | Endpoint sondeado | Qué significa "disponible" |
|---|---|---|
| `relay` | `http://relay:8080/_status` | Buzz arriba, con Postgres y Redis accesibles en una muestra reciente |
| `secure-relay` | `http://secure-relay:8080/` (NIP-11) | Relay de grupos Marmot aceptando conexiones |
| `indexer` | `http://indexer:8081/health` | Mirror respondiendo con su base de datos |
| `identity-service` | `http://identity-service:8082/health` | API de identidad |
| `policy-engine` | `http://policy-engine:8083/health` | Motor de políticas |
| `blob-store` | `http://blob-store:8085/health` | Adjuntos cifrados |
| `web` | `http://web:8080/flags.json` | Cliente web servido con sus flags de despliegue |
| `managed-signer` | `http://managed-signer:8084/health` | Firma custodial (solo SaaS) |
| `edge` | `http://edge:80/_edge_health` | Entrada pública (proxy detrás del ALB) |

Reglas de registro (`deploy/monitoring/prometheus/rules/slo-availability.rules.yml`):

- `sli:availability:ratio_rate<ventana>` para 5m, 30m, 1h, 2h, 6h, 1d, 3d y 30d, agregado por `service`.
- `slo:error_budget_remaining:ratio30d`: 1 = presupuesto intacto, 0 = agotado, negativo = SLO incumplido.
- `sli:buzz_http_errors:ratio_rate5m`: proporción de respuestas 5xx de Buzz (métrica propia de Buzz en
  `:9102`). Informativo, no genera alertas.

Limitaciones conocidas:

- Las sondas son internas al cluster: una caída del ALB, del DNS o del certificado no se ve. Pendiente: una
  sonda externa contra los hosts públicos.
- Las sondas miden disponibilidad, no latencia. La latencia de ACK por relay tiene su propia sección
  ([Latencia](#latencia)).
- Las ventanas de 30 días necesitan 30 días de historia: Prometheus retiene 35 días.

## Latencia

**SLI de latencia = P95 y P99 del tiempo publicación→`OK=true` por relay y región** (NFR-004). `OK=true`
solo significa "aceptado por ese relay" (NIP-01), no "recibido por el destinatario".

### Origen de las métricas

`@sedecim/metrics` (`packages/metrics`) es un exportador Prometheus propio que respeta el perfil de
telemetría (FR-022):

| Nivel de telemetría del perfil | Perfiles | Exportador |
|---|---|---|
| `none` | Soberano, Soberano Tor | **No arranca** (`TelemetryBlockedError`); no registra ni sirve nada |
| `minimal` | Conveniencia, Privado resiliente | Solo salud agregada; el host de cada relay se sustituye por un hash estable (qué relays usa alguien es una huella) |
| `standard` | Institucional, servicios del operador | Host del relay como etiqueta |

Las etiquetas nunca contienen pubkeys, ids de evento u operación, rutas o parámetros de la URL del relay ni
texto de las respuestas: solo `relay` (host; los relays `.onion` y los hosts que parecen identificadores
siempre como `onion-<hash>` / `relay-<hash>`), `region` (mapa configurable `RELAY_REGIONS=host=región,…`) y
clases de resultado. Métricas:

| Métrica | Tipo | Etiquetas |
|---|---|---|
| `nostr_relay_ack_latency_seconds` | histograma (buckets de 25 ms a 30 s) | `relay`, `region` |
| `nostr_relay_publish_total` | contador | `relay`, `region`, `result` (`ok`, `duplicate`, `timeout`, `connection`, `auth`, `rate-limited`, `rejected`, `blocked-policy`, `other`) |
| `nostr_outbox_depth` | gauge | — (operaciones sin quorum todavía) |
| `nostr_outbox_oldest_pending_age_seconds` | gauge | — |
| `nostr_outbox_failed_operations` | gauge | — |
| `nostr_outbox_relay_failures_total` | contador | `relay`, `region`, `reason` (mismas clases de fallo) |

Las cuatro `nostr_outbox_*` solo existen en un proceso que conecta un outbox (`attachEngine`), y hoy
ningún proceso desplegado lo hace:

- los outboxes están en los clientes (la web y el CLI), que no envían telemetría al SaaS;
- el indexer solo se suscribe y sondea, así que no publica un outbox vacío que parezca sano.

Por eso el monitoreo del SaaS no tiene reglas ni alertas de outbox (FR011-06). La web muestra el suyo a quien
lo usa (ver [Sin ocultarla al usuario](#sin-ocultarla-al-usuario)).

En el despliegue, el **indexer** sirve `/metrics` en un puerto interno (`METRICS_PORT=9464`, nunca por la
API pública ni por el edge) y, como el mirror solo se suscribe, publica una **sonda sintética de ACK**
(`ACK_PROBE_INTERVAL_MS`, 30 s en stage; evento efímero vacío, kind 20001, firmado por la identidad de
servicio, sin datos de usuarios). Prometheus lo recoge en el job `nostr-metrics`. El cliente soberano (CLI)
no tiene modo de larga duración y su perfil es `none`: no exporta nada por diseño.

### Reglas y alertas

`deploy/monitoring/prometheus/rules/relay-latency.rules.yml`, probadas con
`promtool test rules deploy/monitoring/prometheus/tests/relay-latency.test.yml`:

- `relay:ack_latency_seconds:p95_rate5m`, `…:p99_rate5m`, `…:p95_rate30m`, `…:p99_rate30m`:
  `histogram_quantile` **por relay y región** (nunca agregado entre relays: la degradación de uno no se diluye).
- `relay:ack_latency_seconds:p95_baseline1d`: P95 del día anterior sin la última hora.
- `relay:publish_failures:ratio_rate5m`.

| Alerta | Condición | `for` | Severidad |
|---|---|---|---|
| `RelayAckLatencyP95High` | P95 (5 min) > 2 s | 10 min | ticket |
| `RelayAckLatencyDegraded` | P95 (30 min) > 2 × línea base de 1 d y > 0,5 s | 30 min | ticket |
| `RelayPublishFailureRateHigh` | > 25 % de publicaciones sin `OK=true` | 15 min | ticket |
| `NostrMetricsMissing` | exportador caído (`up == 0`) | 10 min | ticket |

La alerta relativa detecta degradaciones que no cruzan el umbral absoluto; si la degradación dura más de
unas 2 h la línea base la absorbe y queda la absoluta. Dashboard: **Acceso Nostr · Latencia de relays**
(`grafana/dashboards/relay-latency.json`): tabla P95/P99/fallos por relay y región, series P95 y P99, P95
frente a 2× línea base, resultados de publicación y alertas activas.

### Sin ocultarla al usuario

El cliente web mide lo mismo localmente (P95 de las últimas 50 confirmaciones por relay, `RelayHealth` de
`@sedecim/relay-pool`) y la pestaña **Entrega** muestra la **Salud de relays**: un relay bloqueado,
desconectado, con 3 o más fallos seguidos o con P95 > 2 s (el mismo umbral que la alerta) aparece con el chip
**"degradado · P95 N ms"** y un aviso encima del outbox, en vez de reintentarse en silencio. Estas cifras
se calculan en el navegador y no se envían a ningún sitio.

### Qué hacer cuando salta

1. Dashboard de latencia: ¿un relay o todos? ¿una región? Si es uno, revisar `nostr_relay_publish_total` por
   `result` (timeouts frente a rechazos) y los logs del relay.
2. Si todos los relays de una región se degradan a la vez, sospechar de la red del cluster o del propio
   indexer (la sonda sale de él).

## Trazas (NFR007-02)

Los servicios con API HTTP (identity-service, policy-engine, continuity-vault, managed-signer,
notification-gateway, indexer y blob-store) pueden trazar sus peticiones. **Están apagadas por defecto**
(`TRACE_SAMPLE_RATE=0`): sin esa variable no se crea ninguna traza. **Los clientes no trazan**: la web, el CLI y
la consola no tienen trazador ni envían trazas (un test recorre sus fuentes), como dice su texto de telemetría.

**Qué se traza.** Un span por petición (el servidor común de `service-kit`, y el propio de blob-store) y, dentro
de él, un span hijo por cada `pool.query` a Postgres (`createPgPool`; las consultas de una transacción abierta con
`pool.connect()` no tienen span propio). Los workers (`rotation-worker`, `relay-allowlist`) solo sirven `/health`
y no trazan su trabajo de fondo.

**Muestreo.** Se decide una vez por traza, al empezar la petición, con probabilidad `TRACE_SAMPLE_RATE`: una
traza se guarda entera o no se guarda. Una traza no muestreada no crea spans ni ids. No se lee ni se envía
`traceparent`: las trazas no se encadenan entre servicios y un cliente no puede pedir que lo tracen.

**Redacción por construcción.** Un span solo puede llevar estos atributos. Una clave distinta se descarta, y un
valor que no cumple la regla de su clave también: no se limpia ni se recorta.

| Atributo | Valor |
|---|---|
| `http.request.method` | `GET`, `HEAD`, `POST`, `PUT`, `DELETE`, `PATCH`, `OPTIONS` o `_OTHER` |
| `http.route` | La ruta tal como se registró (`/v1/keys/:id`), nunca la pedida; en blob-store, `/:sha256` |
| `http.response.status_code` | 100-599 |
| `error.type` | En los 5xx y en las consultas que fallan, la clase del error (`TypeError`, `HttpError`) o `_OTHER`; nunca el mensaje |
| `db.system`, `db.operation.name` | `postgresql` y la primera palabra de la sentencia (`SELECT`, `INSERT`…), nunca la sentencia ni sus valores |

Además, cada span tiene ids aleatorios de traza y de span (node:crypto), un nombre (`GET /v1/keys/:id`,
`db.query`), su tipo, su duración y su estado. No lleva URLs con parámetros, cabeceras, cuerpos, IPs, pubkeys,
npub, tokens, contenido ni mensajes de error. Las pruebas intentan colar cada tipo de dato (pubkey hex, npub,
nsec, ncryptsec, IPv4 e IPv6, token Bearer, JWT, email y query string) por atributos, nombres y errores, también
con fuzzing, y miran el log y el cuerpo OTLP (`packages/telemetry-policy/test/tracing.test.ts`,
`packages/service-kit/test/tracing.test.ts`, `services/blob-store/test/tracing.test.ts`).

**Salidas.** Una línea `span` por span terminado en el log estructurado del servicio (nivel `info`, con la
redacción de secretos del logger). Si el operador fija `TRACE_EXPORT_URL`, además OTLP/HTTP JSON a su colector:
es el único destino que la política permite, sin seguir redirecciones, con una cola de 2048 spans (los que no
caben se descartan y se cuentan), un envío a la vez con un timeout de 5 s y sin reintentos. El envío no está en
el camino de la petición: un colector caído o lento no la retrasa. Los descartes se registran (`trace export
dropped spans`, con el motivo y el número de spans, sin la dirección del colector). Lo que queda en cola cuando
el proceso termina se pierde.

**Perfiles Tor y sovereign.** En los clientes, los perfiles sovereign y sovereign-tor tienen telemetría `none`:
su `TelemetryPolicy` no emite nada. Un servicio no sabe qué perfil tiene quien lo llama; para él, «apagadas en
perfiles Tor» significa dos cosas:

- **Un despliegue con `TELEMETRY_LEVEL=none`** (el nivel de esos perfiles) no tiene trazador: no crea spans ni
  ids ni exporta, y las variables `TRACE_*` ni se leen, así que ninguna variable de entorno enciende las trazas.
  `minimal` tampoco traza: las trazas solo existen con `standard`.
- **Una petición dirigida a un `.onion`** (cabecera `Host`), como la de una persona `--onion-only` al vault o
  al blob-store publicados como servicio onion, nunca se traza, diga lo que diga el muestreo.

Lo que queda: una persona Tor que llega por un nodo de salida al nombre clearnet de un servicio con trazas
activas se muestrea como cualquier otra petición. Su span no lleva su IP ni su pubkey, pero sí la hora, la ruta
como plantilla y la duración.

| Variable | Por defecto | Uso |
|---|---|---|
| `TELEMETRY_LEVEL` | `standard` | `none`: sin trazas (y, en el indexer, sin métricas); `minimal`: sin trazas |
| `TRACE_SAMPLE_RATE` | `0` | Fracción de peticiones trazadas, de 0 a 1 |
| `TRACE_EXPORT_URL` | — | Colector OTLP/HTTP del operador (`http(s)://…/v1/traces`, sin credenciales en la URL). Sin ella, solo el log |

En compose y en Kubernetes, `TRACE_SAMPLE_RATE` está con el resto de la observabilidad del indexer y del
managed-signer, a `0`. Los demás servicios la leen igual si se añade a su entorno.

## Alertas (multi-ventana, multi-tasa de consumo)

Método del *SRE Workbook* ("Alerting on SLOs"). La *tasa de consumo* es cuántas veces más rápido que lo
sostenible se gasta el presupuesto (1x = se agota justo en 30 días). Cada alerta exige que la ventana larga
**y** una corta (1/12 de la larga) superen el umbral: la larga da significancia y la corta hace que la
alerta se apague pronto cuando el problema se resuelve.

| Alerta | Severidad | Tasa | Ventanas | Presupuesto consumido si sigue | `for` |
|---|---|---|---|---|---|
| `SLOAvailabilityBurnRateCritical` | page | 14,4x | 1 h y 5 min | 2 % en 1 h | 2 min |
| `SLOAvailabilityBurnRateHigh` | page | 6x | 6 h y 30 min | 5 % en 6 h | 15 min |
| `SLOAvailabilityBurnRateMedium` | ticket | 3x | 1 d y 2 h | 10 % en 1 d | 1 h |
| `SLOAvailabilityBurnRateLow` | ticket | 1x | 3 d y 6 h | 10 % en 3 d | 3 h |
| `SLOErrorBudgetExhausted` | ticket | — | 30 d | presupuesto agotado | 15 min |
| `SLOProbesMissing` | ticket | — | — | el SLI no se mide (exporter caído o sin sondas) | 10 min |

Ejemplo: un servicio caído del todo dispara `Critical` en unos 3-4 minutos. Una sonda fallida suelta no
dispara ningún aviso de guardia (probado en el test de reglas).

## Enrutado de alertas (placeholder)

`deploy/monitoring/alertmanager/alertmanager.yml` define dos receptores **todavía sin integración**:

| Receptor | Severidad | Uso esperado | Responsable (a definir) |
|---|---|---|---|
| `oncall-page` | `page` | Alguien actúa ya (PagerDuty/Opsgenie o canal con menciones) | _pendiente_ |
| `oncall-ticket` | `ticket` | Siguiente día hábil (issue o canal) | _pendiente_ |

Un `page` inhibe los `ticket` del mismo servicio. Las URLs o llaves de las integraciones van en Secrets
Manager (`k8s/<env>/acceso-nostr`), nunca en el repositorio.

## Qué hacer cuando salta

1. Abrir el dashboard **Acceso Nostr · SLO de disponibilidad** (Grafana, `kubectl -n acceso-nostr
   port-forward svc/grafana 3000`) y ver qué servicio y desde cuándo.
2. `kubectl -n acceso-nostr get pods` y `kubectl -n acceso-nostr logs deploy/<servicio>`. Para Buzz, además, el
   bloque `dependencies` de `/_status` en el puerto de salud (qué dependencia falla y desde cuándo) y
   `sli:buzz_http_errors:ratio_rate5m`. `buzz_readiness_state` ya solo refleja el ciclo de vida del proceso.
3. Si hay pérdida de datos, seguir [`runbooks/restore.md`](runbooks/restore.md) con los objetivos de
   [`rpo-rto.md`](rpo-rto.md).
4. **Presupuesto agotado:** congelar despliegues no urgentes del servicio hasta recuperar margen y revisar
   la causa (postmortem si hubo `page`).

## Pendiente

- Primer despliegue en stage (ver [`deploy/README.md`](../deploy/README.md)) y 30 días de datos antes de
  comprometer el SLO con usuarios.
- Integraciones reales de `oncall-page` / `oncall-ticket` y responsables de guardia.
- Sonda externa de los hosts públicos.
