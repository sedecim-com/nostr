# SLO de disponibilidad del SaaS (NFR-001)

- **Objetivo:** 99,9 % de disponibilidad mensual (ventana móvil de 30 días) **por servicio**.
- **Presupuesto de error:** 0,1 % de 30 días = **43,2 minutos** de indisponibilidad al mes por servicio.
- **Implementación:** [`deploy/monitoring`](../deploy/monitoring) (Prometheus, blackbox exporter,
  Alertmanager, Grafana), incluida en el overlay de stage. Reglas probadas con
  `promtool test rules deploy/monitoring/prometheus/tests/slo-availability.test.yml` (CI, job `deploy-config`).

## SLI

**Disponibilidad = fracción de sondas exitosas.** El blackbox exporter consulta cada 30 s el mismo
endpoint de salud que usan los healthchecks de compose y las probes de Kubernetes. Una sonda es exitosa si
responde 200 en menos de 5 s (y, para relays, si el documento NIP-11 tiene `name`).

| Servicio (`service`) | Endpoint sondeado | Qué significa "disponible" |
|---|---|---|
| `relay` | `http://relay:8080/_readiness` | Buzz listo: base de datos, Redis y almacenamiento accesibles |
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
- Solo Buzz exporta métricas propias; los servicios TypeScript no exponen `/metrics`. Las sondas miden
  disponibilidad, no latencia (la latencia P95/P99 es NFR004-02).
- Las ventanas de 30 días necesitan 30 días de historia: Prometheus retiene 35 días.

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
2. `kubectl -n acceso-nostr get pods` y `kubectl -n acceso-nostr logs deploy/<servicio>`; para Buzz, además
   `buzz_readiness_state` y `sli:buzz_http_errors:ratio_rate5m`.
3. Si hay pérdida de datos, seguir [`runbooks/restore.md`](runbooks/restore.md) con los objetivos de
   [`rpo-rto.md`](rpo-rto.md).
4. **Presupuesto agotado:** congelar despliegues no urgentes del servicio hasta recuperar margen y revisar
   la causa (postmortem si hubo `page`).

## Pendiente

- Primer despliegue en stage (ver [`deploy/README.md`](../deploy/README.md)) y 30 días de datos antes de
  comprometer el SLO con usuarios.
- Integraciones reales de `oncall-page` / `oncall-ticket` y responsables de guardia.
- Sonda externa de los hosts públicos.
