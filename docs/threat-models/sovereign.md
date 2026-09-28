# Threat model · sovereign (v0.1)

**Configuración:** llave offline, relay propio o privado, identidad pseudónima, persistencia solo en el
dispositivo, NIP-17, archivos cifrados, **sin telemetría**, sin push, sin backup en la nube, sin crash
reports (no existen todavía, NFR007-03), sin receipts.

## Activos
La llave (generada air-gapped), el stack self-hosted, el historial local.

## Adversarios relevantes
| Adversario | Capacidad supuesta |
|---|---|
| Proveedor de infraestructura del operador | Acceso al host o al disco del VPS |
| Cadena de suministro | Dependencias o imágenes manipuladas |
| Atacante de red | Observa el tráfico hacia el relay propio |
| Pérdida del dispositivo | Sin backup en la nube por diseño |

## Mitigaciones
| Riesgo | Mitigación | Evidencia |
|---|---|---|
| Llave expuesta al generarla | Generador offline con todas las primitivas de red bloqueadas; bundle reproducible con checksum | `apps/key-generator/test` |
| Dependencia del SaaS | Stack completo con Docker Compose sin credenciales del SaaS | `docker-compose.yml`, CI `stack` (OPS-01) |
| Telemetría hacia terceros | Nivel `none`: cero emisiones y endpoints bloqueados | `packages/telemetry-policy/test` |
| Imágenes manipuladas | Imágenes fijadas por digest (salvo postgres y redis, por tag) y reproducibles bit a bit (NFR010-03); SBOM; gitleaks | `docker-compose.yml`, CI |
| Datos en reposo en el host | Mirror sellado en reposo opcional (`MIRROR_AT_REST_KEY`); vault envelope | `services/indexer/test` |

## Riesgos residuales
| Riesgo | Nivel | Nota |
|---|---|---|
| Pérdida del dispositivo sin backup | Alto | Por diseño; la validación advierte `LOSS_RISK`; conviene un backup offline |
| Aún sin release firmado | Medio | `release.yml` firma con cosign keyless, provenance SLSA y SBOM, y `verify-release.sh` lo comprueba; falta publicar el primero (NFR010-02) |
| Filas del mirror sellado intercambiables | Bajo | El sellado en reposo no usa `event_id` como AAD (IR-2026-09-15, SEC-06) |
| IP visible para el relay propio y el ISP | Medio | Usar sovereign-tor si importa |
| Host del VPS comprometido | Medio | Canales en claro en el relay; usar Marmot |

## Supuestos
El operador mantiene el host actualizado y guarda los secretos de `.env` fuera del servidor.
