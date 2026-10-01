# Threat model · sovereign (v0.1)

**Configuración:** llave offline, relay propio o privado, identidad pseudónima, persistencia solo en el
dispositivo, NIP-17, archivos cifrados, **sin telemetría**, sin push, sin backup en la nube, informes de fallo a
mano (`manual-export`: el informe limpio de un fallo solo sale a un archivo si se pide, NFR007-03), sin receipts,
estado de presencia (NIP-38) apagado.

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
| Informes de fallo con datos de la persona | `manual-export`: el informe del último fallo no se guarda en el dispositivo ni se envía; la persona lo ve entero y lo guarda en un archivo si quiere (en el CLI, con `--crash-report`). Es una lista cerrada de campos, sin llaves, pubkeys, URLs, hosts, IPs, rutas ni texto entre comillas; guardarlos en el dispositivo (`opt-in`) solo lo enciende la persona ([informes de fallo](../crash-reports.md)) | `packages/telemetry-policy/test/crash-report.test.ts`, `apps/sovereign-client/test/crash-reports.test.ts`, `apps/web-saas/test/crash.test.ts` (NFR007-03) |
| Telemetría hacia terceros | Nivel `none`: cero emisiones y endpoints bloqueados. Los servicios del stack no trazan salvo que el operador fije `TRACE_SAMPLE_RATE`, y con `TELEMETRY_LEVEL=none` no pueden; ningún exportador de trazas sale por defecto hacia fuera (NFR007-02) | `packages/telemetry-policy/test`, `packages/service-kit/test/tracing.test.ts` |
| Imágenes manipuladas | Imágenes fijadas por digest, también las de terceros (OPS-13), y las propias reproducibles bit a bit (NFR010-03); SBOM; gitleaks | `docker-compose.yml`, `tests/scripts/supply-chain.test.ts`, CI |
| Consultas de la web al mirror | Con identidad pseudónima la web no consulta el mirror (ni contadores de no leídos ni búsqueda de canales), y la vista lo dice (FR014-04) | `apps/web-saas/test/mirror.test.ts`, `packages/profiles/test/profiles.test.ts` |
| Vinculación de la persona por su estado de presencia | Apagado en el preset. Si la persona lo activa en la web, el panel avisa (`PRESENCE_PSEUDONYMOUS`) y solo sale lo que escribe, sin enlaces ni menciones y con caducidad de 24 h como mucho. El CLI no tiene presencia (FR015-05, [presence.md](../presence.md)) | `packages/profiles/test/profiles.test.ts`, `apps/web-saas/test/presence.test.ts` |
| Datos en reposo en el host | Mirror sellado en reposo opcional (`MIRROR_AT_REST_KEY`), cada fila ligada a su `event_id` (SEC-06); vault envelope | `services/indexer/test` |
| Historial local en el disco del dispositivo | Caché de eventos del CLI sellada con la passphrase: XChaCha20-Poly1305, nombres HMAC y 64 cubos, así que una copia del disco no revela ids, autores, canales ni cuántos eventos hay. Los DMs se guardan como gift wraps, nunca abiertos. `cache clear` la borra y `SOVEREIGN_CACHE=off` no guarda nada ([event-cache.md](../event-cache.md), FR013-05) | `packages/sync/test/cache.test.ts`, `apps/sovereign-client/test/event-cache.test.ts` |

## Riesgos residuales
| Riesgo | Nivel | Nota |
|---|---|---|
| Pérdida del dispositivo sin backup | Alto | Por diseño; la validación advierte `LOSS_RISK`; conviene un backup offline |
| Aún sin release firmado | Medio | `release.yml` firma con cosign keyless, provenance SLSA y SBOM, y `verify-release.sh` lo comprueba; falta publicar el primero (NFR010-02) |
| Índice del mirror alterable por quien escribe en la base | Bajo | El payload sellado ya no se puede mover a otra fila (SEC-06), pero las columnas de índice van en claro (canal, destinatarios, listas de miembros); el mirror es una caché derivada de los eventos firmados |
| Estado de presencia de una persona pseudónima | Medio | Solo si la persona lo activa tras el aviso: el relay ve el texto y la hora de cada estado, que pueden relacionarla con otras identidades (FR015-05) |
| Un DM caducado o borrado sigue fuera de este dispositivo | Medio | La caducidad (NIP-40) y el borrado (kind 5 en gift wrap) son peticiones: el relay propio la aplica solo si respeta NIP-40, y los contactos con otro cliente o capturas conservan lo que tenían (PANEL-06, [message-expiration.md](../message-expiration.md)) |
| IP visible para el relay propio y el ISP | Medio | Usar sovereign-tor si importa |
| Host del VPS comprometido | Medio | Canales en claro en el relay; usar Marmot |
| Disco del dispositivo y passphrase en otras manos | Medio | Se lee la caché de eventos: mensajes de canal, metadatos de los gift wraps y cursores de sincronización. Con la llave en el dispositivo, también los DMs; con un signer NIP-46, los DMs no ([event-cache.md](../event-cache.md)) |

## Supuestos
El operador mantiene el host actualizado y guarda los secretos de `.env` fuera del servidor.
