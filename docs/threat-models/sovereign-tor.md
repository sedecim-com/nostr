# Threat model · sovereign-tor (v0.1)

> ⚠️ Según el scope (§2.3), ningún release se recomienda a perfiles de alto riesgo hasta superar una
> revisión independiente (SEC-01, SEC-02). Los tests de fugas con captura de red real (FR020-03, FR020-05)
> corren en CI y cubren canales, DMs, grupos MLS, media y el worker de rotaciones, pero son internos.

**Configuración:** llave en un signer NIP-46 alcanzado por Tor o cifrada en el dispositivo (la especificación
pide una llave offline o un signer; el CLI declara la custodia real, FR004-08), **Tor-only sin fallback
clearnet**, relay `.onion`, identidad pseudónima, persistencia en el dispositivo, **Marmot/MLS** para grupos, archivos cifrados,
sin telemetría, sin push, sin informes de fallo por defecto (`manual-export` se permite y `opt-in` no, NFR007-03),
sin previews remotas, sin receipts, compartimentación por persona.

## Activos
Anonimato de red de la persona, no vinculación con otras identidades del mismo usuario, contenido de
las conversaciones, identidad de las fuentes.

## Adversarios relevantes
| Adversario | Capacidad supuesta |
|---|---|
| Adversario de red local o ISP | Ve todo el tráfico del dispositivo |
| Operador del relay .onion | Ve eventos cifrados y horarios |
| Adversario que correlaciona identidades | Cruza contactos, archivos, horarios y estilo entre personas |
| Compromiso posterior del dispositivo | Obtiene llaves en el futuro |
| Adversario global de Tor | Correlación de extremo a extremo: fuera del alcance de Tor |

## Mitigaciones
| Riesgo | Mitigación | Evidencia |
|---|---|---|
| Fuga a clearnet | NetworkGuard falla cerrado: sin ruta Tor no hay transmisión; el mensaje queda en outbox | `packages/tor-network/test`, `delivery-engine.test.ts`, `sovereign.test.ts` |
| Fuga de DNS | `socks5h`: resolución dentro de Tor; ningún `dns.lookup` local | `tor.test.ts` |
| Correlación entre personas | Circuitos Tor aislados por persona (IsolateSOCKSAuth), stores separados, aviso con confirmación explícita (`--confirm-reuse`) antes de usar un contacto o un archivo que ya usó otra persona del dispositivo, con un registro por persona que solo guarda etiquetas HMAC ([threat model](../threat-model.md#compartimentación-aviso-antes-de-reutilizar-un-contacto-o-un-archivo-fr006-07), FR006-07), prohibición de invitar a una identidad propia | `packages/identity/test`, `apps/sovereign-client/test/compartment.test.ts`, `apps/sovereign-client/test/groups.test.ts` |
| Destinos no autorizados | Allowlist de hosts por persona; `onionOnly` | `sovereign.test.ts` |
| Compromiso futuro de la llave | Grupos Marmot/MLS con forward secrecy y rotación (PCS) | `packages/marmot-adapter/test` |
| Expulsado que sigue leyendo | Autoprueba de secreto post-expulsión (falla cerrado con ts-mls vulnerable) | `docs/marmot.md` |
| Metadatos de push o telemetría | Validación de configuración: errores bloqueantes si se activan | `packages/profiles/test` |
| Informes de fallo que dejan rastro o salen del dispositivo | `off` por defecto; guardar informes en el dispositivo (`opt-in`) es un error bloqueante en Tor-only, porque dejaría las fechas de los fallos para quien abra el almacén; `manual-export` solo escribe un informe limpio (sin hosts, `.onion`, IPs, llaves ni rutas) en un archivo si se pide con `--crash-report`, y ningún modo usa la red. Un fallo imprime una sola línea en stderr, sin pila ni secretos ([informes de fallo](../crash-reports.md#sovereign-tor-manual-export-sí-opt-in-no)) | `apps/sovereign-client/test/crash-reports.test.ts`, `packages/telemetry-policy/test/crash-report.test.ts`, `packages/profiles/test` (NFR007-03) |
| Trazas de los servicios que usa la persona (vault, blob-store, policy-engine) | Apagadas por defecto; con `TELEMETRY_LEVEL=none` el servicio no tiene trazador y ninguna variable lo enciende; una petición a un `.onion` nunca se traza; un span nunca lleva IP, pubkey, ids de la ruta ni contenido ([threat model](../threat-model.md#trazas-de-los-servicios-nfr007-02)) | `packages/telemetry-policy/test/tracing.test.ts`, `packages/service-kit/test/tracing.test.ts`, `services/blob-store/test/tracing.test.ts` (NFR007-02) |
| Custodia declarada mayor que la real | El CLI declara la custodia de la llave real (`local` o `external`), nunca el `offline` del preset; con la llave en el dispositivo avisa (`TOR_DEVICE_KEY`) | `apps/sovereign-client/test/nip46.test.ts`, `packages/profiles/test` |
| Fuga del tráfico del signer NIP-46 | Solo a los relays del signer, por SOCKS con las credenciales de la persona; sin Tor falla cerrado; onion-only también para el signer; permisos mínimos | `apps/sovereign-client/test/nip46.test.ts`, `packages/signer/test` |

## Riesgos residuales
| Riesgo | Nivel | Nota |
|---|---|---|
| No hay cliente dedicado con Tor embebido | Alto | Hoy es un CLI; la web está bloqueada en este perfil (FR020-02) |
| Tests de fugas internos | Alto | La captura real (netns + tcpdump, job `leak-tests`) cubre, con un stub SOCKS local en lugar de Tor, crear persona, canales e historial del CLI (FR020-03), y grupos MLS, media en un Blossom `.onion`, DMs NIP-17 y el worker de rotaciones con dos personas (FR020-05). Falta una revisión independiente |
| marmot-ts es alpha y no está auditado | Alto | SEC-01 |
| DMs NIP-17 sin forward secrecy | Medio | La validación avisa; usar Marmot |
| Llave en el dispositivo conectado (custodia `local`) | Medio | Quien comprometa el dispositivo y consiga la passphrase firma como la persona; con un signer NIP-46 la llave no está en el dispositivo (FR004-08) |
| El signer NIP-46 ve lo que firma y los DMs que descifra | Medio | Propio de NIP-46: el signer es de confianza; se le piden solo los kinds que firma el CLI |
| Jitter de gift wrap reducido a ±5 min por Buzz | Medio | Solo aplica si la persona usa el relay de Buzz; el secure-relay acepta el jitter estándar |
| Estilo de escritura y horarios | Medio | No mitigable técnicamente; formación del usuario |
| Servicio con trazas activas alcanzado por su nombre clearnet a través de Tor | Bajo | Se muestrea como cualquier otra petición: su operador ve la hora, la ruta como plantilla y la duración, no la persona. Con `--onion-only` solo se alcanzan `.onion`, que nunca se trazan (NFR007-02) |
| Adversario global de Tor | Alto | Fuera del alcance de Tor |

## Supuestos
Tor y el sistema operativo no están comprometidos. El usuario no reutiliza la persona fuera de este
compartimento.
