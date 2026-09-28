# Threat model · sovereign-tor (v0.1)

> ⚠️ Según el scope (§2.3), ningún release se recomienda a perfiles de alto riesgo hasta superar una
> revisión independiente (SEC-01, SEC-02). Los tests de fugas con captura de red real (FR020-03) ya corren en
> CI, pero son internos y aún no cubren DMs, grupos ni media (FR020-05).

**Configuración:** llave offline o signer, **Tor-only sin fallback clearnet**, relay `.onion`,
identidad pseudónima, persistencia en el dispositivo, **Marmot/MLS** para grupos, archivos cifrados,
sin telemetría, sin push, sin crash reports, sin previews remotas, sin receipts, compartimentación por
persona.

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
| Correlación entre personas | Circuitos Tor aislados por persona (IsolateSOCKSAuth), stores separados, aviso de reutilización de contactos (archivos: FR006-07), prohibición de invitar a una identidad propia | `packages/identity/test`, `apps/sovereign-client/test/groups.test.ts` |
| Destinos no autorizados | Allowlist de hosts por persona; `onionOnly` | `sovereign.test.ts` |
| Compromiso futuro de la llave | Grupos Marmot/MLS con forward secrecy y rotación (PCS) | `packages/marmot-adapter/test` |
| Expulsado que sigue leyendo | Autoprueba de secreto post-expulsión (falla cerrado con ts-mls vulnerable) | `docs/marmot.md` |
| Metadatos de push o telemetría | Validación de configuración: errores bloqueantes si se activan | `packages/profiles/test` |

## Riesgos residuales
| Riesgo | Nivel | Nota |
|---|---|---|
| No hay cliente dedicado con Tor embebido | Alto | Hoy es un CLI; la web está bloqueada en este perfil (FR020-02) |
| Tests de fugas internos e incompletos | Alto | La captura real (netns + tcpdump, job `leak-tests`) cubre crear persona, canales e historial del CLI, con un stub SOCKS local; faltan DMs, grupos, media y el worker (FR020-05) y una revisión independiente |
| marmot-ts es alpha y no está auditado | Alto | SEC-01 |
| DMs NIP-17 sin forward secrecy | Medio | La validación avisa; usar Marmot |
| Jitter de gift wrap reducido a ±5 min por Buzz | Medio | Solo aplica si la persona usa el relay de Buzz; el secure-relay acepta el jitter estándar |
| Estilo de escritura y horarios | Medio | No mitigable técnicamente; formación del usuario |
| Adversario global de Tor | Alto | Fuera del alcance de Tor |

## Supuestos
Tor y el sistema operativo no están comprometidos. El usuario no reutiliza la persona fuera de este
compartimento.
