# Threat model · private-resilient (v0.1)

**Configuración:** signer externo (NIP-46/NIP-07), varios relays con quorum 2, identidad pseudónima,
persistencia replicada, NIP-17, archivos cifrados en el cliente, telemetría mínima, push de solo aviso (privacy-push, ADR 0010),
backup solo en ciphertext, confirmaciones de entrega activadas y de lectura desactivadas, estado de presencia (NIP-38)
apagado, sin informes de fallo (`off`, NFR007-03).

## Activos
Llave custodiada por el signer, disponibilidad de los mensajes, anonimato relativo de la persona,
adjuntos cifrados.

## Adversarios relevantes
| Adversario | Capacidad supuesta |
|---|---|
| Un relay caído o censor | Descarta eventos o miente con `OK` |
| Operadores de relay en colusión | Correlacionan metadatos entre relays |
| Signer remoto comprometido | Firma lo que se le pide |
| Operador de Blossom curioso | Lee los blobs almacenados |

## Mitigaciones
| Riesgo | Mitigación | Evidencia |
|---|---|---|
| Censura o pérdida en un relay | Quorum 2 de N, ledger por relay, reconciliación | `delivery-engine.test.ts` (quorum, lost OK, reconcile) |
| Cliente comprometido con acceso a la nsec | La nsec vive en el signer; el cliente pide firmas (NIP-46) | `packages/signer/test` |
| Signer que firma de más | Bunker con `allowedKinds` y auditoría de peticiones | `signer.test.ts` |
| Lectura de adjuntos | AES-GCM en el cliente antes de subir; hash verificado antes de abrir | `blossom.test.ts`, `services/blob-store/test` |
| Duplicados entre relays | Dedup por event_id | `pool.test.ts` |
| Registro en el operador de qué canales lees y qué buscas | Con identidad pseudónima la web no consulta el mirror: no hay contadores de no leídos ni búsqueda de canales, y la vista lo dice (FR014-04) | `apps/web-saas/test/mirror.test.ts`, `packages/profiles/test/profiles.test.ts` |
| Vinculación de la persona por su estado de presencia | Apagado en el preset. Si la persona lo activa, el panel avisa (`PRESENCE_PSEUDONYMOUS`) y solo sale lo que escribe, sin enlaces ni menciones y con caducidad de 24 h como mucho; los estados ajenos viajan en la consulta de los perfiles, sin consulta propia ni suscripción con la lista de contactos (FR015-05, [presence.md](../presence.md)) | `packages/profiles/test/profiles.test.ts`, `apps/web-saas/test/presence.test.ts` |
| Oráculo de presencia con los acuses de entrega | Solo a contactos, quien la persona ya escribió (IR-2026-10-09): un desconocido que escribe primero no recibe acuse ni hace que el dispositivo se conecte, y firme un AUTH NIP-42, en sus relays | `packages/messaging/test/inbox.test.ts` |

## Riesgos residuales
| Riesgo | Nivel | Nota |
|---|---|---|
| Correlación de IP entre relays | Alto | Sin Tor, más relays implica más observadores |
| Estado de presencia de una persona pseudónima | Medio | Solo si la persona lo activa tras el aviso: cada relay de la persona ve el texto y la hora de cada estado, que pueden relacionarla con otras identidades (FR015-05) |
| Signer remoto malicioso | Medio | Mitigado con permisos mínimos: la web pide solo los kinds que firma y los lista antes de conectar (FR004-04, FR004-06) |
| Push opaco: revela tiempos de actividad | Medio | El servicio push del navegador ve cuándo hay actividad |
| Sin forward secrecy en DMs | Medio | Usar Marmot en conversaciones sensibles |
| Pérdida del historial si todos los relays lo pierden | Bajo | El Continuity Vault (ADR 0011) guarda sellado el historial (canales, DMs, mensajes de grupo, estado MLS y ledger) y un dispositivo limpio con el backup lo recupera con relays vacíos (VAULT-03). Con la política del perfil, `required-for-resilient`, ningún envío sale hacia los relays sin su copia en el vault (VAULT-04). Quedan dos cosas. Una persona creada antes de VAULT-04 no copia hasta que se elige la política. Si el vault está caído, los envíos esperan. ([threat model del vault](continuity-vault.md)) |

## Supuestos
Al menos `quorum` relays son honestos en disponibilidad. El signer protege su llave.
