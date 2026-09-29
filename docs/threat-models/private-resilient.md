# Threat model · private-resilient (v0.1)

**Configuración:** signer externo (NIP-46/NIP-07), varios relays con quorum 2, identidad pseudónima,
persistencia replicada, NIP-17, archivos cifrados en el cliente, telemetría mínima, push de solo aviso (privacy-push, ADR 0010),
backup solo en ciphertext, confirmaciones de entrega activadas y de lectura desactivadas.

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

## Riesgos residuales
| Riesgo | Nivel | Nota |
|---|---|---|
| Correlación de IP entre relays | Alto | Sin Tor, más relays implica más observadores |
| Signer remoto malicioso | Medio | Mitigado con permisos mínimos: la web pide solo los kinds que firma y los lista antes de conectar (FR004-04, FR004-06) |
| Push opaco: revela tiempos de actividad | Medio | El servicio push del navegador ve cuándo hay actividad |
| Sin forward secrecy en DMs | Medio | Usar Marmot en conversaciones sensibles |
| Pérdida del historial si todos los relays lo pierden | Medio | El Continuity Vault (ADR 0011) guarda sellado el historial (canales, DMs, mensajes de grupo, estado MLS y ledger) y un dispositivo limpio con el backup lo recupera con relays vacíos (VAULT-03). El guardado es manual y el envío aún no espera a esa copia (VAULT-04, S11): lo enviado después del último guardado depende de los relays. Hasta entonces el perfil no se declara GA ([threat model del vault](continuity-vault.md)) |

## Supuestos
Al menos `quorum` relays son honestos en disponibilidad. El signer protege su llave.
