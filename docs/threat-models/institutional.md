# Threat model · institutional (v0.1)

**Configuración:** custodia managed (**custodial**) o signer, relay privado con NIP-42, identidad
verificada por el directorio, persistencia replicada, grupos Marmot/MLS para salas sensibles, archivos
cifrados, telemetría estándar (sin nsec ni plaintext), push opaco, backup gestionado por el operador,
confirmaciones de entrega activadas y de lectura opt-in.

## Activos
Llaves managed en el vault, información clasificada de las salas, directorio organizacional, registros
de auditoría, dispositivos registrados.

## Adversarios relevantes
| Adversario | Capacidad supuesta |
|---|---|
| Insider con rol legítimo | Accede a lo que su rol permite e intenta ir más allá |
| Administrador malicioso | Controla el policy-engine y el directorio |
| Dispositivo robado o perdido | Sesión abierta, sin contraseña del usuario |
| Ex-empleado | Conserva material de grupos antiguos |
| Compromiso del backend SaaS | Accede a bases de datos y servicios |

## Mitigaciones
| Riesgo | Mitigación | Evidencia |
|---|---|---|
| Acceso fuera de rol | RBAC/ABAC con deny por defecto, clearance y dispositivo registrado para recursos sensibles | `packages/policy-client/test`, `services/policy-engine/test` |
| Dispositivo perdido | Revocación: invalida sesiones, bloquea nuevas y señala rotación de grupos | `policy-engine.test.ts` (FR-024) |
| Ex-miembro leyendo la sala | Expulsión MLS sin fuga (autoprueba y conformidad) | `packages/marmot-adapter/test`, `docs/marmot.md` |
| Secretos en logs o tablas | Vault envelope; logs y uso sin secreto; tablas solo con metadatos | `services/managed-signer/test` |
| Uso indebido de la llave managed | Auditoría de cada firma; migración verificada a llave local | `managed-signer.test.ts` (FR-026) |
| Suplantación de otro usuario en el managed-signer | Cada petición lleva el token de Acceso (Cognito) verificado; el dueño es `issuer#sub` y nunca sale de `x-account-id` | `managed-signer.test.ts` (FR005-04) |
| Pérdida del registro de llaves al reiniciar | Registro y log de uso en Postgres; retención de 12 meses para el uso y de 30 días para el material borrado | `registry.test.ts` (FR005-03, DEC-09) |

## Riesgos residuales
| Riesgo | Nivel | Nota |
|---|---|---|
| **El operador puede firmar como el usuario (managed)** | Alto | Declarado en el panel y en la API; el tier con enclave (FR005-05) lo reduce |
| Policy-engine sin persistencia | Alto | Los datos de política se pierden al reiniciar (FR023-03, P0) |
| La rotación MLS tras revocar no es automática | Medio | Se señala pero no se ejecuta (FR024-02) |
| Administrador malicioso | Medio | Falta separación de funciones y auditoría inmutable |
| Canales NIP-29 legibles por el operador | Medio | Por diseño: usar salas Marmot |

## Supuestos
KMS/HSM del operador bien configurado (DEC-09). El directorio lo gestiona la organización.
