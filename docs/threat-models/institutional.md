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
| Dispositivo perdido | Revocación: invalida sesiones y bloquea nuevas; el worker de rotación expulsa las hojas MLS del dueño en cada grupo señalado (época nueva) y marca la rotación hecha solo tras el commit; la revocación llega al managed-signer (sesiones ligadas al dispositivo) y al bunker NIP-46 (sesiones de cliente del dispositivo). Límites en `docs/marmot.md` | `policy-engine.test.ts` (FR-024), `packages/rotation-worker/test` (FR024-02), `devices-limits.test.ts` y `signer.test.ts` (FR024-03), `tests/security/device-loss.test.ts` (SEC-04) |
| Ex-miembro leyendo la sala | Expulsión MLS sin fuga (autoprueba y conformidad) | `packages/marmot-adapter/test`, `docs/marmot.md` |
| Secretos en logs o tablas | Vault envelope; logs y uso sin secreto; tablas solo con metadatos | `services/managed-signer/test` |
| Uso indebido de la llave managed | Auditoría de cada firma (con el dispositivo que la pidió); migración verificada a llave local | `managed-signer.test.ts` (FR-026) |
| Abuso de firma managed (token robado, cliente desbocado) | Token bucket por llave y por kind (por defecto 120/min y 60/min, configurable) → 429 con `Retry-After`; fila `rate-limited` en el log de uso (una por llave y minuto); métricas sin identificadores y alertas de ritmo anómalo (> 3× la línea base de 1 d), 429 sostenidos y dispositivo revocado insistiendo | `devices-limits.test.ts` (FR005-06), `deploy/monitoring/prometheus/tests/managed-signer.test.yml` |
| Suplantación de otro usuario en el managed-signer | Cada petición lleva el token de Acceso (Cognito) verificado o una sesión de dispositivo abierta con él; el dueño es `issuer#sub` y `x-account-id` se rechaza (403, FR005-12) | `managed-signer.test.ts` (FR005-04) |
| Pérdida del registro de llaves al reiniciar | Registro y log de uso en Postgres; retención de 12 meses para el uso y de 30 días para el material borrado | `registry.test.ts` (FR005-03, DEC-09) |
| Pérdida o manipulación del estado de políticas | Persistencia en Postgres (`policy_*`); auditoría append-only por triggers; tokens de sesión con hash | `policy-engine.test.ts` (FR023-03: reinicio, append-only) |
| Acceso al relay de un usuario dado de baja | Allowlist NIP-42 sincronizado desde el engine a Buzz (tabla) y al secure-relay (admisión gRPC) | `allowlist-sync.test.ts` (FR023-04) |
| Lectura del mirror fuera de rol | El indexer evalúa cada lectura en el engine; deny por defecto, también ante errores | `indexer/test/policy.test.ts`, `tests/e2e/institutional-policy.test.ts` (FR023-05) |
| Dispositivo suplantado | Nivel `attested` solo con registro WebAuthn verificado en servidor | `webauthn.test.ts`, `policy-engine.test.ts` (FR023-07) |

## Riesgos residuales
| Riesgo | Nivel | Nota |
|---|---|---|
| **El operador puede firmar como el usuario y descifra sus DMs NIP-44 (managed)** | Alto | Declarado en el panel, en el consentimiento y en la API; el tier con enclave (FR005-05) lo reduce |
| Admisión del secure-relay fail-open | Medio | nostr-rs-relay admite el evento si no alcanza el servidor gRPC de `relay-allowlist`; Buzz es fail-closed (`docs/institutional.md`) |
| El borrado por retención no alcanza réplicas | Medio | Solo borra la copia del mirror; otros relays y clientes conservan la suya (aviso en la API) |
| Lo descifrado antes de revocar sigue en el dispositivo | Medio | La rotación protege solo lo posterior; ventana del intervalo de sondeo del worker (FR-024, `docs/marmot.md`) |
| Credenciales de Acceso en el dispositivo robado | Medio | Pueden abrir sesiones del managed-signer con otro id de dispositivo: cerrar las sesiones de Acceso (cierre global), como dice el runbook de pérdida (`docs/runbooks/device-loss.md`, FR024-05) |
| El worker de rotaciones puede descifrar sus grupos | Medio | Es un miembro más de los grupos que lo tienen como admin: mientras está, descifra lo que se envía, aunque no lo guarda. Quien lo controle podría leer esos grupos; los miembros lo ven en la lista (`docs/institutional.md`, FR024-05) |
| Límites de firma por réplica | Bajo | El token bucket vive en memoria de cada réplica: con N réplicas el límite efectivo es hasta N veces mayor |
| Administrador malicioso | Medio | Falta separación de funciones; la auditoría es append-only en la base, pero un superusuario de Postgres puede desactivar los triggers |
| Canales NIP-29 legibles por el operador | Medio | Por diseño: usar salas Marmot |

## Supuestos
KMS/HSM del operador bien configurado (DEC-09). El directorio lo gestiona la organización.
