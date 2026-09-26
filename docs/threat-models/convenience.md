# Threat model · convenience (v0.1)

**Configuración** (`PRESETS.convenience`): llave local, red directa, identidad vinculada a la cuenta,
persistencia replicada, NIP-17, archivos en claro, telemetría mínima, push opaco, backup en la
nube cifrado con clave del usuario, confirmaciones de entrega activadas y de lectura desactivadas.

## Activos
Llave de la persona (nsec), contenido de DMs, historial de canales, grafo de contactos, vínculo
cuenta↔npub en el identity-service, backup cifrado.

## Adversarios relevantes
| Adversario | Capacidad supuesta |
|---|---|
| Operador del relay/SaaS curioso | Lee todo lo que recibe; no modifica el cliente |
| Atacante de red (Wi-Fi pública) | Observa y manipula tráfico sin romper TLS |
| Ladrón del dispositivo | Acceso físico sin la contraseña local |
| Phishing / malware de navegador | Engaña al usuario o ejecuta código en su sesión |

## Mitigaciones
| Riesgo | Mitigación | Evidencia |
|---|---|---|
| Robo de la llave en el servidor | La nsec se genera y guarda cifrada (NIP-49) en el cliente; el SaaS nunca la recibe | `packages/identity`, E2E en navegador (FR001-05, pendiente de ampliar) |
| Pérdida del dispositivo | Backup NIP-49 con clave del usuario; restauración en un dispositivo limpio | `packages/identity/test` (FR-027) |
| Lectura de DMs por el operador | NIP-44 + gift wrap NIP-59; el relay no ve contenido ni remitente | `packages/messaging/test` |
| Suplantación en DMs | El unwrap verifica que el firmante del seal coincide con el autor del rumor | `messaging.test.ts` (impersonation) |
| Pérdida de mensajes | Outbox cifrada, persistida antes de transmitir; reintentos | `packages/delivery-engine/test` |
| Metadatos EXIF en imágenes | Saneamiento por defecto (`stripFileMetadata`) | `packages/blossom-client/test` |

## Riesgos residuales
| Riesgo | Nivel | Nota |
|---|---|---|
| Canales NIP-29 en claro para el operador | Alto | Por diseño: el panel lo declara; usar grupos Marmot para contenido sensible |
| IP y horarios visibles para relays y servicio push | Alto | Red directa; push opaco (sin contenido, remitente ni recuento) con retardo aleatorio y agrupación (ADR 0010); aceptado en este perfil |
| Sin forward secrecy en DMs (NIP-44) | Medio | Si se compromete la nsec, se expone el historial |
| Correlación cuenta↔npub en el identity-service | Medio | Solo si el usuario registra la persona |
| Contraseña local débil | Medio | scrypt `logN=15` (store) y `logN=16` (NIP-49); falta medidor de fortaleza |
| XSS en la web | Medio | CSP estricta con nonce por petición (sin `unsafe-inline`); la sesión de Acceso no da acceso a las llaves; pentest pendiente (SEC-02) |
| Acceso físico al navegador con llave del dispositivo | Medio | Solo si el usuario la elige (ADR 0007); disclosure y aviso `DEVICE_KEY`; se puede volver a contraseña en cualquier momento |

## Supuestos
El navegador y el sistema operativo no están comprometidos. TLS está bien configurado (OPS-02).
