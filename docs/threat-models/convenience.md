# Threat model · convenience (v0.1)

**Configuración** (`PRESETS.convenience`): llave local, red directa, identidad vinculada a la cuenta,
persistencia replicada, NIP-17, archivos en claro, telemetría mínima, push opaco, backup en la
nube cifrado con clave del usuario, confirmaciones de entrega activadas y de lectura desactivadas, estado de presencia
(NIP-38) apagado.

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
| Robo de la llave en el servidor | La nsec se genera y guarda cifrada (NIP-49) en el cliente; el SaaS nunca la recibe | `packages/identity`, `tests/browser/web-saas.e2e.ts` (FR001-05: ninguna petición ni frame WebSocket contiene la nsec) |
| Pérdida del dispositivo | Backup NIP-49 con clave del usuario; restauración en un dispositivo limpio | `packages/identity/test` (FR-027) |
| Lectura de DMs por el operador | NIP-44 + gift wrap NIP-59; el relay no ve contenido ni remitente | `packages/messaging/test` |
| Suplantación en DMs | El unwrap verifica que el firmante del seal coincide con el autor del rumor | `messaging.test.ts` (impersonation) |
| Oráculo de presencia con los acuses de entrega | Solo a contactos, quien la persona ya escribió (IR-2026-10-09): un desconocido que escribe primero no recibe acuse ni hace que el dispositivo se conecte, y firme un AUTH NIP-42, en sus relays | `packages/messaging/test/inbox.test.ts` |
| Pérdida de mensajes | Outbox cifrada, persistida antes de transmitir; reintentos | `packages/delivery-engine/test` |
| Mensajes ajenos ocultados por un borrado falso | La web solo aplica un 9005 del autor del mensaje o de un admin de la lista 39001 firmada por la llave del canal, y un kind 5 sobre eventos de quien lo firma (FR015-04) | `packages/messaging/test/channels.test.ts`, `apps/web-saas/test/channel-collab.test.ts` |
| Registro en el operador de hasta dónde lees cada canal | La web guarda ese cursor cifrado en el vault del navegador y al mirror solo le pide la hora de los mensajes recientes (FR014-04) | `apps/web-saas/test/mirror.test.ts` |
| Estado de presencia que revela actividad | Apagado en el preset. Si la persona lo activa, solo sale el texto que escribe y confirma, sin enlaces ni menciones, con caducidad de 24 h como mucho y sin etiquetas que lo enlacen con otras personas o lugares; los estados ajenos viajan en la consulta de los perfiles, sin consulta propia (FR015-05, [presence.md](../presence.md)) | `apps/web-saas/test/presence.test.ts`, `packages/messaging/test/presence.test.ts` |
| Metadatos EXIF en imágenes | Saneamiento por defecto (`stripFileMetadata`); las imágenes que no se pueden sanear (HEIC, TIFF/RAW) se rechazan, también en DMs | `packages/blossom-client/test`, `tests/browser/web-saas.e2e.ts` |

## Riesgos residuales
| Riesgo | Nivel | Nota |
|---|---|---|
| Canales NIP-29 en claro para el operador | Alto | Por diseño: el panel lo declara; usar grupos Marmot para contenido sensible |
| IP y horarios visibles para relays y servicio push | Alto | Red directa; push opaco (sin contenido, remitente ni recuento) con retardo aleatorio y agrupación (ADR 0010); aceptado en este perfil |
| Sin forward secrecy en DMs (NIP-44) | Medio | Si se compromete la nsec, se expone el historial |
| Correlación cuenta↔npub en el identity-service | Medio | Solo si el usuario registra la persona |
| Un DM caducado o borrado sigue fuera de este dispositivo | Medio | La caducidad (NIP-40) y el borrado (kind 5 en gift wrap) son peticiones: relays sin NIP-40, clientes de contactos que no cooperan, capturas y copias de seguridad del operador del vault conservan lo que tenían. Este cliente deja de mostrarlo, borra sus copias y las del vault que conoce, y lo dice antes de borrar (PANEL-06, [message-expiration.md](../message-expiration.md)) |
| Borrar un mensaje de canal no retira sus copias | Medio | Quien lo recibió, otros clientes y relays pueden conservarlo, y el mirror conserva la fila marcada; la web lo dice antes de borrar (FR015-04) |
| El mirror ve qué canales consultas, cuándo y qué buscas | Medio | Contadores de no leídos y búsqueda firmados con NIP-98 (FR014-04); la vista de canales lo dice; aceptado en este perfil, con identidad vinculada |
| Estado de presencia publicado | Bajo | Solo si la persona lo activa: los relays y quien pueda leerlos ven el texto y la hora de cada estado, y los que ignoran NIP-40 pueden conservarlo (FR015-05) |
| Contraseña local débil | Medio | scrypt `logN=15` (store) y `logN=16` (NIP-49); falta medidor de fortaleza |
| XSS en la web | Medio | CSP estricta con nonce por petición (sin `unsafe-inline`); la sesión de Acceso no da acceso a las llaves; pentest pendiente (SEC-02) |
| Acceso físico al navegador con llave del dispositivo | Medio | Solo si el usuario la elige (ADR 0007); disclosure y aviso `DEVICE_KEY`; se puede volver a contraseña en cualquier momento |

## Supuestos
El navegador y el sistema operativo no están comprometidos. TLS está bien configurado (OPS-02).
