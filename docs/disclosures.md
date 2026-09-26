# Textos de disclosure del panel de soberanía

> Generado por `npx tsx scripts/disclosures.ts` desde `packages/profiles` (no editar a mano).
> Versión **1.0.0** · huella `e4ecf0a4490a8626` · estado: **pendiente de aprobación legal y UX** (FR028-02).

Cambiar cualquier texto exige subir `DISCLOSURE_VERSION` y volver a pasar la revisión. Las afirmaciones absolutas
("100 % anónimo", "imposible de rastrear") están prohibidas por `assertNoAbsoluteClaims`.

| Control | Opción | Texto mostrado | Refuerza | Reduce | Confías en |
|---|---|---|---|---|---|
| custody | local | La llave se genera y guarda cifrada en este dispositivo. La plataforma no puede firmar ni recuperar tu llave. | soberania, privacidad-operador | recuperabilidad | Seguridad del dispositivo y de tu passphrase. |
| custody | offline | La llave vive fuera de línea (air-gapped/hardware). Nadie más puede firmar; la recuperación es tu responsabilidad. | soberania, privacidad-operador | recuperabilidad | Custodia física del respaldo. |
| custody | external | Un signer externo (NIP-46/NIP-07) firma por ti; este cliente nunca ve la nsec. | soberania, privacidad-operador | — | El signer externo y los permisos que le concedas. |
| custody | encrypted-backup | El operador almacena un backup cifrado con una clave que solo tú controlas: guarda ciphertext, no la clave de descifrado. | recuperabilidad | — | Fortaleza de tu contraseña de backup (scrypt). |
| custody | managed | Managed Key activado: la plataforma tiene capacidad técnica de firmar como tú. Este modo es CUSTODIAL. | recuperabilidad, control-institucional | soberania, privacidad-operador | Operador, su vault (Secrets Manager/KMS) y su personal. |
| custody | managed-enclave | Custodia en enclave: el backend general no ve la llave en claro, pero el servicio de firma sí puede firmar como tú. Sigue siendo CUSTODIAL. | recuperabilidad, control-institucional | soberania | Attestation del enclave y políticas KMS del operador. |
| network | direct | Conexión directa: cada relay ve tu dirección IP y cuándo te conectas. | — | privacidad-operador | Operadores de relay e ISP. |
| network | private-relay | Relay privado con NIP-42: solo miembros autenticados leen/publican; el operador del relay ve IP y metadatos. | control-institucional | — | Operador del relay privado. |
| network | multi-relay | Publicación en varios relays con quorum: más disponibilidad, pero más operadores observan tus metadatos. | recuperabilidad | privacidad-operador | Todos los relays configurados. |
| network | tor-only | Tor-only: no se permite fallback clearnet. Si Tor no está disponible, el mensaje queda en outbox sin enviarse. | privacidad-operador, soberania | recuperabilidad | Red Tor; ausencia de fugas en este cliente (verificado por tests de fugas). |
| identity | pseudonymous | Identidad pseudónima: la app no vincula esta persona con otras ni con datos reales. | privacidad-operador | — | — |
| identity | linked | Identidad vinculada a tu cuenta: el servicio de identidad conoce la relación cuenta↔npub. | recuperabilidad | privacidad-operador | Servicio de identidad del operador. |
| identity | verified | Identidad verificada por la organización: tu npub queda asociado a tu cargo en el directorio. | control-institucional | privacidad-operador | Organización y su directorio. |
| persistence | device | Solo en el dispositivo: perder el dispositivo sin backup implica perder el historial. | soberania, privacidad-operador | recuperabilidad | — |
| persistence | relay | Persistencia en el relay: la disponibilidad depende de ese relay y de su política de retención. | recuperabilidad | — | Operador del relay. |
| persistence | replicated | Replicado en varios relays / mirror: menor riesgo de pérdida, mayor superficie de confianza. | recuperabilidad | privacidad-operador | Relays y mirror configurados. |
| persistence | encrypted-cloud | Copia en la nube cifrada en el cliente: el operador guarda ciphertext. | recuperabilidad | — | Gestión de la clave de cifrado por el usuario. |
| messaging | nip17 | DMs NIP-17 (NIP-44 + gift wrap): el relay no ve el contenido ni el remitente, pero NO hay forward secrecy ni post-compromise security. | privacidad-operador | — | Confidencialidad a largo plazo de tu nsec. |
| messaging | marmot | Grupos Marmot/MLS: forward secrecy y post-compromise security, con menor compatibilidad con clientes Nostr genéricos. | privacidad-operador | — | Implementación Marmot fijada y auditada. |
| files | relay-plain | Archivos sin cifrar en Blossom: el operador del almacenamiento puede ver el contenido. | — | privacidad-operador | Operador del servidor Blossom. |
| files | client-encrypted | Archivos cifrados antes de subir: el servidor Blossom solo ve un blob cifrado y su hash. | privacidad-operador | — | — |
| telemetry | standard | Telemetría estándar (sin nsec ni contenido E2EE): útil para diagnóstico, revela patrones de uso al operador. | — | privacidad-operador | Operador y su stack de observabilidad. |
| telemetry | minimal | Telemetría mínima: solo salud agregada, sin identificadores de usuario. | — | — | Operador. |
| telemetry | none | Sin telemetría: no se emite ninguna llamada de analytics ni crash reporting. | privacidad-operador | — | — |
| notifications | push | Push convencional: Apple/Google y el gateway de push ven cuándo recibes mensajes. | — | privacidad-operador | APNs/FCM y gateway de push. |
| notifications | privacy-push | Push con contenido opaco: los servicios push ven que hubo actividad, no el contenido ni el remitente. | — | — | APNs/FCM (metadatos de tiempo). |
| notifications | none | Sin notificaciones push: nada se revela a servicios push; debes abrir la app para ver mensajes. | privacidad-operador | — | — |
| cloudBackup | off | Sin backup en la nube. | privacidad-operador | recuperabilidad | — |
| cloudBackup | ciphertext-user-key | Backup en la nube cifrado con clave del usuario: el operador almacena ciphertext pero no la clave de descifrado. | recuperabilidad | — | Tu contraseña de backup. |
| cloudBackup | operator-managed | Backup gestionado por el operador: el operador puede restaurar (y por tanto acceder a) los datos. | recuperabilidad, control-institucional | privacidad-operador, soberania | Operador. |
| localProtection | passphrase | El almacén local se abre con tu contraseña (scrypt): sin ella, nadie con acceso a este dispositivo puede leer tus llaves. | soberania, privacidad-operador | recuperabilidad | Fortaleza de tu contraseña local. |
| localProtection | device | Desbloqueo sin contraseña con una llave del dispositivo (WebCrypto, no exportable): cualquiera con acceso a este perfil del navegador puede abrir tus llaves. | — | soberania, privacidad-operador | Seguridad física y de la sesión de este dispositivo. |
| crashReports | off | Crash reporting deshabilitado. | privacidad-operador | — | — |
| crashReports | manual-export | Los informes de fallo quedan en local y solo salen si los exportas manualmente. | privacidad-operador | — | — |
| crashReports | opt-in | Informes de fallo opt-in con limpieza de datos sensibles. | — | privacidad-operador | Operador. |
| remotePreviews | true | Las previews remotas se cargan automáticamente: el servidor de origen ve tu IP. | — | privacidad-operador | — |
| remotePreviews | false | Previews remotas bloqueadas: ningún enlace se carga sin tu acción. | privacidad-operador | — | — |
| deliveryReceipts | true | Confirmaciones de entrega activadas (cifradas con gift wrap): tus contactos saben cuándo recibe tu dispositivo sus mensajes. | — | privacidad-operador | — |
| deliveryReceipts | false | Confirmaciones de entrega desactivadas. | — | — | — |
| readReceipts | true | Confirmaciones de lectura activadas (cifradas): tus contactos sabrán cuándo lees. | — | privacidad-operador | — |
| readReceipts | false | Confirmaciones de lectura desactivadas. | — | — | — |
| quorum | 2 | Un mensaje se considera replicado cuando 2 relay(s) lo aceptan. "Aceptado por relay" no significa "recibido" ni "leído". | recuperabilidad | — | — |

## Aprobación

| Rol | Nombre | Fecha | Versión aprobada |
|---|---|---|---|
| Legal | | | |
| UX | | | |
