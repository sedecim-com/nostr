# Threat model · institutional (v0.1)

**Configuración:** custodia managed (**custodial**) o signer, relay privado con NIP-42, identidad
verificada por el directorio, persistencia replicada, grupos Marmot/MLS para salas sensibles, archivos
cifrados, telemetría estándar (sin nsec ni plaintext), push opaco, backup gestionado por el operador,
confirmaciones de entrega activadas y de lectura opt-in, sin estado de presencia (NIP-38), informes de fallo a mano
(`manual-export`, NFR007-03).

## Activos
Llaves managed en el vault, información clasificada de las salas, directorio organizacional, registros
de auditoría, dispositivos registrados, la llave que firma los eventos y la de los secretos de webhook (OPS-16).

## Adversarios relevantes
| Adversario | Capacidad supuesta |
|---|---|
| Insider con rol legítimo | Accede a lo que su rol permite e intenta ir más allá |
| Administrador malicioso | Controla el policy-engine y el directorio |
| Dispositivo robado o perdido | Sesión abierta, sin contraseña del usuario |
| Ex-empleado | Conserva material de grupos antiguos |
| Compromiso del backend SaaS | Accede a bases de datos y servicios |
| Destino de webhook malicioso, o quien controle su DNS | Recibe los eventos de sus tipos; intenta que el policy-engine llegue a otro sitio (SSRF) o repetir entregas |

## Mitigaciones
| Riesgo | Mitigación | Evidencia |
|---|---|---|
| Acceso fuera de rol | RBAC/ABAC con deny por defecto, clearance y dispositivo registrado para recursos sensibles | `packages/policy-client/test`, `services/policy-engine/test` |
| Dispositivo perdido | Revocación: invalida sesiones y bloquea nuevas; el worker de rotación expulsa las hojas MLS del dueño en cada grupo señalado (época nueva) y marca la rotación hecha solo tras el commit; la revocación llega al managed-signer (sesiones ligadas al dispositivo) y al bunker NIP-46 (sesiones de cliente del dispositivo). Límites en `docs/marmot.md` | `policy-engine.test.ts` (FR-024), `packages/rotation-worker/test` (FR024-02), `devices-limits.test.ts` y `signer.test.ts` (FR024-03), `tests/security/device-loss.test.ts` (SEC-04) |
| Ex-miembro leyendo la sala | Expulsión MLS sin fuga (autoprueba y conformidad) | `packages/marmot-adapter/test`, `docs/marmot.md` |
| Secretos en logs o tablas | Vault envelope; logs y uso sin secreto; tablas solo con metadatos | `services/managed-signer/test` |
| Informes de fallo hacia la organización | Ninguno se envía, tampoco al operador: el informe limpio del último fallo se queda en el dispositivo y la persona decide si lo guarda en un archivo y a quién se lo da ([informes de fallo](../crash-reports.md)) | `packages/telemetry-policy/test/crash-report.test.ts`, `apps/web-saas/test/crash.test.ts` (NFR007-03) |
| Datos de usuarios en las trazas de los servicios (telemetría estándar) | Apagadas por defecto (`TRACE_SAMPLE_RATE=0`); con muestreo, un span solo lleva método, ruta como plantilla, estado, duración, clase del error y operación de base de datos, sin IP, pubkey, ids, cabeceras, cuerpos ni mensajes; van al log del servicio y, si se configura, al colector OTLP del operador ([threat model](../threat-model.md#trazas-de-los-servicios-nfr007-02)) | `packages/telemetry-policy/test/tracing.test.ts`, `packages/service-kit/test/tracing.test.ts` (NFR007-02) |
| Uso indebido de la llave managed | Auditoría de cada firma (con el dispositivo que la pidió); migración verificada a llave local | `managed-signer.test.ts` (FR-026) |
| Abuso de firma managed (token robado, cliente desbocado) | Token bucket por llave y por kind (por defecto 120/min y 60/min, configurable) → 429 con `Retry-After`; fila `rate-limited` en el log de uso (una por llave y minuto); métricas sin identificadores y alertas de ritmo anómalo (> 3× la línea base de 1 d), 429 sostenidos y dispositivo revocado insistiendo | `devices-limits.test.ts` (FR005-06), `deploy/monitoring/prometheus/tests/managed-signer.test.yml` |
| Navegador robado con la sesión abierta (llave managed) | Exportar, confirmar la migración, borrar, cancelar y cerrar las demás sesiones piden un login de Acceso de los últimos 5 min (`auth_time`, que un token refrescado conserva), nunca la sesión del dispositivo: 401 `insufficient_user_authentication` (RFC 9470). «Cerrar las demás sesiones» deja fuera los logins anteriores salvo el de quien las cierra, y ninguna sesión dura más que su vida configurada (12 h). El log de uso sigue visible después de borrar la llave | `reauth.test.ts` (IR-2026-10-03, IR-2026-10-11), `tests/browser/web-saas.e2e.ts` |
| Suplantación de otro usuario en el managed-signer | Cada petición lleva el token de Acceso (Cognito) verificado o una sesión de dispositivo abierta con él; el dueño es `issuer#sub` y `x-account-id` se rechaza (403, FR005-12) | `managed-signer.test.ts` (FR005-04) |
| Backend comprometido (tier enclave) lee la contraseña de una exportación o el `ncryptsec` y la contraseña de una importación | El cliente verifica él mismo la attestation del enclave (raíz Nitro fijada, PCR esperados, nonce propio, frescura) y sella esos secretos hacia su RSA; el backend retransmite un sobre que no puede abrir. La web lo hace si `config.json` trae `managedEnclave`; `ENCLAVE_REQUIRE_SEALED_SECRETS` y `MANAGED_SIGNER_REQUIRE_SEALED_SECRETS` rechazan los secretos en claro ([managed-enclave.md](../managed-enclave.md)) | `enclave-sealed-parent.test.ts`, `enclave-sealed-secrets.test.ts`, `enclave-attestation-portable.test.ts`, `apps/web-saas/test/managed-enclave-export.test.ts` (FR005-10) |
| Pérdida del registro de llaves al reiniciar | Registro y log de uso en Postgres; retención de 12 meses para el uso y de 30 días para el material borrado | `registry.test.ts` (FR005-03, DEC-09) |
| Pérdida o manipulación del estado de políticas | Persistencia en Postgres (`policy_*`); auditoría append-only por triggers; tokens de sesión con hash | `policy-engine.test.ts` (FR023-03: reinicio, append-only) |
| Acceso al relay de un usuario dado de baja | Allowlist NIP-42 sincronizado desde el engine a Buzz (tabla) y al secure-relay (admisión gRPC) | `allowlist-sync.test.ts` (FR023-04) |
| Lectura del mirror fuera de rol | El indexer evalúa cada lectura en el engine; deny por defecto, también ante errores. Los contadores de no leídos y la búsqueda de la web pasan por las mismas lecturas (FR014-04) | `indexer/test/policy.test.ts`, `tests/e2e/institutional-policy.test.ts` (FR023-05), `apps/web-saas/test/mirror.test.ts` |
| Presencia fuera del control de la organización | Con identidad verificada, activar la presencia es un error bloqueante (`PRESENCE_ORGANIZATION`): la política no la gobierna, y lo que la política no gobierna queda denegado. La web no publica ni pide estados (FR015-05, [presence.md](../presence.md)) | `packages/profiles/test/profiles.test.ts`, `apps/web-saas/test/presence.test.ts` |
| Dispositivo suplantado | Nivel `attested` solo con registro WebAuthn verificado en servidor | `webauthn.test.ts`, `policy-engine.test.ts` (FR023-07) |
| Integraciones que sondean la auditoría, o que reciben eventos alterados | Cada entrada de la auditoría se emite como evento firmado con Ed25519 sobre JSON canónico (RFC 8785), con el emisor dentro de lo firmado; las llaves públicas se publican (JWKS), también las anteriores a una rotación salvo las revocadas. El cursor no se salta ni repite eventos con escritores concurrentes. Un evento nunca lleva más que su entrada de auditoría | `events.test.ts` (OPS-16) |
| SSRF por la URL de un webhook | Solo https, sin credenciales ni redirecciones; el nombre se resuelve una vez y se rechaza si alguna dirección no es pública (loopback, privadas, link-local y metadatos de la nube, ULA, formas con una IPv4 dentro); se conecta a esa dirección sin volver a resolver. Se comprueba al dar de alta y antes de cada entrega. `POLICY_WEBHOOKS_ALLOW_PRIVATE` (pruebas) nunca en un manifiesto de producción | `webhooks.test.ts`, `release-gate.test.ts`, `deploy-manifests.test.ts` (OPS-16) |
| Filtración del secreto de una suscripción | Solo sale en la respuesta del alta y no se guarda: se deriva con HMAC-SHA256 de una llave aparte y una sal, así que una copia de la base o de un backup no da ninguno | `webhooks.test.ts` (OPS-16) |
| Entregas repetidas o falsificadas | HMAC-SHA256 de `timestamp.cuerpo` con el secreto de la suscripción y ventana de 300 s en el receptor; el id del evento como `Idempotency-Key`; la firma Ed25519 del evento dentro del cuerpo | `webhooks.test.ts` (OPS-16) |
| Llave Nostr robada sin el autenticador de la persona | Desde que la persona registra su passkey, cada sesión de política pide una aserción WebAuthn de ella: desafío de un solo uso y con caducidad para ese dispositivo, origen y RP id fijados por configuración, firma con la llave registrada y contador contra autenticadores clonados. Revocar el dispositivo que la tenía no quita el requisito, y otra passkey solo la registra un administrador. Una aserción rechazada no dice por qué, y queda en la auditoría con el motivo | `policy-engine.test.ts`, `webauthn.test.ts`, `tests/fuzz/webauthn.test.ts`, `passkey-session.test.ts`, `admin-console.e2e.ts` (FR023-11) |

## Riesgos residuales
| Riesgo | Nivel | Nota |
|---|---|---|
| **El operador puede firmar como el usuario y descifra sus DMs NIP-44 (managed)** | Alto | Declarado en el panel, en el consentimiento y en la API; el tier con enclave (FR005-05) lo reduce |
| Un backend comprometido fabrica su propio sobre (tier enclave) | Medio | Cualquiera con la llave pública del enclave puede sellar: con un token de Acceso retransmitido en su ventana de 300 s, el backend puede sellar una contraseña suya y exportar. Lo cierra una prueba del usuario que no se pueda retransmitir (passkey), que no existe. Además, la web y los PCR esperados los sirve el operador, y el verificador del navegador no se ha probado con un Nitro real (FR005-05, FR005-10) |
| Admisión del secure-relay fail-open | Medio | nostr-rs-relay admite el evento si no alcanza el servidor gRPC de `relay-allowlist`; Buzz es fail-closed (`docs/institutional.md`) |
| El borrado por retención no alcanza réplicas | Medio | Solo borra la copia del mirror; otros relays y clientes conservan la suya (aviso en la API) |
| Lo descifrado antes de revocar sigue en el dispositivo | Medio | La rotación protege solo lo posterior; ventana del intervalo de sondeo del worker (FR-024, `docs/marmot.md`) |
| Credenciales de Acceso en el dispositivo robado | Medio | Mientras su sesión siga abierta firman y descifran, aunque no pueden exportar, migrar, borrar ni cancelar sin la contraseña. «Cerrar las demás sesiones» corta ese login aunque lo refresque (IR-2026-10-11); quien conozca la contraseña puede volver a entrar, así que hay que cambiarla, como dice el runbook de pérdida (`docs/runbooks/device-loss.md`, FR024-05) |
| El worker de rotaciones puede descifrar sus grupos | Medio | Es un miembro más de los grupos que lo tienen como admin: mientras está, descifra lo que se envía, aunque no lo guarda. Quien lo controle podría leer esos grupos; los miembros lo ven en la lista (`docs/institutional.md`, FR024-05) |
| Límites de firma por réplica | Bajo | El token bucket vive en memoria de cada réplica: con N réplicas el límite efectivo es hasta N veces mayor |
| Administrador malicioso | Medio | Falta separación de funciones; la auditoría es append-only en la base, pero un superusuario de Postgres puede desactivar los triggers |
| La passkey protege sesiones que nadie más comprueba | Medio | Ningún otro servicio exige todavía una sesión de política, y no caducan: `evaluate` confía en el dispositivo que le indica el servicio (`x-policy-device-id` en el indexer). La primera passkey la registra quien tenga la llave Nostr, así que con la llave ya robada el ladrón puede adelantarse; que la registre un administrador lo evita (`docs/institutional.md`, FR023-11) |
| Estados de presencia publicados desde clientes de terceros | Medio | `relay-allowlist` admite por npub y por la etiqueta `h`, no por kind: un cliente de terceros con una llave del allowlist puede publicar un kind 30315. El bloqueo es de esta web (FR015-05) |
| Canales NIP-29 legibles por el operador | Medio | Por diseño: usar salas Marmot |
| Los eventos llevan metadatos de administración a terceros | Medio | El destino de un webhook ve lo que la auditoría: qué admin hizo qué, cuándo y sobre quién, y cada aserción rechazada con quién la intentó. La red y el DNS del camino ven el host de destino y la hora y el tamaño de cada entrega. Quien tenga la base ve además las URL completas de las suscripciones y el registro de entregas, nunca los secretos. Se limita con `types` por suscripción (`docs/institutional.md`, «Qué ve cada parte», OPS-16) |
| Redes internas con direcciones públicas | Medio | La guarda de destinos de webhook rechaza los rangos reservados de IANA; si la red del clúster usa direcciones públicas, no las reconoce: conviene una NetworkPolicy de salida para el policy-engine (OPS-16) |
| Llave de firma de eventos comprometida | Medio | Quien la tenga puede falsificar eventos hasta que su `kid` entre en `POLICY_EVENTS_REVOKED_KIDS` y los consumidores recarguen el JWKS (`docs/runbooks/webhooks.md`, OPS-16) |
| Entrega al menos una vez | Bajo | Un receptor que no deduplica por `Idempotency-Key` puede procesar un evento dos veces (OPS-16) |

## Supuestos
KMS/HSM del operador bien configurado (DEC-09). El directorio lo gestiona la organización.
