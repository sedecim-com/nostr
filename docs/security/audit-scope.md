# Alcance de las auditorías externas (SEC-01 y SEC-02)

- **Versión:** v0.1 (2026-09-27) · **Estado:** listo para enviar a proveedores (RFP).
- **Backlog:** SEC-01 (revisión criptográfica independiente, sprint S14) y SEC-02 (pentest, sprint S15), issues #192 y #193.
- **Commit de referencia:** `aac285be38d94ff110adb91a9884c49f9a7aea5c` más los commits de la revisión interna
  previa ([internal-review-2026-09.md](internal-review-2026-09.md)). Antes de firmar hay que fijar el commit
  exacto que se entrega (un tag `audit-2026-XX`) y congelarlo mientras dure el trabajo de campo.
- **Segunda revisión interna (SEC-13):** [internal-review-2026-10.md](internal-review-2026-10.md) revisó lo fusionado
  hasta `d6aaee8`. Su alcance entra en las tablas de abajo (Continuity Vault y worker de rotaciones) y sus hallazgos,
  corregidos o abiertos, van en el paquete que reciben los auditores.

> Este documento prepara la contratación. **No sustituye** a ninguna de las dos auditorías: ni la revisión
> interna ni las herramientas automáticas (CodeQL, fuzzing, `npm audit`) cumplen el criterio de hecho de
> SEC-01 o SEC-02, que exige un informe **externo e independiente**.

## 1. Qué contratamos

| Encargo | Objetivo | Criterio de hecho (backlog) | Esfuerzo orientativo |
|---|---|---|---|
| **SEC-01**: revisión criptográfica | Revisar el diseño y la implementación de NIP-44 v2, NIP-49, NIP-59/NIP-17, la integración MLS/Marmot, el servicio de llaves (managed-signer y tier enclave) y el almacenamiento cifrado | Informe externo **sin hallazgos críticos abiertos** | 10–15 persona-día |
| **SEC-02**: pentest | Probar API, relays, servicio de llaves y clientes (web SaaS, consola de administración, cliente soberano) sobre stage | Informe externo; **críticos y altos corregidos** y verificados en el retest | 10–15 persona-día + retest |

Se pueden contratar al mismo proveedor o a dos distintos. Si es el mismo, conviene que el equipo del pentest
reciba los hallazgos de SEC-01 antes de empezar.

## 2. Componentes y rutas

Todas las rutas son relativas a la raíz del repositorio en el commit de referencia. El
[inventario criptográfico](crypto-inventory.md) da los punteros a nivel de archivo:línea.

### 2.1 SEC-01: criptografía (revisión de código)

| Componente | Rutas | Prioridad |
|---|---|---|
| Primitivas Nostr: eventos (BIP-340), NIP-44 v2, NIP-49, NIP-98, NIP-19 | `packages/nostr-core/src/` | P0 |
| Gift wrap NIP-59 y DMs NIP-17 | `packages/messaging/src/nip59.ts`, `nip17.ts`, `security.ts` | P0 |
| MLS/Marmot: adaptador, codec, medios MIP-04 | `packages/marmot-adapter/src/` (depende de `@internet-privacy/marmot-ts` 0.5.1 y `ts-mls` 2.0.0-rc.16) | P0 |
| Servicio de llaves custodial | `services/managed-signer/src/` (`service.ts`, `vault.ts`, `aws.ts`, `api.ts`) | P0 |
| Tier enclave (Nitro): attestation, CBOR/COSE, DER, CMS, protocolo padre⇄enclave | `services/managed-signer/src/enclave/` | P0 |
| Firmantes: local, NIP-46 (bunker y cliente), NIP-07, cliente managed | `packages/signer/src/` | P0 |
| Almacenamiento cifrado local y bóveda del navegador | `packages/encrypted-store/src/`, `apps/web-saas/src/lib/vault.ts` | P0 |
| Backups de identidad y bóveda de backups en la nube | `packages/identity/src/` (`manager.ts`, `key-backup.ts`, `backup-vault.ts`) | P0 |
| Generador de llaves offline (CLI, HTML air-gapped) | `apps/key-generator/src/` | P1 |
| WebAuthn (registro de dispositivos, ES256, attestation `packed`/`none`) | `services/policy-engine/src/webauthn.ts` | P1 |
| Web Push (RFC 8291/8292) | `services/notification-gateway/src/webpush.ts` | P1 |
| Adjuntos cifrados (AES-GCM) y saneado de metadatos | `packages/blossom-client/src/` | P1 |
| Continuity Vault: sobres sellados (XChaCha20-Poly1305, HKDF por uso, AAD con `key_id` e id), llave de archivo, copia y restauración del historial | `packages/continuity/src/`, `services/continuity-vault/src/` | P0 |
| Espejo cifrado en reposo | `services/indexer/src/codec.ts` | P2 |

Preguntas concretas para el revisor:

1. ¿Es correcta y constante en tiempo nuestra implementación propia de NIP-44 v2 (padding, HMAC con AAD,
   derivación HKDF) frente a la especificación y a los vectores oficiales?
2. ¿Hay confusión de claves o de dominio entre NIP-44, NIP-49, el store cifrado (HKDF con etiquetas
   `sedecim-store-*`) y los backups (`BACKUP_AAD`)?
3. ¿El tier enclave cumple lo que promete [docs/managed-enclave.md](../managed-enclave.md)? En especial: la
   verificación de attestation, el uso de `Recipient` de KMS, la ligadura del blob sellado a la pubkey y los
   riesgos residuales ya conocidos (el padre puede pedir firmas; en una exportación ve el token del dueño y la contraseña, IR-2026-09-01). Además, la verificación de la prueba del dueño dentro del enclave (`proof.ts`, FR005-09): ¿resisten las reglas del JWT (algoritmo fijo, llaves fijadas, `auth_time`, `jti`) y el reloj del NSM un padre hostil?
4. ¿Los parsers escritos a mano (CBOR ×2, DER, CMS, protobuf nauthz, JPEG/PNG/WebP) resisten entradas
   adversariales? Hay fuzzing en `tests/fuzz`, pero no sustituye a una revisión.
5. ¿Es sólida la integración con marmot-ts/ts-mls (versiones alpha/rc): almacenamiento del estado MLS,
   rotación tras revocación de dispositivo, exporter de medios MIP-04?

### 2.2 SEC-02: pentest (caja gris)

| Superficie | Qué es | Stage |
|---|---|---|
| Web SaaS (SPA) | `apps/web-saas`, login con Acceso (Cognito) + npub, bóveda en IndexedDB | `https://nostr-stage.ai.acce.so` |
| Consola de administración | `apps/admin-console`, NIP-98 contra policy-engine e identity-service | servida por el edge de stage |
| Relay principal (Buzz, upstream fijado por digest) | WebSocket Nostr, NIP-42, `/media`. El edge solo reenvía esas dos; el resto de rutas de Buzz y cómo se comprueba, en [`buzz-attack-surface.md`](buzz-attack-surface.md) (SEC-12) | `wss://nostr-stage-relay.ai.acce.so` |
| Relay seguro (nostr-rs-relay + admisión nauthz) | Relay institucional con allowlist | `wss://nostr-stage-secure.ai.acce.so` |
| identity-service | Cuentas, personas, enlaces, bóveda de backups (NIP-98 o token Cognito) | `https://nostr-stage-id.ai.acce.so` |
| policy-engine | Sujetos, recursos, dispositivos, WebAuthn, auditoría (NIP-98 admin; bearer de servicio) | `https://nostr-stage-policy.ai.acce.so` |
| indexer (espejo) | Lecturas derivadas, búsqueda, cursores (NIP-98 opcional/obligatorio) | `https://nostr-stage-mirror.ai.acce.so` |
| blob-store (Blossom) | Subida/descarga por hash, autorización kind 24242 | `https://nostr-stage-blobs.ai.acce.so` |
| managed-signer | Firma custodial, NIP-44, import/export, sesiones de dispositivo (Cognito o `sds_…`) | `https://nostr-stage-signer.ai.acce.so` |
| notification-gateway | Registro de push opaco (NIP-98) y envío a servicios push | componente `deploy/k8s/components/notification-gateway` |
| continuity-vault | Sobres opacos por cuenta (NIP-98 con la llave derivada de la de archivo, o token de Acceso), cuotas, retención y borrado; backend SeaweedFS o S3 | componente `deploy/k8s/components/continuity-vault` |
| rotation-worker | Worker de rotaciones MLS del modo institucional: rotaciones y revocaciones con su token de servicio | componente `deploy/k8s/components/institutional` |
| Cliente soberano (CLI, Tor) | `apps/sovereign-client`, fugas de red en perfiles Tor | local, contra el stack de compose |

Las URLs salen de `deploy/k8s/overlays/stage/` (`kustomization.yaml`, `files/web-config.json`,
`files/admin-config.json`). Infraestructura (Terraform, EKS, RDS, KMS, Secrets Manager) en `deploy/terraform`
y `deploy/k8s`.

## 3. Fronteras de confianza y flujos de datos

Documentación que el proveedor debe leer antes de empezar:

- Arquitectura: [docs/architecture.md](../architecture.md).
- Modelo de amenazas general: [docs/threat-model.md](../threat-model.md); por perfil:
  [convenience](../threat-models/convenience.md), [private-resilient](../threat-models/private-resilient.md),
  [institutional](../threat-models/institutional.md), [sovereign](../threat-models/sovereign.md),
  [sovereign-tor](../threat-models/sovereign-tor.md) (índice en [threat-models/README.md](../threat-models/README.md)).
- ADR relevantes: [0005 receipts](../adr/0005-receipts-de-aplicacion.md),
  [0006 Marmot](../adr/0006-marmot-proveedor-y-ruta-de-relay.md),
  [0007 almacenamiento local cifrado](../adr/0007-almacenamiento-local-cifrado.md),
  [0008 login Acceso en SaaS](../adr/0008-login-acceso-en-saas.md),
  [0009 custodia managed](../adr/0009-custodia-managed-region-y-marco-legal.md),
  [0010 notificaciones push](../adr/0010-notificaciones-push-por-perfil.md), y
  [0002](../adr/0002-subset-y-pin-de-buzz.md)/[0003](../adr/0003-compatibilidad-con-upstream-buzz.md) para Buzz.
- Tier enclave: [docs/managed-enclave.md](../managed-enclave.md). Tor: [docs/sovereign-tor.md](../sovereign-tor.md).
  Marmot: [docs/marmot.md](../marmot.md). Institucional: [docs/institutional.md](../institutional.md).

Fronteras que más interesan:

| Frontera | De → a | Autenticación | Qué no debe cruzar |
|---|---|---|---|
| F1 | Navegador/CLI → relays | NIP-42 (kind 22242), firmas BIP-340 | nsec; contenido de DMs/grupos en claro |
| F2 | Navegador → APIs (identity, policy, indexer, blob, gateway) | NIP-98 (kind 27235, ±60 s, `u`/`method`/`payload`, cada id una sola vez); Blossom kind 24242 | nsec; backups sin cifrar |
| F3 | Navegador → managed-signer | Token Acceso (Cognito RS256) o sesión de dispositivo `sds_…` | Operaciones sobre llaves de otro dueño |
| F4 | Servicios → servicios | Bearer por servicio (comparación en tiempo constante) | Privilegios de administrador |
| F5 | managed-signer (padre) ⇄ enclave | vsock. Solo la exportación exige una prueba del dueño (token de Acceso verificado dentro del enclave, FR005-09); firmar y cifrar obedecen al padre | nsec en claro hacia el padre |
| F6 | Enclave → KMS | TLS terminado en el enclave + attestation (PCR) en `Recipient` | Data keys en claro fuera del enclave |
| F7 | notification-gateway → servicios push | VAPID (ES256), cifrado RFC 8291, allowlist de hosts | Contenido, remitente o recuento de mensajes |
| F8 | Servicios → Postgres/Secrets Manager | Credenciales de servicio, TLS a RDS | Secretos de llaves fuera del vault |

## 4. Dentro y fuera de alcance

**Dentro:** todo el código de `packages/`, `services/` y `apps/`; la configuración de despliegue de
`deploy/k8s` y `deploy/terraform` en lo que afecta a exposición, secretos, IAM/KMS y cabeceras; el
comportamiento de los relays tal y como están desplegados (autenticación, admisión, fugas de metadatos).

**Fuera:**

- El código upstream de Buzz, nostr-rs-relay, marmot-ts, ts-mls, @noble/* y @scure/* como proyectos (sí
  entra cómo los usamos y sus versiones fijadas).
- AWS como proveedor (Cognito, KMS, Nitro Hypervisor): se asumen correctos; sí entra nuestra configuración.
- Ataques de denegación de servicio volumétricos, ingeniería social, acceso físico.
- Producción: el pentest se hace **solo sobre stage** o sobre el stack local.
- Anonimato de red de Nostr en perfiles no Tor (el proyecto no lo promete; ver `SECURITY.md`).

## 5. Entornos y cuentas que entregamos

1. **Stack local reproducible:** `docker compose up` con `docker-compose.yml` (relay Buzz, secure-relay,
   postgres, redis, seaweedfs, indexer, identity-service, policy-engine, blob-store, web, managed-signer,
   notification-gateway, relay-allowlist, tor). Variante TLS: `compose.tls.yml`. Guía en
   [docs/building.md](../building.md).
2. **Stage** (URLs de la sección 2.2), con datos sintéticos únicamente:
   - Dos usuarios Acceso (Cognito) de prueba por tester, sin permisos de administración.
   - Un par de llaves Nostr de administrador institucional (en `POLICY_ADMIN_PUBKEYS` de stage) y dos de usuario.
   - Un token bearer de servicio de prueba para policy-engine (rotado al terminar).
   - Llaves managed creadas para las cuentas de prueba; tier enclave en modo simulado si no hay instancia
     Nitro de stage disponible (debe indicarse en el informe).
3. **Acceso de lectura** al repositorio en el commit de referencia y a los manifiestos de stage.
4. Credenciales entregadas por canal cifrado y revocadas al cierre del retest.

## 6. Reglas de enfrentamiento (pentest)

- Ventana acordada por escrito; horario de pruebas activas en días laborables salvo acuerdo.
- Solo contra los hosts de la sección 2.2 y el stack local. Nada contra servicios de terceros (FCM, APNs,
  Mozilla autopush, Cognito fuera de nuestro pool, relays públicos).
- Sin DoS volumétrico ni pruebas de carga; las pruebas de agotamiento de recursos se hacen con una única
  petición demostrativa y se avisa antes.
- Sin pivotar a la cuenta AWS fuera de los recursos de stage; si se obtiene acceso a credenciales, se para y
  se avisa en menos de 24 h.
- Hallazgos críticos: aviso inmediato (mismo día) al contacto de seguridad, sin esperar al informe.
- Datos: solo cuentas de prueba; cualquier dato real encontrado se notifica y no se conserva.
- Contacto de seguridad y canal de escalado: el definido en `SECURITY.md` (GitHub Security Advisories), más
  un contacto directo acordado en el contrato.

## 7. Entregables y escala de severidad

- Informe ejecutivo y técnico (PDF), con pasos de reproducción y, cuando sea posible, un test que falle.
- Lista de hallazgos en formato máquina (CSV o JSON) con: id, componente, ruta/commit, severidad, CVSS v3.1
  o v4.0, descripción, impacto, recomendación.
- Para SEC-01: comentario explícito sobre cada pregunta de la sección 2.1 aunque no haya hallazgo.
- Declaración de independencia del proveedor y alcance efectivamente cubierto.

Escala (se usa también en la revisión interna):

| Severidad | Criterio |
|---|---|
| Crítica | Compromiso de llaves privadas, descifrado de mensajes o suplantación sin interacción, a escala |
| Alta | Igual que crítica pero con precondiciones realistas (una cuenta, un componente comprometido), o escalada de privilegios a administrador |
| Media | Divulgación de metadatos sensibles, DoS de un servicio con una petición, bypass de un control sin impacto directo en llaves |
| Baja | Endurecimiento, errores que filtran detalles, fallos que requieren capacidades poco realistas |
| Informativa | Buenas prácticas, observaciones sin impacto demostrable |

## 8. Retest

- Incluido en el precio: un retest de todos los críticos, altos y medios en un plazo de hasta 60 días
  desde el informe.
- El informe de retest indica por hallazgo: corregido, parcialmente corregido o no corregido, con el
  commit verificado.
- SEC-02 se cierra cuando el retest confirma críticos y altos corregidos; SEC-01, cuando no quedan críticos
  abiertos.

## 9. Cómo se incorporan los hallazgos al backlog

1. Cada hallazgo crítico, alto o medio se registra como issue privado (GitHub Security Advisory si es
   explotable) y como fila en el backlog con id `SEC-01-Fn` o `SEC-02-Fn`, `Depende de: SEC-01|SEC-02`,
   prioridad P0 (crítico/alto) o P1 (medio), y sprint asignado.
2. La corrección lleva un test de regresión y se referencia en la columna *Evidencia*.
3. Los bajos e informativos se agrupan en una tarea de endurecimiento o se aceptan con justificación escrita.
4. SEC-01 y SEC-02 pasan a *Hecho* solo con el informe externo (y el de retest para SEC-02) enlazado como
   evidencia. La revisión interna no cuenta como evidencia.

## 10. Qué hay que hacer para contratar

1. Fijar el commit/tag de auditoría y congelar cambios en las rutas P0 durante el trabajo de campo.
2. Enviar este documento, el [inventario criptográfico](crypto-inventory.md) y la
   [revisión interna](internal-review-2026-09.md) a dos o tres proveedores con experiencia demostrable en
   criptografía aplicada (idealmente con trabajo previo en MLS o Nostr) y en pentest de aplicaciones web y AWS.
3. Pedir propuesta con equipo, calendario, precio (incluido el retest) y un informe de ejemplo.
4. Firmar NDA y contrato con las reglas de la sección 6; preparar las cuentas de la sección 5.
5. Designar un contacto técnico con disponibilidad diaria durante el trabajo de campo.
6. Resolver antes de empezar los hallazgos abiertos de la revisión interna que se decida no aceptar, para no
   pagar por redescubrirlos.
