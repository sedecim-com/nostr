# Revisión interna de seguridad (2026-09)

- **Fecha:** 2026-09-27 · **Commit revisado:** `aac285b` · **Correcciones:** `a6b968c`
- **Alcance:** el de [audit-scope.md](audit-scope.md), revisado desde dentro del equipo con herramientas
  automáticas y lectura de código.

> **Esto es una revisión interna, no es SEC-01 ni SEC-02.** Su objetivo es llegar a la auditoría externa
> sin hallazgos fáciles, para que el tiempo pagado se dedique a lo difícil. No es independiente, no tiene la
> cobertura de un pentest y no cumple el criterio de hecho de ninguna de las dos tareas. SEC-01 y SEC-02
> siguen **pendientes** hasta tener los informes externos.

## 1. Metodología

1. **Dependencias:** `npm audit --omit=dev` y `npm audit` completo: **0 vulnerabilidades** conocidas.
   Revisión de versiones fijadas de las bibliotecas criptográficas ([crypto-inventory.md](crypto-inventory.md) §1).
2. **Análisis estático en CI** (nuevo): CodeQL `javascript-typescript` con `security-extended` en cada PR, en
   `main` y semanalmente (`.github/workflows/codeql.yml`), y *dependency review* en PRs que falla con
   vulnerabilidades altas o licencias incompatibles (`.github/workflows/dependency-review.yml`). Acciones
   fijadas por SHA de commit. CodeQL no se ha podido ejecutar en local: su primera ejecución en CI debe
   triarse antes de entregar el código a los auditores.
3. **Búsquedas dirigidas** (grep y lectura) de patrones peligrosos: `eval`/`new Function`, `child_process`
   con entrada externa, `innerHTML`/`dangerouslySetInnerHTML`, SQL concatenado, rutas mutantes sin NIP-98,
   comparaciones de secretos no constantes, secretos en logs, CORS comodín, límites de cuerpo, SSRF en
   `fetch` salientes (blob-store, gateway, identity/Cognito), path traversal en blob-store, verificación de
   JWT/Cognito y límites de tasa en rutas de autenticación.
4. **Revisión manual** de los parsers escritos a mano y del tier enclave.
5. **Fuzzing con fast-check** (nuevo, en `tests/fuzz`), que corre en cada `npm test`:
   - `webauthn.test.ts`: CBOR de WebAuthn (ida y vuelta, bytes aleatorios y mutados, regresiones) y
     `verifyRegistration` con attestationObjects mutados, truncados y con x5c/firmas basura.
   - `enclave-parsers.test.ts`: CBOR del enclave, DER (OID y estructuras anidadas), CMS EnvelopedData y
     verificación de attestation con documentos manipulados.
   - `nauthz-proto.test.ts`: codec protobuf de la admisión nauthz (ida y vuelta, entradas aleatorias, decisión).
   - `media-sanitize.test.ts`: saneado JPEG/PNG/WebP (los segmentos de metadatos nunca sobreviven).
   - Ya existían: NIP-44, NIP-49, NIP-19, eventos, codec MLS y parsers de backup (SEC-03).
6. **Tests de regresión** para cada corrección (ver columna *Test*).

Resultados que no fueron hallazgos: todas las consultas SQL están parametrizadas (los fragmentos dinámicos
del indexer solo concatenan texto constante y marcadores `$n`); no hay `eval` ni `new Function`; el único
`spawn` usa una ruta fija de configuración (helper NSM); los dos `innerHTML` del generador escapan y validan
su entrada; el CORS de las APIs es una lista exacta (el comodín de blob-store es deliberado: Blossom público
autenticado por cabecera, sin cookies); todas las rutas mutantes exigen NIP-98, bearer o token verificado;
las rutas de blob-store solo aceptan hashes hex; el gateway de push tiene allowlist de hosts, https y
`redirect: 'error'`; no se registran tokens, contraseñas ni nsec.

## 2. Hallazgos

Severidad según la escala de [audit-scope.md](audit-scope.md) §7.

| Id | Componente | Severidad | Descripción | Estado | Commit / test |
|---|---|---|---|---|---|
| IR-2026-09-01 | managed-signer (enclave) | **Alta** | La operación `export` del enclave cifra la nsec con la contraseña que envía el padre. Como el enclave no autentica al usuario, un backend comprometido puede exportar cualquier blob sellado con su propia contraseña y robar todas las llaves. `ENCLAVE_ALLOW_EXPORT` estaba activo por defecto. La documentación decía que un backend comprometido "no puede robar llaves". | **Mitigado**: la exportación del enclave queda desactivada por defecto (solo `ENCLAVE_ALLOW_EXPORT=1` la activa, para migraciones controladas; test en `enclave-signer.test.ts`) y la documentación está corregida. Sigue abierto el arreglo de fondo: exigir una prueba del usuario verificada dentro del enclave (JWT de Cognito con JWKS fijado en la imagen, o firma de la llave local de destino). | integración S8 |
| IR-2026-09-02 | managed-signer (API y enclave) | Media | `POST /v1/keys/import` ejecutaba scrypt con el `logN` elegido por quien envía el ncryptsec: con logN 20, 1 GiB de memoria y segundos de CPU por petición (DoS del signer y del enclave, que tiene poca memoria). Además una contraseña errónea daba 500. | **Corregido**: tope `MAX_IMPORT_LOG_N = 18` comprobado antes de scrypt (servicio y enclave), opción `maxLogN` en `nip49.decryptKey*`, errores 400. | `a6b968c`, `tests/security/managed-import-limits.test.ts` |
| IR-2026-09-03 | blob-store | Media | Volver a subir un blob existente sobrescribía los metadatos y convertía al nuevo firmante en "uploader". Como el contenido es público por hash, cualquiera con subida permitida podía apropiarse de un adjunto ajeno y borrarlo. | **Corregido**: el primer uploader conserva la propiedad; la subida repetida es idempotente; escritura de metadatos exclusiva (`wx`) y temporal con nombre único. | `a6b968c`, `services/blob-store/test/blob-store.test.ts` |
| IR-2026-09-04 | service-kit (NIP-98) | Media | NIP-98 no tiene protección anti-replay: una cabecera capturada se puede reutilizar durante ±60 s contra la misma URL y método (con el mismo cuerpo). TLS lo mitiga; el riesgo es mayor detrás de proxies que registren cabeceras. | **Abierto**: requiere una caché compartida de ids de evento entre réplicas (Redis) para las rutas mutantes. Candidato a corregir antes de SEC-02. | — |
| IR-2026-09-05 | Edge / APIs | Media | No hay límites de tasa en el edge (`deploy/k8s/base/files/edge-nginx.conf`) ni en identity-service, policy-engine, indexer o blob-store (solo managed-signer por llave y el gateway por pubkey). Afecta a creación de cuentas, NIP-98 inválidos y a la descarga de backups con token Cognito (que facilita ataques offline contra la contraseña del backup si se roba un token). | **Abierto**: añadir `limit_req` en el edge o WAF en el ALB, y límites por cuenta en la bóveda de backups. Decisión operativa. | — |
| IR-2026-09-06 | service-kit (Cognito) | Baja | Un token con un `kid` aleatorio provocaba una descarga del JWKS por petición (amplificación hacia Cognito y latencia); el `fetch` no tenía timeout. | **Corregido**: como mucho un refetch por `kid` desconocido cada 60 s y timeout de 5 s. | `a6b968c`, `packages/service-kit/test/cognito.test.ts` |
| IR-2026-09-07 | service-kit, policy-engine, managed-signer | Baja | Los tokens bearer se comparaban comprobando la longitud en UTF-16 y después `timingSafeEqual` sobre bytes UTF-8: un token con bytes no ASCII de la misma longitud lanzaba `RangeError` (500 y log de error). | **Corregido**: `safeEqual`/`lookupToken` en service-kit comparan longitudes en bytes; usados en las tres APIs. | `a6b968c`, `packages/service-kit/test/hardening.test.ts` |
| IR-2026-09-08 | service-kit | Baja | Un parámetro de ruta con `%` mal formado lanzaba `URIError` (500). | **Corregido**: 400. | `a6b968c`, `hardening.test.ts` |
| IR-2026-09-09 | policy-engine (WebAuthn) | Baja | UTF-8 inválido en CBOR, x5c que no es un certificado o una firma mal formada lanzaban excepciones distintas de `WebAuthnError` (500). Se aceptaban claves duplicadas en mapas CBOR (la última ganaba), bytes sobrantes tras el attestationObject y, con `fmt: none`, claves de credencial fuera de la curva. | **Corregido**: todo es `WebAuthnError` (400); duplicados, bytes sobrantes y puntos inválidos se rechazan. | `a6b968c`, `tests/fuzz/webauthn.test.ts` |
| IR-2026-09-10 | managed-signer (vault y enclave) | Baja | El descifrado AES-GCM no fijaba la longitud del tag: Node acepta tags de 4 a 16 bytes, y el blob sellado del enclave lo controla el padre. | **Corregido**: `authTagLength: 16` en `SecretsManagerVault`, apertura del enclave y KMS simulado. | `a6b968c`, `services/managed-signer/test/aws-vault.test.ts` |
| IR-2026-09-11 | blob-store | Baja | Los blobs se servían con el `content-type` que elige quien sube, sin `nosniff` ni CSP: un HTML o SVG subido se ejecutaba en el origen de blobs. | **Corregido**: `x-content-type-options: nosniff` y `content-security-policy: default-src 'none'; sandbox`. | `a6b968c`, `blob-store.test.ts` |
| IR-2026-09-12 | indexer | Baja | `kinds`, `limit`, `since` y `until` no numéricos o negativos llegaban a SQL (500). | **Corregido**: validación y 400. | `a6b968c`, `services/indexer/test/indexer.test.ts` |
| IR-2026-09-13 | managed-signer (DER) | Informativa | `decodeOid` aceptaba en silencio arcos truncados o no mínimos. | **Corregido**. | `a6b968c`, `tests/fuzz/enclave-parsers.test.ts` |
| IR-2026-09-14 | signer (NIP-46), notification-gateway | Baja | El secreto de `connect` del bunker NIP-46 se comparaba con `===`; los retrasos de push, que ocultan el momento de la actividad (ADR 0010), salían de `Math.random`. | **Corregido**: comparación en tiempo constante; retrasos con CSPRNG. | `a6b968c` |
| IR-2026-09-15 | indexer (espejo sellado) | Baja | El sellado en reposo (`MIRROR_AT_REST_KEY`) usa XChaCha20-Poly1305 sin AAD: quien escriba en la base de datos puede intercambiar payloads sellados entre filas. Los eventos siguen firmados, pero la fila deja de corresponder a su índice. | **Abierto**: añadir `event_id` como AAD exige migrar los datos existentes. | — |
| IR-2026-09-16 | web / edge | Baja | Faltan `frame-ancestors`/`X-Frame-Options`, HSTS y `nosniff` en las respuestas de la web (el CSP va en `<meta>`, que no admite `frame-ancestors`). | **Abierto**: configurar en el edge o el ALB. | — |
| IR-2026-09-17 | policy-engine (WebAuthn) | Informativa | La cadena x5c de `packed` no se valida contra FIDO MDS y la comprobación del OU no está anclada. | **Aceptado**: decisión documentada (la firma prueba que el autenticador creó la credencial; no se confía en el fabricante). | — |
| IR-2026-09-18 | managed-signer (CMS) | Informativa | El contenido de CMS usa AES-256-CBC sin MAC y los errores de padding llegan al padre como mensajes distintos. | **Aceptado**: formato impuesto por KMS; la integridad descansa en TLS con KMS terminado en el enclave. Pedir opinión explícita en SEC-01. | — |
| IR-2026-09-19 | identity-service | Baja | Campos de texto libre (`label`, valores de key-metadata) sin límite propio (hasta el límite de cuerpo, ~513 KiB) y creación de cuentas sin límite de tasa. | **Abierto**: límites de longitud; tasa, con IR-2026-09-05. | — |
| IR-2026-09-20 | managed-signer | Baja | Aun con el tope de logN, cada import o export cuesta hasta 256 MiB y no hay límite de concurrencia ni de tasa por dueño para esas rutas (los límites actuales son por llave). | **Abierto**: límite por dueño y semáforo de scrypt. | — |
| IR-2026-09-21 | notification-gateway | Informativa | `NOTIFY_PUSH_HOSTS=""` desactiva la allowlist anti-SSRF, y el puerto del endpoint no se restringe. | **Aceptado**: opción explícita del operador, documentada; el valor por defecto es la allowlist. | — |
| IR-2026-09-22 | managed-signer (CBOR) | Informativa | La detección de claves duplicadas del CBOR del enclave compara por identidad y no detecta claves duplicadas de tipo bytes o array. | **Aceptado**: los documentos Nitro usan claves de texto y enteras, que son las que se leen. | — |

Resumen (22 hallazgos): 1 alta (mitigada con la exportación desactivada por defecto; el arreglo de fondo sigue abierto), 4 medias (2 corregidas, 2 abiertas), 12 bajas (8
corregidas, 4 abiertas) y 5 informativas (1 corregida, 4 aceptadas). No hay hallazgos críticos conocidos. Esto **no**
equivale a "sin críticos": la ausencia de hallazgos en una revisión interna no es evidencia para SEC-01.

## 3. Qué hacer antes de la auditoría externa

1. IR-2026-09-01: la exportación del enclave ya está desactivada por defecto; decidir si se implementa la prueba de usuario dentro del enclave para poder activarla con seguridad.
2. Corregir IR-2026-09-04 (anti-replay de NIP-98) e IR-2026-09-05 (límites de tasa) para no pagar por
   redescubrirlos en el pentest.
3. Triar la primera ejecución de CodeQL en CI.
4. Añadir los vectores oficiales de NIP-44 ([crypto-inventory.md](crypto-inventory.md) §6).
5. Fijar el commit de auditoría y seguir [audit-scope.md](audit-scope.md) §10.
