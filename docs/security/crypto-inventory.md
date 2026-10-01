# Inventario criptográfico

- **Versión:** v0.1 (2026-09-27), commit de referencia `aac285b` más la revisión interna (`6642ff6`, PR #215).
- **Para qué:** entrada de la revisión criptográfica externa (SEC-01, ver [audit-scope.md](audit-scope.md)).
  Recoge cada primitiva y protocolo, dónde se usa, con qué biblioteca y versión, cómo se gestionan las llaves,
  de dónde sale la aleatoriedad, qué código es propio y qué vectores de prueba hay.
- Los números de línea corresponden al commit `6642ff6`. Si el código se mueve, sirve el nombre de la función.

## 1. Bibliotecas y versiones fijadas

Versiones exactas en `package.json` de cada workspace y en `package-lock.json` (npm 11, sin rangos).

| Biblioteca | Versión | Quién la usa | Para qué |
|---|---|---|---|
| `@noble/curves` | 2.4.0 (nostr-core); 2.2.0 (marmot-adapter y dentro de marmot-ts) | nostr-core, marmot | secp256k1, BIP-340 Schnorr, ECDH; ECDSA P-384 para verificar la attestation Nitro en el cliente (`verifyEcdsaP384`, FR005-10) |
| `@noble/hashes` | 2.4.0 (nostr-core, encrypted-store, continuity, blob-store, metrics, blossom-client, test-relay, marmot-adapter); 2.2.0 (transitiva: marmot-ts y `@noble/curves` 2.2.0) | varios | SHA-256, SHA-384, HMAC, HKDF, scrypt |
| `@noble/ciphers` | 2.4.0 (nostr-core, encrypted-store, identity, indexer, managed-signer, blossom-client); 2.2.0 (marmot) | varios | ChaCha20, XChaCha20-Poly1305, AES-GCM |
| `@scure/base` | 2.4.0 | nostr-core, blossom-client, marmot-adapter | bech32 (NIP-19/49), base64 |
| `ts-mls` | 2.0.0-rc.16 (forzada con `overrides` en la raíz) | marmot-adapter, marmot-ts | MLS (RFC 9420) |
| `@internet-privacy/marmot-ts` | 0.5.1 (alpha upstream) | marmot-adapter | Marmot (MIP-01..04) sobre ts-mls |
| `@hpke/core` / `@hpke/common` | 1.9.0 / 1.10.1 (transitivas de ts-mls) | ts-mls | HPKE (RFC 9180) |
| `@aws-sdk/client-kms`, `client-secrets-manager` | 3.1141.0 | managed-signer | KMS (envelope, `Recipient` con attestation), Secrets Manager |
| `node:crypto` (OpenSSL de Node 22) | runtime | servicios | RSA-OAEP, AES-GCM/CBC, ECDSA P-256/P-384, Ed25519 (eventos del policy-engine, OPS-16), X.509, HMAC, `timingSafeEqual` |
| WebCrypto (navegador) | runtime | encrypted-store (browser); signer (sellado hacia el enclave, FR005-10, también en Node) | AES-GCM 256 no extraíble; RSA-OAEP-SHA256 + AES-256-GCM del sobre sellado |
| `nostr-tools` | 2.25.2 | tests; runtime solo en `packages/sync` | Oráculo diferencial de interoperabilidad; NIP-77 (Negentropy) en el cliente soberano |

Observación: conviven dos versiones de `@noble/*` (2.4.0 en nuestro código, 2.2.0 dentro de marmot-ts) y
versiones 1.x antiguas transitivas de `applesauce-core` (dependencia de marmot-ts). Ninguna de las 1.x se usa
desde nuestro código para cifrar; conviene que el auditor lo confirme.

## 2. Primitivas y protocolos, dónde

### 2.1 Identidad Nostr y firmas

| Qué | Dónde | Notas |
|---|---|---|
| Generación de llave secp256k1 | `packages/nostr-core/src/keys.ts:6` `generateSecretKey` (`secp256k1.utils.randomSecretKey`) | CSPRNG de la plataforma |
| Pubkey x-only BIP-340 | `keys.ts:11` | |
| Autotest de llave (derivación, firma, rechazo de manipulación) | `keys.ts:39` `selfTestKey` | Se ejecuta al generar e importar |
| Id de evento (SHA-256 de la serialización NIP-01) y firma Schnorr | `packages/nostr-core/src/event.ts:37-66` | |
| Verificación de eventos | `event.ts:79` `verifyEvent` | Nunca lanza (fuzz en `tests/fuzz/event.test.ts`) |
| Borrado de llaves en memoria | `keys.ts` `wipe` | Best effort (JS no garantiza) |

### 2.2 NIP-44 v2 (implementación propia sobre @noble)

`packages/nostr-core/src/nip44.ts`

| Paso | Línea | Primitiva |
|---|---|---|
| Clave de conversación | 22-25 | ECDH secp256k1 (`getSharedSecret`, x-coord) + HKDF-Extract(SHA-256, salt `nip44-v2`) |
| Claves por mensaje | 27-32 | HKDF-Expand(conversation_key, nonce 32 B, 76 B) → ChaCha20 key/nonce + HMAC key |
| Padding | 34-58 | `calcPaddedLen` según spec; `unpad` valida longitud |
| Cifrado | 65-70 | ChaCha20 + HMAC-SHA256(aad = nonce ‖ ct) |
| Parseo del payload | 72-83 | Límites de longitud 132..87472 (base64) y 99..65603 (bytes), versión 2 |
| Descifrado | 85-91 | Comparación de MAC en tiempo constante (`@noble/ciphers` `equalBytes`) |

Consumidores: `packages/signer/src/local.ts`, `packages/messaging/src/nip59.ts`, NIP-46
(`packages/signer/src/nip46.ts:158,183,353`), managed-signer (`service.ts` `nip44`).

### 2.3 NIP-49 (ncryptsec)

`packages/nostr-core/src/nip49.ts`: scrypt(NFKC(password), salt 16 B, N = 2^logN, r = 8, p = 1, 32 B) →
XChaCha20-Poly1305 con AAD = byte key-security; formato bech32 `ncryptsec`, versión 0x02 (líneas 26-83).

| Parámetro logN | Dónde |
|---|---|
| 16 por defecto | `encryptKey` (`nip49.ts:26`), llave local del gestor de identidades (`packages/identity/src/manager.ts:113`), backup desde la web (`apps/web-saas/src/lib/session.ts:167`) |
| 18 | Generador offline (`apps/key-generator/src/generate.ts:39,61`), backups completos (`manager.ts:299`), export managed (`services/managed-signer/src/service.ts:318`) |
| 1..22 | Export dentro del enclave (validado, `enclave/enclave.ts` op `export`) |
| Máximo 18 al importar en el servidor | `service.ts:129` `MAX_IMPORT_LOG_N`, `enclave.ts:74`; `decryptKey(..., { maxLogN })` (`nip49.ts:53-76`), añadido en la revisión interna (IR-2026-09-02) |

`@noble/hashes` limita por defecto la memoria de scrypt a 1 GiB (logN ≤ 20).

### 2.4 NIP-59 gift wrap y NIP-17

`packages/messaging/src/nip59.ts`: rumor sin firmar → seal kind 13 (NIP-44 con la llave del autor,
`createSeal`, línea 41) → wrap kind 1059 firmado con una llave efímera nueva por destinatario (`createWrap`,
línea 46, `generateSecretKey`). `created_at` aleatorizado hacia el pasado con `randomInt` (CSPRNG, línea 35;
`packages/nostr-core/src/utils.ts:30`, muestreo por rechazo sin sesgo). `unwrap` (línea 77) comprueba que el
autor del seal coincide con el del rumor. DMs y archivos NIP-17 en `nip17.ts:49-86`.

### 2.5 NIP-98 y NIP-42

- NIP-98: `packages/nostr-core/src/nip98.ts` `verifyAuthHeader`: kind 27235, firma, ventana ±60 s, `u`
  exacto, `method`, `payload` = SHA-256 del cuerpo si hay cuerpo (y rechazo de un `payload` sin cuerpo).
  `buildHttpAuthTemplate` añade un tag `nonce` aleatorio de 16 B. Lo aplica
  `packages/service-kit/src/http.ts` `Service.authenticate`, con anti-replay por id de evento
  (`packages/service-kit/src/replay.ts`: `PgReplayStore` compartido entre réplicas con Postgres,
  `MemoryReplayStore` por proceso sin él; IR-2026-09-04).
- NIP-42: `packages/relay-pool/src/connection.ts` (kind 22242, modos `auto`/`on-demand`).
- Blossom (kind 24242, verbo, `x` = hash, `expiration`): `services/blob-store/src/server.ts` `auth`.
- Prueba de control de una llave nueva (identity-service): evento kind 27235 con tags `account` y `u`,
  ±120 s (`services/identity-service/src/api.ts:84-95`).

### 2.6 MLS / Marmot

- Proveedor: `packages/marmot-adapter/src/marmot-ts.ts` sobre `@internet-privacy/marmot-ts` 0.5.1 y `ts-mls`
  2.0.0-rc.16 (ciphersuite por defecto de marmot-ts; HPKE vía `@hpke/core`).
- Codec del estado (JSON etiquetado para bytes/bigint/Map/Set) persistido en el store cifrado:
  `packages/marmot-adapter/src/marmot-ts.ts` `encodeValue`/`decodeValue`.
- Codec TLS estricto de mensajes y key packages (rechaza bytes sobrantes, que ts-mls ignora):
  `packages/marmot-adapter/src/mls-codec.ts:9-22`.
- Medios MIP-04: `packages/marmot-adapter/src/media.ts:34` `mlsExporter` (label/context MIP-04, 32 B) →
  HKDF-Expand por archivo (línea 39-49) → cifrado AEAD de marmot-ts (`encryptMediaFile`), verificación del
  SHA-256 del claro al descifrar.
- Rotación tras revocación: `packages/rotation-worker`. Riesgo conocido: marmot-ts es alpha
  ([docs/marmot.md](../marmot.md)).

### 2.7 Almacenamiento cifrado en reposo (cliente)

| Qué | Dónde | Primitivas |
|---|---|---|
| Store por frase de paso | `packages/encrypted-store/src/store.ts:44-52` | scrypt (logN 17 por defecto, r 8, p 1) → master key; HKDF-SHA256 → `sedecim-store-enc-v1` y `sedecim-store-names-v1` (líneas 36-37) |
| Sellado de entradas | `store.ts:78-90` | XChaCha20-Poly1305, nonce 24 B aleatorio, AAD = colección ‖ id; nombres de entrada con HMAC (clave `nameKey`) |
| Bóveda con master key envuelta | `packages/encrypted-store/src/vault.ts:34-110` | Master 32 B aleatoria envuelta con scrypt(passphrase) → XChaCha20-Poly1305 (AAD fija) o con llave de dispositivo |
| Llave de dispositivo en navegador | `packages/encrypted-store/src/browser.ts:80-113` | WebCrypto AES-GCM 256 **no extraíble** en IndexedDB, IV 12 B aleatorio |
| Bóveda de la web | `apps/web-saas/src/lib/vault.ts` | Vault anterior con logN 15 en navegador; la nsec local se guarda solo dentro de la bóveda |

Desviación menor: `store.ts:50` usa la sal hex como bytes UTF-8 (no la decodifica). No reduce entropía útil
(32 caracteres hex de 16 B aleatorios) pero es poco convencional.

### 2.8 Formatos de backup

| Formato | Dónde | Contenido |
|---|---|---|
| `sedecim-offline-key` / `acceso-nostr-key-backup` (v1, v2) | `packages/identity/src/key-backup.ts:34` `parseKeyBackup`, `:68` `openKeyBackup` | npub + ncryptsec (NIP-49); KDF declarado solo `scrypt` |
| `sedecim-identity-backup` (paquete completo) | `packages/identity/src/manager.ts:296-370` | Content key 32 B aleatoria envuelta con NIP-49 (logN 18); contenido con XChaCha20-Poly1305, AAD `sedecim-identity-backup-v2` (línea 24) |
| Bóveda de backups en la nube (FR027-03) | `packages/identity/src/backup-vault.ts:52` `validateBackupEnvelope`; servidor `services/identity-service/src/api.ts:216-271` | Sobres opacos ya cifrados en cliente; el validador rechaza cualquier sobre que lleve una nsec en claro |

### 2.9 Servicio de llaves custodial (managed-signer)

| Vault | Dónde | Esquema |
|---|---|---|
| `MemoryVault` | `services/managed-signer/src/vault.ts:24` | Solo tests/dev |
| `LocalEnvelopeVault` (self-hosted) | `vault.ts:44-90` | DEK aleatoria por llave; XChaCha20-Poly1305 (DEK bajo KEK de 32 B por env/HSM; secreto bajo DEK), AAD con el key id |
| `SecretsManagerVault` (SaaS, FR005-02) | `vault.ts:138-199` | KMS `GenerateDataKey` con contexto `{app, purpose, key_id}`; AES-256-GCM local (IV 12 B, AAD = nombre del secreto, tag de 16 B fijado desde la revisión interna, IR-2026-09-10); se ponen a cero la data key y los buffers |

Sesiones de dispositivo `sds_` + 32 B aleatorios, guardadas como SHA-256 (`service.ts:128-150`); desafío de
migración de 16 B aleatorios firmado con la llave exportada (`service.ts:318-350`). Límites de tasa por llave
y por kind: `services/managed-signer/src/ratelimit.ts`; en el mismo archivo, `ScryptGate` limita import y
export (scrypt) por dueño y en concurrencia por réplica (IR-2026-09-20).

### 2.10 Tier enclave (Nitro) — código propio, objetivo prioritario

| Qué | Dónde | Primitivas |
|---|---|---|
| RSA efímera por arranque | `services/managed-signer/src/enclave/enclave.ts:125` | RSA-2048, SPKI dentro de cada attestation |
| Sellado de llaves | `enclave.ts:145` | KMS `GenerateDataKey` con `Recipient` (attestation) → `CiphertextForRecipient` → AES-256-GCM (AAD `acceso-nostr/enclave-key/<pubkey>` y, en los blobs v2, la etiqueta del dueño) |
| Etiqueta del dueño (FR005-09) | `packages/signer/src/enclave/envelope.ts` `ownerTag` (reexportada por `enclave.ts`) | SHA-256 de `acceso-nostr/owner/v1\|<issuer>#<sub>` (noble, la misma en el cliente y en el enclave): va en el contexto de cifrado de KMS (`owner_tag`) y en el AAD; se hashea porque el contexto se escribe en claro en CloudTrail |
| Apertura | `enclave.ts:163` | KMS `Decrypt` con `Recipient`; GCM con tag de 16 B; se comprueba que la llave abierta deriva la pubkey reclamada |
| Prueba del dueño para exportar (FR005-09) | `enclave/proof.ts` `PinnedJwksProofVerifier`; `enclave.ts` `verifyExportProof` y `consumeProof` | JWT RS256 de Cognito (`createVerify('RSA-SHA256')`, algoritmo fijo, llaves RSA ≥ 2048 bits fijadas en la imagen), `iss`, `token_use`, `aud`/`client_id`, `exp`, `iat`, `auth_time` ≤ 300 s contra el reloj del NSM, `jti` de un solo uso (memoria acotada); el dueño del token debe dar la `ot` del blob |
| Secretos sellados hacia el enclave (FR005-10): sellado | `packages/signer/src/enclave/envelope.ts` `sealToEnclave` (WebCrypto) | RSA-OAEP con SHA-256 y MGF1-SHA-256 hacia la SPKI RSA ≥ 2048 de una attestation verificada, de una llave AES-256-GCM aleatoria por sobre (IV de 12 B aleatorio, tag de 16 B). AAD `acceso-nostr/enclave-envelope/v1\|<import\|export>\|<owner_tag>\|<pubkey o vacío>`. Contenido JSON con `at` (timestamp de la attestation); sobre de 4096 caracteres como mucho, base64url estricta (canónica, sin relleno) |
| Secretos sellados: apertura | `enclave/sealed-secrets.ts` `openSealedSecret` | `privateDecrypt` RSA-OAEP (`oaepHash: 'sha256'`) con la RSA efímera del enclave; AES-256-GCM con `authTagLength: 16` y el AAD reconstruido desde la petición; un único mensaje de error para cualquier fallo de apertura (RSA, tamaño de la llave, tag); `at` ≤ 5 min y ≤ 60 s en el futuro contra el reloj del NSM; se ponen a cero la llave AES y los buffers de texto claro, también el parcial que GCM entrega antes de comprobar el tag |
| Verificación de attestation en el cliente (FR005-10) | `packages/signer/src/enclave/attestation.ts` `verifyNitroAttestation` | Las mismas reglas que la del servicio, sin `node:*`: ECDSA P-384/SHA-384 de `@noble/curves` (`verifyEcdsaP384` en `nostr-core`, alta S aceptada como en OpenSSL; forma DER en X.509 y r‖s en COSE), SHA-256 de noble para la huella de la raíz, X.509 propio (basicConstraints, keyUsage, AKID/SKID, extensiones críticas desconocidas rechazadas, nombres comparados como DER, solo ecdsa-with-SHA384), PCR y nonce en tiempo constante. Probada por diferencial contra la de `node:crypto` |
| CMS EnvelopedData (RFC 5652) | `enclave/cms.ts:38-68` | RSAES-OAEP (SHA-1/SHA-256 según parámetros) + AES-256-CBC **sin MAC** (formato impuesto por KMS) |
| Verificación de attestation | `enclave/attestation.ts:130-214` | COSE_Sign1 ES384 (P-384, firma IEEE-P1363), cadena X.509 hasta la raíz Nitro G1 fijada por SHA-256 (línea 26), vigencia, frescura (5 min, ±60 s), nonce en tiempo constante, PCR esperados, rechazo de enclave debug |
| KMS desde el enclave | `enclave/kms.ts` | SDK v3; TLS terminado dentro del enclave vía vsock-proxy |
| Protocolo padre⇄enclave | `enclave/protocol.ts` | Tramas de 4 B de longitud + JSON, máximo 1 MiB, timeout 30 s |
| Simulación (NO segura) | `enclave/simulated.ts` | PKI P-384 de pruebas, KMS simulado con AES-256-GCM |

### 2.11 WebAuthn (policy-engine) — código propio

`services/policy-engine/src/webauthn.ts`: decodificador CBOR propio (línea 22), COSE EC2 P-256 → JWK (línea 95),
verificación de registro (línea 147): `clientDataJSON` (tipo, desafío en tiempo constante, origen,
`crossOrigin`), `rpIdHash` en tiempo constante, flags UP/AT, id de credencial, attestation `packed` (propia o
x5c, ECDSA P-256 SHA-256) o `none` (si se permite). La cadena x5c **no** se valida contra FIDO MDS (decisión
documentada). Desafíos de 32 B aleatorios (línea 129).

### 2.12 Web Push (notification-gateway) — código propio sobre node:crypto

`services/notification-gateway/src/webpush.ts`: RFC 8291 (ECDH P-256 efímero, HMAC-SHA256 como HKDF, AES-128-GCM
en un único registro `aes128gcm` RFC 8188, líneas 30-58); RFC 8292 VAPID (JWT ES256 con `aud` = origen del
endpoint, máximo 24 h, líneas 89-97); llaves VAPID desde `NOTIFY_VAPID_PRIVATE_KEY` o efímeras (líneas 75-86).
La gateway valida que `p256dh` sea un punto de la curva (`gateway.ts` `validateSubscription`) y solo envía a
hosts de servicios push conocidos con `redirect: 'error'`. Los retrasos aleatorios salen del CSPRNG desde la
revisión interna (IR-2026-09-14).

### 2.13 Adjuntos, espejo y autenticación de servicios

| Qué | Dónde | Primitivas |
|---|---|---|
| Adjuntos cifrados en cliente (Blossom) | `packages/blossom-client/src/client.ts:64-90,124-133` | AES-256-GCM (`@noble/ciphers`), llave 32 B y nonce 12 B aleatorios por archivo, que viajan dentro del DM cifrado; integridad por SHA-256 del ciphertext |
| Continuity Vault: sobres de archivo (VAULT-01/02, ADR 0011) | `packages/continuity/src/seal.ts`, `envelope.ts` | Llave de archivo de 32 B aleatorios por persona, nunca la nsec; viaja solo dentro del backup de identidad (NIP-49). HKDF-SHA256 con sal `sedecim-archive-v1` y un `info` por uso: `seal` (llave XChaCha20-Poly1305), `id` (HMAC-SHA256 que convierte una etiqueta en el id opaco del archivo), `auth`/`auth/<i>` (llave secp256k1 que firma el NIP-98 de la cuenta del vault) y `key-id` (huella de 8 B, en claro en el sobre). Sobre `sedecim-archive-envelope` v1: nonce aleatorio de 24 B, texto enmarcado con su longitud (u32) y relleno hasta 256 B como mínimo, AAD `formato:versión:key_id:id`. La restauración verifica la firma y el id de cada evento y que cada archivo esté bajo el id que implica su contenido; el listado debe venir en orden estricto (IR-2026-10-04) |
| Espejo sellado en reposo | `services/indexer/src/codec.ts:45-63` | XChaCha20-Poly1305 con `MIRROR_AT_REST_KEY` (32 B hex por env), nonce aleatorio y AAD `acceso-nostr/mirror/v2/<event_id>` (`seal_version` 2, SEC-06). Las filas anteriores, sin AAD, solo se abren en su propia fila (el evento debe tener el `event_id` de la fila) y el indexer las vuelve a sellar al arrancar |
| Tokens Acceso (Cognito) | `packages/service-kit/src/cognito.ts:56-84` | RS256 contra el JWKS del pool (caché 1 h, refetch por `kid` desconocido limitado a 1/min), `iss`, `exp`, `token_use`, `aud`/`client_id` |
| Tokens bearer entre servicios | `packages/service-kit/src/http.ts:33-43` `safeEqual`/`lookupToken` | `timingSafeEqual` sobre bytes |
| Sesiones de política | `services/policy-engine/src/engine.ts:96-110` | 24 B aleatorios, guardados como hash |
| Secreto del bunker NIP-46 | `packages/signer/src/nip46.ts:83,300,313,396` | 16 B aleatorios; comparación en tiempo constante |
| Referencias en logs | `services/notification-gateway/src/gateway.ts` `ref` | HMAC-SHA256 con llave aleatoria por proceso, truncado |

### 2.14 Eventos firmados y webhooks (policy-engine, OPS-16) — código propio sobre node:crypto

`services/policy-engine/src/events.ts` y `webhooks.ts`; se describe en `docs/institutional.md` («Eventos firmados y
webhooks»).

| Qué | Dónde | Primitivas |
|---|---|---|
| Firma de cada evento | `events.ts` `signPolicyEvent`, `verifyPolicyEvent` | Ed25519 (`sign`/`verify` de `node:crypto`, algoritmo `null`) sobre el JSON canónico RFC 8785 (`canonicalJson`, propio) del evento sin `sig`; lo firmado incluye `issuer` y `kid`. `kid` = huella RFC 7638 (SHA-256) de la llave pública. Al verificar, una entrada del JWKS solo cuenta para el `kid` que da su propia huella |
| Llave de firma | `events.ts` `parseSigningKey`, `config.ts` `eventsConfigFromEnv` | PKCS#8 PEM o semilla de 32 B en hex, leída de `POLICY_EVENTS_SIGNING_KEY_FILE`; sin llave por defecto. Los errores no citan el fichero |
| Secreto de cada suscripción | `events.ts` `webhookSecret` | HMAC-SHA256(`POLICY_WEBHOOK_SECRETS_KEY`, `sedecim/policy-webhook-secret/v1` ‖ id ‖ sal), con una sal de 16 B aleatorios (`randomBytes`). No se guarda: se deriva en cada entrega |
| Firma de cada entrega | `events.ts` `webhookSignatureHeader`, `verifyWebhookSignature` | HMAC-SHA256(secreto, `t.cuerpo`) en hex; la referencia del receptor compara con `timingSafeEqual` y aplica una ventana de 300 s |
| Id de cada evento | `engine.ts` `seal` | `randomUUID` |

## 3. Ciclo de vida de las llaves por tipo

| Llave | Se genera | Se guarda | Se usa | Se destruye / rota |
|---|---|---|---|---|
| nsec local (web) | `generateSecretKey` en el navegador | Dentro de la bóveda cifrada de IndexedDB (§2.7) | `LocalSigner` en memoria tras desbloquear | Al borrar la persona; `wipe` best effort |
| nsec local (CLI soberano) | Idem | NIP-49 dentro del store cifrado en disco (`manager.ts:111-114`) | Tras desbloquear con frase | Idem |
| nsec offline (keygen) | Generador air-gapped | Hoja de respaldo con ncryptsec (logN 18) | Importación en un cliente | Responsabilidad del usuario |
| nsec managed | Servidor (`service.ts` `create`) o importada | Vault (§2.9); nunca en tablas de la aplicación | Por operación, se borra tras usar | Borrado lógico + ventana de retención (DEC-09: 30 días, Secrets Manager recovery window) |
| nsec managed-enclave | Dentro del enclave | Blob sellado (KMS + PCR) en el vault | Solo dentro del enclave | Igual que managed |
| Llave de conversación NIP-44 | Derivada por mensaje | No se guarda | | |
| Llave efímera de gift wrap | Una por wrap | No se guarda | Firma del wrap | Se descarta |
| Estado MLS / secretos de época | ts-mls | Store cifrado (codec §2.6) | Grupos Marmot | Rotación por commit; tras revocación de dispositivo |
| Master key del store / bóveda | Aleatoria (bóveda) o scrypt (store) | Envuelta por frase o llave de dispositivo | Al desbloquear | Rewrap al cambiar la protección |
| Llave de dispositivo WebCrypto | `crypto.subtle.generateKey` | IndexedDB, no extraíble | Envolver la master key | `forget()` |
| Content key de backup | Aleatoria 32 B | Envuelta con NIP-49 en el paquete | Restaurar | Una por backup |
| KEK de `LocalEnvelopeVault` | Operador | Env / HSM | Arranque | Manual (no hay rotación automática) |
| Data keys de KMS | KMS por secreto | Envueltas (`edk`) junto al ciphertext | Por operación | Con el secreto |
| RSA del enclave | Por arranque | Solo memoria del enclave | Recibir data keys de KMS y abrir los secretos que el cliente sella hacia el enclave (FR005-10) | Al reiniciar el enclave: un sobre sellado a la anterior ya no abre |
| VAPID | Operador (`NOTIFY_VAPID_PRIVATE_KEY`) o efímera | Env | Firmar JWT VAPID | Rotarla obliga a re-suscribir |
| `MIRROR_AT_REST_KEY` | Operador | Env (Secret de k8s) | Sellar/abrir el espejo | Sin rotación implementada |
| Tokens bearer de servicio | Operador | Env / Secret | Llamadas entre servicios | Manual |
| Identidad del watcher (`NOTIFY_NSEC`) | Operador o efímera | Env | NIP-42 del gateway | Manual |
| Llave de firma de eventos (Ed25519, OPS-16) | Operador (`openssl genpkey -algorithm ed25519`, o 32 B aleatorios) | Fichero montado desde un Secret (`POLICY_EVENTS_SIGNING_KEY_FILE`); la pública, en `policy_event_keys` | Firmar cada evento al emitirlo | Rotación documentada (`docs/runbooks/webhooks.md`): las públicas anteriores se siguen publicando, salvo las de `POLICY_EVENTS_REVOKED_KIDS` |
| Llave de secretos de webhook (OPS-16) | Operador (32 B aleatorios) | Fichero montado desde un Secret (`POLICY_WEBHOOK_SECRETS_KEY_FILE`) | Derivar el secreto de cada suscripción | Rotarla cambia todos los secretos: baja y alta de las suscripciones (runbook) |
| Secreto de una suscripción de webhook (OPS-16) | Derivado en el alta (§2.14) | No se guarda; se muestra una vez | Firmar cada entrega (HMAC) | Baja y alta de la suscripción |

## 4. Fuentes de aleatoriedad

- `@noble/hashes/utils.js` `randomBytes` → `crypto.getRandomValues` (Node y navegador): llaves, nonces, sales,
  ids (`packages/nostr-core/src/utils.ts:1`).
- `node:crypto.randomBytes` en servicios (tokens, ids, IV de GCM/CBC, desafíos WebAuthn, sesiones, ids de traza y
  de span de `packages/telemetry-policy`, sales de las suscripciones de webhook); `randomUUID` para el id de cada
  evento del policy-engine (OPS-16).
- WebCrypto `getRandomValues` en `encrypted-store/browser.ts:99`.
- `randomInt` sin sesgo (muestreo por rechazo) para el jitter de NIP-59 (`utils.ts:30`).
- `Math.random` **solo** para jitter de reintentos (`packages/delivery-engine/src/engine.ts:44`,
  `packages/relay-pool/src/connection.ts:200`, y el de los webhooks del policy-engine:
  `services/policy-engine/src/webhooks.ts` `WebhookDispatcher`, OPS-16) y muestreo de trazas
  (`packages/telemetry-policy`); ninguno es material criptográfico ni oculta metadatos. El retraso de push ya no lo usa
  (IR-2026-09-14).

## 5. Código criptográfico o de parseo escrito en el repositorio

Objetivos de mayor valor para el auditor:

| Código | Ruta | Por qué importa | Fuzz |
|---|---|---|---|
| NIP-44 v2 | `packages/nostr-core/src/nip44.ts` | Implementación propia de la spec | Vectores oficiales en `packages/nostr-core/test/nip44-vectors.test.ts`; `tests/fuzz/nip44.test.ts` (diferencial con nostr-tools) |
| NIP-49 | `packages/nostr-core/src/nip49.ts` | Formato y KDF | `packages/nostr-core/test/nip49-vectors.test.ts`; `tests/fuzz/nip49.test.ts` |
| Decodificador CBOR WebAuthn | `services/policy-engine/src/webauthn.ts:22` | Entrada de cualquier cliente autenticado | `tests/fuzz/webauthn.test.ts` |
| Decodificador/codificador CBOR + COSE_Sign1 | `packages/signer/src/enclave/cbor.ts` (reexportado en `services/managed-signer/src/enclave/cbor.ts`), `attestation.ts` de los dos | Attestation Nitro; entra por el padre, en el servicio y en el navegador (FR005-10) | `tests/fuzz/enclave-parsers.test.ts` |
| Lector/escritor ASN.1 DER y X.509 del cliente | `packages/signer/src/enclave/der.ts` (reexportado en el servicio), `packages/signer/src/enclave/attestation.ts` | Acepta longitudes BER no mínimas (tolerancia deliberada con KMS); el X.509 propio decide la cadena de la attestation en el navegador | `tests/fuzz/enclave-parsers.test.ts` (diferencial con `node:crypto`) y `services/managed-signer/test/enclave-attestation-portable.test.ts` |
| Sobre sellado hacia el enclave (FR005-10) | `packages/signer/src/enclave/envelope.ts`, `services/managed-signer/src/enclave/sealed-secrets.ts` | Entra por el padre y se abre dentro del enclave | `tests/fuzz/enclave-parsers.test.ts` |
| Parser CMS EnvelopedData | `services/managed-signer/src/enclave/cms.ts` | Descifra la data key dentro del enclave | `tests/fuzz/enclave-parsers.test.ts` |
| Codec protobuf nauthz (gRPC h2c) | `services/policy-engine/src/allowlist-sync.ts:77-150` | Decide la admisión en el relay seguro | `tests/fuzz/nauthz-proto.test.ts` |
| Web Push RFC 8291/8292 | `services/notification-gateway/src/webpush.ts` | Criptografía propia sobre node:crypto | Vector RFC 8291 (tests) |
| Saneado JPEG/PNG/WebP | `packages/blossom-client/src/sanitize.ts` | Privacidad de metadatos de archivos | `tests/fuzz/media-sanitize.test.ts` |
| Codec del estado MLS y codec TLS estricto | `packages/marmot-adapter/src/marmot-ts.ts`, `mls-codec.ts` | Persistencia de secretos de grupo | `tests/fuzz/mls-codec.test.ts` |
| Parsers de backup | `packages/identity/src/key-backup.ts`, `backup-vault.ts` | Entrada de archivos del usuario y del servidor | `tests/fuzz/backup.test.ts` |
| TLV NIP-19 | `packages/nostr-core/src/nip19.ts` | Enlaces y QR | `tests/fuzz/nip19.test.ts` |
| JSON canónico y verificación de eventos (OPS-16) | `services/policy-engine/src/events.ts` `canonicalJson`, `verifyPolicyEvent` | Lo que se firma y se verifica de cada evento; la verificación recibe JSON de cualquier consumidor | Sin fuzz: casos fijos en `services/policy-engine/test/events.test.ts` |
| Guarda de destinos de webhook (OPS-16) | `services/policy-engine/src/webhooks.ts` `checkWebhookUrl`, `resolveDestination`, `isPublicAddress` | Decide a qué direcciones se conecta el servidor (SSRF) | Sin fuzz: cada clase de dirección en `services/policy-engine/test/webhooks.test.ts` |

Desviaciones conocidas respecto a lo habitual:

1. CMS con AES-256-CBC sin autenticación: impuesto por KMS; la integridad depende de TLS con KMS terminado en
   el enclave. Los errores de padding llegan al padre como mensajes distintos (IR-2026-09-18).
2. WebAuthn sin validación de la cadena x5c ni de AAGUID (IR-2026-09-17).
3. ~~Espejo sellado sin AAD (IR-2026-09-15)~~: corregido en SEC-06.
4. Sal del store como texto hex (§2.7).
5. Anti-replay de NIP-98 solo por proceso en servicios sin Postgres (notification-gateway), y tokens Blossom
   (kind 24242) reutilizables hasta su `expiration`, como permite BUD-02 (IR-2026-09-04).

## 6. Vectores y tests criptográficos presentes

| Área | Qué hay | Dónde |
|---|---|---|
| Eventos, NIP-19, NIP-44, NIP-49 | Interoperabilidad y diferencial con nostr-tools, propiedades de manipulación | `packages/nostr-core/test/core.test.ts`, `tests/fuzz/*.test.ts` |
| NIP-44 | Vectores oficiales v2 completos (`nip44.vectors.json`, con el SHA-256 publicado en la NIP comprobado por el test): llaves de conversación y de mensaje, padding, cifrado y descifrado en ambos sentidos, mensajes de 64 KiB y todos los casos inválidos (SEC-07) | `packages/nostr-core/test/nip44-vectors.test.ts` |
| NIP-49, NIP-59 | Vectores exportables en JSON (ADR 0004, SEC-07), generados de forma determinista con `@noble` y no con el código que prueban. NIP-49: el vector publicado en la NIP, normalización NFKC, casos válidos con sal y nonce, y cinco inválidos. NIP-59: DM y copia al emisor, y cinco rechazos (destinatario, firma del wrap, kind del seal, suplantación, rumor editado) | `packages/nostr-core/test/vectors/`, `nip49-vectors.test.ts`, `packages/messaging/test/nip59-vectors.test.ts` |
| Web Push | Ejemplo trabajado de RFC 8291 §5 / Apéndice A | `services/notification-gateway/test/webpush.test.ts` |
| Attestation Nitro | Raíz G1 fijada por huella; PKI simulada; documentos manipulados, caducados, debug, PCR y nonce distintos | `services/managed-signer/test/enclave-attestation.test.ts` |
| Attestation Nitro en el cliente (FR005-10) | Diferencial con la verificación de `node:crypto` sobre una matriz de mutaciones (mismo veredicto y código) y autofirma de la raíz real de AWS; ECDSA P-384 frente a firmas de OpenSSL (DER y r‖s, alta S) | `services/managed-signer/test/enclave-attestation-portable.test.ts`, `packages/nostr-core/test/p384.test.ts` |
| Secretos sellados (FR005-10) | Sobre abierto a mano con `node:crypto` (formato y AAD exactos), manipulaciones de cada parte, AAD, frescura, tamaño; lo que ve el padre durante una importación y una exportación selladas | `packages/signer/test/enclave-seal.test.ts`, `services/managed-signer/test/enclave-sealed-*.test.ts` |
| Enclave extremo a extremo | Generar, importar, firmar, NIP-44, exportar con KMS simulado | `services/managed-signer/test/enclave-signer.test.ts` |
| Vault AWS | Unitario con KMS falso; integración con moto en CI | `services/managed-signer/test/aws-vault.test.ts` |
| WebAuthn | Autenticador de prueba (packed propia y none) | `services/policy-engine/test/webauthn*.ts` |
| MLS/Marmot | Informes de interoperabilidad con MDK 0.8.0 y nostr-rs-relay | `docs/interop/marmot-*.json`, `tests/interop` |
| Pérdida de dispositivo | Revocación → rotación MLS → el estado robado no lee | `tests/security/device-loss.test.ts` |
| Límite de coste de import | logN atacante, contraseña errónea | `tests/security/managed-import-limits.test.ts` |

Campañas de fuzz más largas: `FUZZ_RUNS=2000 npx vitest run tests/fuzz --testTimeout=0`.
