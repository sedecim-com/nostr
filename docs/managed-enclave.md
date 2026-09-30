# Custodia managed en enclave Nitro (FR005-05)

- **Estado:** prototipo. **Tarea:** FR005-05 (P3), **Parcial**.
- **Madurez:** Preview. Va apagado en producción, igual que su exportación: el gate de release (OPS-20,
  [`deploy/production-gates.json`](../deploy/production-gates.json)) falla si la configuración de producción usa
  `MANAGED_SIGNER_BACKEND=enclave`, `ENCLAVE_ALLOW_EXPORT=1`, `enable_enclave_signer = true` o, en la web,
  `managedEnclave`. Para salir de Preview hacen falta FR005-05 y FR005-09 verificados en AWS real, y su auditoría.
  FR005-09 (el enclave exige una prueba del dueño para exportar) y FR005-10 (los secretos de una importación y la
  contraseña de una exportación llegan sellados hacia el enclave) ya están en el código y probados sin AWS; ver
  «Exportar exige la prueba del dueño» y «Secretos sellados hacia el enclave».
- **Criterio:** "Prototipo con attestation verificada; backend general sin llave en claro".
- **Depende de:** [ADR 0009](adr/0009-custodia-managed-region-y-marco-legal.md) (custodia managed en `us-east-1`,
  KMS + Secrets Manager) y [`docs/disclosures.md`](disclosures.md) (modo `managed-enclave`).

El tier enclave sigue siendo **custodial**: el servicio puede firmar como el usuario. Lo que cambia es
*dónde* existe la llave en claro. En el tier managed normal, la nsec se descifra en memoria del proceso
`managed-signer`. En el tier enclave, la nsec solo existe dentro de un AWS Nitro Enclave. El backend guarda
blobs sellados que no puede descifrar y recibe solo llaves públicas, eventos firmados y resultados NIP-44.

## Arquitectura

```
 cliente ──HTTPS──► managed-signer (backend, pod/host padre)      KMS (us-east-1)
 (verifica la        │  registro Postgres + vault (blobs sellados)     ▲
  attestation y      │  retransmite sin abrir los secretos sellados    │
  sella secretos)    │                                                 │
                     │  EnclaveClient: verifica attestation            │ Decrypt / GenerateDataKey
                     │  (nonce, raíz Nitro, PCR0/1/2[/8])              │ con Recipient = attestation
                     ▼                                                 │ → CiphertextForRecipient
                   vsock (socat ⇄ socket local) ──► enclave: EnclaveSigner
                                                    ├─ NSM: documento de attestation (clave RSA efímera)
                                                    ├─ descifra la data key (CMS, RSA-OAEP-SHA256)
                                                    ├─ AES-256-GCM → nsec solo en memoria del enclave
                                                    └─ firma Schnorr (BIP-340) / NIP-44 → borra la nsec
```

Código en `services/managed-signer/src/enclave/`:

| Archivo | Qué hace |
|---|---|
| `enclave.ts` | `EnclaveSigner`: programa del enclave. Genera, importa (NIP-49), sella con el dueño, abre, firma, cifra NIP-44 y exporta (FR-026) solo con la prueba del dueño (FR005-09). Ninguna respuesta lleva material de llave. |
| `sealed-secrets.ts` | Abre, con la RSA efímera del enclave, los secretos que el cliente sella hacia él (FR005-10): formato, AAD, frescura con el reloj del NSM. |
| `proof.ts` | `PinnedJwksProofVerifier`: verifica dentro del enclave el token de Acceso del dueño (RS256, con las llaves de la user pool fijadas en la imagen) y lee la configuración `ENCLAVE_PROOF_*` (FR005-09). |
| `protocol.ts` | Protocolo padre ⇄ enclave: tramas de 4 bytes de longitud + JSON. Hay transporte por socket (unix o TCP, puenteado a vsock con socat) y transporte en proceso (tests). |
| `attestation.ts` | Verificación del documento de attestation: COSE_Sign1/CBOR, cadena de certificados hasta la raíz Nitro fijada, firma ES384, vigencia, frescura, nonce y PCR. |
| `cbor.ts`, `der.ts`, `cms.ts` | CBOR mínimo, DER mínimo, y CMS EnvelopedData (`CiphertextForRecipient` de KMS). No añaden dependencias. CBOR y DER viven en `packages/signer/src/enclave/` (sin `node:*`, los usa también el navegador) y aquí se reexportan. |
| `kms.ts` | KMS con `Recipient` (SDK v3). Rechaza cualquier respuesta con `Plaintext`. |
| `client.ts` | `EnclaveClient` (lado backend). Verifica la attestation antes de operar y la repite cada 10 min. Comprueba cada evento devuelto: firma válida y pubkey esperada. |
| `wiring.ts` | `MANAGED_SIGNER_BACKEND=enclave` y el modo simulado. |
| `simulated.ts` | Enclave **SIMULADO, NO SEGURO**. Ver abajo. |
| `main.ts` | Punto de entrada de la imagen del enclave (EIF). |

Y en `packages/signer/src/enclave/`, lo que usa el cliente (navegador incluido) para hablar con el enclave (FR005-10):

| Archivo | Qué hace |
|---|---|
| `attestation.ts` | `verifyNitroAttestation`: la verificación de attestation sin `node:*`, con las mismas reglas y códigos de error que `attestation.ts` del servicio (ECDSA P-384 de `@noble/curves` vía `verifyEcdsaP384` de `nostr-core`). |
| `envelope.ts` | Formato del sobre, AAD, `ownerTag`, `sealToEnclave` (WebCrypto) y la lectura estricta que comparten cliente y enclave. |

### Sellado de una llave

1. El enclave genera una llave RSA-2048 efímera al arrancar. La parte pública va en el campo `public_key`
   de cada documento de attestation.
2. **Crear.** El enclave genera la nsec. Llama a `GenerateDataKey` con
   `Recipient = {AttestationDocument, RSAES_OAEP_SHA_256}` y contexto de cifrado
   `{app, purpose: enclave-key, pubkey, owner_tag}`. KMS no devuelve la data key en claro: devuelve `CiphertextBlob` y
   `CiphertextForRecipient` (CMS cifrado a la RSA del enclave). El enclave descifra la data key, sella la
   nsec con AES-256-GCM (AAD = pubkey y `owner_tag`), borra ambas y devuelve `{pubkey, sealed}`.
   `owner_tag` es el SHA-256 del dueño (`<issuer>#<sub>` de Acceso, como el managed-signer nombra al dueño) con una
   etiqueta de dominio: un hash y no el dueño, porque el contexto de cifrado se escribe en claro en CloudTrail, que ya
   ve la pubkey y no debe ver además qué cuenta de Acceso hay detrás. El blob (v2) lleva esa etiqueta en `ot`; quien la
   reescriba no abre la llave, porque la etiqueta está dentro del contexto de KMS y del AAD. Los blobs v1 (sin dueño)
   se siguen leyendo para firmar y cifrar, pero no se pueden exportar.
3. **Usar.** El backend manda `sealed` y la pubkey. El enclave llama a `Decrypt` con un documento de
   attestation nuevo, abre la nsec y comprueba que su pubkey coincide con la esperada. Después firma,
   destruye el `LocalSigner` y devuelve el evento.
4. El backend guarda `sealed` en el vault que ya usa (`MANAGED_SIGNER_VAULT`: Secrets Manager o local). El
   registro en Postgres no cambia. `provider` pasa a ser `nitro-enclave+aws-secrets-manager` y la vista
   devuelve `custody: managed-enclave`.
5. Los tiers no se mezclan. Las llaves creadas con el backend en proceso guardan la nsec (cifrada por el
   vault) y el enclave no las acepta. Pasar una llave existente al tier enclave requiere una migración
   explícita: exportar e importar con `POST /v1/keys/import` (con el `consent_version` que el usuario aceptó, FR005-08), que en el tier enclave se descifra dentro del
   enclave; con `sealed_secrets`, sin que el padre vea el `ncryptsec` ni su contraseña (FR005-10).

### Exportar exige la prueba del dueño (FR005-09)

Antes, el enclave cifraba la nsec con la contraseña que le mandaba el padre sin saber para quién: un backend
comprometido podía exportar cualquier blob con una contraseña suya (IR-2026-09-01). Ahora el enclave se niega a
exportar sin que el dueño de la llave le demuestre, a él y no al padre, que lo pide:

1. **La prueba es el token de Acceso del dueño** (el mismo que autentica la llamada en el backend). El backend lo
   reenvía tal cual y el enclave lo verifica con `PinnedJwksProofVerifier`: RS256 (el algoritmo lo fija el enclave, no
   el token), con las llaves de la user pool **fijadas en la imagen** (`ENCLAVE_PROOF_JWKS`, parte de las medidas PCR:
   el padre puede retransmitir un token, no fabricarlo ni cambiar las llaves con que se comprueba), `iss`, `token_use`,
   `aud` o `client_id`, `exp`, `iat`, y un identificador `jti`.
2. **El token tiene que ser del dueño de esa llave**: `<iss>#<sub>` del token, hasheado, igual al `ot` del blob. Un token
   válido de otro usuario no abre la llave, y un blob sin dueño (v1) no se exporta.
3. **Con un inicio de sesión reciente**: `auth_time` de los últimos 300 s (`ENCLAVE_PROOF_MAX_AGE_S`), el mismo límite que
   aplica el backend (IR-2026-10-03), pero juzgado con **el reloj del enclave**, que es la marca de tiempo de un
   documento de su propio NSM (Nitro Secure Module). El padre no aporta hora ni puede torcerla, así que no puede
   envejecer un token robado hasta hacerlo válido otra vez.
4. **Un token sirve una vez**: el enclave recuerda los `jti` que aceptó hasta que caducan (en memoria, hasta 10 000;
   lleno, rechaza antes que olvidar uno). Repetir una exportación pide iniciar sesión otra vez.
5. **Sin verificador no hay exportación**: con `ENCLAVE_ALLOW_EXPORT=1` la imagen no arranca si faltan
   `ENCLAVE_PROOF_ISSUER`, `ENCLAVE_PROOF_CLIENT_ID` o `ENCLAVE_PROOF_JWKS`, y un enclave sin verificador rechaza todas
   las exportaciones (403). Los rechazos del enclave llegan al cliente como 401 (falta o falla la prueba, o ya se usó) o 403
   (no es del dueño, sin dueño, o sin verificador).

La rotación de las llaves de firma de la user pool es un cambio de imagen: hay una EIF nueva con el `jwks.json` nuevo,
PCR nuevos y su actualización en `enclave_pcr*` (Terraform) y en `MANAGED_SIGNER_ENCLAVE_PCR*`. Mientras tanto los tokens
firmados con la llave nueva no sirven como prueba y la exportación se niega (falla cerrada); firmar, cifrar y abrir
blobs no dependen de ello.

### Secretos sellados hacia el enclave (FR005-10)

Con la prueba del dueño el padre ya no exporta solo, pero seguía viendo, en una importación, el `ncryptsec` y su
contraseña y, en una exportación legítima, la contraseña con la que el enclave cifra la llave (con ella y el `ncryptsec`
que retransmite, la nsec). Ahora el cliente puede cifrar esos secretos hacia la llave RSA efímera del enclave, y el
padre solo retransmite una cadena que no puede abrir.

1. **El cliente verifica la attestation él mismo.** Pide `GET /v1/enclave/attestation?nonce=<base64url>` con un nonce
   aleatorio propio de 32 bytes y comprueba el documento en su lado con `verifyNitroAttestation`: cadena hasta la raíz
   Nitro G1 fijada por SHA-256, firma ES384, vigencia, frescura (5 min, ±60 s, con su reloj), su nonce exacto y los PCR
   que fija quien lo usa (`EnclaveTrust`: PCR0, PCR1 y PCR2, y PCR8 si se da; sin los tres primeros no se acepta). Si
   confiara en la llave que le da el padre, el padre pondría la suya. El padre también comprueba el documento con su
   política antes de retransmitirlo, pero el cliente no depende de eso.
2. **El sobre**: `ae1.<ek>.<iv>.<ct>`, en base64url sin relleno y como mucho 4096 caracteres, que se miran antes de
   descifrar nada. `ek` es RSA-OAEP (SHA-256, MGF1-SHA-256) de una llave AES-256-GCM aleatoria hacia la SPKI del
   documento; `iv`, 12 bytes; `ct`, el contenido cifrado con su tag de 16 bytes al final. AAD:
   `acceso-nostr/enclave-envelope/v1|<import o export>|<owner_tag>|<pubkey, o vacío al importar>`. Contenido:
   `{ncryptsec, password, at}` al importar y `{password, at}` al exportar, donde `at` es el `timestamp` del documento
   que verificó el cliente. Se sella con WebCrypto (el del navegador, o el de Node ≥ 20).
3. **El enclave lo abre** con su llave privada RSA, que no sale de él. Reconstruye el AAD desde la petición (al importar,
   el `owner_tag` del dueño que declara el padre; al exportar, el `ot` del blob y la pubkey de la petición), exige que
   `at` sea de los últimos 5 minutos (y no más de 60 s en el futuro) según **su reloj**, el del NSM, y aplica las mismas
   reglas que en claro: logN 18 como mucho al importar, contraseña de exportación de al menos 12 caracteres. Todo fallo
   al abrir recibe la misma respuesta, un 400 (sellado para otra llave, para otra petición, o alterado). La llave RSA es
   efímera por arranque: si el enclave reinició, el sobre ya no abre y el error pide una attestation nueva; nunca es un
   500. Al exportar, el sobre se abre antes de gastar la prueba del dueño: un sobre que falla no le cuesta al usuario
   otro inicio de sesión. Lo que se puede se borra de memoria; las cadenas (contraseña, `ncryptsec`) quedan en el heap
   de JavaScript hasta que las recoge el recolector, como las que llegan en claro.
4. **La API** acepta `sealed_secrets` en `POST /v1/keys/import` en lugar de `ncryptsec` y `password`, y
   `sealed_password` en `POST /v1/keys/:id/export` en lugar de `password`; nunca los dos ni ninguno (400). El servicio
   los reenvía tal cual: mira tipo y tamaño y no los registra. Consentimiento, inicio de sesión reciente sin sesión de
   dispositivo, límites de scrypt y prueba del dueño valen igual en los dos modos. El backend vault responde 400 a los
   sellados: descifra en su propio proceso, y sellar no protegería nada.
5. **El cliente y la web.** `ManagedSignerClient.exportForMigration(password, { enclave })` nunca manda la contraseña
   en claro, y `ManagedSignerClient.importEncrypted(conn, ncryptsec, password, { consentVersion, enclave })` sella la
   importación; sin `enclave`, los dos se comportan como antes. El dueño del AAD (`<iss>#<sub>`) sale de las claims del
   token de Acceso, sin verificarlo aquí: lo comprueba el enclave. Si la verificación de la attestation falla, el cliente
   no envía nada. La web lo hace en la migración a custodia local y en el respaldo antes de cancelar cuando su
   `config.json` trae `managedEnclave` (ver «Configuración»); sin él, exporta como antes.
6. **Hacerlo obligatorio.** `ENCLAVE_REQUIRE_SEALED_SECRETS=1` (en la imagen) hace que el enclave rechace con 403 los
   secretos en claro, y `MANAGED_SIGNER_REQUIRE_SEALED_SECRETS=1` (en el backend, solo con `MANAGED_SIGNER_BACKEND=enclave`)
   los rechaza con 400 antes de reenviarlos. Con ellos, además, el dueño de una llave **importada** queda atado al
   cliente: el dueño va en el AAD, así que el padre ya no puede importarla bajo otro. No cierra la creación
   (`generate`), donde el dueño lo sigue declarando el padre.

Lo que **no** resuelve:

- **Un padre que fabrica su propio sobre.** Cualquiera con la llave pública del enclave, que va en cada attestation,
  puede sellar. Un padre comprometido que retransmite el token de Acceso de un usuario (dentro de su ventana de 300 s,
  FR005-09) puede sellar él mismo una contraseña que elija y exportar con ella. Lo cierra una prueba del usuario que el
  padre no pueda retransmitir (por ejemplo, una firma con passkey sobre un reto del enclave), que todavía no existe.
- **Un despliegue web hostil.** El HTML y el JavaScript de la web, y los PCR esperados (`managedEnclave`), los sirve el
  operador: quien los controla puede servir un cliente que mande la contraseña en claro o que espere los PCR de otra
  imagen. Esto protege frente a un managed-signer comprometido, no frente a quien controla la web.
- **Nunca se ha probado contra un Nitro real** (FR005-05). El verificador del navegador solo ha visto documentos de la
  PKI simulada y la autofirma de la raíz real de AWS; falta un documento de un enclave real, con sus certificados y su
  reloj. En la cadena es más estricto que OpenSSL (rechaza extensiones críticas que no conoce, compara los nombres como
  DER y solo acepta P-384 con SHA-384): si un certificado real de Nitro no cumpliera algo de eso, la exportación sellada
  fallaría cerrada hasta corregirlo.
- **Los PCR esperados son el punto de confianza.** El cliente confía en el enclave cuyos PCR le dan. Si son los de una
  imagen que nadie revisó o que no se construyó de forma reproducible, sellar hacia ella no protege nada (ver «Cadena de
  suministro de la EIF»).
- **`generate` sigue declarando el dueño el padre**, y firmar y cifrar NIP-44 siguen obedeciendo al padre (ver
  «Riesgos residuales»).
- **Repetición dentro de la ventana.** `at` limita un sobre capturado a 5 minutos, no a un uso. Una exportación
  repetida necesita además un token de Acceso sin usar (FR005-09); una importación repetida da la misma llave para el
  mismo dueño, y el registro la rechaza si ya está gestionada (409).
- **El reloj del navegador.** El cliente rechaza documentos de más de 5 minutos según su reloj: con la hora muy
  desviada no puede sellar (falla cerrado, no manda la contraseña en claro).

### Política KMS (`deploy/terraform/modules/acceso-nostr/enclave.tf`)

Con `enable_enclave_signer = true` se crea `alias/acceso-nostr-<env>-enclave-signer` con esta política:

- `EnclaveUseWithAttestation`: permite `kms:Decrypt` y `kms:GenerateDataKey` a los principales del host
  padre, pero solo con `kms:RecipientAttestation:ImageSha384 = enclave_pcr0`, `PCR1`, `PCR2` y, si se
  define, `PCR8`. Los principales son el usuario IAM del signer en kops o `enclave_principal_arns`.
- `DenyWithoutEnclaveAttestation`: deniega explícitamente a todos (`*`) las operaciones que devuelven data
  keys o texto claro si `ImageSha384` no coincide. Una petición sin attestation no tiene la clave de
  condición, así que cuenta como "no igual" y se deniega. Esto incluye a administradores y a quien tenga
  `kms:*` por IAM.
- `DenyReEncrypt`: nadie puede re-cifrar el material hacia otra llave.
- `KeyAdministration`: administración sin permisos de uso. No incluye `kms:*`.

Las credenciales que el enclave usa para llamar a KMS son las del padre. Aun así, el padre no obtiene nada
útil: sin un documento firmado por el hipervisor Nitro con esos PCR, KMS deniega. Con un documento válido,
la respuesta va cifrada a una clave privada que solo existe dentro del enclave.

Opcional: `aws_launch_template.enclave_host` crea un host padre con `enclave_options { enabled = true }` e
IMDSv2 obligatorio. Se activa con `enclave_host_ami_id`. Los nodos de kops pueden usar la misma opción en su
launch template.

## Modelo de amenazas

| Amenaza | Tier managed | Tier enclave | Cómo |
|---|---|---|---|
| Volcado de memoria / RCE en el backend | Expone las nsec en uso | Expone solo blobs sellados | La nsec nunca sale del enclave. Ninguna operación del protocolo la devuelve (`protocol.ts`) |
| Robo de la base de datos o de Secrets Manager | Protegido por KMS; el backend sí puede descifrar | Protegido por KMS; el backend no puede descifrar | Política KMS condicionada a PCR, con deny explícito |
| Credenciales IAM del signer filtradas | Permiten descifrar todas las llaves | No permiten descifrar | Sin attestation, KMS deniega; con attestation, la respuesta va cifrada a la RSA del enclave |
| Imagen del enclave modificada (código malicioso) | n/a | KMS deniega | PCR0/1/2 distintos. Probado en `enclave-signer.test.ts` |
| Enclave en modo debug (consola visible) | n/a | Rechazado | En debug los PCR0-2 valen cero. `verifyAttestation` lo rechaza y KMS no casa los PCR |
| Backend comprometido pide firmas en nombre del usuario | Puede firmar | **Puede firmar** | **No mitigado**: el enclave obedece al padre. Ver "Riesgos residuales" |
| Backend comprometido pide exportar una llave (FR-026) | Puede | **No, sin un token del dueño** (FR005-09) | Desactivada por defecto. Activada, el enclave verifica dentro el token de Acceso del dueño (llaves fijadas en la imagen, reloj del NSM, un solo uso) y que la llave es suya. Sigue abierto que el padre retransmita un token del dueño en su ventana: ver "Riesgos residuales" |
| Backend comprometido lee la contraseña de una exportación legítima, o el `ncryptsec` y la contraseña de una importación | Los ve | **No, si el cliente los sella** (FR005-10) | El cliente verifica él mismo la attestation y los cifra hacia la RSA del enclave; el padre retransmite un sobre que no puede abrir. En claro (sin `enclave` en el cliente) los sigue viendo, salvo que `ENCLAVE_REQUIRE_SEALED_SECRETS` / `MANAGED_SIGNER_REQUIRE_SEALED_SECRETS` lo rechacen. Ver «Secretos sellados hacia el enclave» |
| Backend comprometido sustituye el documento de attestation (su llave RSA, otra imagen, debug, viejo, otro nonce) | n/a | El cliente no sella nada | Verificación en el cliente: raíz fijada, firma, PCR esperados, nonce propio y frescura. Probado en `enclave-sealed-parent.test.ts` |
| Canal padre ⇄ enclave manipulado (eventos falsos) | n/a | Detectado | El cliente verifica cada evento: firma, pubkey, kind y contenido |
| Blob sellado presentado con otra pubkey | n/a | Rechazado | El contexto KMS incluye la pubkey y el enclave compara la pubkey derivada |
| Administrador de KMS cambia la política | Puede | Puede | **Residual**: `kms:PutKeyPolicy`. Mitigación operativa: rol de break-glass y alarma de CloudTrail sobre `PutKeyPolicy` en esta llave |

### Riesgos residuales (el tier sigue siendo custodial)

- **Autorización de las firmas fuera del enclave.** Para firmar y cifrar NIP-44, el backend verifica el token de Acceso
  (Cognito) y el enclave obedece. Un backend comprometido no puede robar llaves, pero sí pedir firmas mientras controle el
  proceso. Extender a la firma la verificación que ya hace el enclave para exportar es posible con el mismo
  verificador, pero no con sesiones de dispositivo, que no llevan token.
- **Exportación FR-026 (FR005-09 cerrado en código; IR-2026-09-01).** El enclave ya no exporta por orden del padre: pide
  el token de Acceso del dueño y lo verifica dentro (ver «Exportar exige la prueba del dueño»). Lo que queda:
  - **El padre ve el token que el usuario le manda.** Con uno que aún no ha expirado y que no ha gastado el propio
    usuario puede pedir al enclave la exportación de **cualquier llave de ese dueño** con una contraseña suya, dentro de
    los 300 s siguientes al inicio de sesión con contraseña de ese usuario (el que el usuario hace para exportar, cancelar,
    borrar o cerrar sesiones). Es una ventana por usuario y por inicio de sesión, no «cualquier llave en cualquier
    momento». Lo cierra del todo una prueba que el padre no pueda retransmitir: una firma del usuario sobre un reto del
    enclave (passkey o llave de destino), que no existe todavía.
  - **La contraseña de exportación, en claro, pasa por el padre.** Con la prueba basta para que el padre no pueda
    exportar solo, pero en una exportación legítima en claro ve la contraseña y el `ncryptsec`, y con ellos la nsec. Con
    un cliente que la sella hacia el enclave (FR005-10: `exportForMigration(password, { enclave })`, y la web con
    `managedEnclave`) ya no la ve; sin él, sí, salvo que el despliegue exija secretos sellados.
  - **El dueño de una llave nueva lo dice el padre.** Al crear, el enclave sella el dueño que le pasa el padre; solo las
    llaves ya selladas quedan fuera de su alcance. Un padre comprometido en el momento de crear una llave podría
    sellarla para otro dueño. Al importar con secretos sellados (FR005-10) el dueño va en el AAD del sobre y el padre ya
    no puede cambiarlo; en claro, sí. Exigir también la prueba al crear es viable con el token de Acceso, pero no con
    las sesiones de dispositivo (`MANAGED_SIGNER_REQUIRE_DEVICE_SESSION`), que no llevan token.
  - **Memoria de tokens.** Se pierde si el enclave se reinicia: dentro de los 300 s siguientes a un reinicio, un token
    usado podría volver a servir.
- **Política KMS.** Quien pueda ejecutar `PutKeyPolicy` puede quitar las condiciones. Hay que restringir
  quién la administra (`enclave_key_admin_arns`) y auditar.
- **Cadena de suministro de la EIF.** Los PCR solo prueban qué imagen corre, no que la imagen sea correcta.
  La EIF debe construirse de forma reproducible desde un commit revisado y los PCR deben publicarse.

## Qué verifica este repositorio (sin AWS)

Tests en `services/managed-signer/test/`:

- `enclave-attestation.test.ts`: CBOR y la raíz Nitro. El PEM incluido coincide con la huella SHA-256
  publicada `641A0321…79BB5B`. Documentos válidos, con y sin tag COSE 18. Rechazos: firma inválida, firma
  con otra clave, PCR incorrecto (0 y 8), enclave en debug, certificado hoja vencido, documento viejo o del
  futuro, nonce incorrecto o ausente, raíz no fijada, cadena rota, intermedio que no es CA, algoritmo o
  digest distintos, estructura malformada, falta de `public_key`. También CMS EnvelopedData de ida y vuelta
  y el rechazo con otra clave RSA.
- `enclave-signer.test.ts`:
  - Enclave real (`EnclaveSigner`) detrás de un socket unix en lugar de vsock, con NSM y KMS simulados.
    Cubre attestation con nonce, generar, firmar, NIP-44 en ambos sentidos, importar y exportar. El blob
    sellado no contiene la nsec. Un blob con otra pubkey se rechaza.
  - KMS niega al padre sin attestation. Un enclave con otros PCR no obtiene data keys. El padre rechaza un
    enclave con PCR distintos y eventos falsificados.
  - API HTTP completa con `MANAGED_SIGNER_BACKEND=enclave` simulado: crear, firmar, importar, exportar y
    confirmar la migración. El vault solo recibe blobs sellados.
  - El adaptador SDK de KMS envía `Recipient` y rechaza respuestas con `Plaintext`.
- `enclave-proof.test.ts` (FR005-09):
  - `PinnedJwksProofVerifier`: acepta tokens id y access de la pool; rechaza otro emisor, otro cliente, `token_use`
    desconocido, tokens firmados con otra llave (mismo `kid`), `kid` desconocido, `alg: none`, HS256 con la llave
    pública como secreto, cuerpo alterado, tokens caducados o emitidos en el futuro, sin `jti`, y un inicio de sesión
    de hace más de 300 s (en el límite exacto pasa, 301 no), juzgado con la hora que se le pasa. También una
    configuración sin llaves usables, con RSA de menos de 2048 bits, `kid` repetido o emisor que no sea https.
  - Enclave: exporta con el token fresco del dueño; se niega sin prueba (401), sin verificador (403), con un token de
    otro usuario (403), con tokens falsificados, caducados o de sesión vieja, con un blob sin dueño (403) y con la
    etiqueta de dueño reescrita para casar con un token en la mano (KMS lo rechaza). Usa el reloj del NSM: un token
    fresco para esta máquina y viejo para el enclave se rechaza. Un token sirve una vez; uno rechazado por no ser del dueño
    no se gasta; la memoria de tokens tiene tope y olvida los caducados. El contexto de KMS lleva `owner_tag` y nunca el
    dueño. Crear o importar pide dueño y una contraseña de importación errónea es un 400.
  - API con el tier enclave: el token que autentica la exportación viaja al enclave y repetirlo da 401.
  - Configuración: la imagen no arranca con `ENCLAVE_ALLOW_EXPORT=1` sin la pool fijada; el enclave simulado de desarrollo la
    toma de `MANAGED_SIGNER_ENCLAVE_PROOF_*` o se niega a exportar.
- Secretos sellados (FR005-10):
  - `enclave-attestation-portable.test.ts`: el verificador portable del navegador frente al de `node:crypto`, sobre una
    matriz de documentos y mutaciones construidos con `node:crypto` (raíz equivocada o no fijada, raíz sin autofirma,
    cadena rota, cabundle desordenado o vacío, intermedio que no es CA, CA sin `keyCertSign`, extensiones duplicadas o
    mal formadas, AKID que no casa, algoritmos distintos dentro y fuera del certificado, firmas y payload alterados,
    certificados caducados o aún no válidos, llave hoja P-256 o RSA, ES256, SHA256, PCR 0/1/2/8, nonce, documento viejo
    o del futuro en los límites exactos, debug, sin `public_key`, estructura mal formada...): los dos dan el mismo
    veredicto y el mismo código, y los mismos campos cuando aceptan. Aparte quedan escritas las diferencias en las que el
    portable es más estricto (extensión crítica desconocida, bytes tras el DER, nombres comparados como DER, cadena solo
    P-384). También verifica con su propio código la autofirma de la raíz real de AWS.
  - `enclave-sealed-secrets.test.ts`: sobre sellado con WebCrypto y con `node:crypto` que abre en el enclave; no abre
    con otro propósito, otro dueño u otra pubkey, ni tras reiniciar el enclave (otra RSA); cualquier byte cambiado de
    `ek`, `iv`, `ct` o tag da la misma respuesta; `at` viejo o del futuro; demasiado grande (antes de descifrar), formato
    y contenido inválidos; tope de logN y contraseña errónea al importar; contraseña corta al exportar, y un sobre que
    falla no gasta la prueba del dueño; en claro o sellado, nunca los dos ni ninguno; `ENCLAVE_REQUIRE_SEALED_SECRETS`.
  - `enclave-sealed-api.test.ts`: la ruta de attestation con el nonce del cliente (y sus rechazos), importación y
    exportación selladas por la API, el dueño del sobre ligado a la llave, las reglas de siempre en los dos modos,
    `MANAGED_SIGNER_REQUIRE_SEALED_SECRETS` (rechaza antes de llegar al enclave) y el backend vault (404 y 400).
  - `enclave-sealed-parent.test.ts`: captura lo que ve el padre (cuerpos HTTP, tramas hacia el enclave byte a byte,
    logs y escrituras al vault) durante una importación y una exportación hechas con el cliente real y no encuentra
    las contraseñas, el `ncryptsec` importado ni la nsec, en claro, hex o base64; un control comprueba que la misma
    captura sí ve una contraseña en claro. Un padre que sustituye la attestation (su llave RSA, su PKI, otra imagen,
    debug, un documento viejo u otro nonce) hace que el cliente se pare antes de enviar nada.
  - Fuera de esta carpeta: `packages/signer/test/enclave-seal.test.ts` (formato del sobre abierto con `node:crypto`
    a mano, `EnclaveTrust`, dueño desde el token), `apps/web-saas/test/managed-enclave-export.test.ts` (la web con y sin
    `managedEnclave`), `packages/nostr-core/test/p384.test.ts` y el fuzz de `tests/fuzz/enclave-parsers.test.ts`, que
    exige al verificador portable el veredicto del de `node:crypto` en documentos manipulados y que un sobre con
    cualquier carácter cambiado nunca abra.

Las cadenas de certificados de prueba se generan con `node:crypto` (`buildCertificate`, P-384/ES384). Se
usan las mismas estructuras que produce Nitro: cabundle raíz → intermedio → hoja.

## Modo simulado (NO SEGURO)

`MANAGED_SIGNER_BACKEND=enclave` con `MANAGED_SIGNER_ENCLAVE_SIMULATED=1` ejecuta el enclave **dentro del
proceso backend**. La CA de attestation y la llave de "KMS" son locales, así que el backend puede leer
todas las llaves. Solo sirve para desarrollo y tests del protocolo. Al arrancar emite un aviso y se niega
con `NODE_ENV=production`.

## Configuración

Backend (`managed-signer`):

| Variable | Valor |
|---|---|
| `MANAGED_SIGNER_BACKEND` | `local` (default, firma en proceso) o `enclave` |
| `MANAGED_SIGNER_ENCLAVE_SOCKET` | Ruta del socket unix o `host:puerto` del puente socat hacia vsock |
| `MANAGED_SIGNER_ENCLAVE_PCR0/1/2` | PCR esperados (96 hex, salida de `nitro-cli build-enclave`). `PCR8` opcional |
| `MANAGED_SIGNER_ENCLAVE_ROOT_SHA256` | Sustituye la huella de la raíz fijada (default: AWS Nitro G1) |
| `MANAGED_SIGNER_ENCLAVE_SIMULATED` | `1` = simulado, NO SEGURO |
| `MANAGED_SIGNER_ENCLAVE_PROOF_ISSUER`, `_CLIENT_ID`, `_JWKS`, `_MAX_AGE_S` | Solo con el modo simulado: la user pool contra la que el enclave simulado comprueba las pruebas de exportación (`_JWKS` es la ruta de su `jwks.json`). Sin ellas, el simulado rechaza toda exportación, como el real |
| `MANAGED_SIGNER_REQUIRE_SEALED_SECRETS` | `1`: importaciones y exportaciones solo con secretos sellados hacia el enclave; en claro, 400 antes de reenviarlos (FR005-10). Solo con `MANAGED_SIGNER_BACKEND=enclave` (con el vault el servicio no arranca). Otro valor que no sea `0` o vacío no arranca |

Enclave (EIF): `ENCLAVE_LISTEN`, `ENCLAVE_KMS_KEY_ID` (salida `enclave_signer_kms_alias`),
`ENCLAVE_KMS_REGION`, `ENCLAVE_KMS_ENDPOINT`, `ENCLAVE_NSM_HELPER`, `ENCLAVE_ALLOW_EXPORT` y
`ENCLAVE_REQUIRE_SEALED_SECRETS` (`1`: el enclave rechaza con 403 los secretos en claro, FR005-10; con otro valor que no
sea `0` o vacío la imagen no arranca).

Web (`config.json`), FR005-10: `"managedEnclave": { "pcr0": "…", "pcr1": "…", "pcr2": "…", "pcr8": "…" }`, con los PCR de la
imagen publicada, 96 caracteres hex cada uno (`pcr8` opcional). Salen de `nitro-cli build-enclave` al construir la EIF, o de
`nitro-cli describe-eif --eif-path signer.eif` sobre la EIF publicada, y son los mismos valores que `enclave_pcr*` en
Terraform y `MANAGED_SIGNER_ENCLAVE_PCR*`. Con ellos, la web verifica la attestation en el navegador y sella la contraseña
de exportación; si alguno falta o está mal formado, la app no arranca (falla cerrada). Si el managed-signer no tiene enclave,
la exportación falla (404 en la attestation) en vez de mandar la contraseña en claro. Mientras el enclave sea Preview, el gate
de release no deja `managedEnclave` en la configuración de producción.

Con `ENCLAVE_ALLOW_EXPORT=1` (FR005-09) la imagen necesita además la user pool de Acceso cuyos tokens prueban al dueño, y no
arranca sin ella:

| Variable | Valor |
|---|---|
| `ENCLAVE_PROOF_ISSUER` | `iss` de la pool: `https://cognito-idp.<región>.amazonaws.com/<userPoolId>` |
| `ENCLAVE_PROOF_CLIENT_ID` | App client de la web de Acceso (`aud` de los id tokens, `client_id` de los access tokens) |
| `ENCLAVE_PROOF_JWKS` | Ruta, dentro de la imagen, del `jwks.json` de la pool (`<issuer>/.well-known/jwks.json`, copiado al construir la EIF) |
| `ENCLAVE_PROOF_MAX_AGE_S` | Antigüedad máxima del inicio de sesión con contraseña (por defecto 300) |

## Qué falta probar en AWS real (por eso FR005-05 queda Parcial)

1. **Construir la EIF.** Dockerfile del enclave: Node 22, `services/managed-signer` y un helper NSM
   compilado desde [`aws-nitro-enclaves-nsm-api`](https://github.com/aws/aws-nitro-enclaves-nsm-api). Node
   no puede hacer el ioctl de `/dev/nsm`; el contrato del helper está en `ExecNsm`. Después
   `nitro-cli build-enclave --docker-uri … --output-file signer.eif`, que imprime PCR0/1/2. Firmar la EIF
   para obtener PCR8.
2. **Medir y fijar.** Pasar los PCR a `enclave_pcr*` (Terraform) y a `MANAGED_SIGNER_ENCLAVE_PCR*`. Ejecutar
   `terraform apply` con `enable_enclave_signer = true`.
3. **Host Nitro.** Instancia con `enclave_options` (launch template del módulo o InstanceGroup de kops),
   `aws-nitro-enclaves-cli` y el allocator (CPU/memoria para el enclave).
   `nitro-cli run-enclave --eif-path signer.eif --cpu-count 2 --memory 1024` **sin** `--debug-mode`.
4. **vsock.** Dentro del enclave: `socat VSOCK-LISTEN:5005,fork UNIX-CONNECT:/run/enclave-signer.sock`, y un
   puente TCP local hacia `vsock-proxy 8000 kms.us-east-1.amazonaws.com 443`, que corre en el padre. En el
   padre: `socat UNIX-LISTEN:/run/enclave.sock,fork VSOCK-CONNECT:<cid>:5005`.
5. **Pruebas reales.**
   - Attestation verificada por el backend contra la raíz Nitro de verdad: `EnclaveClient.verify()` al
     arrancar.
   - `Decrypt` desde el padre sin Recipient → `AccessDenied`.
   - EIF modificada → `AccessDenied`.
   - Enclave en `--debug-mode` → rechazado.
   - Registrar cada resultado en este documento.
6. **La prueba del dueño con Cognito real (FR005-09).** Construir la EIF con el `jwks.json` de la user pool y las
   variables `ENCLAVE_PROOF_*`; comprobar con un token real de Acceso que la exportación funciona una vez y que el mismo
   token, uno de otro usuario y uno de un inicio de sesión de hace más de 5 minutos se rechazan. Comprobar también que el
   NSM real devuelve en `timestamp` una hora coherente con la de Cognito (`auth_time` se juzga con ella) y documentar el
   procedimiento de rotación de llaves de la pool (imagen nueva, PCR nuevos, Terraform).
7. **Formato CMS de KMS.** El parser acepta RSAES-OAEP (SHA-256 o SHA-1) y AES-256-CBC, que es lo que
   documenta KMS para `CiphertextForRecipient`. Falta confirmarlo con una respuesta real.
8. **Secretos sellados con un enclave real (FR005-10).** Verificar documentos de un enclave real con
   `verifyNitroAttestation` en un navegador y comparar su veredicto con el de `verifyAttestation` (la cadena real, con sus
   certificados intermedios, extensiones y `pathLen`, y la hora del NSM real); exportar e importar con secretos sellados
   desde la web con `managedEnclave` y los PCR de la EIF medida, también alrededor de un reinicio del enclave (un sobre
   sellado antes no abre; uno nuevo, con otra attestation, sí), y con `ENCLAVE_REQUIRE_SEALED_SECRETS=1` en la imagen.

Hasta completar esos pasos, el criterio queda cumplido **solo como prototipo verificado localmente**. Está
el backend sin llave en claro (forzado por la interfaz `SealedKeyOps` y probado) y la verificación de
attestation completa contra una PKI de prueba. Falta la attestation real de AWS.
