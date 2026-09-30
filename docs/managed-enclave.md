# Custodia managed en enclave Nitro (FR005-05)

- **Estado:** prototipo. **Tarea:** FR005-05 (P3), **Parcial**.
- **Madurez:** Preview. Va apagado en producción, igual que su exportación: el gate de release (OPS-20,
  [`deploy/production-gates.json`](../deploy/production-gates.json)) falla si la configuración de producción usa
  `MANAGED_SIGNER_BACKEND=enclave`, `ENCLAVE_ALLOW_EXPORT=1` o `enable_enclave_signer = true`. Para salir de
  Preview hacen falta FR005-05 y FR005-09 verificados en AWS real, y su auditoría. FR005-09 (el enclave exige una prueba
  del dueño para exportar) ya está en el código y probado sin AWS; ver «Exportar exige la prueba del dueño».
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
                     │  registro Postgres + vault (blobs sellados)     ▲
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
| `proof.ts` | `PinnedJwksProofVerifier`: verifica dentro del enclave el token de Acceso del dueño (RS256, con las llaves de la user pool fijadas en la imagen) y lee la configuración `ENCLAVE_PROOF_*` (FR005-09). |
| `protocol.ts` | Protocolo padre ⇄ enclave: tramas de 4 bytes de longitud + JSON. Hay transporte por socket (unix o TCP, puenteado a vsock con socat) y transporte en proceso (tests). |
| `attestation.ts` | Verificación del documento de attestation: COSE_Sign1/CBOR, cadena de certificados hasta la raíz Nitro fijada, firma ES384, vigencia, frescura, nonce y PCR. |
| `cbor.ts`, `der.ts`, `cms.ts` | CBOR mínimo, DER mínimo, y CMS EnvelopedData (`CiphertextForRecipient` de KMS). No añaden dependencias. |
| `kms.ts` | KMS con `Recipient` (SDK v3). Rechaza cualquier respuesta con `Plaintext`. |
| `client.ts` | `EnclaveClient` (lado backend). Verifica la attestation antes de operar y la repite cada 10 min. Comprueba cada evento devuelto: firma válida y pubkey esperada. |
| `wiring.ts` | `MANAGED_SIGNER_BACKEND=enclave` y el modo simulado. |
| `simulated.ts` | Enclave **SIMULADO, NO SEGURO**. Ver abajo. |
| `main.ts` | Punto de entrada de la imagen del enclave (EIF). |

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
   enclave.

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
| Backend comprometido pide exportar una llave (FR-026) | Puede | **No, sin un token del dueño** (FR005-09) | Desactivada por defecto. Activada, el enclave verifica dentro el token de Acceso del dueño (llaves fijadas en la imagen, reloj del NSM, un solo uso) y que la llave es suya. Sigue abierto lo que el padre ve durante una exportación legítima: ver "Riesgos residuales" |
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
  - **La contraseña de exportación pasa por el padre.** Con la prueba basta para que el padre no pueda exportar solo,
    pero en una exportación legítima ve la contraseña y el `ncryptsec`, y con ellos la nsec. Que el cliente la cifre hacia
    la llave atestada del enclave es FR005-10.
  - **El dueño de una llave nueva lo dice el padre.** Al crear o importar, el enclave sella el dueño que le pasa el padre;
    solo las llaves ya selladas quedan fuera de su alcance. Un padre comprometido en el momento de crear una llave
    podría sellarla para otro dueño. Exigir también la prueba al crear es viable con el token de Acceso, pero no con las
    sesiones de dispositivo (`MANAGED_SIGNER_REQUIRE_DEVICE_SESSION`), que no llevan token.
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

Enclave (EIF): `ENCLAVE_LISTEN`, `ENCLAVE_KMS_KEY_ID` (salida `enclave_signer_kms_alias`),
`ENCLAVE_KMS_REGION`, `ENCLAVE_KMS_ENDPOINT`, `ENCLAVE_NSM_HELPER` y `ENCLAVE_ALLOW_EXPORT`.

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

Hasta completar esos pasos, el criterio queda cumplido **solo como prototipo verificado localmente**. Está
el backend sin llave en claro (forzado por la interfaz `SealedKeyOps` y probado) y la verificación de
attestation completa contra una PKI de prueba. Falta la attestation real de AWS.
