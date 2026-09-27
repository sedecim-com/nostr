# Custodia managed en enclave Nitro (FR005-05)

- **Estado:** prototipo. **Tarea:** FR005-05 (P3), **Parcial**.
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
| `enclave.ts` | `EnclaveSigner`: programa del enclave. Genera, importa (NIP-49), sella, abre, firma, cifra NIP-44 y exporta (FR-026). Ninguna respuesta lleva material de llave. |
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
   `{app, purpose: enclave-key, pubkey}`. KMS no devuelve la data key en claro: devuelve `CiphertextBlob` y
   `CiphertextForRecipient` (CMS cifrado a la RSA del enclave). El enclave descifra la data key, sella la
   nsec con AES-256-GCM (AAD = pubkey), borra ambas y devuelve `{pubkey, sealed}`.
3. **Usar.** El backend manda `sealed` y la pubkey. El enclave llama a `Decrypt` con un documento de
   attestation nuevo, abre la nsec y comprueba que su pubkey coincide con la esperada. Después firma,
   destruye el `LocalSigner` y devuelve el evento.
4. El backend guarda `sealed` en el vault que ya usa (`MANAGED_SIGNER_VAULT`: Secrets Manager o local). El
   registro en Postgres no cambia. `provider` pasa a ser `nitro-enclave+aws-secrets-manager` y la vista
   devuelve `custody: managed-enclave`.
5. Los tiers no se mezclan. Las llaves creadas con el backend en proceso guardan la nsec (cifrada por el
   vault) y el enclave no las acepta. Pasar una llave existente al tier enclave requiere una migración
   explícita: exportar e importar con `POST /v1/keys/import`, que en el tier enclave se descifra dentro del
   enclave.

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
| Canal padre ⇄ enclave manipulado (eventos falsos) | n/a | Detectado | El cliente verifica cada evento: firma, pubkey, kind y contenido |
| Blob sellado presentado con otra pubkey | n/a | Rechazado | El contexto KMS incluye la pubkey y el enclave compara la pubkey derivada |
| Administrador de KMS cambia la política | Puede | Puede | **Residual**: `kms:PutKeyPolicy`. Mitigación operativa: rol de break-glass y alarma de CloudTrail sobre `PutKeyPolicy` en esta llave |

### Riesgos residuales (el tier sigue siendo custodial)

- **Autorización fuera del enclave.** El backend verifica el token de Acceso (Cognito), no el enclave. Un
  backend comprometido no puede robar llaves, pero sí pedir firmas mientras controle el proceso. Siguiente
  paso posible: que el enclave verifique el JWT de Cognito con el JWKS fijado en la imagen, dentro del PCR2.
- **Exportación FR-026.** El enclave devuelve un `ncryptsec` cifrado con la contraseña del usuario, que pasa
  por el backend. Un backend comprometido podría capturar la contraseña y el `ncryptsec`. La EIF puede
  arrancar con `ENCLAVE_ALLOW_EXPORT=0` si un despliegue no necesita migración.
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

Enclave (EIF): `ENCLAVE_LISTEN`, `ENCLAVE_KMS_KEY_ID` (salida `enclave_signer_kms_alias`),
`ENCLAVE_KMS_REGION`, `ENCLAVE_KMS_ENDPOINT`, `ENCLAVE_NSM_HELPER` y `ENCLAVE_ALLOW_EXPORT`.

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
6. **Formato CMS de KMS.** El parser acepta RSAES-OAEP (SHA-256 o SHA-1) y AES-256-CBC, que es lo que
   documenta KMS para `CiphertextForRecipient`. Falta confirmarlo con una respuesta real.

Hasta completar esos pasos, el criterio queda cumplido **solo como prototipo verificado localmente**. Está
el backend sin llave en claro (forzado por la interfaz `SealedKeyOps` y probado) y la verificación de
attestation completa contra una PKI de prueba. Falta la attestation real de AWS.
