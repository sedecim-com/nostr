# ADR 0009 · Región cloud y marco legal de la custodia managed

- **Estado:** Aceptado (términos pendientes de aprobación legal) · **Tarea:** DEC-09 (P1) · **Fecha:** 2026-09-26
- **Aprobación:** responsable de producto (vic2099), 2026-09-26. Asesoría legal: pendiente de aprobar
  [`docs/legal/custodia-managed.md`](../legal/custodia-managed.md).

## Contexto
La custodia managed es opt-in y custodial: la plataforma puede firmar como el usuario (spec §8.4). Hay que
fijar dónde viven las llaves, bajo qué marco legal y cuánto tiempo se conservan. El responsable pidió
decidir la región a partir de los repositorios de Sedecim. Evidencia encontrada:
- **Región:** `sedecim-com/infrastructure/terraform/main.tf` fija el provider de AWS en `us-east-1`.
  Sedecim ya usa Secrets Manager en esa región (credenciales de Aurora). Acceso (Cognito, backends)
  también está en `us-east-1`.
- **Marco legal:** los textos de Acceso remiten a la protección de datos personales en México (LFPDPPP).

## Decisión
- **Región:** `us-east-1`, en la misma cuenta y perímetro de IAM que el resto de Sedecim.
- **Almacenamiento:**
  - Cifrado por sobre (envelope) con una llave de **KMS** dedicada (`MANAGED_SIGNER_KMS_KEY_ID`), con rotación anual activada.
  - La nsec se cifra con AES-256-GCM usando una data key de KMS.
  - El ciphertext y la data key cifrada se guardan en **Secrets Manager**, bajo un prefijo propio.
  - El texto claro solo existe en memoria del managed-signer durante la operación.
- **Autorización:** cada firma requiere el token de Acceso (Cognito) del usuario final, que el managed-signer verifica contra el JWKS del pool. El dueño de una llave es `issuer#sub`. No hay firma por cuenta ajena.
- **Marco legal:** LFPDPPP (México). El aviso de privacidad y los términos de custodia están en [`docs/legal/custodia-managed.md`](../legal/custodia-managed.md) como borrador.
- **Retención:**
  - Al borrar una llave managed, el material cifrado se destruye a los **30 días** (`MANAGED_SIGNER_RETENTION_DAYS`, ventana de recuperación de Secrets Manager entre 7 y 30).
  - El log de uso (qué llave firmó, cuándo, qué kind, desde qué cliente, nunca el contenido) se conserva **12 meses**.
- **Migración:** exportar la llave a custodia local (FR-026) exige verificar la posesión antes de borrarla del servicio. El borrado sigue la misma ventana de 30 días.

## Consecuencias
- Operación: la llave KMS y los permisos IAM del managed-signer deben añadirse al Terraform de Sedecim. Los permisos mínimos son `kms:GenerateDataKey`/`kms:Decrypt` sobre esa llave y `secretsmanager:*Secret*` sobre el prefijo.
- Los usuarios fuera de México no tienen, por ahora, garantías adicionales como el GDPR. Si se abre a la UE, este ADR se revisa.
- DEC-09 queda **Parcial** hasta que legal apruebe los términos.
