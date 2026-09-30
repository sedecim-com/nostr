# Runbook: salida de la custodia gestionada y derechos ARCO

Qué hacer cuando una llave sale de la custodia gestionada (FR026-04): porque su dueño la cancela desde la web, porque
pide la cancelación por el contacto de privacidad (derecho ARCO, [términos §4](../legal/custodia-managed.md)) o
porque su cuenta de Acceso se cerró. Las pruebas están en `services/managed-signer/test/managed-signer.test.ts`,
`services/managed-signer/test/registry.test.ts` (también contra Postgres) y `apps/web-saas/test/managed-exit.test.ts`; con el
enclave, `apps/web-saas/test/managed-enclave-export.test.ts`.

**Qué pasa con una llave que sale.**

| Momento | Qué queda | Quién lo hace |
|---|---|---|
| Al salir (cancelada o migrada) | La llave deja de firmar en todos los dispositivos. Su material cifrado sigue en el vault durante la ventana de retención (`MANAGED_SIGNER_RETENTION_DAYS`, 30 días, DEC-09). | El dueño desde la web, o el operador con `close-owner` |
| Durante la ventana | El dueño la ve en «Llaves gestionadas en eliminación» con la fecha de destrucción (`GET /v1/keys/closed`). | — |
| Al acabar la ventana | Se destruye el material. En el mismo paso se borra lo que la ligaba a su dueño: el usuario de Acceso y la versión de los términos aceptados (`scrubbed_at`). Queda solo el id, la npub y las fechas. | El job de retención (cada hora; también `ops.ts retention`) |
| A los 12 meses | Se borra el log de uso de la llave (`MANAGED_SIGNER_USAGE_RETENTION_MONTHS`). | El job de retención |

Con el vault de AWS, el material no lo borra el job: al salir, el servicio programa el borrado del secreto en Secrets
Manager con esa misma ventana de recuperación (Secrets Manager la acota entre 7 y 30 días), y el job solo lo marca
como destruido cuando vence.

## 1. El dueño cancela desde la web

En «Personas», con la persona gestionada abierta, la tarjeta «Cancelar la custodia gestionada sin migrar»:

1. Pide una contraseña y descarga el respaldo cifrado (NIP-49, `acceso-nostr-key-backup` con la npub y la llave de
   archivo del Continuity Vault). El navegador comprueba que la llave exportada es la de esa persona antes de ofrecerlo.
   Antes pide también la contraseña de Acceso: exportar y cancelar solo se aceptan con un login de los últimos
   minutos (IR-2026-10-03). Si el managed-signer guarda las llaves en el enclave y la web trae `managedEnclave`, el
   navegador verifica la attestation del enclave y le sella la contraseña del respaldo: el managed-signer no la recibe
   en claro, y si la verificación falla no se envía nada (FR005-10, [managed-enclave.md](../managed-enclave.md)).
2. Pide confirmar que guardó el archivo y escribir los últimos 8 caracteres de la npub.
3. Cancela (`POST /v1/keys/:id/cancel`, con la npub completa como confirmación). La persona sale de ese navegador.
   Con el archivo y la contraseña se puede volver a importar como llave local.

Si el dueño quiere conservar la identidad y seguir usándola, lo que busca es la migración a custodia local (FR026-03,
tarjeta «Migrar a custodia local»), no la cancelación.

## 2. Solicitud ARCO por el contacto de privacidad, o cuenta de Acceso cerrada

1. Verifica la identidad de quien lo pide según el procedimiento de datos personales de Sedecim, y abre un ticket.
2. Averigua el dueño tal como lo registra el signer: `<issuer>#<sub>` de su usuario de Acceso (el `issuer` es la URL
   del user pool de Cognito, por ejemplo `https://cognito-idp.us-east-1.amazonaws.com/<pool>`).
3. Si puede entrar a la web, recomiéndale descargar antes su respaldo (sección 1, paso 1): sin él, pasada la
   ventana, no hay forma de recuperar la llave.
4. Ejecuta el cierre donde corre el servicio, con su misma configuración (vault, `DATABASE_URL`, retención):

   ```sh
   # docker compose
   docker compose exec managed-signer node_modules/.bin/tsx services/managed-signer/src/ops.ts close-owner '<issuer>#<sub>' <ticket>
   # Kubernetes
   kubectl exec deploy/managed-signer -- node_modules/.bin/tsx services/managed-signer/src/ops.ts close-owner '<issuer>#<sub>' <ticket>
   ```

   La salida es JSON: `{"owner": "...", "closed": [{"key_id": "...", "destroy_after": "..."}]}`. Una llave que ya
   estaba migrada sale como «migrada»; las demás, como «cancelada». En el log de uso de cada una queda la acción con
   el principal `operator:<ticket>`. Sin `DATABASE_URL` el comando se niega: nunca actúa sobre un registro vacío en
   memoria.
5. Responde al solicitante con las fechas `destroy_after`. Si pide que se destruya antes de la ventana, eso requiere
   una decisión de legal (la ventana protege contra borrados por error y cuentas robadas).

## 3. Comprobar que el borrado se cumplió

- `ops.ts retention` ejecuta el job en el momento y devuelve
  `{usagePurged, keysDestroyed, keysScrubbed, sessionsPurged, loginCutoffsPurged}`.
- En Postgres, una llave destruida tiene `destroyed_at` y `scrubbed_at`, y `owner`, `consent_version` y `consent_at`
  vacíos:

  ```sql
  SELECT key_id, state, exit_reason, deleted_at, destroyed_at, scrubbed_at, owner IS NULL AS sin_dueno
  FROM managed_keys WHERE key_id = '<key_id>';
  ```

- **Pendiente en AWS (FR005-13, stage):** comprobar en la cuenta real que Secrets Manager programa el borrado con la
  ventana de 30 días, que el secreto desaparece al vencer y que los logs de CloudTrail y del servicio respetan sus
  retenciones. Hasta hacerlo en stage, FR026-04 queda parcial.
