# Aprobación legal: términos de custodia managed y aviso de privacidad

- Documento: docs/legal/custodia-managed.md
- Versión: PENDIENTE
- SHA-256: PENDIENTE
- Dictamen: PENDIENTE
- Aprobado por: PENDIENTE
- Fecha: PENDIENTE

Registro de DEC-12. Mientras esté pendiente, la custodia gestionada no puede aparecer en la configuración de
producción: `node scripts/release-gate.mjs config` (OPS-20) falla si la web de producción define
`managedSigner` o `managedTerms`, o si un overlay de producción incluye el componente `managed-signer`
([checklist de release](../../release-checklist.md), gate 9).

Cómo se rellena cuando la asesoría legal aprueba el texto final:

1. Deja `docs/legal/custodia-managed.md` tal como se aprobó, sin «BORRADOR» en el título ni en el estado.
2. `Versión`: la que se publica y queda registrada con el consentimiento. En la configuración de la web va en
   `managedTerms.version`, y el gate exige que coincidan.
3. `SHA-256`: la salida de `sha256sum docs/legal/custodia-managed.md`. Si el texto cambia después, la
   aprobación deja de valer y hay que aprobarlo de nuevo.
4. `Dictamen`: enlace o ruta al dictamen firmado. `Aprobado por`: la persona o el despacho que lo firma.
   `Fecha`: AAAA-MM-DD.

La PR que rellena este registro la aprueba una persona distinta de quien la abre. Además de esta aprobación,
managed necesita los informes de SEC-01 y SEC-02 en `docs/security/audits/<tag>.md`; un waiver no basta.
