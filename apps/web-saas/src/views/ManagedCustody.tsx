import { useState } from 'react';
import { Alert, Box, Button, Card, CardContent, Checkbox, FormControlLabel, Link, Stack, Step, StepLabel, Stepper, TextField, Typography } from '@mui/material';
import { disclose, MANAGED_CONSENT_TEXTS, managedConsentVersion, preset } from '@sedecim/profiles';
import { ManagedSignerClient } from '@sedecim/signer';
import { migrateManagedToLocal } from '../lib/session';
import { useWorkspace } from '../lib/workspace';

/** The exact disclosure the panel shows for managed custody, reused for the opt-in (FR005-07, FR-028). */
export const MANAGED_DISCLOSURE = disclose({ ...preset('convenience'), custody: 'managed' }).find((d) => d.control === 'custody')!.statement;

/**
 * FR005-07: never by default; the user must acknowledge that the platform can sign as them. FR005-08: the texts are
 * the reviewed ones (docs/disclosures.md), the terms are linked when the deployment publishes them, and the
 * version of what was accepted is recorded with the key.
 */
export function ManagedOptIn({ accepted, onChange, terms }: { accepted: boolean; onChange(v: boolean): void; terms?: { url: string; version: string } }) {
  return (
    <Stack spacing={1}>
      <Alert severity="warning">{MANAGED_DISCLOSURE}</Alert>
      <Alert severity="warning" id="managed-decryption">
        {MANAGED_CONSENT_TEXTS.decryption}
      </Alert>
      <Typography variant="body2">{MANAGED_CONSENT_TEXTS.storage}</Typography>
      {terms ? (
        <Link id="managed-terms" href={terms.url} target="_blank" rel="noopener noreferrer">
          Términos de la custodia gestionada (versión {terms.version})
        </Link>
      ) : (
        <Alert severity="info" id="managed-terms-missing">
          Este despliegue todavía no publica los términos de la custodia gestionada: están en revisión legal.
        </Alert>
      )}
      <FormControlLabel control={<Checkbox id="managed-consent" checked={accepted} onChange={(e) => onChange(e.target.checked)} />} label={MANAGED_CONSENT_TEXTS.accept} />
      <Typography variant="caption" color="text.secondary" id="managed-consent-version">
        Tu aceptación queda registrada con su versión: {managedConsentVersion(terms?.version)}.
      </Typography>
    </Stack>
  );
}

const STEPS = ['Exportar', 'Verificar posesión', 'Borrar la copia gestionada'];

/** FR026-03: managed → local, step by step, with verification before anything is deleted. */
export function MigrationWizard() {
  const ws = useWorkspace();
  const s = ws.session!;
  // A migrated persona keeps managedKeyId until the managed copy is deleted: resume at that step.
  const [step, setStep] = useState(s.persona.custody === 'managed' ? 0 : 2);
  const [password, setPassword] = useState('');
  const [ncryptsec, setNcryptsec] = useState('');
  const [destroyAfter, setDestroyAfter] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [client] = useState(() => new ManagedSignerClient({ baseUrl: ws.managedEnv.baseUrl!, keyId: s.persona.managedKeyId!, token: ws.managedEnv.token! }));

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError('');
    try {
      await fn();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const exportAndVerify = () =>
    run(async () => {
      const res = await migrateManagedToLocal(ws.book, s.persona, client, password);
      setNcryptsec(res.ncryptsec);
      setPassword('');
      setStep(2);
      await ws.reloadPersonas();
      await ws.selectPersona(res.persona.id);
      ws.notify('La llave ya está en este navegador y la posesión quedó verificada', 'success');
    });

  const saveBackup = () => {
    if (!ncryptsec) return ws.notify('El backup de la migración ya no está en memoria: usa "Descargar backup cifrado (NIP-49)" de la persona.', 'info');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([JSON.stringify({ format: 'acceso-nostr-key-backup', version: 1, ncryptsec }, null, 2)], { type: 'application/json' }));
    a.download = 'acceso-nostr-backup-migrada.json';
    a.click();
    URL.revokeObjectURL(a.href);
  };

  const deleteManaged = () =>
    run(async () => {
      const { destroyAfter } = await client.deleteKey();
      const current = (await ws.book.get(s.persona.id))!;
      const { managedKeyId: _gone, ...rest } = current;
      await ws.book.save(rest);
      setDestroyAfter(destroyAfter);
      setStep(3);
    });

  return (
    <Card id="migration-wizard">
      <CardContent>
        <Stack spacing={2}>
          <Typography variant="h6" component="h2">
            Migrar a custodia local
          </Typography>
          <Stepper activeStep={step} alternativeLabel>
            {STEPS.map((l) => (
              <Step key={l}>
                <StepLabel>{l}</StepLabel>
              </Step>
            ))}
          </Stepper>
          {step < 2 && (
            <>
              <Typography variant="body2">La plataforma te entregará tu llave cifrada con esta contraseña. Este navegador la descifra, comprueba que es la misma npub y firma un reto para demostrar que la tienes.</Typography>
              <TextField id="migration-pass" label="Contraseña de exportación (mínimo 12 caracteres)" type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />
              <Box>
                <Button variant="contained" onClick={() => void exportAndVerify()} disabled={busy || password.length < 12}>
                  Exportar y verificar
                </Button>
              </Box>
            </>
          )}
          {step === 2 && (
            <>
              <Alert severity="success">Tu llave ya vive en este navegador. Guarda el backup antes de borrar la copia gestionada.</Alert>
              <Box>
                <Button onClick={saveBackup}>Descargar backup cifrado</Button>
              </Box>
              <Alert severity="warning">Borrar la copia gestionada es definitivo: el material cifrado se destruye tras la ventana de retención (30 días).</Alert>
              <Box>
                <Button color="error" variant="outlined" onClick={() => void deleteManaged()} disabled={busy}>
                  Borrar la copia gestionada
                </Button>
              </Box>
            </>
          )}
          {step === 3 && <Alert severity="info" id="migration-done">Copia gestionada borrada. Se destruirá definitivamente el {new Date(destroyAfter).toLocaleDateString()}.</Alert>}
          {error && <Alert severity="error">{error}</Alert>}
        </Stack>
      </CardContent>
    </Card>
  );
}
