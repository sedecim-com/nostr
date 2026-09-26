import { useEffect, useState, type FormEvent } from 'react';
import { Alert, Box, Button, Card, CardContent, CircularProgress, FormControlLabel, Radio, RadioGroup, Stack, TextField, Typography } from '@mui/material';
import type { DeploymentConfig } from '../lib/config';
import { createPersona } from '../lib/session';
import { clearLegacyKey, createVault, forgetBrowser, hasLegacyKey, PersonaBook, readLegacyKey, unlockVault, vaultState } from '../lib/vault';
import { BRAND } from '../theme';

type State = { s: 'loading' } | { s: 'none' } | { s: 'locked'; kind: 'passphrase' | 'device' };

/**
 * Local vault (ADR 0007). A password (scrypt) protects every profile; the device key (no password in this
 * browser) is offered only for the convenience profile and says so.
 */
export function VaultGate({ cfg, onUnlocked }: { cfg: DeploymentConfig; onUnlocked: (b: PersonaBook) => void }) {
  const [state, setState] = useState<State>({ s: 'loading' });
  const [pass, setPass] = useState('');
  const [mode, setMode] = useState<'passphrase' | 'device'>('passphrase');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const legacy = hasLegacyKey();

  useEffect(() => {
    void vaultState().then((v) => setState(v.exists ? { s: 'locked', kind: v.kind } : { s: 'none' }));
  }, []);

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

  const create = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      const vault = await createVault(mode === 'device' ? { kind: 'device' } : { kind: 'passphrase', passphrase: pass });
      const book = new PersonaBook(vault);
      // v0.1 kept one key in localStorage protected by the same local password: move it into the vault.
      if (legacy && mode === 'passphrase') {
        try {
          await createPersona(book, { kind: 'secret', secretKey: await readLegacyKey(pass) }, { label: 'Personal', relays: cfg.relays, preset: 'convenience' });
          clearLegacyKey();
        } catch {
          /* different password: the user can still import the key from a backup */
        }
      }
      onUnlocked(book);
    });
  };

  const unlock = (e?: FormEvent) => {
    e?.preventDefault();
    if (state.s !== 'locked') return;
    void run(async () => onUnlocked(new PersonaBook(await unlockVault(state.kind === 'device' ? { kind: 'device' } : { kind: 'passphrase', passphrase: pass }))));
  };

  const forget = () => {
    if (!confirm('Se borrarán de este navegador todas las personas, llaves y la outbox. Sin un backup no podrás recuperarlas. ¿Continuar?')) return;
    void run(async () => {
      await forgetBrowser();
      setState({ s: 'none' });
    });
  };

  return (
    <Box component="main" sx={{ display: 'grid', placeItems: 'center', minHeight: '100vh', p: 2 }}>
      <Card sx={{ maxWidth: 480, width: '100%' }}>
        <CardContent>
          <Stack spacing={2}>
            <Typography variant="h5" component="h1">
              {BRAND}
            </Typography>
            {state.s === 'loading' && <CircularProgress aria-label="Cargando" />}
            {state.s === 'none' && (
              <Stack component="form" spacing={2} onSubmit={create}>
                <Typography variant="body2">Crea el almacén local cifrado de este navegador. Tus llaves y tu outbox solo existen aquí, cifradas.</Typography>
                <RadioGroup value={mode} onChange={(e) => setMode(e.target.value as 'passphrase' | 'device')} aria-label="Protección del almacén">
                  <FormControlLabel value="passphrase" control={<Radio />} label="Con contraseña local (obligatoria en perfiles soberano, Tor e institucional)" />
                  <FormControlLabel value="device" control={<Radio />} label="Sin contraseña en este navegador (solo perfil convenience)" />
                </RadioGroup>
                {mode === 'device' && <Alert severity="warning">Cualquiera con acceso a este perfil del navegador podrá abrir tus llaves. Podrás añadir una contraseña después.</Alert>}
                {mode === 'passphrase' && <TextField id="local-pass" label="Contraseña local" type="password" autoComplete="new-password" value={pass} onChange={(e) => setPass(e.target.value)} required slotProps={{ htmlInput: { minLength: 8 } }} helperText="Mínimo 8 caracteres. No se puede recuperar." />}
                {legacy && mode === 'passphrase' && <Alert severity="info">Hay una llave de la versión anterior en este navegador: si usas la misma contraseña, se moverá al almacén nuevo.</Alert>}
                <Button type="submit" variant="contained" disabled={busy}>
                  Crear almacén
                </Button>
              </Stack>
            )}
            {state.s === 'locked' && (
              <Stack component="form" spacing={2} onSubmit={unlock}>
                {state.kind === 'passphrase' ? (
                  <TextField id="local-pass" label="Contraseña local" type="password" autoComplete="current-password" value={pass} onChange={(e) => setPass(e.target.value)} required autoFocus />
                ) : (
                  <Alert severity="warning">Este navegador abre tus llaves sin contraseña (perfil convenience).</Alert>
                )}
                <Button type="submit" variant="contained" disabled={busy}>
                  Desbloquear
                </Button>
                <Button color="error" onClick={forget} disabled={busy}>
                  Olvidar este navegador
                </Button>
              </Stack>
            )}
            {error && <Alert severity="error">{error}</Alert>}
          </Stack>
        </CardContent>
      </Card>
    </Box>
  );
}
