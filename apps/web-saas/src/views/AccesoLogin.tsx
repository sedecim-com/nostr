import { useState, type FormEvent } from 'react';
import { Alert, Box, Button, Card, CardContent, Stack, TextField, Typography } from '@mui/material';
import { accesoNewPassword, accesoSignIn, type AccesoUser } from '../lib/acceso';
import { BRAND } from '../theme';

/** SaaS gate (ADR 0008): the same Acceso (Cognito) account used across Sedecim apps. */
export function AccesoLogin({ onSignedIn }: { onSignedIn: (u: AccesoUser) => void }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [needsNew, setNeedsNew] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      const res = needsNew ? await accesoNewPassword(newPassword) : await accesoSignIn(username.trim(), password);
      if (res.done) onSignedIn(res.user);
      else setNeedsNew(true);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Box component="main" sx={{ display: 'grid', placeItems: 'center', minHeight: '100vh', p: 2 }}>
      <Card sx={{ maxWidth: 420, width: '100%' }}>
        <CardContent component="form" onSubmit={submit}>
          <Stack spacing={2}>
            <Typography variant="h5" component="h1">
              {BRAND}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Entra con tu cuenta de Acceso. Tu llave Nostr no sale de este navegador: Acceso solo autoriza el uso del servicio.
            </Typography>
            {needsNew ? (
              <TextField label="Nueva contraseña de Acceso" type="password" autoComplete="new-password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} required />
            ) : (
              <>
                <TextField id="acceso-user" label="Usuario de Acceso" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required />
                <TextField id="acceso-pass" label="Contraseña" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
              </>
            )}
            {error && <Alert severity="error">{error}</Alert>}
            <Button type="submit" variant="contained" disabled={busy}>
              {needsNew ? 'Cambiar contraseña' : 'Entrar con Acceso'}
            </Button>
          </Stack>
        </CardContent>
      </Card>
    </Box>
  );
}
