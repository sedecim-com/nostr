import { useState, type FormEvent } from 'react';
import { Alert, Box, Button, Card, CardContent, Stack, TextField, Typography } from '@mui/material';
import { accesoNewPassword, accesoSignIn, type AccesoUser } from '../lib/acceso';
import { BRAND } from '../theme';

/** SaaS gate (ADR 0008): the same Acceso (Cognito) account used across Sedecim apps. */
export function AccesoLogin({ onSignedIn, managed = false }: { onSignedIn: (u: AccesoUser) => void; managed?: boolean }) {
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
            <Typography variant="body2" sx={{ color: 'text.secondary' }}>
              {/* FR005-08: with managed custody on offer, the platform can hold the key: never claim it stays here. */}
              {managed
                ? 'Entra con tu cuenta de Acceso: solo autoriza el uso del servicio. Con una llave local, tu llave Nostr se queda en este navegador; con un signer externo, en tu signer; con la custodia gestionada (opcional), la guarda la plataforma, que puede firmar como tú.'
                : 'Entra con tu cuenta de Acceso: solo autoriza el uso del servicio. Tu llave Nostr se queda en este navegador o en tu signer externo.'}
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
