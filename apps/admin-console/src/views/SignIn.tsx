import { useEffect, useState } from 'react';
import { Alert, Box, Button, Card, CardContent, Chip, Divider, Link, Stack, TextField, Typography } from '@mui/material';
import { ApiError, PolicyAdminApi } from '../api';
import type { AdminConfig } from '../config';
import { hasNip07, signInLocalDev, signInNip07, signInNip46, type AdminSession, type ConsoleSession } from '../signers';
import { errorText } from '../ui';

/**
 * The admin signs in with a Nostr signer; nothing is stored. The session is accepted once the policy-engine answers an
 * admin-only NIP-98 request with that key. FR023-11: a key it refuses as admin (403) opens its own devices only.
 */
export function SignIn({ cfg, onSignedIn }: { cfg: AdminConfig; onSignedIn(s: ConsoleSession): void }) {
  const [bunker, setBunker] = useState('');
  const [nsec, setNsec] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | undefined>();
  const [authUrl, setAuthUrl] = useState<string | undefined>();
  const [nip07, setNip07] = useState(hasNip07);

  // Extensions may inject window.nostr after the page loads.
  useEffect(() => {
    if (nip07) return;
    let tries = 0;
    const t = setInterval(() => {
      if (hasNip07()) setNip07(true);
      if (hasNip07() || ++tries > 12) clearInterval(t);
    }, 250);
    return () => clearInterval(t);
  }, [nip07]);

  const run = async (open: () => Promise<AdminSession>) => {
    setBusy(true);
    setError(undefined);
    let s: AdminSession | undefined;
    try {
      s = await open();
      let admin = true;
      try {
        await new PolicyAdminApi(cfg.policyEngineUrl, s.signer).listSubjects();
      } catch (e) {
        if (!(e instanceof ApiError && e.status === 403)) throw e;
        admin = false;
      }
      setNsec('');
      onSignedIn({ ...s, admin });
    } catch (e) {
      s?.close();
      setError(errorText(e));
    } finally {
      setBusy(false);
      setAuthUrl(undefined);
    }
  };

  return (
    <Box component="main" sx={{ display: 'grid', placeItems: 'center', minHeight: '100vh', p: 2 }}>
      <Card sx={{ maxWidth: 560, width: '100%' }}>
        <CardContent>
          <Stack spacing={2}>
            <Typography variant="h5" component="h1">
              Consola de administración
            </Typography>
            <Typography variant="body2" sx={{ color: 'text.secondary' }}>
              Entra con tu identidad Nostr. Con una llave de administrador gestionas la organización; con otra llave, tus propios dispositivos y su passkey. Cada petición al policy-engine va firmada con NIP-98; la consola no guarda tu llave.
            </Typography>
            {error && (
              <Alert severity="error" id="signin-error">
                {error}
              </Alert>
            )}
            {authUrl && (
              <Alert severity="info">
                Tu signer pide aprobación:{' '}
                <Link href={authUrl} target="_blank" rel="noopener noreferrer">
                  abrir la página de aprobación
                </Link>
              </Alert>
            )}

            <Typography variant="h6" component="h2">
              Extensión del navegador (NIP-07)
            </Typography>
            <Button variant="contained" disabled={busy || !nip07} onClick={() => void run(signInNip07)}>
              Entrar con extensión NIP-07
            </Button>
            {!nip07 && (
              <Typography variant="caption" sx={{ color: 'text.secondary' }}>
                No se detectó ninguna extensión NIP-07.
              </Typography>
            )}

            <Divider />
            <Typography variant="h6" component="h2">
              Signer remoto (NIP-46)
            </Typography>
            <TextField id="bunker-url" label="URL bunker://" value={bunker} onChange={(e) => setBunker(e.target.value)} size="small" helperText="Solo se piden permisos para firmar autenticación HTTP (kind 27235)." />
            <Button variant="outlined" disabled={busy || !bunker.trim()} onClick={() => void run(() => signInNip46(bunker, setAuthUrl))}>
              Conectar bunker
            </Button>

            {cfg.devLocalKey && (
              <>
                <Divider />
                <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
                  <Typography variant="h6" component="h2">
                    Llave local
                  </Typography>
                  <Chip label="Solo desarrollo" color="warning" size="small" />
                </Stack>
                <Alert severity="warning">Pegar una nsec en una web expone la llave. Úsalo solo en entornos de desarrollo; en producción desactiva devLocalKey en config.json.</Alert>
                <TextField id="dev-nsec" label="nsec (desarrollo)" type="password" value={nsec} onChange={(e) => setNsec(e.target.value)} size="small" autoComplete="off" />
                <Button variant="outlined" color="warning" disabled={busy || !nsec.trim()} onClick={() => void run(() => signInLocalDev(nsec))}>
                  Entrar con llave local
                </Button>
              </>
            )}
          </Stack>
        </CardContent>
      </Card>
    </Box>
  );
}
