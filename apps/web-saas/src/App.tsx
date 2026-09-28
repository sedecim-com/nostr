import { lazy, Suspense, useEffect, useState } from 'react';
import { Alert, Box, CircularProgress } from '@mui/material';
import type { DeploymentFlags } from '@sedecim/messaging';
import type { AccesoUser } from './lib/acceso';
import { onAccesoSignOut } from './lib/authChannel';
import { loadConfig, loadFlags, type DeploymentConfig } from './lib/config';
import type { PersonaBook } from './lib/vault';
import { VaultGate } from './views/VaultGate';
import { Workspace } from './views/Workspace';

// Amplify is only loaded in SaaS mode.
const AccesoLogin = lazy(() => import('./views/AccesoLogin').then((m) => ({ default: m.AccesoLogin })));

type Boot = { state: 'loading' } | { state: 'error'; message: string } | { state: 'ready'; cfg: DeploymentConfig; flags: DeploymentFlags | undefined };

/**
 * Order of gates: deployment config → Acceso login (SaaS only, ADR 0008) → local vault (ADR 0007) →
 * workspace. Self-hosted deployments never contact Cognito.
 */
export function App() {
  const [boot, setBoot] = useState<Boot>({ state: 'loading' });
  const [user, setUser] = useState<AccesoUser | undefined>();
  const [checkingUser, setCheckingUser] = useState(true);
  const [book, setBook] = useState<PersonaBook | undefined>();

  useEffect(() => {
    void (async () => {
      try {
        const [cfg, flags] = await Promise.all([loadConfig(), loadFlags()]);
        if (cfg.mode === 'saas') {
          const acceso = await import('./lib/acceso');
          acceso.configureAcceso(cfg.cognito!);
          setUser(await acceso.currentAccesoUser());
        }
        setBoot({ state: 'ready', cfg, flags });
      } catch (e) {
        setBoot({ state: 'error', message: (e as Error).message });
      } finally {
        setCheckingUser(false);
      }
    })();
  }, []);

  // Signing out of Acceso in any tab locks the vault here too.
  useEffect(
    () =>
      onAccesoSignOut(() => {
        book?.vault.lock();
        setBook(undefined);
        setUser(undefined);
      }),
    [book],
  );

  if (boot.state === 'loading' || checkingUser)
    return (
      <Box sx={{ display: 'grid', placeItems: 'center', minHeight: '100vh' }}>
        <CircularProgress aria-label="Cargando" />
      </Box>
    );
  if (boot.state === 'error')
    return (
      <Box sx={{ p: 4 }}>
        <Alert severity="error">No se pudo iniciar: {boot.message}</Alert>
      </Box>
    );
  if (boot.cfg.mode === 'saas' && !user)
    return (
      <Suspense fallback={<CircularProgress aria-label="Cargando" />}>
        <AccesoLogin onSignedIn={setUser} managed={!!boot.cfg.managedSigner} />
      </Suspense>
    );
  if (!book) return <VaultGate cfg={boot.cfg} onUnlocked={setBook} />;
  return (
    <Workspace
      cfg={boot.cfg}
      flags={boot.flags}
      book={book}
      user={user}
      onLock={() => {
        book.vault.lock();
        setBook(undefined);
      }}
      onSignedOut={() => {
        book.vault.lock();
        setBook(undefined);
        setUser(undefined);
      }}
    />
  );
}
