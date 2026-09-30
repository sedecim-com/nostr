import { useEffect, useMemo, useState } from 'react';
import { Alert, AppBar, Box, Button, Chip, CircularProgress, Container, Tab, Tabs, Toolbar, Typography } from '@mui/material';
import { IdentityLookupApi, PolicyAdminApi } from './api';
import { loadConfig, type AdminConfig } from './config';
import { shortNpub, type AdminSession, type ConsoleSession } from './signers';
import { SignIn } from './views/SignIn';
import { SubjectsView } from './views/SubjectsView';
import { ResourcesView } from './views/ResourcesView';
import { DevicesView } from './views/DevicesView';
import { RotationsView } from './views/RotationsView';
import { DirectoryView } from './views/DirectoryView';
import { RetentionView } from './views/RetentionView';
import { AuditView } from './views/AuditView';
import { AccessLogView } from './views/AccessLogView';
import { IdentityView } from './views/IdentityView';
import { MyDevicesView } from './views/MyDevicesView';

type Boot = { state: 'loading' } | { state: 'error'; message: string } | { state: 'ready'; cfg: AdminConfig };

const KIND_LABEL: Record<AdminSession['kind'], string> = { nip07: 'Extensión NIP-07', nip46: 'Bunker NIP-46', 'local-dev': 'Llave local (solo desarrollo)' };

export function App() {
  const [boot, setBoot] = useState<Boot>({ state: 'loading' });
  const [session, setSession] = useState<ConsoleSession | undefined>();

  useEffect(() => {
    loadConfig().then(
      (cfg) => setBoot({ state: 'ready', cfg }),
      (e: Error) => setBoot({ state: 'error', message: e.message }),
    );
  }, []);

  if (boot.state === 'loading')
    return (
      <Box sx={{ display: 'grid', placeItems: 'center', minHeight: '100vh' }}>
        <CircularProgress aria-label="Cargando" />
      </Box>
    );
  if (boot.state === 'error')
    return (
      <Box component="main" sx={{ p: 4 }}>
        <Alert severity="error">No se pudo iniciar la consola: {boot.message}</Alert>
      </Box>
    );
  if (!session) return <SignIn cfg={boot.cfg} onSignedIn={setSession} />;
  const signOut = () => {
    session.close();
    setSession(undefined);
  };
  return session.admin ? <Console cfg={boot.cfg} session={session} onSignOut={signOut} /> : <MemberConsole cfg={boot.cfg} session={session} onSignOut={signOut} />;
}

/** FR023-11: what a key that is not an admin gets: its own devices, their passkey and sessions opened with it. */
function MemberConsole({ cfg, session, onSignOut }: { cfg: AdminConfig; session: AdminSession; onSignOut(): void }) {
  const api = useMemo(() => new PolicyAdminApi(cfg.policyEngineUrl, session.signer), [cfg, session]);
  return (
    <>
      <AppBar position="static" color="default" elevation={1}>
        <Toolbar sx={{ gap: 2, flexWrap: 'wrap' }}>
          <Typography variant="h6" component="h1" sx={{ flexGrow: 1 }}>
            Mis dispositivos
          </Typography>
          <Chip id="member-identity" label={`${shortNpub(session.pubkey)} · ${KIND_LABEL[session.kind]} · sin permisos de administración`} color={session.kind === 'local-dev' ? 'warning' : 'default'} variant="outlined" />
          <Button onClick={onSignOut}>Cerrar sesión</Button>
        </Toolbar>
      </AppBar>
      <Container component="main" maxWidth="lg" sx={{ py: 3 }}>
        <MyDevicesView api={api} pubkey={session.pubkey} />
      </Container>
    </>
  );
}

const TABS = ['Personas', 'Recursos y políticas', 'Dispositivos', 'Rotaciones pendientes', 'Directorio', 'Retención', 'Auditoría', 'Accesos', 'Vínculos de identidad', 'Mis dispositivos'] as const;

function Console({ cfg, session, onSignOut }: { cfg: AdminConfig; session: AdminSession; onSignOut(): void }) {
  const api = useMemo(() => new PolicyAdminApi(cfg.policyEngineUrl, session.signer), [cfg, session]);
  const identity = useMemo(() => (cfg.identityServiceUrl ? new IdentityLookupApi(cfg.identityServiceUrl, session.signer) : undefined), [cfg, session]);
  const tabs = TABS.filter((t) => t !== 'Vínculos de identidad' || identity);
  const [tab, setTab] = useState(0);
  const current = tabs[tab];
  return (
    <>
      <AppBar position="static" color="default" elevation={1}>
        <Toolbar sx={{ gap: 2, flexWrap: 'wrap' }}>
          <Typography variant="h6" component="h1" sx={{ flexGrow: 1 }}>
            Consola de administración
          </Typography>
          <Chip id="admin-identity" label={`${shortNpub(session.pubkey)} · ${KIND_LABEL[session.kind]}`} color={session.kind === 'local-dev' ? 'warning' : 'default'} variant="outlined" />
          <Button onClick={onSignOut}>Cerrar sesión</Button>
        </Toolbar>
        <Tabs value={tab} onChange={(_e, v: number) => setTab(v)} variant="scrollable" scrollButtons="auto" aria-label="Secciones">
          {tabs.map((t, i) => (
            <Tab key={t} label={t} id={`tab-${i}`} aria-controls={`panel-${i}`} />
          ))}
        </Tabs>
      </AppBar>
      <Container component="main" maxWidth="lg" sx={{ py: 3 }} id={`panel-${tab}`} role="tabpanel" aria-labelledby={`tab-${tab}`}>
        {current === 'Personas' && <SubjectsView api={api} />}
        {current === 'Recursos y políticas' && <ResourcesView api={api} />}
        {current === 'Dispositivos' && <DevicesView api={api} />}
        {current === 'Rotaciones pendientes' && <RotationsView api={api} />}
        {current === 'Directorio' && <DirectoryView api={api} />}
        {current === 'Retención' && <RetentionView api={api} />}
        {current === 'Auditoría' && <AuditView api={api} />}
        {current === 'Accesos' && <AccessLogView api={api} />}
        {current === 'Vínculos de identidad' && identity && <IdentityView api={identity} />}
        {current === 'Mis dispositivos' && <MyDevicesView api={api} pubkey={session.pubkey} />}
      </Container>
    </>
  );
}
