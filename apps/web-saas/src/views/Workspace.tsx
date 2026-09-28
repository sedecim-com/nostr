import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Alert, AppBar, Box, Button, Chip, Container, MenuItem, Snackbar, Tab, Tabs, TextField, Toolbar, Typography } from '@mui/material';
import type { DeploymentFlags } from '@sedecim/messaging';
import type { SovereigntyConfig } from '@sedecim/profiles';
import type { AccesoUser } from '../lib/acceso';
import type { DeploymentConfig } from '../lib/config';
import { custodyLabel, openPersona, publishDmRelays, shortNpub, type ManagedEnv, type PersonaSession } from '../lib/session';
import type { PersonaBook, PersonaRecord } from '../lib/vault';
import { WorkspaceContext, type Workspace as Ws } from '../lib/workspace';
import { onSignerAuthUrl } from '../lib/authUrl';
import { BRAND } from '../theme';
import { ChannelsView } from './ChannelsView';
import { DmView } from './DmView';
import { OutboxView } from './OutboxView';
import { PanelView } from './PanelView';
import { PersonasView } from './PersonasView';

// MLS (marmot-ts / ts-mls) is heavy: the high-security groups view and its crypto load on first use.
const GroupsView = lazy(() => import('./GroupsView').then((m) => ({ default: m.GroupsView })));

const TABS = [
  { id: 'personas', label: 'Personas' },
  { id: 'channels', label: 'Canales' },
  { id: 'dm', label: 'Mensajes directos' },
  { id: 'groups', label: 'Grupos seguros' },
  { id: 'outbox', label: 'Entrega' },
  { id: 'panel', label: 'Soberanía y privacidad' },
] as const;
type TabId = (typeof TABS)[number]['id'];

interface Props {
  cfg: DeploymentConfig;
  flags: DeploymentFlags | undefined;
  book: PersonaBook;
  user: AccesoUser | undefined;
  onLock(): void;
  onSignedOut(): void;
}

export function Workspace({ cfg, flags, book, user, onLock, onSignedOut }: Props) {
  const [personas, setPersonas] = useState<PersonaRecord[]>([]);
  const [session, setSession] = useState<PersonaSession | undefined>();
  const [tab, setTab] = useState<TabId>('personas');
  const [toast, setToast] = useState<{ message: string; severity: 'success' | 'info' | 'warning' | 'error' } | undefined>();
  const current = useRef<PersonaSession | undefined>(undefined);
  const [authUrl, setAuthUrl] = useState<string | undefined>();
  useEffect(() => onSignerAuthUrl(setAuthUrl), []);

  // Managed personas authorize each signature with the Acceso access token (FR005-04); Amplify loads lazily.
  const managedEnv = useMemo<ManagedEnv>(
    () => (cfg.mode === 'saas' && cfg.managedSigner && user ? { baseUrl: cfg.managedSigner, token: async () => (await import('../lib/acceso')).accesoAccessToken() } : {}),
    [cfg, user],
  );

  const reloadPersonas = useCallback(async () => setPersonas(await book.list()), [book]);

  const selectPersona = useCallback(
    async (id: string) => {
      const p = await book.get(id);
      if (!p) return;
      current.current?.close();
      const s = await openPersona(book, p, managedEnv, { discoveryRelays: cfg.discoveryRelays });
      current.current = s;
      setSession(s);
    },
    [book, managedEnv, cfg],
  );

  useEffect(() => {
    void (async () => {
      const list = await book.list();
      setPersonas(list);
      if (list[0]) await selectPersona(list[0].id);
    })();
    return () => current.current?.close();
  }, [book, selectPersona]);

  // FR011-02: resume the outbox as soon as the browser is back online.
  useEffect(() => {
    const onOnline = () => void current.current?.engine.resume();
    window.addEventListener('online', onOnline);
    return () => window.removeEventListener('online', onOnline);
  }, []);

  const saveConfig = useCallback(
    async (config: SovereigntyConfig) => {
      if (!session) return;
      const persona = { ...session.persona, config, preset: 'custom' as const };
      await book.save(persona);
      const s = { ...session, persona };
      current.current = s;
      setSession(s);
      await reloadPersonas();
    },
    [book, session, reloadPersonas],
  );

  const ws = useMemo<Ws>(
    () => ({ cfg, flags, book, user, personas, session, config: session?.persona.config, selectPersona, reloadPersonas, saveConfig, publishDmRelays: async () => current.current && publishDmRelays(current.current), managedEnv, notify: (message, severity = 'info') => setToast({ message, severity }) }),
    [cfg, flags, book, user, personas, session, selectPersona, reloadPersonas, saveConfig, managedEnv],
  );

  const sendingAs = session ? `Enviando como ${session.persona.label} · ${shortNpub(session.pubkey)} · ${custodyLabel(session.persona)} · ${session.persona.config.network === 'tor-only' ? 'Tor-only' : 'red directa'}` : 'Sin identidad activa';

  return (
    <WorkspaceContext.Provider value={ws}>
      {/* NFR009-02: keyboard users jump past the header and tabs. */}
      <Box component="a" href="#main" sx={{ position: 'absolute', left: -9999, top: 8, zIndex: 2000, p: 1, bgcolor: 'background.paper', '&:focus': { left: 8 } }}>
        Saltar al contenido
      </Box>
      <AppBar position="sticky" color="default" elevation={1}>
        <Toolbar sx={{ gap: 2, flexWrap: 'wrap' }}>
          <Typography variant="h6" component="h1" sx={{ flexGrow: 1 }}>
            {BRAND}
          </Typography>
          {personas.length > 0 && (
            <TextField select size="small" id="persona-select" label="Persona" value={session?.persona.id ?? ''} onChange={(e) => void selectPersona(e.target.value)} sx={{ minWidth: 200 }}>
              {personas.map((p) => (
                <MenuItem key={p.id} value={p.id}>
                  {p.label} · {shortNpub(p.pubkey)}
                </MenuItem>
              ))}
            </TextField>
          )}
          {user && <Chip label={`Acceso: ${user.username}`} variant="outlined" />}
          <Button onClick={onLock}>Bloquear</Button>
          {user && (
            <Button
              onClick={() =>
                void import('../lib/acceso')
                  .then((m) => m.accesoSignOut())
                  .catch(() => undefined)
                  .then(onSignedOut)
              }
            >
              Salir de Acceso
            </Button>
          )}
        </Toolbar>
        {/* Always visible so the user never posts with the wrong persona (FR-006). */}
        <Box id="sending-as" role="status" aria-live="polite" sx={{ px: 3, py: 0.5, bgcolor: 'action.hover', typography: 'body2' }}>
          {sendingAs}
        </Box>
        {/* FR004-05: the remote signer asks for approval in its own page; opened only by an explicit click. */}
        {authUrl && (
          <Alert
            severity="warning"
            onClose={() => setAuthUrl(undefined)}
            action={
              <Button color="inherit" href={authUrl} target="_blank" rel="noopener noreferrer" onClick={() => setAuthUrl(undefined)}>
                Abrir aprobación
              </Button>
            }
          >
            Tu signer remoto pide aprobar esta acción en {new URL(authUrl).host}.
          </Alert>
        )}
        <Tabs value={tab} onChange={(_, v: TabId) => setTab(v)} variant="scrollable" aria-label="Secciones">
          {TABS.map((t) => (
            <Tab key={t.id} value={t.id} label={t.label} id={`tab-${t.id}`} aria-controls={`view-${t.id}`} />
          ))}
        </Tabs>
      </AppBar>
      <Container component="main" id="main" tabIndex={-1} maxWidth="lg" sx={{ py: 3, outline: 'none' }}>
        {TABS.map((t) => (
          <Box key={t.id} role="tabpanel" id={`view-${t.id}`} aria-labelledby={`tab-${t.id}`} hidden={tab !== t.id}>
            {tab === t.id && (!session && t.id !== 'personas' ? <Alert severity="info">Crea o elige una persona primero.</Alert> : <View id={t.id} />)}
          </Box>
        ))}
      </Container>
      <Snackbar open={!!toast} autoHideDuration={6000} onClose={() => setToast(undefined)}>
        {toast ? (
          <Alert severity={toast.severity} onClose={() => setToast(undefined)} variant="filled">
            {toast.message}
          </Alert>
        ) : undefined}
      </Snackbar>
    </WorkspaceContext.Provider>
  );
}

function View({ id }: { id: TabId }) {
  switch (id) {
    case 'personas':
      return <PersonasView />;
    case 'channels':
      return <ChannelsView />;
    case 'dm':
      return <DmView />;
    case 'groups':
      return (
        <Suspense fallback={<Alert severity="info">Cargando grupos seguros…</Alert>}>
          <GroupsView />
        </Suspense>
      );
    case 'outbox':
      return <OutboxView />;
    case 'panel':
      return <PanelView />;
  }
}
