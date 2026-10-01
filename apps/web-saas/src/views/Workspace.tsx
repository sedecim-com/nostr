import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Alert, AppBar, Box, Button, Chip, Container, MenuItem, Snackbar, Stack, Tab, Tabs, TextField, Toolbar, Typography } from '@mui/material';
import { BUZZ_PINNED_ADAPTER, wrapOptionsFromFlags, type DeploymentFlags, type DirectMessage, type DmInbox } from '@sedecim/messaging';
import type { OutboxRecord } from '@sedecim/delivery-engine';
import { receiptPolicy, type SovereigntyConfig } from '@sedecim/profiles';
import type { AccesoUser } from '../lib/acceso';
import type { DeploymentConfig } from '../lib/config';
import { custodyLabel, openDmInbox, openPersona, personaConfig, publishDmRelays, shortNpub, type ManagedEnv, type PersonaSession } from '../lib/session';
import { BrowserManagedSession } from '../lib/managed-session';
import type { PersonaBook, PersonaRecord } from '../lib/vault';
import { sendBlockedReason, WorkspaceContext, type Workspace as Ws } from '../lib/workspace';
import { onSignerAuthUrl } from '../lib/authUrl';
import { fetchLinks, LINK_LEVEL_LABEL, linkLevel } from '../lib/identity';
import { webCrashReports } from '../lib/crash';
import { BRAND } from '../theme';
import { CrashBoundary, CrashReportsCard } from './CrashReports';
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
  const [nip17, setNip17] = useState(flags?.nip17.enabled ?? false);
  useEffect(() => setNip17(flags?.nip17.enabled ?? false), [flags]);
  const [dmInbox, setDmInbox] = useState<DmInbox<OutboxRecord> | undefined>();
  const [dmMessages, setDmMessages] = useState<DirectMessage[]>([]);
  const [dmUnseen, setDmUnseen] = useState(0);
  const tabNow = useRef<TabId>(tab);
  tabNow.current = tab;

  // Managed personas sign through this browser's device session, opened with the Acceso login (FR005-04, FR005-11);
  // Amplify loads lazily.
  const managedEnv = useMemo<ManagedEnv>(() => {
    if (!(cfg.mode === 'saas' && cfg.managedSigner && user)) return {};
    const token = async () => (await import('../lib/acceso')).accesoAccessToken();
    const reauthenticate = async (password: string) => (await import('../lib/acceso')).accesoReauthenticate(password);
    return { baseUrl: cfg.managedSigner, token, session: new BrowserManagedSession(book.store, cfg.managedSigner, token), reauthenticate };
  }, [cfg, user, book]);

  const reloadPersonas = useCallback(async () => setPersonas(await book.list()), [book]);

  const updatePersona = useCallback(
    async (persona: PersonaRecord) => {
      if (!current.current || current.current.persona.id !== persona.id) return reloadPersonas();
      const s = { ...current.current, persona };
      current.current = s;
      setSession(s);
      await reloadPersonas();
    },
    [reloadPersonas],
  );

  const selectPersona = useCallback(
    async (id: string) => {
      const p = await book.get(id);
      if (!p) return;
      current.current?.close();
      // VAULT-04: the engine reads the persona's Continuity Vault policy as the panel leaves it.
      const config = () => personaConfig(current.current?.persona.id === p.id ? current.current.persona : p);
      const s = await openPersona(book, p, managedEnv, { discoveryRelays: cfg.discoveryRelays, continuityVault: cfg.continuityVault, config });
      current.current = s;
      setSession(s);
      // FR007-05: the banner's link level, read again from the identity service when the persona already has an
      // account there (links made from another device); a persona without one never asks it.
      if (p.identityAccount && cfg.identityService)
        void fetchLinks(s.signer, cfg.identityService)
          .then(async (links) => {
            const now = current.current?.persona;
            if (!now || now.id !== p.id || JSON.stringify(now.links ?? []) === JSON.stringify(links)) return;
            const next = { ...now, links };
            await book.save(next);
            await updatePersona(next);
          })
          .catch(() => undefined);
    },
    [book, managedEnv, cfg, updatePersona],
  );

  useEffect(() => {
    void (async () => {
      const list = await book.list();
      setPersonas(list);
      if (list[0]) await selectPersona(list[0].id);
    })();
    return () => current.current?.close();
  }, [book, selectPersona]);

  // FR009-03: while NIP-17 is on, the persona's DM inbox reads its own DM relays in the background. Receipts for its
  // DMs move them to RECIPIENT_ACKED from any view; messages that arrive while the user is elsewhere are counted on
  // the tab. Keyed on the pool: a panel change keeps the same inbox (the receipt policy is read for each message).
  const pool = session?.pool;
  useEffect(() => {
    const s = current.current;
    if (!s || s.pool !== pool || !nip17 || sendBlockedReason(personaConfig(s.persona))) return;
    const inbox = openDmInbox(book, s, {
      policy: () => receiptPolicy(personaConfig((current.current ?? s).persona)),
      wrapOptions: wrapOptionsFromFlags(flags, BUZZ_PINNED_ADAPTER.wrap),
      onMessage: (m, live) => {
        setDmMessages(inbox.list());
        if (live && m.sender !== s.pubkey && tabNow.current !== 'dm') setDmUnseen((n) => n + 1);
      },
    });
    setDmInbox(inbox);
    if (s.persona.custody !== 'nip07') void inbox.start().catch(() => undefined);
    return () => {
      inbox.close();
      setDmInbox(undefined);
      setDmMessages([]);
      setDmUnseen(0);
    };
  }, [pool, nip17, book, flags]);

  // NFR007-03: failures are captured as the active persona's profile says; another persona does not see the last
  // failure of the previous one, and locking (unmount) captures nothing and forgets it.
  const crashMode = session ? personaConfig(session.persona).crashReports : undefined;
  const crashProfile = session?.persona.preset;
  const crashPersona = session?.persona.id;
  useEffect(() => webCrashReports().configure({ mode: crashMode, ...(crashProfile ? { profile: crashProfile } : {}), store: book.store }), [crashMode, crashProfile, book]);
  useEffect(() => webCrashReports().capture.forgetLast(), [crashPersona]);
  useEffect(() => () => webCrashReports().configure({ mode: 'off' }), []);

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
      // VAULT-04: a relaxed Continuity Vault policy releases the sends it was holding.
      void s.engine.resume();
      await reloadPersonas();
    },
    [book, session, reloadPersonas],
  );

  const ws = useMemo<Ws>(
    () => ({
      cfg,
      flags,
      book,
      user,
      personas,
      session,
      config: session ? personaConfig(session.persona) : undefined,
      selectPersona,
      reloadPersonas,
      saveConfig,
      updatePersona,
      publishDmRelays: async () => current.current && publishDmRelays(current.current),
      nip17,
      setNip17,
      dm: { inbox: dmInbox, messages: dmMessages, background: !!dmInbox && session?.persona.custody !== 'nip07' },
      managedEnv,
      notify: (message, severity = 'info') => setToast({ message, severity }),
    }),
    [cfg, flags, book, user, personas, session, selectPersona, reloadPersonas, saveConfig, updatePersona, nip17, dmInbox, dmMessages, managedEnv],
  );

  // FR006-02, FR007-05: identity, custody, network and link level, always visible above the composer.
  const sendingAs = session
    ? `Enviando como ${session.persona.label} · ${shortNpub(session.pubkey)} · ${custodyLabel(session.persona)} · ${session.persona.config.network === 'tor-only' ? 'Tor-only' : 'red directa'} · ${LINK_LEVEL_LABEL[linkLevel(session.persona.links)]}`
    : 'Sin identidad activa';

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
        <Tabs
          value={tab}
          onChange={(_, v: TabId) => {
            setTab(v);
            if (v === 'dm') setDmUnseen(0);
          }}
          variant="scrollable"
          aria-label="Secciones"
        >
          {TABS.map((t) => (
            <Tab key={t.id} value={t.id} label={t.id === 'dm' && dmUnseen > 0 ? `${t.label} · ${dmUnseen} ${dmUnseen === 1 ? 'nuevo' : 'nuevos'}` : t.label} id={`tab-${t.id}`} aria-controls={`view-${t.id}`} />
          ))}
        </Tabs>
      </AppBar>
      <Container component="main" id="main" tabIndex={-1} maxWidth="lg" sx={{ py: 3, outline: 'none' }}>
        {TABS.map((t) => (
          <Box key={t.id} role="tabpanel" id={`view-${t.id}`} aria-labelledby={`tab-${t.id}`} hidden={tab !== t.id}>
            {tab === t.id &&
              (!session && t.id !== 'personas' ? (
                <Alert severity="info">Crea o elige una persona primero.</Alert>
              ) : (
                <CrashBoundary key={t.id}>
                  <View id={t.id} />
                </CrashBoundary>
              ))}
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
      // NFR007-03: each in its own boundary, so that a failure of the panel does not hide the report of that failure.
      return (
        <Stack spacing={2}>
          <CrashBoundary>
            <PanelView />
          </CrashBoundary>
          <CrashBoundary>
            <CrashReportsCard />
          </CrashBoundary>
        </Stack>
      );
  }
}
