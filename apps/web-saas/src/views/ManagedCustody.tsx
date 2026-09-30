import { useCallback, useEffect, useState } from 'react';
import { Alert, Box, Button, Card, CardContent, Checkbox, FormControlLabel, Link, List, ListItem, ListItemText, Radio, RadioGroup, Stack, Step, StepLabel, Stepper, TextField, Typography } from '@mui/material';
import { disclose, MANAGED_CONSENT_TEXTS, managedConsentVersion, preset } from '@sedecim/profiles';
import { npubEncode } from '@sedecim/nostr-core';
import { ManagedSignerClient, ManagedSignerReauthError, type ClosedManagedKey, type ManagedDeviceSession, type ManagedKeyInfo, type ManagedKeyUsage, type ManagedSignerConnection } from '@sedecim/signer';
import { cancelManagedCustody, managedCancellationBackup, managedConnection, managedExitBackupJson, managedLogin, migrateManagedToLocal, shortNpub } from '../lib/session';
import { useWorkspace } from '../lib/workspace';
import { MaturityChip } from './MaturityChip';

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
      <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }} id="managed-maturity">
        <Typography variant="body2">Custodia gestionada:</Typography>
        <MaturityChip id="managed-custody" />
      </Stack>
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
      <Typography variant="caption" sx={{ color: 'text.secondary' }} id="managed-consent-version">
        Tu aceptación queda registrada con su versión: {managedConsentVersion(terms?.version)}.
      </Typography>
    </Stack>
  );
}

const STEPS = ['Exportar', 'Verificar posesión', 'Borrar la copia gestionada'];

/** The managed-signer wants a sign-in from the last 5 minutes; past 4, the password is asked again. */
const RECENT_SIGN_IN_MS = 4 * 60_000;

/**
 * IR-2026-10-03: exporting, migrating, deleting or cancelling the managed key, and closing the other sessions, ask for
 * the Acceso password again. The managed-signer only accepts them from a sign-in of the last minutes and never through
 * this browser's device session, so whoever has this browser open without the password cannot do them. `run` signs in
 * again when needed and hands the Acceso login (not the device session) to the call.
 */
function useRecentSignIn(id: string) {
  const ws = useWorkspace();
  const [password, setPassword] = useState('');
  const [signedInAt, setSignedInAt] = useState<number>();
  const needed = signedInAt === undefined || Date.now() - signedInAt > RECENT_SIGN_IN_MS;
  const field = needed ? (
    <TextField
      id={id}
      label="Tu contraseña de Acceso"
      helperText="Te la pedimos otra vez para confirmar que eres tú."
      type="password"
      autoComplete="current-password"
      value={password}
      onChange={(e) => setPassword(e.target.value)}
    />
  ) : null;
  const run = async <T,>(fn: (login: ManagedSignerConnection) => Promise<T>): Promise<T> => {
    if (needed) {
      if (!ws.managedEnv.reauthenticate) throw new Error('sin sesión de Acceso');
      if (!password) throw new Error('Escribe tu contraseña de Acceso para confirmar que eres tú.');
      await ws.managedEnv.reauthenticate(password);
      setPassword('');
      setSignedInAt(Date.now());
    }
    try {
      return await fn(managedLogin(ws.managedEnv));
    } catch (e) {
      if (!(e instanceof ManagedSignerReauthError)) throw e;
      setSignedInAt(undefined);
      throw new Error('Tu inicio de sesión ya no es reciente: escribe otra vez tu contraseña de Acceso.');
    }
  };
  return { field, ready: !needed || password.length > 0, run };
}

/** Offers a JSON file to save (the browser's own download). */
function download(json: string, name: string) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([json], { type: 'application/json' }));
  a.download = name;
  a.click();
  URL.revokeObjectURL(a.href);
}

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
  const recent = useRecentSignIn('migration-reauth');
  const keyId = s.persona.managedKeyId!;

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
      const res = await recent.run((login) => migrateManagedToLocal(ws.book, s.persona, new ManagedSignerClient({ ...login, keyId }), password));
      setNcryptsec(res.ncryptsec);
      setPassword('');
      setStep(2);
      await ws.reloadPersonas();
      await ws.selectPersona(res.persona.id);
      ws.notify('La llave ya está en este navegador y la posesión quedó verificada', 'success');
    });

  const saveBackup = () =>
    run(async () => {
      if (!ncryptsec) return ws.notify('El backup de la migración ya no está en memoria: usa "Descargar backup cifrado (NIP-49)" de la persona.', 'info');
      // FR026-04: with its npub, so the restore flows accept the file.
      download(await managedExitBackupJson(s.persona, ncryptsec), 'acceso-nostr-backup-migrada.json');
    });

  const deleteManaged = () =>
    run(async () => {
      const { destroyAfter } = await recent.run((login) => new ManagedSignerClient({ ...login, keyId }).deleteKey());
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
              {recent.field}
              <Box>
                <Button variant="contained" onClick={() => void exportAndVerify()} disabled={busy || password.length < 12 || !recent.ready}>
                  Exportar y verificar
                </Button>
              </Box>
            </>
          )}
          {step === 2 && (
            <>
              <Alert severity="success">Tu llave ya vive en este navegador. Guarda el backup antes de borrar la copia gestionada.</Alert>
              <Box>
                <Button onClick={() => void saveBackup()}>Descargar backup cifrado</Button>
              </Box>
              <Alert severity="warning">Borrar la copia gestionada es definitivo: el material cifrado se destruye tras la ventana de retención (30 días).</Alert>
              {recent.field}
              <Box>
                <Button color="error" variant="outlined" onClick={() => void deleteManaged()} disabled={busy || !recent.ready}>
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

/**
 * FR026-04: leaving managed custody without migrating (ARCO cancellation, docs/legal/custodia-managed.md §4). First the
 * backup, checked against this persona's npub; then the confirmation with the end of the npub. The key stops signing
 * everywhere at once and its material is destroyed after the retention window.
 */
export function CancelCustody() {
  const ws = useWorkspace();
  const s = ws.session!;
  const npub = npubEncode(s.persona.pubkey);
  const [password, setPassword] = useState('');
  const [downloaded, setDownloaded] = useState(false);
  const [kept, setKept] = useState(false);
  const [typed, setTyped] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const recent = useRecentSignIn('cancel-reauth');
  const keyId = s.persona.managedKeyId!;

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
  const saveBackup = () =>
    run(async () => {
      const json = await recent.run((login) => managedCancellationBackup(s.persona, new ManagedSignerClient({ ...login, keyId }), password));
      setPassword('');
      download(json, 'acceso-nostr-backup-cancelacion.json');
      setDownloaded(true);
    });
  const cancel = () =>
    run(async () => {
      const { destroyAfter } = await recent.run((login) => cancelManagedCustody(ws.book, s.persona, new ManagedSignerClient({ ...login, keyId }), typed));
      ws.notify(`Custodia gestionada cancelada: la llave ya no firma y su material cifrado se destruye el ${new Date(destroyAfter).toLocaleDateString()}.`, 'success');
      await ws.reloadPersonas();
      const rest = await ws.book.list();
      if (rest[0]) await ws.selectPersona(rest[0].id);
      else window.location.reload();
    });

  return (
    <Card id="cancel-custody">
      <CardContent>
        <Stack spacing={2}>
          <Typography variant="h6" component="h2">
            Cancelar la custodia gestionada sin migrar
          </Typography>
          <Typography variant="body2">
            Borra tu llave de la plataforma sin pasarla a este navegador. Deja de firmar en todos tus dispositivos en cuanto confirmes, y su material cifrado se destruye pasada la ventana de retención (30 días). Después no se puede recuperar desde la plataforma.
          </Typography>
          {recent.field}
          <Typography variant="subtitle1" component="h3">
            1. Descarga tu respaldo
          </Typography>
          <Typography variant="body2" sx={{ color: 'text.secondary' }}>
            La plataforma te entrega tu llave cifrada con esta contraseña y este navegador comprueba que es la de {shortNpub(s.persona.pubkey)}. Con el archivo y la contraseña puedes volver a usar esta identidad como llave local.
          </Typography>
          <TextField id="cancel-pass" label="Contraseña del respaldo (mínimo 12 caracteres)" type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />
          <Box>
            <Button id="cancel-backup" variant="outlined" onClick={() => void saveBackup()} disabled={busy || password.length < 12 || !recent.ready}>
              {downloaded ? 'Descargar otra vez' : 'Descargar el respaldo cifrado'}
            </Button>
          </Box>
          <FormControlLabel control={<Checkbox id="cancel-kept" checked={kept} disabled={!downloaded} onChange={(e) => setKept(e.target.checked)} />} label="Guardé el archivo y recuerdo su contraseña" />
          <Typography variant="subtitle1" component="h3">
            2. Confirma con el final de tu npub
          </Typography>
          <TextField
            id="cancel-confirm"
            label={`Escribe los últimos 8 caracteres: …${npub.slice(-8)}`}
            value={typed}
            disabled={!downloaded || !kept}
            onChange={(e) => setTyped(e.target.value)}
            slotProps={{ htmlInput: { autoComplete: 'off', spellCheck: false } }}
          />
          <Box>
            <Button id="cancel-custody-confirm" color="error" variant="contained" onClick={() => void cancel()} disabled={busy || !downloaded || !kept || typed.trim() !== npub.slice(-8) || !recent.ready}>
              Cancelar la custodia y borrar la llave
            </Button>
          </Box>
          {error && <Alert severity="error">{error}</Alert>}
        </Stack>
      </CardContent>
    </Card>
  );
}

/**
 * FR026-04: the keys this Acceso login took out of managed custody, and when the material of each one is destroyed. A
 * destroyed key is no longer tied to the account, so it stops appearing.
 */
export function ClosedManagedKeys() {
  const ws = useWorkspace();
  const [keys, setKeys] = useState<ClosedManagedKey[] | undefined>();
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const load = async () => {
    setBusy(true);
    setError('');
    try {
      setKeys(await ManagedSignerClient.closedKeys(managedConnection(ws.managedEnv)));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Stack spacing={1} id="closed-managed-keys">
      <Typography variant="subtitle1" component="h3">
        Llaves gestionadas en eliminación
      </Typography>
      <Box>
        <Button id="closed-managed-keys-load" variant="outlined" onClick={() => void load()} disabled={busy}>
          Ver el estado de eliminación
        </Button>
      </Box>
      {keys && keys.length === 0 && <Alert severity="info">No hay llaves gestionadas pendientes de destrucción en tu cuenta.</Alert>}
      {keys && keys.length > 0 && (
        <List dense>
          {keys.map((k) => (
            <ListItem key={k.keyId}>
              <ListItemText
                primary={`${shortNpub(k.pubkey)} · ${k.exit === 'cancelled' ? 'custodia cancelada' : 'migrada a tu custodia'} el ${new Date(k.deletedAt).toLocaleDateString()}`}
                secondary={`Ya no firma. Su material cifrado se destruye el ${new Date(k.destroyAfter).toLocaleDateString()}; después no queda nada que la ligue a tu cuenta.`}
              />
            </ListItem>
          ))}
        </List>
      )}
      {error && <Alert severity="error">{error}</Alert>}
    </Stack>
  );
}

/**
 * FR005-11: a new browser, the same Acceso login: the managed keys its owner already has, to open one here. Only
 * keys that still sign are offered, and none this browser already holds.
 */
export function ManagedRecovery({ selected, onSelect }: { selected?: ManagedKeyInfo; onSelect(key: ManagedKeyInfo | undefined): void }) {
  const ws = useWorkspace();
  const [keys, setKeys] = useState<ManagedKeyInfo[] | undefined>();
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const search = async () => {
    setBusy(true);
    setError('');
    try {
      const held = new Set(ws.personas.flatMap((p) => [p.managedKeyId, p.pubkey]));
      const all = await ManagedSignerClient.listKeys(managedConnection(ws.managedEnv));
      const usable = all.filter((k) => k.state === 'active' && !held.has(k.keyId) && !held.has(k.pubkey));
      setKeys(usable);
      onSelect(usable.length === 1 ? usable[0] : undefined);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Stack spacing={1} id="managed-recovery">
      <Alert severity="warning">{MANAGED_DISCLOSURE}</Alert>
      <Typography variant="body2">Con tu login de Acceso, este navegador vuelve a firmar con la llave gestionada que ya tienes. No se crea otra llave ni cambia tu npub.</Typography>
      <Box>
        <Button id="managed-recovery-search" variant="outlined" onClick={() => void search()} disabled={busy}>
          Buscar mis llaves gestionadas
        </Button>
      </Box>
      {keys && keys.length === 0 && <Alert severity="info">No tienes llaves gestionadas que recuperar en este navegador.</Alert>}
      {keys && keys.length > 0 && (
        <RadioGroup value={selected?.keyId ?? ''} onChange={(e) => onSelect(keys.find((k) => k.keyId === e.target.value))} aria-label="Llave gestionada">
          {keys.map((k) => (
            <FormControlLabel key={k.keyId} value={k.keyId} control={<Radio />} label={`${shortNpub(k.pubkey)} · creada el ${new Date(k.createdAt).toLocaleDateString()}${k.consentVersion ? ` · aceptaste «${k.consentVersion}»` : ''}`} />
          ))}
        </RadioGroup>
      )}
      {error && <Alert severity="error">{error}</Alert>}
    </Stack>
  );
}

/** FR005-11: what each usage log action means, in the words of the view. */
const USAGE_LABELS: Record<string, string> = {
  created: 'Llave creada',
  imported: 'Llave importada',
  sign: 'Firma',
  nip44_encrypt: 'Cifrado de un mensaje (NIP-44)',
  nip44_decrypt: 'Descifrado de un mensaje (NIP-44)',
  export: 'Exportación',
  'migration-confirmed': 'Migración confirmada',
  deleted: 'Llave borrada',
  cancelled: 'Custodia cancelada sin migrar',
  destroyed: 'Material destruido',
  'rate-limited': 'Firma rechazada por el límite de ritmo',
};

/**
 * FR005-11: what the managed-signer did with this persona's key (the usage log it keeps 12 months, DEC-09) and the
 * device sessions of this Acceso login, which the user closes here.
 */
export function ManagedActivity() {
  const ws = useWorkspace();
  const s = ws.session!;
  const [usage, setUsage] = useState<ManagedKeyUsage[] | undefined>();
  const [sessions, setSessions] = useState<ManagedDeviceSession[] | undefined>();
  const [thisDevice, setThisDevice] = useState('');
  const [orgDevice, setOrgDevice] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  /** IR-2026-10-11: another browser closed the other sessions after this one signed in. */
  const [cutOff, setCutOff] = useState(false);
  const recent = useRecentSignIn('sessions-reauth');

  const load = useCallback(async () => {
    // The device first: shown even when the managed-signer turns this browser away (FR024-03).
    setThisDevice((await ws.managedEnv.session?.deviceId()) ?? '');
    const conn = managedConnection(ws.managedEnv);
    const client = new ManagedSignerClient({ ...conn, keyId: s.persona.managedKeyId! });
    const [u, list] = await Promise.all([client.usage(), ManagedSignerClient.listDeviceSessions(conn)]);
    setUsage(u.slice(-20).reverse());
    setSessions(list);
  }, [ws.managedEnv, s.persona.managedKeyId]);

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError('');
    try {
      await fn();
    } catch (e) {
      if (e instanceof ManagedSignerReauthError) setCutOff(true);
      else setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  useEffect(() => {
    void run(load);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [load]);

  const login = () => {
    if (!ws.managedEnv.session) throw new Error('sin sesión de Acceso');
    return ws.managedEnv.session.login();
  };
  const closeOne = (x: ManagedDeviceSession) =>
    run(async () => {
      await ManagedSignerClient.closeDeviceSession(login(), x.id);
      if (x.current) await ws.managedEnv.session?.forget();
      await load();
      ws.notify(x.current ? 'Sesión de este navegador cerrada: la próxima firma abre otra con tu login de Acceso.' : `Sesión de ${x.deviceId} cerrada.`, 'success');
    });
  // IR-2026-10-11: it also cuts off the logins of the other browsers, so it asks for the password (IR-2026-10-03).
  const closeOthers = () =>
    run(async () => {
      const current = sessions?.find((x) => x.current);
      const closed = await recent.run((login) => ManagedSignerClient.closeDeviceSessions(login, current ? { except: current.id } : {}));
      await load();
      ws.notify(closed === 1 ? 'Se cerró 1 sesión. Los demás navegadores tendrán que escribir otra vez tu contraseña de Acceso.' : `Se cerraron ${closed} sesiones. Los demás navegadores tendrán que escribir otra vez tu contraseña de Acceso.`, 'success');
    });
  const signInAgain = () =>
    run(async () => {
      await recent.run(async () => undefined);
      setCutOff(false);
      await load();
      ws.notify('Este navegador vuelve a firmar con tu llave gestionada.', 'success');
    });
  const others = (sessions ?? []).filter((x) => !x.current).length;
  // FR024-03: the session carries the device id the organisation registered, so revoking it reaches this browser.
  const bind = () =>
    run(async () => {
      if (!ws.managedEnv.session) throw new Error('sin sesión de Acceso');
      await ws.managedEnv.session.bindDevice(orgDevice);
      setOrgDevice('');
      await load();
      ws.notify('Este navegador firma ahora como el dispositivo de tu organización: si lo revoca, deja de firmar.', 'success');
    });
  const bound = !!thisDevice && !thisDevice.startsWith('web-');

  return (
    <Card id="managed-activity">
      <CardContent>
        <Stack spacing={2}>
          <Typography variant="h6" component="h2">
            Actividad de tu llave gestionada
          </Typography>
          <Typography variant="subtitle1" component="h3" id="managed-sessions-h">
            Sesiones que pueden firmar
          </Typography>
          <List id="managed-sessions" dense aria-labelledby="managed-sessions-h">
            {(sessions ?? []).map((x) => (
              <ListItem
                key={x.id}
                secondaryAction={
                  <Button size="small" disabled={busy} aria-label={`Cerrar la sesión de ${x.current ? 'este navegador' : x.deviceId}`} onClick={() => void closeOne(x)}>
                    Cerrar
                  </Button>
                }
              >
                <ListItemText primary={x.current ? `${x.deviceId} (este navegador)` : x.deviceId} secondary={`abierta el ${new Date(x.createdAt).toLocaleString()} · caduca el ${new Date(x.expiresAt).toLocaleString()}`} />
              </ListItem>
            ))}
          </List>
          {cutOff && (
            <Alert severity="warning" id="managed-cut-off">
              Se cerraron las sesiones de tu llave gestionada desde otro navegador después de que entraras en este. Escribe otra vez tu contraseña de Acceso para volver a firmar aquí.
            </Alert>
          )}
          {(cutOff || others > 0) && recent.field}
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}>
            {cutOff && (
              <Button id="managed-sign-in-again" variant="contained" disabled={busy || !recent.ready} onClick={() => void signInAgain()}>
                Volver a entrar
              </Button>
            )}
            <Button id="managed-close-others" variant="outlined" disabled={busy || others === 0 || !recent.ready} onClick={() => void closeOthers()}>
              Cerrar las demás sesiones
            </Button>
          </Stack>
          <Typography variant="caption" sx={{ color: 'text.secondary' }}>
            Cerrar una sesión corta la firma en ese navegador hasta que vuelva a entrar con tu login de Acceso. «Cerrar las demás sesiones» además obliga a los otros navegadores a escribir otra vez tu contraseña: úsalo si perdiste un dispositivo, y cambia también tu contraseña de Acceso.
          </Typography>
          {ws.cfg.organizationDevices && (
            <Stack spacing={1} id="managed-org">
              <Typography variant="subtitle1" component="h3">
                Dispositivo de tu organización
              </Typography>
              {bound ? (
                <Typography variant="body2" id="managed-org-bound">
                  Este navegador firma como el dispositivo {thisDevice} de tu organización. Si lo revoca, deja de firmar con tu llave gestionada, también al volver a entrar con tu login.
                </Typography>
              ) : (
                <>
                  <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                    Tu organización registra cada dispositivo. Vincula este navegador al suyo para que, si lo pierdes y lo revoca, deje de poder firmar.
                  </Typography>
                  <Stack
                    component="form"
                    direction={{ xs: 'column', sm: 'row' }}
                    spacing={1}
                    onSubmit={(e) => {
                      e.preventDefault();
                      void bind();
                    }}
                  >
                    <TextField id="managed-org-device" label="Id del dispositivo que te dio tu organización" size="small" value={orgDevice} onChange={(e) => setOrgDevice(e.target.value)} />
                    <Button type="submit" variant="outlined" disabled={busy || !orgDevice.trim()}>
                      Vincular este navegador
                    </Button>
                  </Stack>
                </>
              )}
            </Stack>
          )}
          <Typography variant="subtitle1" component="h3" id="managed-usage-h">
            Uso de la llave (últimos 20; el registro se guarda 12 meses)
          </Typography>
          <List id="managed-usage" dense aria-labelledby="managed-usage-h">
            {(usage ?? []).map((u, i) => (
              <ListItem key={`${u.at}-${i}`}>
                <ListItemText
                  primary={`${USAGE_LABELS[u.action] ?? u.action}${u.kind !== undefined ? ` · kind ${u.kind}` : ''}`}
                  secondary={`${new Date(u.at).toLocaleString()} · ${u.deviceId ? (u.deviceId === thisDevice ? 'este navegador' : u.deviceId) : 'sin sesión de dispositivo'}`}
                />
              </ListItem>
            ))}
          </List>
          <Box>
            <Button id="managed-activity-refresh" disabled={busy} onClick={() => void run(load)}>
              Actualizar
            </Button>
          </Box>
          {error && <Alert severity="error">{error}</Alert>}
        </Stack>
      </CardContent>
    </Card>
  );
}
