import { useCallback, useEffect, useState } from 'react';
import { Alert, Box, Button, Card, CardContent, Checkbox, FormControlLabel, Link, List, ListItem, ListItemText, Radio, RadioGroup, Stack, Step, StepLabel, Stepper, TextField, Typography } from '@mui/material';
import { disclose, MANAGED_CONSENT_TEXTS, managedConsentVersion, preset } from '@sedecim/profiles';
import { ManagedSignerClient, type ManagedDeviceSession, type ManagedKeyInfo, type ManagedKeyUsage } from '@sedecim/signer';
import { managedConnection, migrateManagedToLocal, shortNpub } from '../lib/session';
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
      <Stack direction="row" spacing={1} alignItems="center" id="managed-maturity">
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
  const [client] = useState(() => new ManagedSignerClient({ ...managedConnection(ws.managedEnv), keyId: s.persona.managedKeyId! }));

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
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    const conn = managedConnection(ws.managedEnv);
    const client = new ManagedSignerClient({ ...conn, keyId: s.persona.managedKeyId! });
    const [u, list, device] = await Promise.all([client.usage(), ManagedSignerClient.listDeviceSessions(conn), ws.managedEnv.session?.deviceId()]);
    setUsage(u.slice(-20).reverse());
    setSessions(list);
    setThisDevice(device ?? '');
  }, [ws.managedEnv, s.persona.managedKeyId]);

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
  const closeOthers = () =>
    run(async () => {
      const current = sessions?.find((x) => x.current);
      const closed = await ManagedSignerClient.closeDeviceSessions(login(), current ? { except: current.id } : {});
      await load();
      ws.notify(closed === 1 ? 'Se cerró 1 sesión.' : `Se cerraron ${closed} sesiones.`, 'success');
    });
  const others = (sessions ?? []).filter((x) => !x.current).length;

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
          <Box>
            <Button id="managed-close-others" variant="outlined" disabled={busy || others === 0} onClick={() => void closeOthers()}>
              Cerrar las demás sesiones
            </Button>
          </Box>
          <Typography variant="caption" color="text.secondary">
            Cerrar una sesión corta la firma en ese navegador hasta que vuelva a entrar con tu login de Acceso. Si perdiste un dispositivo, cambia también tu contraseña de Acceso.
          </Typography>
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
