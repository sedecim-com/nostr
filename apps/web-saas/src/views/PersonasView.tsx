import { useState, type FormEvent } from 'react';
import { Alert, Box, Button, Card, CardActions, CardContent, Checkbox, FormControlLabel, List, ListItem, ListItemText, MenuItem, Radio, RadioGroup, Stack, TextField, Typography } from '@mui/material';
import { PRESETS, type PresetName } from '@sedecim/profiles';
import { linkAccesoLogin } from '../lib/identity';
import { createPersona, custodyFacts, custodyLabel, exportBackup, shortNpub, type NewPersona } from '../lib/session';
import { deviceKeyAllowed, setProtection } from '../lib/vault';
import { useWorkspace } from '../lib/workspace';
import { LinkPersonas } from './LinkPersonas';
import { RemoteSigner } from './RemoteSigner';
import { ManagedOptIn, MigrationWizard } from './ManagedCustody';
import type { Nip46Signer, NostrConnectOffer } from '@sedecim/signer';

type Mode = 'create' | 'import' | 'nip07' | 'nip46' | 'managed';

export function PersonasView() {
  const ws = useWorkspace();
  const { book, personas, session, cfg } = ws;
  const [label, setLabel] = useState('Personal');
  const [presetName, setPresetName] = useState<PresetName>('convenience');
  const [mode, setMode] = useState<Mode>('create');
  const [secret, setSecret] = useState('');
  const [ncPass, setNcPass] = useState('');
  const [managedConsent, setManagedConsent] = useState(false);
  const managedAvailable = !!ws.managedEnv.baseUrl;
  const [nip46Mode, setNip46Mode] = useState<'bunker' | 'nostrconnect'>('nostrconnect');
  const [relays, setRelays] = useState(cfg.relays.join('\n'));
  const [vaultPass, setVaultPass] = useState('');
  const [backupPass, setBackupPass] = useState('');
  const [linkConsent, setLinkConsent] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const deviceVault = book.vault.kind === 'device';
  // A stricter profile in a password-less vault needs a password first (ADR 0007).
  const needsPassword = deviceVault && presetName !== 'convenience';

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

  const create = (e?: FormEvent, connected?: { signer: Nip46Signer; offer: NostrConnectOffer }) => {
    e?.preventDefault();
    if (mode === 'nip46' && nip46Mode === 'nostrconnect' && !connected) return;
    void run(async () => {
      if (needsPassword) await setProtection(book.vault, { kind: 'passphrase', passphrase: vaultPass });
      const input: NewPersona = connected
        ? { kind: 'nip46-connected', signer: connected.signer, clientSecretKey: connected.offer.clientSecretKey }
        : mode === 'create'
          ? { kind: 'create' }
          : mode === 'import'
            ? { kind: 'import', secret, ncryptsecPass: ncPass }
            : mode === 'nip07'
              ? { kind: 'nip07' }
              : mode === 'managed'
                ? { kind: 'managed', baseUrl: ws.managedEnv.baseUrl!, token: ws.managedEnv.token! }
                : { kind: 'nip46', bunker: secret };
      if (mode === 'managed' && !managedConsent) throw new Error('La custodia gestionada requiere tu consentimiento explícito.');
      const p = await createPersona(book, input, { label: label.trim() || 'Persona', relays: relays.split('\n').map((s) => s.trim()).filter(Boolean), preset: presetName, deviceKey: book.vault.kind === 'device' });
      setSecret('');
      setNcPass('');
      await ws.reloadPersonas();
      await ws.selectPersona(p.id);
      await ws.publishDmRelays();
      ws.notify(`Persona "${p.label}" creada; sus relays de DM (kind 10050) se publicaron`, 'success');
    });
  };

  const download = () =>
    void run(async () => {
      const blob = await exportBackup(session!.persona, backupPass);
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `acceso-nostr-backup-${session!.persona.label}.json`;
      a.click();
      URL.revokeObjectURL(a.href);
      setBackupPass('');
    });

  const toggleProtection = () =>
    void run(async () => {
      if (deviceVault) await setProtection(book.vault, { kind: 'passphrase', passphrase: vaultPass });
      else {
        if (!deviceKeyAllowed(personas)) throw new Error('Todas las personas deben usar el perfil convenience con "sin contraseña" activado en su panel.');
        await setProtection(book.vault, { kind: 'device' });
      }
      setVaultPass('');
      await ws.reloadPersonas();
      ws.notify(deviceVault ? 'Almacén protegido con contraseña' : 'Este navegador abrirá el almacén sin contraseña', 'warning');
    });

  const link = () =>
    void run(async () => {
      await linkAccesoLogin(session!.signer, cfg.identityService!, await (await import('../lib/acceso')).accesoIdToken(), session!.persona.custody === 'local' ? 'local' : 'external');
      setLinkConsent(false);
      ws.notify('Cuenta de Acceso vinculada a esta persona', 'success');
    });

  return (
    <Stack spacing={3}>
      {session && (
        <Card>
          <CardContent>
            <Typography variant="h6" component="h2">
              {session.persona.label} · {shortNpub(session.pubkey)}
            </Typography>
            <List dense id="custody-facts">
              {custodyFacts(session).map((f) => (
                <ListItem key={f}>
                  <ListItemText primary={f} />
                </ListItem>
              ))}
            </List>
          </CardContent>
          <CardActions sx={{ flexWrap: 'wrap', gap: 1 }}>
            <Button onClick={() => void run(async () => (await ws.publishDmRelays(), ws.notify('Relays de DM publicados (kind 10050)', 'success')))} disabled={busy}>
              Publicar mis relays de DM
            </Button>
            {session.persona.custody === 'local' && (
              <>
                <TextField size="small" id="backup-pass" label="Contraseña del backup" type="password" autoComplete="new-password" value={backupPass} onChange={(e) => setBackupPass(e.target.value)} />
                <Button id="export-backup" onClick={download} disabled={busy || backupPass.length < 8}>
                  Descargar backup cifrado (NIP-49)
                </Button>
              </>
            )}
          </CardActions>
          {ws.user && cfg.identityService && (
            <CardContent>
              <FormControlLabel control={<Checkbox checked={linkConsent} onChange={(e) => setLinkConsent(e.target.checked)} />} label={`Vincular esta persona con mi cuenta de Acceso (${ws.user.username}). El servicio de identidad sabrá que esta npub es tuya.`} />
              <Button onClick={link} disabled={!linkConsent || busy}>
                Vincular
              </Button>
            </CardContent>
          )}
        </Card>
      )}

      {session && <LinkPersonas />}
      {session?.persona.managedKeyId && managedAvailable && <MigrationWizard key={session.persona.id} />}

      <Card component="form" onSubmit={create}>
        <CardContent>
          <Stack spacing={2}>
            <Typography variant="h6" component="h2">
              Nueva persona
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Cada persona es una identidad Nostr separada, con sus relays, su outbox y su configuración de privacidad.
            </Typography>
            <TextField id="persona-label" label="Nombre visible solo para ti" value={label} onChange={(e) => setLabel(e.target.value)} required />
            <TextField select id="persona-preset" label="Perfil" value={presetName} onChange={(e) => setPresetName(e.target.value as PresetName)}>
              {Object.keys(PRESETS).map((n) => (
                <MenuItem key={n} value={n}>
                  {n}
                </MenuItem>
              ))}
            </TextField>
            <RadioGroup value={mode} onChange={(e) => setMode(e.target.value as Mode)} aria-label="Modo de llave">
              <FormControlLabel value="create" control={<Radio />} label="Crear llave local nueva (la nsec no sale del navegador)" />
              <FormControlLabel value="import" control={<Radio />} label="Importar nsec / ncryptsec" />
              <FormControlLabel value="nip07" control={<Radio />} label="Extensión del navegador (NIP-07)" />
              <FormControlLabel value="nip46" control={<Radio />} label="Signer remoto (NIP-46)" />
              {managedAvailable && <FormControlLabel value="managed" control={<Radio />} label="Llave gestionada por la plataforma (custodial, opcional)" />}
            </RadioGroup>
            {mode === 'managed' && <ManagedOptIn accepted={managedConsent} onChange={setManagedConsent} />}
            {mode === 'import' && <TextField id="secret-input" label="nsec o ncryptsec" type="password" autoComplete="off" value={secret} onChange={(e) => setSecret(e.target.value)} required />}
            {mode === 'nip46' && (
              <RemoteSigner
                relays={relays.split('\n').map((r) => r.trim()).filter(Boolean)}
                bunker={secret}
                onBunkerChange={setSecret}
                mode={nip46Mode}
                onModeChange={setNip46Mode}
                onConnected={(signer, offer) => create(undefined, { signer, offer })}
              />
            )}
            {mode === 'import' && secret.startsWith('ncryptsec') && <TextField id="ncryptsec-pass" label="Contraseña del ncryptsec" type="password" autoComplete="off" value={ncPass} onChange={(e) => setNcPass(e.target.value)} />}
            <TextField id="relays" label="Relays (uno por línea; el mismo relay que Buzz Desktop/Mobile)" multiline minRows={2} value={relays} onChange={(e) => setRelays(e.target.value)} />
            {needsPassword && (
              <>
                <Alert severity="info">El perfil {presetName} exige que el almacén de este navegador tenga contraseña.</Alert>
                <TextField label="Nueva contraseña local" type="password" autoComplete="new-password" value={vaultPass} onChange={(e) => setVaultPass(e.target.value)} required slotProps={{ htmlInput: { minLength: 8 } }} />
              </>
            )}
            {error && <Alert severity="error">{error}</Alert>}
            {!(mode === 'nip46' && nip46Mode === 'nostrconnect') && (
              <Box>
                <Button type="submit" variant="contained" disabled={busy || (mode === 'managed' && !managedConsent)}>
                  Crear persona
                </Button>
              </Box>
            )}
          </Stack>
        </CardContent>
      </Card>

      <Card>
        <CardContent>
          <Stack spacing={2}>
            <Typography variant="h6" component="h2">
              Protección de este navegador
            </Typography>
            <Typography variant="body2">{deviceVault ? 'El almacén se abre sin contraseña (llave del dispositivo). Cualquiera con acceso a este perfil del navegador puede abrir tus llaves.' : 'El almacén se abre con tu contraseña local.'}</Typography>
            {deviceVault && <TextField label="Nueva contraseña local" type="password" autoComplete="new-password" value={vaultPass} onChange={(e) => setVaultPass(e.target.value)} />}
            <Box>
              <Button onClick={toggleProtection} disabled={busy || (deviceVault && vaultPass.length < 8)}>
                {deviceVault ? 'Proteger con contraseña' : 'Quitar la contraseña en este navegador'}
              </Button>
            </Box>
          </Stack>
        </CardContent>
      </Card>

      {personas.length > 1 && (
        <List aria-label="Personas">
          {personas.map((p) => (
            <ListItem key={p.id} secondaryAction={<Button onClick={() => void ws.selectPersona(p.id)}>Usar</Button>}>
              <ListItemText primary={`${p.label} · ${shortNpub(p.pubkey)}`} secondary={`${custodyLabel(p)} · perfil ${p.preset}`} />
            </ListItem>
          ))}
        </List>
      )}
    </Stack>
  );
}
