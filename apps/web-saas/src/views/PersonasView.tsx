import { useState, type FormEvent } from 'react';
import { Alert, Box, Button, Card, CardActions, CardContent, Checkbox, FormControlLabel, List, ListItem, ListItemText, MenuItem, Radio, RadioGroup, Stack, TextField, Typography } from '@mui/material';
import { managedConsentVersion, PRESETS, type PresetName } from '@sedecim/profiles';
import { fetchCloudBackup, linkAccesoLogin, saveCloudBackup } from '../lib/identity';
import { backupJson, createPersona, custodyFacts, custodyLabel, ensureArchiveKey, exportBackup, managedConnection, realCustody, shortNpub, type NewPersona } from '../lib/session';
import { deviceKeyAllowed, setProtection } from '../lib/vault';
import { useWorkspace } from '../lib/workspace';
import { LinkPersonas } from './LinkPersonas';
import { BlossomServers } from './BlossomServers';
import { ContinuityVault } from './ContinuityVault';
import { RemoteSigner } from './RemoteSigner';
import { CancelCustody, ClosedManagedKeys, ManagedActivity, ManagedOptIn, ManagedRecovery, MigrationWizard } from './ManagedCustody';
import { QrCode } from './QrCode';
import { openKeyBackup, parseKeyBackup, type ParsedKeyBackup } from '@sedecim/identity/key-backup';
import { npubEncode } from '@sedecim/nostr-core';
import type { ManagedKeyInfo, Nip46Signer, NostrConnectOffer } from '@sedecim/signer';

type Mode = 'create' | 'import' | 'backup' | 'nip07' | 'nip46' | 'managed' | 'recover';

export function PersonasView() {
  const ws = useWorkspace();
  const { book, personas, session, cfg } = ws;
  const [label, setLabel] = useState('Personal');
  const [presetName, setPresetName] = useState<PresetName>('convenience');
  const [mode, setMode] = useState<Mode>('create');
  const [secret, setSecret] = useState('');
  const [ncPass, setNcPass] = useState('');
  const [managedConsent, setManagedConsent] = useState(false);
  const [recoverKey, setRecoverKey] = useState<ManagedKeyInfo | undefined>();
  const [backupFile, setBackupFile] = useState<{ json: string; parsed: ParsedKeyBackup } | undefined>();
  const [showNpubQr, setShowNpubQr] = useState(false);
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
      // FR002-03: a backup from the offline generator (or this web) must decrypt to the npub it declares.
      if (mode === 'backup') {
        if (!backupFile) throw new Error('Elige un archivo de backup.');
        if (!backupFile.parsed.ncryptsec) throw new Error('Este backup solo trae la llave de archivo: abre la persona con su signer y restáurala en la tarjeta «Continuity Vault».');
        // VAULT-02: a v2 backup also brings the persona's archive key, so its vault archives open here.
        const { secretKey, archiveKey } = await openKeyBackup(backupFile.json, ncPass);
        const p = await createPersona(book, { kind: 'secret', secretKey, ...(archiveKey ? { archiveKey } : {}) }, { label: label.trim() || 'Persona', relays: relays.split('\n').map((s) => s.trim()).filter(Boolean), preset: presetName, deviceKey: book.vault.kind === 'device', continuityVault: !!cfg.continuityVault });
        setNcPass('');
        setBackupFile(undefined);
        await ws.reloadPersonas();
        await ws.selectPersona(p.id);
        await ws.publishDmRelays();
        ws.notify(`Persona "${p.label}" importada desde el backup (npub verificada)`, 'success');
        return;
      }
      // FR005-11: the managed key this Acceso user already has, reopened in this browser. Its DM relay list is the one
      // published from the other browser: not overwritten from here.
      if (mode === 'recover') {
        if (!recoverKey) throw new Error('Elige la llave gestionada que quieres recuperar.');
        const p = await createPersona(book, { kind: 'managed-existing', key: recoverKey }, { label: label.trim() || 'Persona', relays: relays.split('\n').map((s) => s.trim()).filter(Boolean), preset: presetName, deviceKey: book.vault.kind === 'device', continuityVault: !!cfg.continuityVault });
        setRecoverKey(undefined);
        await ws.reloadPersonas();
        await ws.selectPersona(p.id);
        ws.notify(`Persona "${p.label}" recuperada: este navegador firma con tu llave gestionada`, 'success');
        return;
      }
      const input: NewPersona = connected
        ? { kind: 'nip46-connected', signer: connected.signer, clientSecretKey: connected.offer.clientSecretKey }
        : mode === 'create'
          ? { kind: 'create' }
          : mode === 'import'
            ? { kind: 'import', secret, ncryptsecPass: ncPass }
            : mode === 'nip07'
              ? { kind: 'nip07' }
              : mode === 'managed'
                ? { kind: 'managed', conn: managedConnection(ws.managedEnv), consentVersion: managedConsentVersion(ws.cfg.managedTerms?.version) }
                : { kind: 'nip46', bunker: secret };
      if (mode === 'managed' && !managedConsent) throw new Error('La custodia gestionada requiere tu consentimiento explícito.');
      const p = await createPersona(book, input, { label: label.trim() || 'Persona', relays: relays.split('\n').map((s) => s.trim()).filter(Boolean), preset: presetName, deviceKey: book.vault.kind === 'device', continuityVault: !!cfg.continuityVault });
      setSecret('');
      setNcPass('');
      await ws.reloadPersonas();
      await ws.selectPersona(p.id);
      await ws.publishDmRelays();
      ws.notify(`Persona "${p.label}" creada; sus relays de DM (kind 10050) se publicaron`, 'success');
    });
  };

  // VAULT-02: every backup carries the archive key; personas made before the vault get theirs now.
  const withArchiveKey = async () => {
    const p = await ensureArchiveKey(book, session!.persona);
    if (p !== session!.persona) await ws.updatePersona(p);
    return p;
  };
  const download = () =>
    void run(async () => {
      const blob = await exportBackup(await withArchiveKey(), backupPass);
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `acceso-nostr-backup-${session!.persona.label}.json`;
      a.click();
      URL.revokeObjectURL(a.href);
      setBackupPass('');
    });

  // FR007-05: the persona now has an identity account: later sessions read its links from the service for the banner.
  const markIdentityAccount = async () => {
    const p = ws.session!.persona;
    if (p.identityAccount) return;
    const next = { ...p, identityAccount: true };
    await book.save(next);
    await ws.updatePersona(next);
  };

  // FR027-03: the same NIP-49 file, uploaded to the vault. Only ciphertext leaves the browser.
  const cloudVault = cfg.backupVault;
  const cloudAllowed = !!cloudVault && session?.persona.config?.cloudBackup !== 'off';
  const saveToCloud = () =>
    void run(async () => {
      const p = await withArchiveKey();
      await saveCloudBackup(session!.signer, cloudVault!, await backupJson(p, backupPass), realCustody(p.custody));
      await markIdentityAccount();
      setBackupPass('');
      ws.notify('Copia cifrada guardada en la nube. Sin la contraseña del backup no se puede descifrar: guárdala aparte.', 'success');
    });
  // In SaaS the Acceso login authorizes the download (new device); otherwise the open persona signs it.
  const restoreFromCloud = () =>
    void run(async () => {
      const auth = ws.user ? { token: async () => (await import('../lib/acceso')).accesoAccessToken() } : session ? { signer: session.signer } : undefined;
      if (!auth) throw new Error('Para restaurar desde la nube necesitas iniciar sesión con Acceso o abrir una persona de la misma cuenta.');
      const json = await fetchCloudBackup(cloudVault!, auth);
      setBackupFile({ json, parsed: parseKeyBackup(json) });
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
      await markIdentityAccount();
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
          {showNpubQr && (
            <CardContent>
              <QrCode text={`nostr:${npubEncode(session.pubkey)}`} label="Código QR de tu npub" />
            </CardContent>
          )}
          <CardActions sx={{ flexWrap: 'wrap', gap: 1 }}>
            <Button onClick={() => setShowNpubQr((v) => !v)}>{showNpubQr ? 'Ocultar QR' : 'Mostrar QR de mi npub'}</Button>
            <Button onClick={() => void run(async () => (await ws.publishDmRelays(), ws.notify('Relays de DM publicados (kind 10050)', 'success')))} disabled={busy}>
              Publicar mis relays de DM
            </Button>
            <TextField size="small" id="backup-pass" label="Contraseña del backup" type="password" autoComplete="new-password" value={backupPass} onChange={(e) => setBackupPass(e.target.value)} />
            <Button id="export-backup" onClick={download} disabled={busy || backupPass.length < 8}>
              {session.persona.custody === 'local' ? 'Descargar backup cifrado (NIP-49)' : 'Descargar la llave de archivo cifrada (NIP-49)'}
            </Button>
            {cloudAllowed && (
              <Button id="cloud-backup" onClick={saveToCloud} disabled={busy || backupPass.length < 8}>
                Guardar copia cifrada en la nube
              </Button>
            )}
          </CardActions>
          <CardContent sx={{ pt: 0 }}>
            <Typography variant="body2" sx={{ color: 'text.secondary' }} id="backup-facts">
              {session.persona.custody === 'local'
                ? 'El backup lleva tu llave y la llave de archivo del Continuity Vault, cifradas con la contraseña del backup.'
                : 'Tu llave vive en tu signer, así que este backup solo lleva la llave de archivo del Continuity Vault, cifrada con la contraseña del backup.'}
            </Typography>
          </CardContent>
          {cloudAllowed && (
            <CardContent sx={{ pt: 0 }}>
              <Typography variant="body2" sx={{ color: 'text.secondary' }} id="cloud-backup-facts">
                La copia en la nube se cifra en este navegador con la contraseña del backup (NIP-49). El servidor guarda el texto cifrado y tu npub, pero no recibe la contraseña: si la olvidas, el operador no puede recuperar la copia.
              </Typography>
            </CardContent>
          )}
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
      {session && <BlossomServers key={session.persona.id} />}
      {session && cfg.continuityVault && <ContinuityVault key={session.persona.id} url={cfg.continuityVault} />}
      {session?.persona.managedKeyId && session.persona.custody === 'managed' && managedAvailable && <ManagedActivity key={session.persona.id} />}
      {session?.persona.managedKeyId && managedAvailable && <MigrationWizard key={session.persona.id} />}
      {session?.persona.managedKeyId && session.persona.custody === 'managed' && managedAvailable && <CancelCustody key={`cancel-${session.persona.id}`} />}
      {managedAvailable && (
        <Card>
          <CardContent>
            <ClosedManagedKeys />
          </CardContent>
        </Card>
      )}

      <Card component="form" onSubmit={create}>
        <CardContent>
          <Stack spacing={2}>
            <Typography variant="h6" component="h2">
              Nueva persona
            </Typography>
            <Typography variant="body2" sx={{ color: 'text.secondary' }}>
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
              <FormControlLabel value="backup" control={<Radio />} label="Importar archivo de backup (generador offline o esta web)" />
              <FormControlLabel value="nip07" control={<Radio />} label="Extensión del navegador (NIP-07)" />
              <FormControlLabel value="nip46" control={<Radio />} label="Signer remoto (NIP-46)" />
              {managedAvailable && <FormControlLabel value="managed" control={<Radio />} label="Llave gestionada por la plataforma (custodial, opcional)" />}
              {managedAvailable && <FormControlLabel value="recover" control={<Radio />} label="Recuperar mi persona gestionada (con este login de Acceso)" />}
            </RadioGroup>
            {mode === 'backup' && (
              <Stack spacing={1}>
                <Button component="label" variant="outlined">
                  Elegir archivo .json
                  <input
                    id="backup-file"
                    hidden
                    type="file"
                    accept="application/json,.json"
                    onChange={async (e) => {
                      const f = e.target.files?.[0];
                      if (!f) return;
                      try {
                        const json = await f.text();
                        setBackupFile({ json, parsed: parseKeyBackup(json) });
                        setError('');
                      } catch (err) {
                        setBackupFile(undefined);
                        setError((err as Error).message);
                      }
                    }}
                  />
                </Button>
                {cloudVault && (ws.user || session) && (
                  <Button id="cloud-restore" variant="outlined" onClick={restoreFromCloud} disabled={busy}>
                    Restaurar desde la nube
                  </Button>
                )}
                {backupFile && (
                  <Alert severity="info" id="backup-npub">
                    Backup de {backupFile.parsed.npub} ({backupFile.parsed.format}
                    {backupFile.parsed.archiveKey ? ', con la llave de archivo del Continuity Vault' : ''}). Se comprobará al descifrarlo.
                  </Alert>
                )}
                <TextField id="import-backup-pass" label="Contraseña del archivo de backup" type="password" autoComplete="off" value={ncPass} onChange={(e) => setNcPass(e.target.value)} required />
              </Stack>
            )}
            {mode === 'managed' && <ManagedOptIn accepted={managedConsent} onChange={setManagedConsent} terms={ws.cfg.managedTerms} />}
            {mode === 'recover' && <ManagedRecovery selected={recoverKey} onSelect={setRecoverKey} />}
            {mode === 'import' && <TextField id="secret-input" label="nsec o ncryptsec" type="password" autoComplete="off" value={secret} onChange={(e) => setSecret(e.target.value)} required />}
            {mode === 'nip46' && (
              <RemoteSigner
                relays={relays.split('\n').map((r) => r.trim()).filter(Boolean)}
                bunker={secret}
                onBunkerChange={setSecret}
                mode={nip46Mode}
                onModeChange={setNip46Mode}
                onConnected={(signer, offer) => create(undefined, { signer, offer })}
                renderQr={(t) => <QrCode text={t} label="Código QR de conexión nostrconnect" />}
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
                <Button type="submit" variant="contained" disabled={busy || (mode === 'managed' && !managedConsent) || (mode === 'recover' && !recoverKey)}>
                  {mode === 'recover' ? 'Recuperar persona' : 'Crear persona'}
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
