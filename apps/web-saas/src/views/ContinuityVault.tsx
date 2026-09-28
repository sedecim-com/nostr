import { useState } from 'react';
import { Alert, Button, Card, CardContent, List, ListItem, ListItemText, Stack, TextField, Typography } from '@mui/material';
import { openArchiveKeyBackup } from '@sedecim/identity/key-backup';
import { CONTINUITY_VAULT_TEXTS } from '@sedecim/profiles';
import { pushLedger, vaultUsage, verifyVault } from '../lib/continuity';
import { ensureArchiveKey, setArchiveKey } from '../lib/session';
import { useWorkspace } from '../lib/workspace';

const kb = (bytes: number) => `${Math.ceil(bytes / 1024)} KB`;

/**
 * VAULT-02 and VAULT-07 (ADR 0011): the persona's Continuity Vault. What the operator can see is shown before
 * anything is uploaded; every archive is sealed in this browser with the persona's archive key, which travels
 * only inside the persona's backup file.
 */
export function ContinuityVault({ url }: { url: string }) {
  const ws = useWorkspace();
  const s = ws.session!;
  const off = s.persona.config.cloudBackup === 'off';
  const [status, setStatus] = useState('');
  const [file, setFile] = useState<string>();
  const [pass, setPass] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

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
  // Personas created before the vault get their archive key here, the first time it is needed.
  const persona = async () => {
    const p = await ensureArchiveKey(ws.book, s.persona);
    if (p !== s.persona) await ws.updatePersona(p);
    return p;
  };

  const push = () =>
    void run(async () => {
      const p = await persona();
      const r = await pushLedger(url, { ...s, persona: p });
      const u = await vaultUsage(url, p);
      setStatus(`Estado de entrega sellado en este navegador y guardado: ${r.operations} operaciones. Tu cuenta del vault tiene ${u.archives} archivos, ${kb(u.bytes)} de ${kb(u.limits.max_bytes)}.`);
      ws.notify('Estado de entrega guardado en el Continuity Vault', 'success');
    });
  const verify = () =>
    void run(async () => {
      const r = await verifyVault(url, await persona());
      setStatus(r.archives ? `${r.opened} de ${r.archives} archivos se abren con la llave de archivo de este navegador.` : 'El vault no tiene archivos de esta persona.');
    });
  const restoreKey = () =>
    void run(async () => {
      const key = await openArchiveKeyBackup(file!, pass, s.pubkey);
      try {
        await ws.updatePersona(await setArchiveKey(ws.book, s.persona, key));
      } finally {
        key.fill(0);
      }
      setPass('');
      setFile(undefined);
      setStatus('');
      ws.notify('Llave de archivo restaurada: los archivos del vault de esta persona se abren en este navegador', 'success');
    });

  return (
    <Card>
      <CardContent>
        <Stack spacing={2}>
          <Typography variant="h6" component="h2" id="continuity-vault-h">
            Continuity Vault
          </Typography>
          <List dense id="vault-facts">
            {[CONTINUITY_VAULT_TEXTS.what, CONTINUITY_VAULT_TEXTS.sealed, CONTINUITY_VAULT_TEXTS.metadata, CONTINUITY_VAULT_TEXTS.key].map((t) => (
              <ListItem key={t} disableGutters>
                <ListItemText primary={t} />
              </ListItem>
            ))}
          </List>
          {off ? (
            <Alert severity="info" id="vault-off">
              El backup en la nube está apagado en el panel de esta persona, así que no se usa el vault. Puedes cambiarlo en Soberanía y privacidad.
            </Alert>
          ) : (
            <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap', gap: 1 }}>
              <Button id="vault-push" variant="outlined" onClick={push} disabled={busy}>
                Guardar el estado de entrega en el vault
              </Button>
              <Button id="vault-verify" onClick={verify} disabled={busy}>
                Comprobar el vault
              </Button>
            </Stack>
          )}
          {status && (
            <Typography variant="body2" id="vault-status" role="status">
              {status}
            </Typography>
          )}
          <Typography variant="subtitle2" component="h3">
            Restaurar la llave de archivo
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Si abriste esta persona otra vez (por ejemplo, con su signer en un navegador nuevo), elige el backup que descargaste de ella para abrir sus archivos del vault.
          </Typography>
          <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap', gap: 1, alignItems: 'center' }}>
            <Button component="label" variant="outlined">
              {file ? 'Backup elegido' : 'Elegir backup .json'}
              <input id="archive-key-file" hidden type="file" accept="application/json,.json" onChange={async (e) => setFile(await e.target.files?.[0]?.text())} />
            </Button>
            <TextField size="small" id="archive-key-pass" label="Contraseña del backup" type="password" autoComplete="off" value={pass} onChange={(e) => setPass(e.target.value)} />
            <Button id="archive-key-restore" onClick={restoreKey} disabled={busy || !file || !pass}>
              Restaurar la llave de archivo
            </Button>
          </Stack>
          {error && <Alert severity="error">{error}</Alert>}
        </Stack>
      </CardContent>
    </Card>
  );
}
