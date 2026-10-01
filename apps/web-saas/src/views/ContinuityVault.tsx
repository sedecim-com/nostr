import { useEffect, useState } from 'react';
import { Alert, Button, Card, CardContent, Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle, List, ListItem, ListItemText, MenuItem, Stack, TextField, Typography } from '@mui/material';
import { VAULT_EXPORT_FORMAT, type ArchiveRetention } from '@sedecim/continuity';
import { openArchiveKeyBackup } from '@sedecim/identity/key-backup';
import { CONTINUITY_VAULT_TEXTS, continuityPolicy, vaultExpirationNotice } from '@sedecim/profiles';
import { deleteVault, exportVault, pushVault, restoreVault, setVaultRetention, vaultUsage, verifyVault } from '../lib/continuity';
import { shortestExpiration } from '../lib/expiration';
import { ensureArchiveKey, setArchiveKey } from '../lib/session';
import { useWorkspace } from '../lib/workspace';

const kb = (bytes: number) => `${Math.ceil(bytes / 1024)} KB`;

/** VAULT-05: what the vault account keeps, in words. */
const retentionText = (r: ArchiveRetention) =>
  `La cuenta del vault conserva cada archivo ${r.effective_days ? `${r.effective_days} días desde que se guardó por última vez` : 'hasta que lo borres'}${r.max_days ? ` (el operador no guarda nada más de ${r.max_days} días)` : ''}.`;
const RETENTION_CHOICES = [30, 90, 365];

/**
 * VAULT-02, VAULT-03 and VAULT-07 (ADR 0011): the persona's Continuity Vault. What the operator can see is shown
 * before anything is uploaded; every archive is sealed in this browser with the persona's archive key, which travels
 * only inside the persona's backup file. A browser with nothing but that backup gets the history back from here.
 */
export function ContinuityVault({ url }: { url: string }) {
  const ws = useWorkspace();
  const s = ws.session!;
  const off = s.persona.config.cloudBackup === 'off';
  const policy = continuityPolicy(s.persona.config);
  const [status, setStatus] = useState('');
  const [file, setFile] = useState<string>();
  const [pass, setPass] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  // VAULT-05: the account's retention as the vault last said it (unknown until the vault is used: no request on open).
  const [retention, setRetention] = useState<ArchiveRetention>();
  const [confirmDelete, setConfirmDelete] = useState(false);
  // PANEL-06: once the retention is known, whether it outlasts the shortest expiration of the persona's messages.
  const [expirationNotice, setExpirationNotice] = useState<string>();
  useEffect(() => {
    if (!retention) return setExpirationNotice(undefined);
    let live = true;
    void shortestExpiration(ws.book.store, s.persona).then((o) => live && setExpirationNotice(vaultExpirationNotice(o, { cloudBackup: s.persona.config.cloudBackup, continuityVault: true, retentionDays: retention.effective_days })));
    return () => {
      live = false;
    };
  }, [retention, s.persona, ws.book]);

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
      const r = await pushVault(url, { ...s, persona: p }, ws.book.store);
      const u = await vaultUsage(url, p);
      if (u.retention) setRetention(u.retention);
      const invalid = r.events.invalid ? ` ${r.events.invalid} eventos con firma inválida no se guardaron.` : '';
      const forgotten = r.forgotten ? ` Se borraron del vault ${r.forgotten} copias de mensajes caducados o borrados.` : '';
      setStatus(
        `Historial sellado en este navegador y guardado: ${r.events.uploaded} eventos nuevos (${r.events.kept} ya estaban), ${r.groupMessages.uploaded} mensajes de grupo nuevos, ledger de ${r.operations} operaciones${r.snapshots.includes('mls') ? ' y estado de los grupos' : ''}.${invalid}${forgotten} Tu cuenta del vault tiene ${u.archives} archivos, ${kb(u.bytes)} de ${kb(u.limits.max_bytes)}.`,
      );
      ws.notify('Historial guardado en el Continuity Vault', 'success');
    });
  const restore = () =>
    void run(async () => {
      const r = await restoreVault(url, { ...s, persona: await persona() }, ws.book.store);
      const groups = r.mls === 'restored' ? ' Los grupos seguros vuelven como copia del otro dispositivo: entra otra vez en cada uno para escribir.' : r.mls === 'kept' ? ' El estado de los grupos de este navegador se mantiene.' : '';
      const skipped = r.skipped ? ` ${r.skipped} archivos no se abren con esta llave o no son de esta persona.` : '';
      const saved = r.savedAt ? ` La copia se guardó el ${new Date(r.savedAt).toLocaleString()}.` : '';
      const missing = r.missing ? ` Faltan ${r.missing} archivos que el vault tenía en esa copia: caducaron por la retención, se borraron o se perdieron.` : '';
      setStatus(
        `Restaurado desde el vault: ${r.events} eventos verificados, ${r.published} publicados otra vez en tus relays${r.rejected ? ` y ${r.rejected} rechazados` : ''}${r.othersWraps ? ` (${r.othersWraps} mensajes cifrados para otras personas siguen en el vault)` : ''}; ${r.groupMessages} mensajes de grupo; ledger: ${r.ledger} operaciones añadidas.${saved}${missing}${skipped}${groups}`,
      );
      ws.notify('Historial restaurado desde el Continuity Vault', 'success');
    });
  const verify = () =>
    void run(async () => {
      const r = await verifyVault(url, await persona());
      setStatus(r.archives ? `${r.opened} de ${r.archives} archivos se abren con la llave de archivo de este navegador.` : 'El vault no tiene archivos de esta persona.');
    });
  // VAULT-05: retention, portable export and deletion.
  const changeRetention = (choice: string) =>
    void run(async () => {
      const r = await setVaultRetention(url, await persona(), choice === 'max' ? null : Number(choice));
      setRetention(r);
      setStatus(retentionText(r));
    });
  const exportAll = () =>
    void run(async () => {
      const { export: data, skipped } = await exportVault(url, await persona());
      const a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
      a.download = `acceso-nostr-vault-${s.persona.label}.json`;
      a.click();
      URL.revokeObjectURL(a.href);
      setStatus(
        `Exportado (${VAULT_EXPORT_FORMAT}): ${data.events.length} eventos firmados, ${data.groupMessages.length} mensajes de grupo y ${data.ledger.length} operaciones del ledger.${skipped ? ` ${skipped} archivos no se abren con esta llave y no van en el archivo.` : ''} ${CONTINUITY_VAULT_TEXTS.export}`,
      );
    });
  const removeAll = () => {
    setConfirmDelete(false);
    void run(async () => {
      const deleted = await deleteVault(url, await persona());
      setRetention(undefined);
      setStatus(
        `Se borraron ${deleted} archivos y la cuenta del vault de esta persona.${policy !== 'off' ? ' La copia automática sigue encendida: los próximos envíos volverán a guardarse en el vault. Apágala en Soberanía y privacidad si no quieres más copias.' : ''}`,
      );
      ws.notify('Vault borrado', 'success');
    });
  };

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
            {[CONTINUITY_VAULT_TEXTS.what, CONTINUITY_VAULT_TEXTS.sealed, CONTINUITY_VAULT_TEXTS.metadata, CONTINUITY_VAULT_TEXTS.key, CONTINUITY_VAULT_TEXTS.groups, CONTINUITY_VAULT_TEXTS.retention].map((t) => (
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
              <Typography variant="body2" id="vault-policy" sx={{ flexBasis: '100%' }}>
                {policy === 'off'
                  ? 'Copia automática de cada envío: apagada. Puedes guardar el historial a mano o encenderla en Soberanía y privacidad.'
                  : policy === 'best-effort'
                    ? 'Copia automática de cada envío: best-effort. Cada envío sale aunque el vault no responda, y su copia se reintenta.'
                    : 'Copia automática de cada envío: required-for-resilient. Un envío no sale hacia los relays hasta que su copia está en el vault.'}
              </Typography>
              <Button id="vault-push" variant="outlined" onClick={push} disabled={busy}>
                Guardar el historial en el vault
              </Button>
              <Button id="vault-verify" onClick={verify} disabled={busy}>
                Comprobar el vault
              </Button>
              <Button id="vault-restore" onClick={restore} disabled={busy}>
                Restaurar desde el vault
              </Button>
              <Button id="vault-export" onClick={exportAll} disabled={busy}>
                Exportar el vault
              </Button>
              <Button id="vault-delete" color="error" onClick={() => setConfirmDelete(true)} disabled={busy}>
                Borrar todo el vault
              </Button>
              <TextField
                select
                size="small"
                id="vault-retention"
                label="Conservar los archivos"
                value={retention ? (retention.days === null ? 'max' : String(retention.days)) : ''}
                onChange={(e) => changeRetention(e.target.value)}
                disabled={busy}
                sx={{ minWidth: 240 }}
              >
                <MenuItem value="max">{retention?.max_days ? `El máximo del vault (${retention.max_days} días)` : 'Hasta que los borre'}</MenuItem>
                {[...new Set([...RETENTION_CHOICES, ...(retention?.days ? [retention.days] : [])])]
                  .filter((d) => d === retention?.days || !retention?.max_days || d < retention.max_days)
                  .sort((a, b) => a - b)
                  .map((d) => (
                    <MenuItem key={d} value={String(d)}>
                      {d === 365 ? '1 año' : `${d} días`}
                    </MenuItem>
                  ))}
              </TextField>
            </Stack>
          )}
          <Dialog open={confirmDelete} onClose={() => setConfirmDelete(false)} aria-labelledby="vault-delete-title">
            <DialogTitle id="vault-delete-title">¿Borrar todo el vault de esta persona?</DialogTitle>
            <DialogContent>
              <DialogContentText>Se borran todos sus archivos y su cuenta del vault. Sin ellos, una restauración con relays vacíos no recupera nada.</DialogContentText>
              <DialogContentText sx={{ mt: 1 }}>{CONTINUITY_VAULT_TEXTS.deletion}</DialogContentText>
            </DialogContent>
            <DialogActions>
              <Button onClick={() => setConfirmDelete(false)}>Cancelar</Button>
              <Button id="vault-delete-confirm" color="error" onClick={removeAll}>
                Borrar
              </Button>
            </DialogActions>
          </Dialog>
          {status && (
            <Typography variant="body2" id="vault-status" role="status">
              {status}
            </Typography>
          )}
          {expirationNotice && (
            <Alert severity="warning" id="vault-expiration">
              {expirationNotice}
            </Alert>
          )}
          <Typography variant="subtitle2" component="h3">
            Restaurar la llave de archivo
          </Typography>
          <Typography variant="body2" sx={{ color: 'text.secondary' }}>
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
