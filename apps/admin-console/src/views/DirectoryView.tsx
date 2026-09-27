import { useState } from 'react';
import { Alert, Button, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TextField, Typography } from '@mui/material';
import type { DirectoryEntry, PolicyAdminApi } from '../api';
import { parsePubkey, shortNpub } from '../signers';
import { ConfirmDialog, errorText, useLoad } from '../ui';

export function DirectoryView({ api }: { api: PolicyAdminApi }) {
  const { data, error, reload } = useLoad(api.directory, [api]);
  const [pubkey, setPubkey] = useState('');
  const [title, setTitle] = useState('');
  const [unit, setUnit] = useState('');
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState<string | undefined>();
  const [deleting, setDeleting] = useState<DirectoryEntry | undefined>();

  const act = async (fn: () => Promise<void>) => {
    setBusy(true);
    setFormError(undefined);
    try {
      await fn();
      await reload();
    } catch (e) {
      setFormError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  const save = () =>
    act(async () => {
      const pk = parsePubkey(pubkey);
      await api.putDirectory(pk, { ...(title.trim() ? { title: title.trim() } : {}), ...(unit.trim() ? { unit: unit.trim() } : {}) });
      setPubkey('');
      setTitle('');
      setUnit('');
    });

  const remove = () =>
    act(async () => {
      const e = deleting!;
      setDeleting(undefined);
      await api.deleteDirectory(e.pubkey);
    });

  return (
    <Stack spacing={2}>
      <Typography variant="h5" component="h2">
        Directorio organizacional
      </Typography>
      <Alert severity="info" id="directory-notice">
        Este directorio relaciona cargos y unidades con npubs solo dentro de la organización: nunca se publica en relays, perfiles Nostr ni en el identity-service.
      </Alert>
      {error && <Alert severity="error">{error}</Alert>}
      {formError && <Alert severity="error">{formError}</Alert>}
      <Stack direction={{ xs: 'column', md: 'row' }} spacing={1}>
        <TextField id="dir-pubkey" label="npub o hex" size="small" value={pubkey} onChange={(e) => setPubkey(e.target.value)} sx={{ flexGrow: 2 }} />
        <TextField id="dir-title" label="Cargo" size="small" value={title} onChange={(e) => setTitle(e.target.value)} sx={{ flexGrow: 1 }} />
        <TextField id="dir-unit" label="Unidad" size="small" value={unit} onChange={(e) => setUnit(e.target.value)} sx={{ flexGrow: 1 }} />
        <Button variant="contained" disabled={busy || !pubkey.trim()} onClick={() => void save()}>
          Guardar entrada
        </Button>
      </Stack>
      <TableContainer>
        <Table size="small" aria-label="Directorio">
          <TableHead>
            <TableRow>
              <TableCell>npub</TableCell>
              <TableCell>Cargo</TableCell>
              <TableCell>Unidad</TableCell>
              <TableCell>Acciones</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {data?.map((e) => (
              <TableRow key={e.pubkey} data-directory={e.pubkey}>
                <TableCell title={e.pubkey}>{shortNpub(e.pubkey)}</TableCell>
                <TableCell>{e.title ?? '—'}</TableCell>
                <TableCell>{e.unit ?? '—'}</TableCell>
                <TableCell>
                  <Button size="small" onClick={() => (setPubkey(e.pubkey), setTitle(e.title ?? ''), setUnit(e.unit ?? ''))}>
                    Editar
                  </Button>
                  <Button size="small" color="error" onClick={() => setDeleting(e)}>
                    Borrar
                  </Button>
                </TableCell>
              </TableRow>
            ))}
            {data?.length === 0 && (
              <TableRow>
                <TableCell colSpan={4}>El directorio está vacío.</TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>
      <ConfirmDialog id="delete-directory" open={!!deleting} title="Borrar entrada del directorio" confirm="Borrar" danger busy={busy} onClose={() => setDeleting(undefined)} onConfirm={() => void remove()}>
        <Typography>Se borra el cargo y la unidad de {deleting ? shortNpub(deleting.pubkey) : ''}. La persona y sus permisos no cambian.</Typography>
      </ConfirmDialog>
    </Stack>
  );
}
