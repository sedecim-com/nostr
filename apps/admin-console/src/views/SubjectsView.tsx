import { useState } from 'react';
import { Alert, Box, Button, Chip, Dialog, DialogActions, DialogContent, DialogTitle, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TextField, Typography } from '@mui/material';
import type { PolicyAdminApi, RotationRequired, Subject } from '../api';
import { parsePubkey, shortNpub } from '../signers';
import { formatAttributes, parseAttributes, splitList } from '../forms';
import { ConfirmDialog, errorText, RotationsResult, useLoad } from '../ui';

type Editing = { isNew: boolean; pubkey: string; roles: string; attributes: string; suspended?: boolean };

export function SubjectsView({ api }: { api: PolicyAdminApi }) {
  const { data, error, reload } = useLoad(api.listSubjects, [api]);
  const [editing, setEditing] = useState<Editing | undefined>();
  const [formError, setFormError] = useState<string | undefined>();
  const [revoking, setRevoking] = useState<Subject | undefined>();
  const [reactivating, setReactivating] = useState<Subject | undefined>();
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<RotationRequired[] | undefined>();
  const [actionError, setActionError] = useState<string | undefined>();

  const save = async () => {
    if (!editing) return;
    setBusy(true);
    setFormError(undefined);
    try {
      const pubkey = parsePubkey(editing.pubkey);
      await api.putSubject(pubkey, { roles: splitList(editing.roles), attributes: parseAttributes(editing.attributes) });
      setEditing(undefined);
      await reload();
    } catch (e) {
      setFormError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  const revoke = async () => {
    if (!revoking) return;
    setBusy(true);
    setActionError(undefined);
    try {
      setResult(await api.revokeSubject(revoking.pubkey));
      setRevoking(undefined);
      await reload();
    } catch (e) {
      setActionError(errorText(e));
      setRevoking(undefined);
    } finally {
      setBusy(false);
    }
  };

  const reactivate = async () => {
    if (!reactivating) return;
    setBusy(true);
    setActionError(undefined);
    try {
      await api.reactivateSubject(reactivating.pubkey);
      setReactivating(undefined);
      setResult(undefined);
      await reload();
    } catch (e) {
      setActionError(errorText(e));
      setReactivating(undefined);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Stack spacing={2}>
      <Stack direction="row" sx={{ alignItems: 'center', justifyContent: 'space-between' }}>
        <Typography variant="h5" component="h2">
          Personas
        </Typography>
        <Button variant="contained" onClick={() => (setFormError(undefined), setEditing({ isNew: true, pubkey: '', roles: '', attributes: '' }))}>
          Nueva persona
        </Button>
      </Stack>
      <Typography variant="body2" sx={{ color: 'text.secondary' }}>
        Sujetos del modo institucional: npubs con roles y atributos que la organización decide asignar.
      </Typography>
      {error && <Alert severity="error">{error}</Alert>}
      {actionError && <Alert severity="error">{actionError}</Alert>}
      {result && <RotationsResult rotations={result} id="subject-revoke-result" />}
      <TableContainer>
        <Table size="small" aria-label="Personas">
          <TableHead>
            <TableRow>
              <TableCell>npub</TableCell>
              <TableCell>Roles</TableCell>
              <TableCell>Atributos</TableCell>
              <TableCell>Estado</TableCell>
              <TableCell>Acciones</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {data?.map((s) => (
              <TableRow key={s.pubkey} data-pubkey={s.pubkey}>
                <TableCell title={s.pubkey}>{shortNpub(s.pubkey)}</TableCell>
                <TableCell>
                  {s.roles.map((r) => (
                    <Chip key={r} label={r} size="small" sx={{ mr: 0.5 }} />
                  ))}
                </TableCell>
                <TableCell sx={{ whiteSpace: 'pre-line' }}>{formatAttributes(s.attributes)}</TableCell>
                <TableCell>{s.suspended ? <Chip label="Revocada" color="error" size="small" /> : <Chip label="Activa" color="success" size="small" variant="outlined" />}</TableCell>
                <TableCell>
                  <Button size="small" onClick={() => (setFormError(undefined), setEditing({ isNew: false, pubkey: s.pubkey, roles: s.roles.join(', '), attributes: formatAttributes(s.attributes), suspended: s.suspended }))}>
                    Editar
                  </Button>
                  {s.suspended ? (
                    <Button size="small" onClick={() => setReactivating(s)}>
                      Reactivar
                    </Button>
                  ) : (
                    <Button size="small" color="error" onClick={() => setRevoking(s)}>
                      Revocar
                    </Button>
                  )}
                </TableCell>
              </TableRow>
            ))}
            {data?.length === 0 && (
              <TableRow>
                <TableCell colSpan={5}>No hay personas registradas.</TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>

      <Dialog open={!!editing} onClose={() => setEditing(undefined)} aria-labelledby="subject-dialog-title" fullWidth>
        <DialogTitle id="subject-dialog-title">{editing?.isNew ? 'Nueva persona' : 'Editar persona'}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ pt: 1 }}>
            {formError && <Alert severity="error">{formError}</Alert>}
            {editing?.suspended && <Alert severity="info">Esta persona está revocada. Editar sus roles o atributos no la reactiva: para eso usa «Reactivar».</Alert>}
            <TextField id="subject-pubkey" label="npub o clave hex" value={editing?.pubkey ?? ''} disabled={!editing?.isNew} onChange={(e) => setEditing((x) => x && { ...x, pubkey: e.target.value })} />
            <TextField id="subject-roles" label="Roles" helperText="Separados por comas, p. ej. staff, legal" value={editing?.roles ?? ''} onChange={(e) => setEditing((x) => x && { ...x, roles: e.target.value })} />
            <TextField id="subject-attributes" label="Atributos" multiline minRows={3} helperText="Uno por línea: clave=valor; varios valores con |, p. ej. clearance=secret" value={editing?.attributes ?? ''} onChange={(e) => setEditing((x) => x && { ...x, attributes: e.target.value })} />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditing(undefined)}>Cancelar</Button>
          <Button variant="contained" disabled={busy} onClick={() => void save()}>
            Guardar
          </Button>
        </DialogActions>
      </Dialog>

      <ConfirmDialog id="revoke-subject" open={!!revoking} title="Revocar persona" confirm="Revocar persona" danger busy={busy} onClose={() => setRevoking(undefined)} onConfirm={() => void revoke()}>
        <Box sx={{ display: 'grid', gap: 1 }}>
          <Typography>
            Vas a revocar a <strong>{revoking ? shortNpub(revoking.pubkey) : ''}</strong>. La persona queda suspendida, se revocan todos sus dispositivos (sus sesiones dejan de valer) y sale de la lista de miembros de cada recurso.
          </Typography>
          <Typography>
            En cada grupo MLS del que era miembro hay que rotar la clave: un commit que la elimine del grupo. Hasta que se haga, sus dispositivos podrían seguir descifrando mensajes nuevos de ese grupo. Lo que ya descargó sigue en sus dispositivos y no se puede retirar.
          </Typography>
          <Typography>Las rotaciones quedan en «Rotaciones pendientes».</Typography>
        </Box>
      </ConfirmDialog>

      <ConfirmDialog id="reactivate-subject" open={!!reactivating} title="Reactivar persona" confirm="Reactivar persona" busy={busy} onClose={() => setReactivating(undefined)} onConfirm={() => void reactivate()}>
        <Box sx={{ display: 'grid', gap: 1 }}>
          <Typography>
            Vas a reactivar a <strong>{reactivating ? shortNpub(reactivating.pubkey) : ''}</strong>. La acción queda en la auditoría.
          </Typography>
          <Typography>
            Sus dispositivos siguen revocados y no recupera la membresía de los recursos: registra un dispositivo nuevo y vuelve a añadirla a los grupos que correspondan. Hasta entonces ningún relay la deja entrar.
          </Typography>
        </Box>
      </ConfirmDialog>
    </Stack>
  );
}
