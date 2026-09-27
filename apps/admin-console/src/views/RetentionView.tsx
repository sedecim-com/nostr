import { useState } from 'react';
import { Alert, AlertTitle, Button, Chip, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, Stack, Switch, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TextField, Typography } from '@mui/material';
import type { PolicyAdminApi, RetentionPolicy } from '../api';
import { errorText, useLoad } from '../ui';

type Editing = { resourceId: string; days: string; legalHold: boolean };

export function RetentionView({ api }: { api: PolicyAdminApi }) {
  const { data, error, reload } = useLoad(async () => {
    const [r, resources] = await Promise.all([api.retention(), api.listResources().catch(() => [])]);
    // Resources without a policy are listed too, so one can be set.
    const byId = new Map<string, RetentionPolicy>(r.policies.map((p) => [p.resourceId, p]));
    for (const res of resources) if (!byId.has(res.id)) byId.set(res.id, { resourceId: res.id, days: null, legalHold: false });
    return { notice: r.notice, rows: [...byId.values()].sort((a, b) => a.resourceId.localeCompare(b.resourceId)), configured: new Set(r.policies.map((p) => p.resourceId)) };
  }, [api]);
  const [editing, setEditing] = useState<Editing | undefined>();
  const [formError, setFormError] = useState<string | undefined>();
  const [busy, setBusy] = useState(false);

  const save = async () => {
    if (!editing) return;
    setBusy(true);
    setFormError(undefined);
    try {
      const raw = editing.days.trim();
      const days = raw === '' ? null : Number(raw);
      if (days !== null && (!Number.isInteger(days) || days < 1)) throw new Error('los días deben ser un entero ≥ 1, o vacío para no borrar automáticamente');
      await api.putRetention(editing.resourceId, { days, legalHold: editing.legalHold });
      setEditing(undefined);
      await reload();
    } catch (e) {
      setFormError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Stack spacing={2}>
      <Typography variant="h5" component="h2">
        Retención
      </Typography>
      {data?.notice && (
        <Alert severity="warning" variant="outlined" id="retention-notice" sx={{ fontSize: '1rem' }}>
          <AlertTitle>Alcance de la retención</AlertTitle>
          {data.notice}
        </Alert>
      )}
      {error && <Alert severity="error">{error}</Alert>}
      <TableContainer>
        <Table size="small" aria-label="Retención por recurso">
          <TableHead>
            <TableRow>
              <TableCell>Recurso</TableCell>
              <TableCell>Días</TableCell>
              <TableCell>Retención legal</TableCell>
              <TableCell>Acciones</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {data?.rows.map((p) => (
              <TableRow key={p.resourceId} data-retention={p.resourceId}>
                <TableCell>{p.resourceId}</TableCell>
                <TableCell>{p.days === null ? (data.configured.has(p.resourceId) ? 'Sin límite' : 'Sin política') : `${p.days} días`}</TableCell>
                <TableCell>{p.legalHold ? <Chip size="small" color="warning" label="Retención legal activa" /> : 'No'}</TableCell>
                <TableCell>
                  <Button size="small" onClick={() => (setFormError(undefined), setEditing({ resourceId: p.resourceId, days: p.days === null ? '' : String(p.days), legalHold: p.legalHold }))}>
                    Editar
                  </Button>
                </TableCell>
              </TableRow>
            ))}
            {data?.rows.length === 0 && (
              <TableRow>
                <TableCell colSpan={4}>No hay recursos ni políticas de retención.</TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>

      <Dialog open={!!editing} onClose={() => setEditing(undefined)} aria-labelledby="retention-dialog-title" fullWidth>
        <DialogTitle id="retention-dialog-title">Retención de {editing?.resourceId}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ pt: 1 }}>
            {formError && <Alert severity="error">{formError}</Alert>}
            {data?.notice && <Alert severity="warning">{data.notice}</Alert>}
            <TextField id="retention-days" label="Días de retención" type="number" value={editing?.days ?? ''} onChange={(e) => setEditing((x) => x && { ...x, days: e.target.value })} helperText="Vacío: sin borrado automático." slotProps={{ htmlInput: { min: 1 } }} />
            <FormControlLabel control={<Switch id="retention-hold" checked={editing?.legalHold ?? false} onChange={(e) => setEditing((x) => x && { ...x, legalHold: e.target.checked })} />} label="Retención legal (suspende el borrado)" />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditing(undefined)}>Cancelar</Button>
          <Button variant="contained" disabled={busy} onClick={() => void save()}>
            Guardar
          </Button>
        </DialogActions>
      </Dialog>
    </Stack>
  );
}
