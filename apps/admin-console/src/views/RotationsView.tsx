import { useState } from 'react';
import { Alert, Button, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Typography } from '@mui/material';
import type { PolicyAdminApi } from '../api';
import { shortNpub } from '../signers';
import { errorText, fmtDate, useLoad } from '../ui';

export function RotationsView({ api }: { api: PolicyAdminApi }) {
  const { data, error, reload } = useLoad(api.pendingRotations, [api]);
  const [busy, setBusy] = useState<string | undefined>();
  const [actionError, setActionError] = useState<string | undefined>();

  const done = async (id: string) => {
    setBusy(id);
    setActionError(undefined);
    try {
      await api.markRotationDone(id);
      await reload();
    } catch (e) {
      setActionError(errorText(e));
    } finally {
      setBusy(undefined);
    }
  };

  return (
    <Stack spacing={2}>
      <Typography variant="h5" component="h2">
        Rotaciones pendientes
      </Typography>
      <Typography variant="body2" color="text.secondary">
        Cada fila es un grupo MLS del que salió un miembro o dispositivo. Un administrador del grupo debe publicar un commit que lo elimine; márcala como hecha solo después.
      </Typography>
      {error && <Alert severity="error">{error}</Alert>}
      {actionError && <Alert severity="error">{actionError}</Alert>}
      <TableContainer>
        <Table size="small" aria-label="Rotaciones pendientes">
          <TableHead>
            <TableRow>
              <TableCell>Fecha</TableCell>
              <TableCell>Grupo</TableCell>
              <TableCell>Miembro a quitar</TableCell>
              <TableCell>Motivo</TableCell>
              <TableCell>Acciones</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {data?.map((r) => (
              <TableRow key={r.id} data-rotation={r.id}>
                <TableCell>{fmtDate(r.at)}</TableCell>
                <TableCell>{r.resourceId}</TableCell>
                <TableCell title={r.removedPubkey}>{shortNpub(r.removedPubkey)}</TableCell>
                <TableCell>{r.reason}</TableCell>
                <TableCell>
                  <Button size="small" disabled={busy === r.id} onClick={() => void done(r.id)}>
                    Marcar como hecha
                  </Button>
                </TableCell>
              </TableRow>
            ))}
            {data?.length === 0 && (
              <TableRow>
                <TableCell colSpan={5}>No hay rotaciones pendientes.</TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>
    </Stack>
  );
}
