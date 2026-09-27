import { useCallback, useEffect, useState } from 'react';
import { Alert, Button, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TextField, Typography } from '@mui/material';
import type { AuditEntry, PolicyAdminApi } from '../api';
import { shortNpub } from '../signers';
import { errorText, fmtDate } from '../ui';

export const AUDIT_PAGE = 20;

/**
 * Server-side pagination (newest first, `before` = `id` of the last row shown); the actor/action
 * filters only narrow the page already loaded.
 */
export function AuditView({ api }: { api: PolicyAdminApi }) {
  // cursors[i] is the `before` of page i (undefined: newest page).
  const [cursors, setCursors] = useState<Array<number | undefined>>([undefined]);
  const [rows, setRows] = useState<AuditEntry[]>([]);
  const [error, setError] = useState<string | undefined>();
  const [loading, setLoading] = useState(false);
  const [actor, setActor] = useState('');
  const [action, setAction] = useState('');
  const page = cursors.length - 1;

  const load = useCallback(
    async (before: number | undefined) => {
      setLoading(true);
      try {
        setRows(await api.audit({ limit: AUDIT_PAGE, ...(before !== undefined ? { before } : {}) }));
        setError(undefined);
      } catch (e) {
        setError(errorText(e));
      } finally {
        setLoading(false);
      }
    },
    [api],
  );

  useEffect(() => {
    void load(cursors[cursors.length - 1]);
  }, [load, cursors]);

  const a = actor.trim().toLowerCase();
  const act = action.trim().toLowerCase();
  const visible = rows.filter((r) => (!a || r.actor.toLowerCase().includes(a) || shortNpub(r.actor).toLowerCase().includes(a)) && (!act || r.action.toLowerCase().includes(act)));
  const last = rows[rows.length - 1];

  return (
    <Stack spacing={2}>
      <Typography variant="h5" component="h2">
        Auditoría
      </Typography>
      <Typography variant="body2" color="text.secondary">
        Registro del policy-engine, del más reciente al más antiguo. Nunca incluye contenido de mensajes.
      </Typography>
      {error && <Alert severity="error">{error}</Alert>}
      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}>
        <TextField id="audit-actor" label="Filtrar por actor" size="small" value={actor} onChange={(e) => setActor(e.target.value)} />
        <TextField id="audit-action" label="Filtrar por acción" size="small" value={action} onChange={(e) => setAction(e.target.value)} />
      </Stack>
      <TableContainer>
        <Table size="small" aria-label="Auditoría">
          <TableHead>
            <TableRow>
              <TableCell>Fecha</TableCell>
              <TableCell>Actor</TableCell>
              <TableCell>Acción</TableCell>
              <TableCell>Objetivo</TableCell>
              <TableCell>Detalles</TableCell>
            </TableRow>
          </TableHead>
          <TableBody id="audit-rows">
            {visible.map((r) => (
              <TableRow key={r.id} data-action={r.action}>
                <TableCell>{fmtDate(r.at)}</TableCell>
                <TableCell title={r.actor}>{/^[0-9a-f]{64}$/.test(r.actor) ? shortNpub(r.actor) : r.actor}</TableCell>
                <TableCell>{r.action}</TableCell>
                <TableCell sx={{ wordBreak: 'break-all' }}>{/^[0-9a-f]{64}$/.test(r.target) ? shortNpub(r.target) : r.target}</TableCell>
                <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.8rem', wordBreak: 'break-all' }}>{r.details ? JSON.stringify(r.details) : ''}</TableCell>
              </TableRow>
            ))}
            {!loading && visible.length === 0 && (
              <TableRow>
                <TableCell colSpan={5}>Sin entradas.</TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>
      <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
        <Button disabled={loading || page === 0} onClick={() => setCursors((c) => c.slice(0, -1))}>
          Más recientes
        </Button>
        <Typography id="audit-page" aria-live="polite">
          Página {page + 1}
        </Typography>
        <Button disabled={loading || rows.length < AUDIT_PAGE || !last} onClick={() => last && setCursors((c) => [...c, last.id])}>
          Anteriores
        </Button>
      </Stack>
    </Stack>
  );
}
