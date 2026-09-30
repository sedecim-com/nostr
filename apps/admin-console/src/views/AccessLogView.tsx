import { useCallback, useEffect, useState } from 'react';
import { Alert, Button, Chip, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TextField, Typography } from '@mui/material';
import type { AccessLogEntry, PolicyAdminApi } from '../api';
import { shortNpub } from '../signers';
import { errorText, fmtDate } from '../ui';

export const ACCESS_PAGE = 20;

const ACTION_LABEL: Record<string, string> = { read: 'Leer', publish: 'Publicar', admin: 'Administrar', invite: 'Invitar' };

/**
 * FR023-12: the access decisions of the policy-engine, apart from the audit (which records what admins do). Paged on the
 * server like the audit; the resource filter is applied by the server, so it reaches past the page loaded.
 */
export function AccessLogView({ api }: { api: PolicyAdminApi }) {
  // cursors[i] is the `before` of page i (undefined: newest page).
  const [cursors, setCursors] = useState<Array<number | undefined>>([undefined]);
  const [rows, setRows] = useState<AccessLogEntry[]>([]);
  const [days, setDays] = useState<number | undefined>();
  const [error, setError] = useState<string | undefined>();
  const [loading, setLoading] = useState(false);
  const [resourceInput, setResourceInput] = useState('');
  const [resource, setResource] = useState('');
  const page = cursors.length - 1;

  const load = useCallback(
    async (before: number | undefined) => {
      setLoading(true);
      try {
        const r = await api.accessLog({ limit: ACCESS_PAGE, ...(before !== undefined ? { before } : {}), ...(resource ? { resource } : {}) });
        setRows(r.access);
        setDays(r.retentionDays);
        setError(undefined);
      } catch (e) {
        setError(errorText(e));
      } finally {
        setLoading(false);
      }
    },
    [api, resource],
  );

  useEffect(() => {
    void load(cursors[cursors.length - 1]);
  }, [load, cursors]);

  const last = rows[rows.length - 1];
  const filter = (value: string) => {
    setResource(value.trim());
    setCursors([undefined]);
  };

  return (
    <Stack spacing={2}>
      <Typography variant="h5" component="h2">
        Accesos
      </Typography>
      <Typography variant="body2" color="text.secondary" id="access-scope">
        Decisiones de acceso del policy-engine: quién pidió leer o publicar en qué recurso y qué se le respondió, de la más
        reciente a la más antigua. Nunca incluye contenido de mensajes. Se guardan {days ?? '…'} días; las de un recurso con
        retención legal, mientras dure. Los cambios que hacen los administradores están en «Auditoría».
      </Typography>
      {error && <Alert severity="error">{error}</Alert>}
      <Stack
        component="form"
        direction={{ xs: 'column', sm: 'row' }}
        spacing={1}
        onSubmit={(e) => {
          e.preventDefault();
          filter(resourceInput);
        }}
      >
        <TextField id="access-resource" label="Recurso" size="small" value={resourceInput} onChange={(e) => setResourceInput(e.target.value)} />
        <Button type="submit" disabled={loading}>
          Filtrar
        </Button>
        {resource && (
          <Button onClick={() => (setResourceInput(''), filter(''))} disabled={loading}>
            Ver todos
          </Button>
        )}
      </Stack>
      <TableContainer>
        <Table size="small" aria-label="Accesos">
          <TableHead>
            <TableRow>
              <TableCell>Fecha</TableCell>
              <TableCell>Persona</TableCell>
              <TableCell>Dispositivo</TableCell>
              <TableCell>Recurso</TableCell>
              <TableCell>Acción</TableCell>
              <TableCell>Decisión</TableCell>
            </TableRow>
          </TableHead>
          <TableBody id="access-rows">
            {rows.map((r) => (
              <TableRow key={r.id} data-resource={r.resourceId} data-allow={String(r.allow)}>
                <TableCell>{fmtDate(r.at)}</TableCell>
                <TableCell title={r.pubkey}>{shortNpub(r.pubkey)}</TableCell>
                <TableCell sx={{ wordBreak: 'break-all' }}>{r.deviceId ?? '—'}</TableCell>
                <TableCell sx={{ wordBreak: 'break-all' }}>{r.resourceId}</TableCell>
                <TableCell>{ACTION_LABEL[r.action] ?? r.action}</TableCell>
                <TableCell>{r.allow ? <Chip size="small" color="success" variant="outlined" label="Permitido" /> : <Chip size="small" color="error" variant="outlined" label="Denegado" />}</TableCell>
              </TableRow>
            ))}
            {!loading && rows.length === 0 && (
              <TableRow>
                <TableCell colSpan={6}>Sin decisiones{resource ? ` sobre ${resource}` : ''}.</TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>
      <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
        <Button disabled={loading || page === 0} onClick={() => setCursors((c) => c.slice(0, -1))}>
          Más recientes
        </Button>
        <Typography id="access-page" aria-live="polite">
          Página {page + 1}
        </Typography>
        <Button disabled={loading || rows.length < ACCESS_PAGE || !last} onClick={() => last && setCursors((c) => [...c, last.id])}>
          Anteriores
        </Button>
      </Stack>
    </Stack>
  );
}
