import { useEffect, useState } from 'react';
import { Button, Stack, Table, TableBody, TableCell, TableHead, TableRow, Typography } from '@mui/material';
import type { OutboxRecord } from '@sedecim/delivery-engine';
import { useWorkspace } from '../lib/workspace';

/** Delivery state per operation and relay: accepted ≠ received ≠ read (spec §11). */
export function OutboxView() {
  const s = useWorkspace().session!;
  const [rows, setRows] = useState<OutboxRecord[]>([]);
  useEffect(() => {
    const load = () => void s.engine.list().then((r) => setRows(r.reverse().slice(0, 50)));
    load();
    return s.engine.onChange(load);
  }, [s]);
  return (
    <Stack spacing={2}>
      <Stack direction="row" justifyContent="space-between" alignItems="center">
        <Typography variant="h6" component="h2" id="outbox-h">
          Estado de entrega
        </Typography>
        <Button id="outbox-resume" onClick={() => void s.engine.resume()}>
          Reintentar pendientes
        </Button>
      </Stack>
      <Table size="small" aria-labelledby="outbox-h">
        <TableHead>
          <TableRow>
            <TableCell>Operación</TableCell>
            <TableCell>Estado</TableCell>
            <TableCell>Relays</TableCell>
            <TableCell>Motivo</TableCell>
          </TableRow>
        </TableHead>
        <TableBody id="outbox-rows">
          {rows.map((r) => (
            <TableRow key={r.opId}>
              <TableCell>{r.opId.slice(0, 8)}</TableCell>
              <TableCell>{r.state}</TableCell>
              <TableCell sx={{ whiteSpace: 'pre-line' }}>{Object.values(r.relayStatus).map((x) => `${new URL(x.relay).host}: ${x.acceptedAt ? 'OK' : x.permanent ? 'rechazado' : 'pendiente'} (${x.attemptCount})`).join('\n')}</TableCell>
              <TableCell>{r.blockedReason ?? r.failureReason ?? (r.meta?.dmRelaySource === 'fallback' || r.meta?.dmRelaySource === 'nip65-read' ? 'Destinatario sin relays de DM' : '')}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Stack>
  );
}
