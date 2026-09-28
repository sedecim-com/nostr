import { useEffect, useState } from 'react';
import { Alert, Button, Chip, Stack, Table, TableBody, TableCell, TableHead, TableRow, Typography } from '@mui/material';
import type { OutboxRecord } from '@sedecim/delivery-engine';
import { normalizeRelayUrl, relayDegradation, type RelayDegradation, type RelayHealth } from '@sedecim/relay-pool';
import { useWorkspace } from '../lib/workspace';
import { cappedQuorumNotice } from '../lib/outbox';

/** Same threshold as the RelayAckLatencyP95High alert (docs/slo.md, "Latencia"). */
export const DEGRADED_P95_MS = 2000;

interface RelayRow {
  url: string;
  health?: RelayHealth;
  verdict?: RelayDegradation;
}

/**
 * NFR004-02 "sin ocultarla": relay health as this client measures it (status, P95 of publish→OK over the
 * last acks). A degraded relay is shown as such, with its P95, instead of being retried silently.
 */
function RelayHealthPanel() {
  const s = useWorkspace().session!;
  const [rows, setRows] = useState<RelayRow[]>([]);
  useEffect(() => {
    const load = () => {
      const byUrl = new Map(s.pool.health().map((h) => [h.url, h]));
      const urls = [...new Set([...s.persona.relays.map((u) => { try { return normalizeRelayUrl(u); } catch { return u; } }), ...byUrl.keys()])];
      setRows(urls.map((url) => {
        const health = byUrl.get(url);
        return { url, ...(health ? { health, verdict: relayDegradation(health, { p95Ms: DEGRADED_P95_MS }) } : {}) };
      }));
    };
    load();
    const t = setInterval(load, 5000);
    const off = s.engine.onChange(load);
    return () => {
      clearInterval(t);
      off();
    };
  }, [s]);
  const degraded = rows.filter((r) => r.verdict?.degraded);
  return (
    <Stack spacing={1}>
      <Typography variant="h6" component="h2" id="relay-health-h">
        Salud de relays
      </Typography>
      {degraded.length > 0 && (
        <Alert severity="warning" id="relay-degraded-alert">
          {degraded.length === 1 ? 'Un relay está degradado' : `${degraded.length} relays están degradados`}: tus mensajes pueden tardar más en replicarse o quedar pendientes.
        </Alert>
      )}
      <Table size="small" aria-labelledby="relay-health-h">
        <TableHead>
          <TableRow>
            <TableCell>Relay</TableCell>
            <TableCell>Estado</TableCell>
            <TableCell>P95 de confirmación</TableCell>
            <TableCell>Detalle</TableCell>
          </TableRow>
        </TableHead>
        <TableBody id="relay-health-rows">
          {rows.map((r) => (
            <TableRow key={r.url} data-relay={r.url}>
              <TableCell>{new URL(r.url).host}</TableCell>
              <TableCell>{!r.health ? <Chip size="small" variant="outlined" label="sin uso aún" /> : r.verdict?.degraded ? <Chip size="small" color="error" className="relay-degraded" label={r.verdict.p95AckLatencyMs !== undefined ? `degradado · P95 ${Math.round(r.verdict.p95AckLatencyMs)} ms` : 'degradado'} /> : <Chip size="small" variant="outlined" label={r.health.status === 'connected' ? 'OK' : r.health.status} />}</TableCell>
              <TableCell>{r.health?.p95AckLatencyMs !== undefined ? `${Math.round(r.health.p95AckLatencyMs)} ms (${r.health.ackSamples} muestras)` : '—'}</TableCell>
              <TableCell>{r.verdict?.reasons.join('; ') || r.health?.lastError || ''}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Stack>
  );
}

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
      <RelayHealthPanel />
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
              <TableCell>{[r.blockedReason ?? r.failureReason ?? (r.meta?.dmRelaySource === 'fallback' || r.meta?.dmRelaySource === 'nip65-read' ? 'Destinatario sin relays de DM' : ''), cappedQuorumNotice(r)].filter(Boolean).join(' ')}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Stack>
  );
}
