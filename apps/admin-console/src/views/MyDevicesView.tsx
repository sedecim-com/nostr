import { useState } from 'react';
import { Alert, Button, Chip, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Typography } from '@mui/material';
import { ApiError, type Device, type PolicyAdminApi } from '../api';
import { fmtDate, useLoad } from '../ui';
import { openSessionWithPasskey, registerPasskey, webauthnAvailable } from '../webauthn';
import { TrustBadge } from './DevicesView';

/** The server's reason, or the browser's when the passkey ceremony was cancelled or timed out. */
function reason(e: unknown): string {
  if (e instanceof ApiError) return e.status ? `Error ${e.status}: ${e.message}` : e.message;
  if (e instanceof Error && e.name === 'NotAllowedError') return 'El navegador canceló la operación con la passkey, o se agotó el tiempo.';
  return (e as Error)?.message ?? String(e);
}

/**
 * FR023-11: the devices the organisation registered for the signed-in key. Their owner registers the passkey on the
 * device in use (the first one: any other goes through an admin, also after the device that held it is revoked) and
 * opens policy sessions with it, each one asking the authenticator for an assertion. The session token is not kept.
 */
export function MyDevicesView({ api, pubkey }: { api: PolicyAdminApi; pubkey: string }) {
  const { data: devices, error: loadError, reload } = useLoad(() => api.listDevices(pubkey), [api, pubkey]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | undefined>();
  const [notice, setNotice] = useState<string | undefined>();
  const [session, setSession] = useState<{ deviceId: string; at: number } | undefined>();
  // Revoked devices count: once a passkey was registered, the policy-engine keeps asking for one.
  const hasPasskey = !!devices?.some((d) => d.trust === 'attested');
  const canPasskey = webauthnAvailable();

  const act = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError(undefined);
    setNotice(undefined);
    try {
      await fn();
    } catch (e) {
      setError(reason(e));
    } finally {
      setBusy(false);
    }
  };

  const register = (d: Device) =>
    act(async () => {
      await registerPasskey(api, d.id);
      setNotice(`Passkey registrada en el dispositivo ${d.id}. Desde ahora, cada sesión te la pide.`);
      await reload();
    });

  const open = (d: Device) =>
    act(async () => {
      const s = await openSessionWithPasskey(api, d.id);
      setSession({ deviceId: s.deviceId, at: Date.now() });
    });

  return (
    <Stack spacing={2} id="my-devices">
      <Typography variant="h5" component="h2">
        Dispositivos a tu nombre
      </Typography>
      <Typography variant="body2" sx={{ color: 'text.secondary' }}>
        Tu organización registra los dispositivos con los que usas tu identidad. Registra una passkey en el dispositivo que estás usando: desde entonces, cada sesión que abras en el policy-engine pide que tu autenticador firme un desafío de un solo uso con esa passkey.
      </Typography>
      <Typography variant="body2" sx={{ color: 'text.secondary' }}>
        El policy-engine solo guarda la llave pública de la passkey. Si pierdes el dispositivo, pide a tu organización que lo revoque: sus sesiones dejan de valer.
      </Typography>
      {hasPasskey && (
        <Typography variant="body2" id="my-devices-admin-only">
          Ya registraste una passkey. Otra, para un dispositivo nuevo o para sustituirla (también si tu organización revoca el dispositivo que la tenía), la registra un administrador.
        </Typography>
      )}
      {!canPasskey && (
        <Typography variant="caption" sx={{ color: 'text.secondary' }}>
          Este navegador no admite passkeys.
        </Typography>
      )}
      {(error ?? loadError) && (
        <Alert severity="error" id="my-devices-error">
          {error ?? loadError}
        </Alert>
      )}
      {notice && (
        <Alert severity="success" id="my-devices-notice">
          {notice}
        </Alert>
      )}
      {session && (
        <Alert severity="success" id="my-session">
          Sesión abierta el {fmtDate(session.at)} en el dispositivo {session.deviceId} con su passkey. Deja de valer si tu organización revoca el dispositivo o registra otra passkey en él.
        </Alert>
      )}
      {devices && (
        <TableContainer>
          <Table size="small" aria-label="Dispositivos a tu nombre">
            <TableHead>
              <TableRow>
                <TableCell>ID</TableCell>
                <TableCell>Confianza</TableCell>
                <TableCell>Registrado</TableCell>
                <TableCell>Estado</TableCell>
                <TableCell>Acciones</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {devices.map((d) => (
                <TableRow key={d.id} data-own-device={d.id}>
                  <TableCell sx={{ fontFamily: 'monospace' }}>{d.id}</TableCell>
                  <TableCell>
                    <TrustBadge trust={d.trust} />
                  </TableCell>
                  <TableCell>{fmtDate(d.registeredAt)}</TableCell>
                  <TableCell>{d.revokedAt !== undefined ? <Chip size="small" color="error" label={`Revocado ${fmtDate(d.revokedAt)}`} /> : 'Activo'}</TableCell>
                  <TableCell>
                    {d.revokedAt === undefined && d.trust === 'attested' && (
                      <Button size="small" disabled={busy || !canPasskey} onClick={() => void open(d)}>
                        Abrir sesión con passkey
                      </Button>
                    )}
                    {d.revokedAt === undefined && d.trust !== 'attested' && !hasPasskey && (
                      <Button size="small" disabled={busy || !canPasskey} onClick={() => void register(d)}>
                        Registrar passkey
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
              {devices.length === 0 && (
                <TableRow>
                  <TableCell colSpan={5}>No tienes dispositivos registrados a tu nombre. Pide a tu organización que registre el tuyo.</TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </Stack>
  );
}
