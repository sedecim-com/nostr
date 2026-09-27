import { useState } from 'react';
import { Alert, Button, Chip, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TextField, Typography } from '@mui/material';
import type { Device, PolicyAdminApi, RotationRequired } from '../api';
import { parsePubkey, shortNpub } from '../signers';
import { ConfirmDialog, errorText, fmtDate, RotationsResult } from '../ui';
import { registerPasskey, webauthnAvailable } from '../webauthn';

const TRUST: Record<Device['trust'], { label: string; color: 'default' | 'info' | 'success' }> = {
  unverified: { label: 'Sin verificar', color: 'default' },
  registered: { label: 'Registrado', color: 'info' },
  attested: { label: 'Atestiguado (passkey)', color: 'success' },
};

export function TrustBadge({ trust }: { trust: Device['trust'] }) {
  const t = TRUST[trust] ?? { label: trust, color: 'default' as const };
  return <Chip size="small" label={t.label} color={t.color} variant={trust === 'unverified' ? 'outlined' : 'filled'} />;
}

export function DevicesView({ api }: { api: PolicyAdminApi }) {
  const [ownerInput, setOwnerInput] = useState('');
  const [owner, setOwner] = useState<string | undefined>();
  const [devices, setDevices] = useState<Device[] | undefined>();
  const [trust, setTrust] = useState<Device['trust']>('registered');
  const [error, setError] = useState<string | undefined>();
  const [notice, setNotice] = useState<string | undefined>();
  const [busy, setBusy] = useState(false);
  const [revoking, setRevoking] = useState<Device | undefined>();
  const [reason, setReason] = useState('');
  const [rotations, setRotations] = useState<RotationRequired[] | undefined>();

  const act = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError(undefined);
    try {
      await fn();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  const load = (o: string) => act(async () => setDevices(await api.listDevices(o)));

  const search = () =>
    act(async () => {
      const o = parsePubkey(ownerInput);
      setOwner(o);
      setNotice(undefined);
      setRotations(undefined);
      setDevices(await api.listDevices(o));
    });

  const register = () =>
    act(async () => {
      const d = await api.registerDevice(owner!, trust);
      setNotice(`Dispositivo ${d.id} registrado.`);
      await load(owner!);
    });

  const revoke = () =>
    act(async () => {
      const d = revoking!;
      setRevoking(undefined);
      setRotations(await api.revokeDevice(d.id, reason.trim() || undefined));
      setReason('');
      await load(owner!);
    });

  const passkey = (d: Device) =>
    act(async () => {
      setNotice(undefined);
      const updated = await registerPasskey(api, d.id);
      setNotice(`Passkey registrada para ${d.id}: nivel de confianza «${TRUST[updated.trust]?.label ?? updated.trust}».`);
      await load(owner!);
    });

  return (
    <Stack spacing={2}>
      <Typography variant="h5" component="h2">
        Dispositivos
      </Typography>
      <Typography variant="body2" color="text.secondary">
        Revocar un dispositivo invalida sus sesiones; si la persona pertenece a grupos MLS, cada grupo queda pendiente de rotación de clave.
      </Typography>
      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}>
        <TextField id="device-owner" label="Titular (npub o hex)" size="small" value={ownerInput} onChange={(e) => setOwnerInput(e.target.value)} sx={{ flexGrow: 1 }} />
        <Button variant="contained" disabled={busy || !ownerInput.trim()} onClick={() => void search()}>
          Buscar dispositivos
        </Button>
      </Stack>
      {error && (
        <Alert severity="error" id="devices-error">
          {error}
        </Alert>
      )}
      {notice && (
        <Alert severity="success" id="devices-notice">
          {notice}
        </Alert>
      )}
      {rotations && <RotationsResult rotations={rotations} id="device-revoke-result" />}
      {owner && devices && (
        <>
          <Typography variant="subtitle1" component="h3">
            Dispositivos de {shortNpub(owner)}
          </Typography>
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} sx={{ alignItems: { sm: 'center' } }}>
            <TextField id="device-trust" select label="Confianza inicial" size="small" value={trust} onChange={(e) => setTrust(e.target.value as Device['trust'])} slotProps={{ select: { native: true } }}>
              <option value="registered">Registrado</option>
              <option value="unverified">Sin verificar</option>
            </TextField>
            <Button variant="outlined" disabled={busy} onClick={() => void register()}>
              Registrar dispositivo
            </Button>
            {!webauthnAvailable() && (
              <Typography variant="caption" color="text.secondary">
                Este navegador no admite passkeys.
              </Typography>
            )}
          </Stack>
          <TableContainer>
            <Table size="small" aria-label="Dispositivos">
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
                  <TableRow key={d.id} data-device={d.id}>
                    <TableCell sx={{ fontFamily: 'monospace' }}>{d.id}</TableCell>
                    <TableCell>
                      <TrustBadge trust={d.trust} />
                    </TableCell>
                    <TableCell>{fmtDate(d.registeredAt)}</TableCell>
                    <TableCell>{d.revokedAt !== undefined ? <Chip size="small" color="error" label={`Revocado ${fmtDate(d.revokedAt)}`} /> : 'Activo'}</TableCell>
                    <TableCell>
                      <Button size="small" disabled={busy || d.revokedAt !== undefined || !webauthnAvailable()} onClick={() => void passkey(d)}>
                        Registrar passkey
                      </Button>
                      <Button size="small" color="error" disabled={busy || d.revokedAt !== undefined} onClick={() => setRevoking(d)}>
                        Revocar
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
                {devices.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={5}>Sin dispositivos.</TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>
        </>
      )}

      <ConfirmDialog id="revoke-device" open={!!revoking} title="Revocar dispositivo" confirm="Revocar dispositivo" danger busy={busy} onClose={() => setRevoking(undefined)} onConfirm={() => void revoke()}>
        <Stack spacing={2}>
          <Typography>
            El dispositivo <strong>{revoking?.id}</strong> dejará de poder abrir sesiones y las actuales se invalidan. Si su titular está en grupos MLS, hay que rotar la clave de cada grupo para que el dispositivo no descifre mensajes nuevos.
          </Typography>
          <TextField id="revoke-reason" label="Motivo (opcional)" size="small" value={reason} onChange={(e) => setReason(e.target.value)} />
        </Stack>
      </ConfirmDialog>
    </Stack>
  );
}
