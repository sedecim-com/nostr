import { useState } from 'react';
import { Alert, Button, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TextField, Typography } from '@mui/material';
import type { IdentityLookupApi, VisibleLink } from '../api';
import { parsePubkey, shortNpub } from '../signers';
import { errorText } from '../ui';

const VIS: Record<VisibleLink['visibility'], string> = { private: 'Privado', selective: 'Selectivo (te incluye)', public: 'Público' };

/** identity-service exposes no admin listing by design: only links the person made visible. */
export function IdentityView({ api }: { api: IdentityLookupApi }) {
  const [input, setInput] = useState('');
  const [links, setLinks] = useState<VisibleLink[] | undefined>();
  const [error, setError] = useState<string | undefined>();
  const [busy, setBusy] = useState(false);

  const lookup = async () => {
    setBusy(true);
    setError(undefined);
    try {
      setLinks(await api.visibleLinks(parsePubkey(input)));
    } catch (e) {
      setLinks(undefined);
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Stack spacing={2}>
      <Typography variant="h5" component="h2">
        Vínculos de identidad
      </Typography>
      <Alert severity="info">
        El identity-service no ofrece listados de cuentas a los administradores. Aquí solo ves los vínculos entre personas que su titular hizo públicos, o selectivos con tu npub en la audiencia.
      </Alert>
      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}>
        <TextField id="identity-pubkey" label="npub o hex" size="small" value={input} onChange={(e) => setInput(e.target.value)} sx={{ flexGrow: 1 }} />
        <Button variant="contained" disabled={busy || !input.trim()} onClick={() => void lookup()}>
          Consultar vínculos
        </Button>
      </Stack>
      {error && <Alert severity="error">{error}</Alert>}
      {links && (
        <TableContainer>
          <Table size="small" aria-label="Vínculos visibles">
            <TableHead>
              <TableRow>
                <TableCell>Desde</TableCell>
                <TableCell>Hacia</TableCell>
                <TableCell>Visibilidad</TableCell>
              </TableRow>
            </TableHead>
            <TableBody id="identity-links">
              {links.map((l, i) => (
                <TableRow key={i}>
                  <TableCell title={l.from}>{l.from ? shortNpub(l.from) : '—'}</TableCell>
                  <TableCell title={l.to}>{l.to ? shortNpub(l.to) : '—'}</TableCell>
                  <TableCell>{VIS[l.visibility] ?? l.visibility}</TableCell>
                </TableRow>
              ))}
              {links.length === 0 && (
                <TableRow>
                  <TableCell colSpan={3}>No hay vínculos visibles para esta clave.</TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </Stack>
  );
}
