import { useEffect, useRef, useState } from 'react';
import { Alert, Box, Button, FormControlLabel, List, ListItem, ListItemText, Radio, RadioGroup, Stack, TextField, Typography } from '@mui/material';
import { RelayPool } from '@sedecim/relay-pool';
import { createNostrConnect, describePermissions, LocalSigner, Nip46Signer, WEB_NIP46_PERMISSIONS, type NostrConnectOffer } from '@sedecim/signer';
import { raiseSignerAuthUrl } from '../lib/authUrl';

/** FR004-04: the permissions are listed before any connection is made. */
export function Nip46Permissions() {
  return (
    <Box>
      <Typography variant="subtitle2" component="h3">
        Permisos que se pedirán a tu signer
      </Typography>
      <List dense id="nip46-permissions" aria-label="Permisos solicitados">
        {describePermissions(WEB_NIP46_PERMISSIONS).map((p) => (
          <ListItem key={p.permission} disableGutters>
            <ListItemText primary={p.label} secondary={p.permission} />
          </ListItem>
        ))}
      </List>
      <Typography variant="body2" sx={{ color: 'text.secondary' }}>
        Nada más: si el signer lo permite, puedes aprobar solo estos métodos y kinds.
      </Typography>
    </Box>
  );
}

interface Props {
  relays: string[];
  bunker: string;
  onBunkerChange(v: string): void;
  mode: 'bunker' | 'nostrconnect';
  onModeChange(m: 'bunker' | 'nostrconnect'): void;
  /** Called once a signer answers the nostrconnect:// offer (FR004-03). */
  onConnected(signer: Nip46Signer, offer: NostrConnectOffer): void;
  renderQr?: (text: string) => React.ReactNode;
}

export function RemoteSigner({ relays, bunker, onBunkerChange, mode, onModeChange, onConnected, renderQr }: Props) {
  const [offer, setOffer] = useState<NostrConnectOffer | undefined>();
  const [preparing, setPreparing] = useState(false);
  const [error, setError] = useState('');
  const abort = useRef<AbortController | undefined>(undefined);
  useEffect(() => () => abort.current?.abort(), []);

  const start = () => {
    setError('');
    abort.current?.abort();
    const o = createNostrConnect({ relays, name: 'Acceso Nostr', url: location.origin });
    setOffer(undefined);
    setPreparing(true);
    abort.current = new AbortController();
    // NIP-42 on the signer relays authenticates the ephemeral client key, never the user's identity.
    Nip46Signer.fromNostrConnect(o, { pool: new RelayPool({ signer: new LocalSigner(o.clientSecretKey), authMode: 'on-demand' }), onAuthUrl: raiseSignerAuthUrl, timeoutMs: 300_000, signal: abort.current.signal, onReady: () => (setPreparing(false), setOffer(o)) })
      .then((signer) => onConnected(signer, o))
      .catch((e: Error) => {
        setPreparing(false);
        if (!/cancelled/.test(e.message)) setError(e.message);
      });
  };

  return (
    <Stack spacing={2}>
      <RadioGroup value={mode} onChange={(e) => onModeChange(e.target.value as 'bunker' | 'nostrconnect')} aria-label="Cómo conectar el signer remoto">
        <FormControlLabel value="nostrconnect" control={<Radio />} label="Mostrar un código nostrconnect:// para escanearlo en el signer" />
        <FormControlLabel value="bunker" control={<Radio />} label="Pegar una URL bunker:// del signer" />
      </RadioGroup>
      <Nip46Permissions />
      {mode === 'bunker' ? (
        <TextField id="secret-input" label="bunker://" type="password" autoComplete="off" value={bunker} onChange={(e) => onBunkerChange(e.target.value)} required />
      ) : (
        <Stack spacing={1}>
          <Button variant="outlined" onClick={start} disabled={relays.length === 0 || preparing}>
            {offer ? 'Generar otro código' : 'Generar código de conexión'}
          </Button>
          {preparing && <Alert severity="info">Conectando con los relays del signer…</Alert>}
          {offer && (
            <>
              {renderQr?.(offer.uri)}
              <TextField id="nostrconnect-uri" label="nostrconnect://" value={offer.uri} slotProps={{ htmlInput: { readOnly: true } }} multiline />
              <Button size="small" onClick={() => void navigator.clipboard?.writeText(offer.uri)}>
                Copiar
              </Button>
              <Alert severity="info">Esperando a que el signer acepte la conexión…</Alert>
            </>
          )}
          {error && <Alert severity="error">{error}</Alert>}
        </Stack>
      )}
    </Stack>
  );
}
