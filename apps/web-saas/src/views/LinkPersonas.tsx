import { useState } from 'react';
import { Alert, Button, Card, CardContent, Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle, FormControlLabel, MenuItem, Radio, RadioGroup, Stack, TextField, Typography } from '@mui/material';
import { normalizePubkey } from '@sedecim/nostr-core';
import { LINK_CONSEQUENCES, linkPersonas, type LinkVisibility } from '../lib/identity';
import { openPersona, shortNpub } from '../lib/session';
import { useWorkspace } from '../lib/workspace';

const CUSTODY = { local: 'local', nip07: 'external', nip46: 'external', managed: 'managed' } as const;

/** FR007-03: linking personas explains the de-anonymization consequences before anything is sent. */
export function LinkPersonas() {
  const ws = useWorkspace();
  const s = ws.session!;
  const others = ws.personas.filter((p) => p.id !== s.persona.id);
  const [target, setTarget] = useState(others[0]?.id ?? '');
  const [visibility, setVisibility] = useState<LinkVisibility>('private');
  const [audience, setAudience] = useState('');
  const [confirming, setConfirming] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  if (!ws.cfg.identityService || others.length === 0) return null;
  const pseudonymous = s.persona.config.identity === 'pseudonymous' || ws.personas.find((p) => p.id === target)?.config.identity === 'pseudonymous';

  const link = async () => {
    setBusy(true);
    setError('');
    try {
      const other = (await ws.book.get(target))!;
      const toSession = await openPersona(ws.book, other);
      try {
        const aud = visibility === 'selective' ? audience.split(/[\s,]+/).filter(Boolean).map(normalizePubkey) : [];
        await linkPersonas({ signer: s.signer, custody: CUSTODY[s.persona.custody] }, { signer: toSession.signer, custody: CUSTODY[other.custody] }, ws.cfg.identityService!, visibility, aud);
      } finally {
        toSession.close();
      }
      setConfirming(false);
      ws.notify(`Personas vinculadas (${visibility})`, 'success');
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card>
      <CardContent>
        <Stack spacing={2}>
          <Typography variant="h6" component="h2">
            Vincular con otra persona
          </Typography>
          <TextField select id="link-target" label="Persona a vincular" value={target} onChange={(e) => setTarget(e.target.value)}>
            {others.map((p) => (
              <MenuItem key={p.id} value={p.id}>
                {p.label} · {shortNpub(p.pubkey)}
              </MenuItem>
            ))}
          </TextField>
          <RadioGroup value={visibility} onChange={(e) => setVisibility(e.target.value as LinkVisibility)} aria-label="Visibilidad del vínculo">
            <FormControlLabel value="private" control={<Radio />} label="Privado (solo el servicio de identidad)" />
            <FormControlLabel value="selective" control={<Radio />} label="Selectivo (solo las personas que elijas)" />
            <FormControlLabel value="public" control={<Radio />} label="Público" />
          </RadioGroup>
          {visibility === 'selective' && <TextField id="link-audience" label="npubs que podrán verlo (separados por coma)" value={audience} onChange={(e) => setAudience(e.target.value)} />}
          <Button variant="outlined" onClick={() => setConfirming(true)} disabled={!target}>
            Vincular…
          </Button>
          {error && <Alert severity="error">{error}</Alert>}
        </Stack>
      </CardContent>
      <Dialog open={confirming} onClose={() => setConfirming(false)} aria-labelledby="link-dialog-title">
        <DialogTitle id="link-dialog-title">Antes de vincular estas identidades</DialogTitle>
        <DialogContent>
          <DialogContentText>{LINK_CONSEQUENCES[visibility]}</DialogContentText>
          {pseudonymous && <Alert severity="warning" sx={{ mt: 2 }}>Una de estas personas usa un perfil pseudónimo: vincularla contradice ese perfil.</Alert>}
          {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfirming(false)} autoFocus>
            Cancelar
          </Button>
          <Button color="warning" onClick={() => void link()} disabled={busy}>
            Entiendo las consecuencias, vincular
          </Button>
        </DialogActions>
      </Dialog>
    </Card>
  );
}
