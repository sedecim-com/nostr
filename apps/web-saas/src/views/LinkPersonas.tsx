import { useState } from 'react';
import { Alert, Button, Card, CardContent, Checkbox, Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle, FormControlLabel, MenuItem, Radio, RadioGroup, Stack, TextField, Typography } from '@mui/material';
import { assertPublicLinkAllowed, createPublicLink } from '@sedecim/identity/public-link';
import { normalizePubkey } from '@sedecim/nostr-core';
import { LINK_CONSEQUENCES, linkPersonas, type LinkVisibility } from '../lib/identity';
import { openPersona, shortNpub } from '../lib/session';
import type { PersonaRecord } from '../lib/vault';
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
  // FR007-04: publishing the link as a signed Nostr event is a separate, default-off choice.
  const [publishNostr, setPublishNostr] = useState(false);
  const [ackPermanent, setAckPermanent] = useState(false);
  if (!ws.cfg.identityService || others.length === 0) return null;
  const targetPersona = ws.personas.find((p) => p.id === target);
  const pseudonymous = s.persona.config.identity === 'pseudonymous' || targetPersona?.config.identity === 'pseudonymous';
  const nostrRefusal = (() => {
    try {
      assertPublicLinkAllowed([s.persona.config, targetPersona?.config]);
      return undefined;
    } catch {
      return 'Un perfil soberano o Tor-only no publica vínculos entre personas.';
    }
  })();
  const wantsNostr = visibility === 'public' && publishNostr && !nostrRefusal;

  const link = async () => {
    setBusy(true);
    setError('');
    try {
      const other = (await ws.book.get(target))!;
      const toSession = await openPersona(ws.book, other, ws.managedEnv, { discoveryRelays: ws.cfg.discoveryRelays });
      try {
        const aud = visibility === 'selective' ? audience.split(/[\s,]+/).filter(Boolean).map(normalizePubkey) : [];
        await linkPersonas({ signer: s.signer, custody: CUSTODY[s.persona.custody] }, { signer: toSession.signer, custody: CUSTODY[other.custody] }, ws.cfg.identityService!, visibility, aud);
        // FR007-05: both personas now carry the link in their «Enviando como…» banner.
        const withLink = (p: PersonaRecord, peer: string): PersonaRecord => ({ ...p, identityAccount: true, links: [...(p.links ?? []).filter((l) => l.with !== peer), { with: peer, visibility }] });
        await ws.book.save(withLink(other, s.pubkey));
        const active = withLink(s.persona, other.pubkey);
        await ws.book.save(active);
        await ws.updatePersona(active);
        if (wantsNostr) {
          // Both personas sign (docs/public-link.md); anyone can verify it without trusting the identity service.
          const evt = await createPublicLink(s.signer, toSession.signer, { confirm: true, acknowledgePermanent: ackPermanent, profiles: [s.persona.config, other.config] });
          await s.engine.submit({ event: evt }, { relays: s.persona.relays, quorum: 1 });
        }
      } finally {
        toSession.close();
      }
      setConfirming(false);
      setAckPermanent(false);
      ws.notify(wantsNostr ? 'Personas vinculadas; el vínculo firmado por ambas se está publicando en tus relays' : `Personas vinculadas (${visibility})`, 'success');
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
          {visibility === 'public' && (
            <Stack spacing={1}>
              <FormControlLabel control={<Checkbox id="link-publish-nostr" checked={publishNostr && !nostrRefusal} disabled={!!nostrRefusal} onChange={(e) => setPublishNostr(e.target.checked)} />} label="Además, publicar el vínculo en Nostr como evento firmado por ambas personas (opcional)" />
              {nostrRefusal && <Typography variant="body2" color="text.secondary">{nostrRefusal}</Typography>}
            </Stack>
          )}
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
          {wantsNostr && (
            <Alert severity="error" sx={{ mt: 2 }} id="link-nostr-warning">
              El evento firmado se copia a relays que no controlas: cualquiera podrá guardarlo y demostrar que ambas claves son tuyas. Una solicitud de borrado posterior no lo retira de las copias existentes.
              <FormControlLabel sx={{ display: 'flex', mt: 1 }} control={<Checkbox id="link-ack-permanent" checked={ackPermanent} onChange={(e) => setAckPermanent(e.target.checked)} />} label="Entiendo que es público y permanente" />
            </Alert>
          )}
          {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfirming(false)} autoFocus>
            Cancelar
          </Button>
          <Button color="warning" onClick={() => void link()} disabled={busy || (wantsNostr && !ackPermanent)}>
            Entiendo las consecuencias, vincular
          </Button>
        </DialogActions>
      </Dialog>
    </Card>
  );
}
