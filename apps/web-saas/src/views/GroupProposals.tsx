import { useEffect, useState, type FormEvent } from 'react';
import { Alert, Button, Checkbox, Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle, FormControlLabel, List, ListItem, ListItemText, MenuItem, Stack, TextField, Typography } from '@mui/material';
import type { GroupHandle, GroupProposal, GroupProposalType, GroupSession } from '@sedecim/marmot-adapter';
import { SECURE_GROUP_TEXTS } from '@sedecim/profiles';
import { decideProposals, exclusive, parseMembers, pendingProposals, proposeChange } from '../lib/groups';
import { authorLabel } from '../lib/profiles';
import { useWorkspace } from '../lib/workspace';
import type { ReuseConfirm } from './ReuseConfirm';

interface Props {
  gs: GroupSession;
  group: GroupHandle;
  relays: string[];
  isAdmin: boolean;
  /** This browser cannot propose here (removed, or a restored copy that has not joined again). */
  readOnly: boolean;
  busy: boolean;
  act: (what: () => Promise<void>) => Promise<void>;
  /** Syncs the group and reads its state again after a change. */
  onChanged: () => Promise<void>;
  reuse: ReuseConfirm;
}

const TYPE_LABELS: Record<GroupProposalType, string> = {
  add: 'Alta',
  remove: 'Baja',
  update: 'Renovación de claves',
  'group-context-extensions': 'Cambio de la configuración del grupo',
  other: 'Otra propuesta',
};

/**
 * FR025-14: the proposals of the group (the sovereign client's `group propose`, `group proposals` and `group commit`).
 * Everyone sees the pending ones; an admin confirms the ones it marks, which discards the rest, or rejects them all with a
 * rotation of its keys. A member who is not an admin proposes adding or removing someone.
 */
export function GroupProposals({ gs, group, relays, isAdmin, readOnly, busy, act, onChanged, reuse }: Props) {
  const ws = useWorkspace();
  const s = ws.session!;
  const [proposals, setProposals] = useState<GroupProposal[]>([]);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [npub, setNpub] = useState('');
  const [removal, setRemoval] = useState('');
  const [confirmRemoval, setConfirmRemoval] = useState<string | undefined>();
  const count = group.pendingProposals ?? 0;
  const who = (pubkey: string) => (pubkey === s.pubkey ? 'ti' : authorLabel(s, pubkey));
  const removable = group.members.filter((m) => m !== s.pubkey && !group.admins.includes(m));

  // The pending proposals of this epoch, read again whenever their number or the epoch changes.
  useEffect(() => {
    if (!count) {
      setProposals([]);
      return;
    }
    let alive = true;
    void exclusive(gs, (g) => pendingProposals(g, group.groupId))
      .then((list) => {
        if (!alive) return;
        setProposals(list);
        setPicked(new Set(list.filter((p) => p.admissible).map((p) => p.ref)));
      })
      .catch(() => undefined);
    return () => {
      alive = false;
    };
  }, [gs, group.groupId, group.epoch, count]);

  const line = (p: GroupProposal) => {
    const kind = p.type === 'add' && p.target && group.members.includes(p.target) ? 'Dispositivo nuevo' : TYPE_LABELS[p.type];
    return `${kind}${p.target ? ` de ${p.target === s.pubkey ? 'ti' : authorLabel(s, p.target)}` : ''} · propuesta por ${p.proposer ? who(p.proposer) : 'alguien de fuera del grupo'}`;
  };

  const decide = (approve: string[]) =>
    act(async () => {
      const h = await exclusive(gs, (g) => decideProposals(g, group.groupId, approve));
      await onChanged();
      if (h.pending?.some((p) => (p.type === 'proposals' || p.type === 'rotate') && !p.failed)) ws.notify('Sin conexión con el relay de grupos: tu decisión quedó pendiente y se aplicará sola cuando vuelva la conexión.', 'info');
      else ws.notify(approve.length ? 'Propuestas confirmadas; las no marcadas se descartaron.' : 'Propuestas rechazadas: rotaste tus claves y quedaron descartadas.', 'success');
    });

  const proposeAdd = (e: FormEvent) => {
    e.preventDefault();
    void act(async () => {
      const pubkeys = parseMembers(npub, ws.personas.map((p) => p.pubkey), group.members);
      if (pubkeys.length === 0) throw new Error('Esa persona ya está en el grupo.');
      if (pubkeys.length > 1) throw new Error('Propón las altas de una en una.');
      // FR006-07: proposing someone another persona of this browser already wrote to or invited waits for an explicit
      // confirmation, as an invitation does. Recorded before the lookup of their key packages.
      const uses = [{ contact: pubkeys[0]! }];
      if (!(await reuse.confirm(uses))) return;
      await reuse.record(uses);
      await exclusive(gs, (g) => proposeChange(g, group.groupId, { add: pubkeys[0]! }, relays));
      setNpub('');
      await onChanged();
      ws.notify('Propuesta de alta enviada: un admin del grupo tiene que confirmarla.', 'info');
    });
  };

  const proposeRemoval = () => {
    const target = confirmRemoval!;
    setConfirmRemoval(undefined);
    void act(async () => {
      await exclusive(gs, (g) => proposeChange(g, group.groupId, { remove: target }, relays));
      setRemoval('');
      await onChanged();
      ws.notify('Propuesta de baja enviada: un admin del grupo tiene que confirmarla.', 'info');
    });
  };

  return (
    <>
      {proposals.length > 0 && (
        <Alert severity="warning" icon={false} id="group-proposals" aria-labelledby="group-proposals-h">
          <Stack spacing={1}>
            <Typography variant="subtitle2" component="h3" id="group-proposals-h">
              Propuestas pendientes ({proposals.length})
            </Typography>
            <Typography variant="body2">{SECURE_GROUP_TEXTS.proposals}</Typography>
            <List dense disablePadding aria-label="Propuestas pendientes">
              {proposals.map((p) => (
                <ListItem key={p.ref} disableGutters>
                  {isAdmin && p.admissible ? (
                    <FormControlLabel
                      control={
                        <Checkbox
                          checked={picked.has(p.ref)}
                          onChange={(e) => {
                            const next = new Set(picked);
                            if (e.target.checked) next.add(p.ref);
                            else next.delete(p.ref);
                            setPicked(next);
                          }}
                        />
                      }
                      label={line(p)}
                    />
                  ) : (
                    <ListItemText primary={line(p)} secondary={p.admissible ? undefined : 'No admisible: ningún commit la aplica.'} />
                  )}
                </ListItem>
              ))}
            </List>
            {isAdmin ? (
              <>
                <Typography variant="body2" id="group-proposals-decide">
                  {SECURE_GROUP_TEXTS.decide}
                </Typography>
                <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap' }} useFlexGap>
                  <Button id="group-proposals-confirm" size="small" variant="contained" disabled={busy || !proposals.some((p) => picked.has(p.ref))} onClick={() => void decide(proposals.filter((p) => picked.has(p.ref)).map((p) => p.ref))}>
                    Confirmar las marcadas
                  </Button>
                  <Button id="group-proposals-reject" size="small" color="inherit" disabled={busy} onClick={() => void decide([])}>
                    Rechazar todas
                  </Button>
                </Stack>
              </>
            ) : (
              <Typography variant="body2">Esperando a que un admin del grupo las confirme o las rechace.</Typography>
            )}
          </Stack>
        </Alert>
      )}
      {!isAdmin && !readOnly && (
        <Stack spacing={1} id="group-propose">
          <Typography variant="subtitle1" component="h3" id="group-propose-h">
            Proponer un cambio
          </Typography>
          <Typography variant="caption" sx={{ color: 'text.secondary' }}>
            Solo los admins cambian quién está en el grupo: tu propuesta les llega cifrada y deciden ellos.
          </Typography>
          <Stack component="form" id="group-propose-add" direction="row" spacing={1} sx={{ alignItems: 'flex-start', flexWrap: 'wrap' }} useFlexGap onSubmit={proposeAdd}>
            <TextField id="group-propose-npub" size="small" label="Proponer que entre (npub)" value={npub} onChange={(e) => setNpub(e.target.value)} required sx={{ minWidth: 280 }} />
            <Button type="submit" size="small" variant="outlined" disabled={busy || !npub.trim()}>
              Proponer alta
            </Button>
          </Stack>
          {removable.length > 0 && (
            <Stack direction="row" spacing={1} sx={{ alignItems: 'center', flexWrap: 'wrap' }} useFlexGap id="group-propose-remove">
              <TextField select size="small" id="group-propose-remove-member" label="Proponer que salga" value={removal} onChange={(e) => setRemoval(e.target.value)} sx={{ minWidth: 280 }}>
                {removable.map((m) => (
                  <MenuItem key={m} value={m}>
                    {authorLabel(s, m)}
                  </MenuItem>
                ))}
              </TextField>
              <Button size="small" variant="outlined" color="error" disabled={busy || !removal} onClick={() => setConfirmRemoval(removal)}>
                Proponer baja
              </Button>
            </Stack>
          )}
        </Stack>
      )}
      <Dialog open={!!confirmRemoval} onClose={() => setConfirmRemoval(undefined)} aria-labelledby="group-propose-remove-title">
        <DialogTitle id="group-propose-remove-title">¿Proponer que salga del grupo?</DialogTitle>
        <DialogContent>
          <DialogContentText>{confirmRemoval ? `${authorLabel(s, confirmRemoval)}. ${SECURE_GROUP_TEXTS.proposals}` : ''}</DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfirmRemoval(undefined)}>Cancelar</Button>
          <Button color="error" onClick={proposeRemoval}>
            Proponer baja
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
}
