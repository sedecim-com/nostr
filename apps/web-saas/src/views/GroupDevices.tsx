import { useState } from 'react';
import { Alert, Button, Checkbox, Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle, FormControlLabel, List, ListItem, ListItemText, MenuItem, Stack, TextField, Typography } from '@mui/material';
import type { GroupDevice, GroupHandle, GroupSession } from '@sedecim/marmot-adapter';
import type { NostrEvent } from '@sedecim/nostr-core';
import { SECURE_GROUP_TEXTS } from '@sedecim/profiles';
import { addGroupDevices, exclusive, missingDevices, removeGroupDevice } from '../lib/groups';
import { authorLabel } from '../lib/profiles';
import { useWorkspace } from '../lib/workspace';
import type { ReuseConfirm } from './ReuseConfirm';

interface Props {
  gs: GroupSession;
  group: GroupHandle;
  relays: string[];
  isAdmin: boolean;
  /** An admin's commits wait until the pending proposals are decided (they would carry some of them). */
  commitsBlocked: boolean;
  busy: boolean;
  act: (what: () => Promise<void>) => Promise<void>;
  /** Syncs the group and reads its state again after a change. */
  onChanged: () => Promise<void>;
  reuse: ReuseConfirm;
}

interface Adding {
  owner: string;
  candidates?: NostrEvent[];
  picked: Set<string>;
}

const slotOf = (kp: NostrEvent) => kp.tags.find((t) => t[0] === 'd')?.[1] ?? kp.id;

/**
 * FR025-14: the devices (MLS leaves) of a group, one per device of each member, with the sovereign client's add-device
 * and remove-device. An admin adds the new devices of a persona with a commit; any other member proposes them for an
 * admin to confirm. The user picks which key packages go in: one published by a lost device would show up too.
 */
export function GroupDevices({ gs, group, relays, isAdmin, commitsBlocked, busy, act, onChanged, reuse }: Props) {
  const ws = useWorkspace();
  const s = ws.session!;
  const devices = group.devices ?? [];
  const [adding, setAdding] = useState<Adding | undefined>();
  const [removing, setRemoving] = useState<GroupDevice | undefined>();
  const who = (pubkey: string) => (pubkey === s.pubkey ? `${authorLabel(s, pubkey)} (tú)` : authorLabel(s, pubkey));
  const deviceName = (d: GroupDevice) => (d.label ? `«${d.label}»` : 'sin nombre');

  const search = (owner: string) =>
    act(async () => {
      setAdding({ owner, picked: new Set() });
      if (owner !== s.pubkey) {
        // Same rules as an invitation: another persona of this browser is never added from this one (every member would
        // see both), and someone another persona already wrote to or invited waits for an explicit confirmation
        // (FR006-07). Recorded before the lookup: the relay sees this persona ask for their key packages.
        if (ws.personas.some((p) => p.pubkey === owner)) throw new Error('compartimentación: esa npub es otra de tus personas; no añadas sus dispositivos desde esta.');
        const uses = [{ contact: owner }];
        if (!(await reuse.confirm(uses))) return setAdding(undefined);
        await reuse.record(uses);
      }
      const candidates = await exclusive(gs, (g) => missingDevices(g, group.groupId, owner, relays));
      // Closed (or pointed at someone else) while it searched: the answer is not shown.
      setAdding((cur) => (cur?.owner === owner ? { owner, candidates, picked: new Set(candidates.map((k) => k.id)) } : cur));
    });

  const confirmAdd = () => {
    const { candidates = [], picked } = adding!;
    const keyPackages = candidates.filter((k) => picked.has(k.id));
    setAdding(undefined);
    void act(async () => {
      const r = await exclusive(gs, (g) => addGroupDevices(g, group.groupId, keyPackages));
      await onChanged();
      if (!r.committed) return ws.notify('Propuesta enviada: un admin del grupo tiene que confirmarla.', 'info');
      const waiting = r.group.pending?.some((p) => (p.type === 'add' || p.type === 'welcome') && !p.failed);
      if (waiting) ws.notify('Sin conexión con el relay de grupos: el alta de los dispositivos quedó pendiente y se enviará sola cuando vuelva la conexión.', 'info');
      else ws.notify(`${keyPackages.length === 1 ? 'Dispositivo añadido' : `${keyPackages.length} dispositivos añadidos`}: cada uno entra al aceptar su invitación en «Grupos seguros».`, 'success');
    });
  };

  const confirmRemove = () => {
    const d = removing!;
    setRemoving(undefined);
    void act(async () => {
      const h = await exclusive(gs, (g) => removeGroupDevice(g, group.groupId, d.leafIndex));
      await onChanged();
      if (h.pending?.some((p) => p.type === 'remove' && !p.failed)) ws.notify('Sin conexión con el relay de grupos: la baja del dispositivo quedó pendiente y se aplicará sola.', 'info');
      else ws.notify('Dispositivo quitado: la época avanzó y ya no puede leer los mensajes nuevos.', 'success');
    });
  };

  const onlyDevice = (d: GroupDevice) => devices.filter((x) => x.pubkey === d.pubkey).length === 1;

  return (
    <>
      <Typography variant="subtitle1" component="h3" id="group-devices-h">
        Dispositivos
      </Typography>
      <Typography variant="caption" id="group-devices-facts" sx={{ color: 'text.secondary' }}>
        {SECURE_GROUP_TEXTS.devices}
      </Typography>
      <List id="group-devices" dense aria-labelledby="group-devices-h">
        {devices.map((d) => (
          <ListItem
            key={`${d.leafIndex}-${d.pubkey}`}
            secondaryAction={
              isAdmin && !d.self && !commitsBlocked ? (
                <Button size="small" color="error" disabled={busy} aria-label={`Quitar el dispositivo ${deviceName(d)} de ${who(d.pubkey)}`} onClick={() => setRemoving(d)}>
                  Quitar
                </Button>
              ) : undefined
            }
          >
            <ListItemText primary={`${who(d.pubkey)}${d.self ? ' · este navegador' : ''}`} secondary={`${deviceName(d)} · ${d.deviceId ?? 'sin anunciar'}`} />
          </ListItem>
        ))}
      </List>
      <Button id="group-add-devices" size="small" variant="outlined" disabled={busy || (isAdmin && commitsBlocked)} sx={{ alignSelf: 'flex-start' }} onClick={() => void search(s.pubkey)}>
        {isAdmin ? 'Añadir dispositivos' : 'Proponer dispositivos'}
      </Button>

      <Dialog open={!!adding} onClose={() => setAdding(undefined)} aria-labelledby="group-add-devices-title">
        <DialogTitle id="group-add-devices-title">{isAdmin ? 'Añadir dispositivos al grupo' : 'Proponer dispositivos al grupo'}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ pt: 1 }}>
            <DialogContentText id="group-add-devices-facts">{SECURE_GROUP_TEXTS.addDevices}</DialogContentText>
            <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
              <TextField select size="small" id="group-add-devices-owner" label="Dispositivos de" value={adding?.owner ?? s.pubkey} onChange={(e) => setAdding({ owner: e.target.value, picked: new Set() })} sx={{ minWidth: 240 }}>
                {group.members.map((m) => (
                  <MenuItem key={m} value={m}>
                    {who(m)}
                  </MenuItem>
                ))}
              </TextField>
              <Button id="group-add-devices-search" size="small" disabled={busy || !adding} onClick={() => void search(adding!.owner)}>
                Buscar
              </Button>
            </Stack>
            {adding?.candidates?.length === 0 && (
              <Alert severity="info" id="group-add-devices-none">
                {adding.owner === s.pubkey
                  ? 'No hay key packages de otros dispositivos tuyos fuera del grupo: abre «Grupos seguros» en el otro dispositivo y publica su key package.'
                  : 'No hay key packages de dispositivos de esa persona fuera del grupo: tiene que publicarlos desde cada dispositivo.'}
              </Alert>
            )}
            {!!adding?.candidates?.length && (
              <List id="group-add-devices-candidates" dense aria-label="Dispositivos que se pueden añadir">
                {adding.candidates.map((k) => (
                  <ListItem key={k.id} disableGutters>
                    <FormControlLabel
                      control={
                        <Checkbox
                          checked={adding.picked.has(k.id)}
                          onChange={(e) => {
                            const picked = new Set(adding.picked);
                            if (e.target.checked) picked.add(k.id);
                            else picked.delete(k.id);
                            setAdding({ ...adding, picked });
                          }}
                        />
                      }
                      label={`Key package publicado el ${new Date(k.created_at * 1000).toLocaleString()} · dispositivo ${slotOf(k).slice(0, 8)}`}
                    />
                  </ListItem>
                ))}
              </List>
            )}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setAdding(undefined)}>Cancelar</Button>
          <Button id="group-add-devices-confirm" variant="contained" disabled={busy || !adding?.candidates?.some((k) => adding.picked.has(k.id))} onClick={confirmAdd}>
            {isAdmin ? 'Añadir los marcados' : 'Proponer los marcados'}
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={!!removing} onClose={() => setRemoving(undefined)} aria-labelledby="group-remove-device-title">
        <DialogTitle id="group-remove-device-title">¿Quitar este dispositivo?</DialogTitle>
        <DialogContent>
          <DialogContentText>
            {removing ? `${deviceName(removing)} de ${who(removing.pubkey)}. ${onlyDevice(removing) ? 'Es su único dispositivo en el grupo: sin él, esa persona sale del grupo. ' : ''}${SECURE_GROUP_TEXTS.removeDevice}` : ''}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRemoving(undefined)}>Cancelar</Button>
          <Button color="error" onClick={confirmRemove}>
            Quitar
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
}
