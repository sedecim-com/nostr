import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react';
import { Alert, Button, Card, CardContent, Chip, CircularProgress, Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle, List, ListItem, ListItemButton, ListItemText, Stack, TextField, Typography } from '@mui/material';
import type { GroupHandle, GroupSession, PendingGroupOperation } from '@sedecim/marmot-adapter';
import { fileDigest } from '@sedecim/identity/usage';
import { npubEncode } from '@sedecim/nostr-core';
import {
  discardPendingGroupOperation,
  exclusive,
  forgetRemovedGroup,
  groupDeviceLabel,
  groupErrorMessage,
  GroupHistory,
  groupMediaUploader,
  groupRelays,
  inviteMembers,
  membership,
  openGroupSession,
  parseMembers,
  prepareGroupFile,
  rejoinRestoredGroup,
  retryPendingGroupOperations,
  saveGroupDeviceLabel,
  sendGroupFile,
  type StoredGroupMessage,
} from '../lib/groups';
import { shortNpub } from '../lib/session';
import { authorLabel, lookupGroupMembers } from '../lib/profiles';
import { AuthorAvatar, AvatarsToggle, useProfiles } from './Profile';
import { PUBLIC_PROFILE_TEXTS, SECURE_GROUP_TEXTS } from '@sedecim/profiles';
import { sendBlockedReason, useWorkspace } from '../lib/workspace';
import { GroupAttachment } from './GroupAttachment';
import { GroupDevices } from './GroupDevices';
import { GroupProposals } from './GroupProposals';
import { MaturityChip } from './MaturityChip';
import { useReuseConfirm } from './ReuseConfirm';

const POLL_MS = 4000;

type Confirm = { kind: 'remove'; member: string } | { kind: 'leave' } | { kind: 'rotate' };

/** FR025-12: what a pending group operation is, in the words of the view. */
const PENDING_LABELS: Record<PendingGroupOperation['type'], string> = {
  message: 'Mensaje',
  add: 'Invitación (commit)',
  remove: 'Expulsión (commit)',
  rotate: 'Rotación de claves (commit)',
  proposals: 'Propuestas aceptadas (commit)',
  welcome: 'Invitación cifrada al nuevo miembro',
};
/** FR025-14: a removal of some devices of a persona is not an expulsion. */
const pendingLabel = (p: PendingGroupOperation) => (p.type === 'remove' && p.leaves ? 'Baja de dispositivo (commit)' : PENDING_LABELS[p.type]);

const CONFIRM_TITLES: Record<Confirm['kind'], string> = { remove: '¿Expulsar a este miembro?', leave: '¿Salir del grupo?', rotate: '¿Rotar tus claves en este grupo?' };
const CONFIRM_ACTIONS: Record<Confirm['kind'], string> = { remove: 'Expulsar', leave: 'Salir', rotate: 'Rotar' };

/**
 * High-security groups (FR025-07): Marmot over MLS (RFC 9420) through the adapter's GroupSession. MLS state
 * and the decrypted history are sealed in the vault per persona; traffic goes to the secure relay.
 */
export function GroupsView() {
  const ws = useWorkspace();
  const s = ws.session!;
  const blocked = sendBlockedReason(ws.config);
  const { relays, source } = groupRelays(ws.cfg, s);
  const [gs, setGs] = useState<GroupSession | undefined>();
  const [openError, setOpenError] = useState('');
  const [groups, setGroups] = useState<GroupHandle[]>([]);
  const [openId, setOpenId] = useState('');
  const [messages, setMessages] = useState<StoredGroupMessage[]>([]);
  // FR025-14: this browser can be removed with its whole persona or alone (another device keeps the persona in).
  const [standing, setStanding] = useState<ReturnType<typeof membership>>('member');
  const removed = standing !== 'member';
  const [kp, setKp] = useState<'unknown' | 'published' | 'missing'>('unknown');
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [invitees, setInvitees] = useState('');
  const [missingKp, setMissingKp] = useState<string[]>([]);
  const [text, setText] = useState('');
  const [file, setFile] = useState<File | undefined>();
  const [deviceLabel, setDeviceLabel] = useState('');
  const [labelDraft, setLabelDraft] = useState('');
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState<Confirm | undefined>();
  // FR006-04: members' profiles only from this persona's cache, or looked up when the user asks (it tells the relays
  // who is in the group); their avatars as the panel allows.
  useProfiles(s);
  const [avatars, setAvatars] = useState(!!ws.config?.remotePreviews);
  const history = useRef(new GroupHistory(ws.book.store, s.persona.id));
  const reuse = useReuseConfirm();

  const current = groups.find((g) => g.groupId === openId);
  const isAdmin = !!current?.admins.includes(s.pubkey);
  // FR025-14: while proposals wait, no message goes out, and an admin's other commits would carry some of them.
  const proposalsPending = (current?.pendingProposals ?? 0) > 0;
  const commitsBlocked = isAdmin && proposalsPending;
  const pendingMessages = new Set((current?.pending ?? []).flatMap((p) => (p.type === 'message' && p.rumorId ? [p.rumorId] : [])));

  const reloadGroups = useCallback(async (session: GroupSession) => setGroups(await exclusive(session, (g) => g.groups())), []);

  // Open (or reuse) the persona's MLS session; never for a configuration the browser cannot honour.
  useEffect(() => {
    if (blocked) return;
    let alive = true;
    history.current = new GroupHistory(ws.book.store, s.persona.id);
    setGs(undefined);
    setGroups([]);
    setOpenId('');
    setOpenError('');
    void (async () => {
      try {
        const session = await openGroupSession(s, ws.book.store, ws.cfg);
        if (!alive) return;
        setGs(session);
        const label = await groupDeviceLabel(ws.book.store, s.persona.id);
        if (alive) {
          setDeviceLabel(label);
          setLabelDraft(label);
        }
        await reloadGroups(session);
        // FR025-12: what an earlier visit left without a relay goes out now, in the background.
        void exclusive(session, (g) => retryPendingGroupOperations(g))
          .then(async () => {
            if (alive) await reloadGroups(session);
          })
          .catch(() => undefined);
        const own = await exclusive(session, (g) => g.findKeyPackage(s.pubkey, relays));
        if (alive) setKp(own ? 'published' : 'missing');
      } catch (e) {
        if (alive) setOpenError((e as Error).message);
      }
    })();
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [s.pool, blocked]);

  const act = async (what: () => Promise<void>) => {
    setBusy(true);
    try {
      await what();
    } catch (e) {
      ws.notify(groupErrorMessage(e), 'error');
    } finally {
      setBusy(false);
    }
  };

  /** Fetch new kind 445 events of the open group and refresh epoch/members; the session keeps the decrypted chat. */
  const sync = useCallback(
    async (session: GroupSession, groupId: string) => {
      await exclusive(session, (g) => g.sync(groupId));
      const log = await history.current.list(groupId);
      let handle: GroupHandle | undefined;
      try {
        handle = await exclusive(session, (g) => g.group(groupId));
      } catch {
        handle = undefined;
      }
      setMessages(log);
      setStanding(membership(handle, s.pubkey));
      if (handle) setGroups((gs0) => gs0.map((g) => (g.groupId === groupId ? handle : g)));
    },
    [s.pubkey],
  );

  // FR025-12: when the browser is back online, the pending group operations go out without waiting for a poll.
  useEffect(() => {
    if (!gs) return;
    const online = () =>
      void exclusive(gs, (g) => retryPendingGroupOperations(g))
        .then(() => reloadGroups(gs))
        .catch(() => undefined);
    window.addEventListener('online', online);
    return () => window.removeEventListener('online', online);
  }, [gs, reloadGroups]);

  /** The open group's state and log as stored here, without asking the relay (it may be unreachable). */
  const refresh = async (session: GroupSession, groupId: string) => {
    const handle = await exclusive(session, (g) => g.group(groupId));
    setGroups((gs0) => gs0.map((g) => (g.groupId === groupId ? handle : g)));
    setMessages(await history.current.list(groupId));
    return handle;
  };

  // While a group is open, poll the secure relay for new group messages.
  useEffect(() => {
    if (!gs || !openId) return;
    let alive = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = async () => {
      try {
        await sync(gs, openId);
      } catch {
        /* relay unreachable: retried on the next tick */
      }
      if (alive) timer = setTimeout(() => void tick(), POLL_MS);
    };
    void history.current.list(openId).then((log) => alive && setMessages(log));
    void tick();
    return () => {
      alive = false;
      if (timer) clearTimeout(timer);
    };
  }, [gs, openId, sync]);

  const publishKeyPackage = () =>
    act(async () => {
      await exclusive(gs!, (g) => g.publishKeyPackage(relays));
      setKp('published');
      ws.notify('Key package publicado: ya pueden invitarte a grupos seguros.', 'success');
    });

  const acceptInvites = () =>
    act(async () => {
      const joined = await exclusive(gs!, (g) => g.acceptInvites());
      await reloadGroups(gs!);
      ws.notify(joined.length ? `Te uniste a ${joined.map((g) => `"${g.name}"`).join(', ')}.` : 'No hay invitaciones pendientes.', joined.length ? 'success' : 'info');
      if (joined[0]) setOpenId(joined[0].groupId);
    });

  const create = (e: FormEvent) => {
    e.preventDefault();
    void act(async () => {
      // FR024-05: the organisation's rotation worker is an admin of every group, so that it can remove revoked devices.
      const worker = ws.cfg.rotationWorker;
      const g = await exclusive(gs!, (x) => x.createGroup({ name: name.trim(), description: description.trim(), relays, ...(worker ? { admins: [s.pubkey, worker] } : {}) }));
      setName('');
      setDescription('');
      let workerError: string | undefined;
      if (worker) {
        try {
          const keyPackage = await exclusive(gs!, (x) => x.findKeyPackage(worker, relays));
          if (!keyPackage) throw new Error('no tiene key package en el relay de grupos');
          await exclusive(gs!, (x) => x.invite(g.groupId, keyPackage));
        } catch (err) {
          workerError = (err as Error).message;
        }
      }
      await reloadGroups(gs!);
      setOpenId(g.groupId);
      if (workerError) ws.notify(`Grupo "${g.name}" creado, pero sin el worker de rotaciones de tu organización (${workerError}): no podrá sacar del grupo un dispositivo revocado. Invítalo con «Invitar»: ${npubEncode(worker!)}.`, 'warning');
      else ws.notify(`Grupo "${g.name}" creado${worker ? ' con el worker de rotaciones de tu organización como admin' : ''}.`, 'success');
    });
  };

  const invite = (e: FormEvent) => {
    e.preventDefault();
    void act(async () => {
      // Compartmentalisation (same rule as the sovereign client): never tie two of your own identities.
      const pubkeys = parseMembers(invitees, ws.personas.map((p) => p.pubkey), current?.members ?? []);
      // FR006-07: someone another persona of this browser already wrote to or invited waits for an explicit
      // confirmation. Recorded before the key package lookups: the relay already sees this persona ask for them.
      const uses = pubkeys.map((contact) => ({ contact }));
      if (uses.length && !(await reuse.confirm(uses))) return;
      await reuse.record(uses);
      // FR025-14: every current device of each invitee, in one commit (the sovereign client's invite).
      const { added, missing } = await exclusive(gs!, (g) => inviteMembers(g, openId, pubkeys, relays));
      setMissingKp(missing);
      setInvitees(missing.map((p) => npubEncode(p)).join('\n'));
      await sync(gs!, openId);
      const waiting = (await refresh(gs!, openId)).pending?.some((p) => (p.type === 'add' || p.type === 'welcome') && !p.failed);
      if (added.length && waiting) ws.notify('Sin conexión con el relay de grupos: la invitación quedó pendiente y se enviará sola cuando vuelva la conexión.', 'info');
      else if (added.length) ws.notify(added.length === 1 ? 'Miembro añadido: cada uno de sus dispositivos recibirá la invitación cifrada.' : `${added.length} miembros añadidos.`, 'success');
    });
  };

  const send = (e: FormEvent) => {
    e.preventDefault();
    void act(async () => {
      const content = text.trim();
      if (!content && !file) return;
      if (file) return sendFile(file, content);
      // Catch up first: a message must be encrypted for the current epoch.
      await sync(gs!, openId);
      // The session keeps the sent message under its rumor id (an MLS sender cannot decrypt its own ciphertext).
      const sent = await exclusive(gs!, (g) => g.send(openId, content));
      setText('');
      await refresh(gs!, openId);
      // FR025-12: no relay took it; it is kept and goes out on its own (next poll, back online, next visit).
      if (sent.pending) ws.notify('Sin conexión con el relay de grupos: el mensaje quedó pendiente y se enviará solo cuando vuelva la conexión.', 'info');
    });
  };

  /**
   * FR025-14 (MIP-04, the sovereign client's send-file): the file as chosen names the FR006-07 check; its metadata goes
   * (FR019) before it is encrypted with the group's epoch; only the ciphertext is uploaded, and the text is its caption.
   */
  const sendFile = async (chosen: File, caption: string) => {
    // FR018-06 (pending in @sedecim/blossom-client): checkAttachmentSize('group', chosen.size) goes here, before the file is read.
    const bytes = new Uint8Array(await chosen.arrayBuffer());
    // FR006-07: a file another persona of this browser already sent waits for an explicit confirmation; it is recorded
    // once it passes the metadata rule, before the upload.
    const uses = [{ fileHash: await fileDigest(bytes) }];
    if (!(await reuse.confirm(uses))) return;
    const data = prepareGroupFile(bytes, chosen.type, !!ws.config?.stripFileMetadata);
    await reuse.record(uses);
    const upload = await groupMediaUploader(s, ws.cfg);
    await sync(gs!, openId);
    const ref = await exclusive(gs!, (g) => sendGroupFile(g, openId, { data, filename: chosen.name, type: chosen.type }, upload, caption));
    setText('');
    setFile(undefined);
    await refresh(gs!, openId);
    if (ref.pending) ws.notify('Sin conexión con el relay de grupos: el mensaje con el archivo quedó pendiente y se enviará solo cuando vuelva la conexión (si antes cambia la época, habrá que enviar el archivo otra vez).', 'info');
  };

  const runConfirmed = () => {
    const c = confirm!;
    setConfirm(undefined);
    void act(async () => {
      if (c.kind === 'rotate') {
        // FR025-14 (the sovereign client's rotate): a self-update commit; the adapter reads what is pending first.
        const before = current?.epoch ?? 0;
        const h = await exclusive(gs!, (g) => g.rotate(openId));
        await refresh(gs!, openId);
        if (h.pending?.some((p) => p.type === 'rotate' && !p.failed)) ws.notify('Sin conexión con el relay de grupos: la rotación quedó pendiente y se aplicará sola cuando vuelva la conexión.', 'info');
        else ws.notify(`Claves rotadas: el grupo pasó de la época ${before} a la ${h.epoch}.`, 'success');
      } else if (c.kind === 'remove') {
        await sync(gs!, openId);
        const h = await exclusive(gs!, (g) => g.removeMember(openId, c.member));
        if (h.members.includes(c.member)) {
          await refresh(gs!, openId);
          ws.notify(`Sin conexión con el relay de grupos: la expulsión de ${shortNpub(c.member)} quedó pendiente y se aplicará sola. Los mensajes que escribas mientras tanto esperan detrás de ella: no los leerá.`, 'info');
        } else {
          await sync(gs!, openId);
          ws.notify(`${shortNpub(c.member)} fue expulsado: la época avanzó y ya no puede leer los mensajes nuevos.`, 'success');
        }
      } else {
        await exclusive(gs!, (g) => g.leave(openId));
        await history.current.forget(openId);
        setOpenId('');
        await reloadGroups(gs!);
        ws.notify('Saliste del grupo y se borró su estado local.', 'info');
      }
    });
  };

  // VAULT-03: a group restored from the vault is a copy of the other device's leaf; this browser joins as a new one.
  const rejoin = () =>
    act(async () => {
      const r = await exclusive(gs!, (g) => rejoinRestoredGroup(g, openId, relays));
      await reloadGroups(gs!);
      ws.notify(r.status === 'joined' ? 'Volviste a entrar en el grupo como dispositivo nuevo: ya puedes escribir.' : 'Pediste volver a entrar: un admin del grupo debe aceptar tu nuevo dispositivo.', r.status === 'joined' ? 'success' : 'info');
    });

  const discard = (id: string) =>
    act(async () => {
      await exclusive(gs!, (g) => discardPendingGroupOperation(g, id));
      await refresh(gs!, openId);
    });

  // FR025-12 (the sovereign client's `group retry`): sync this group and send what waits, now.
  const retryNow = () =>
    act(async () => {
      await exclusive(gs!, (g) => retryPendingGroupOperations(g, openId));
      await sync(gs!, openId);
    });

  // FR025-14 (the sovereign client's `group device --label`): the name this browser announces inside the groups.
  const saveLabel = () =>
    act(async () => {
      const session = await saveGroupDeviceLabel(s, ws.book.store, ws.cfg, labelDraft);
      const label = await groupDeviceLabel(ws.book.store, s.persona.id);
      setDeviceLabel(label);
      setLabelDraft(label);
      setGs(session);
      await reloadGroups(session);
      ws.notify(label ? `Este navegador se llama «${label}» en los grupos.` : 'Este navegador ya no tiene nombre en los grupos.', 'success');
    });

  const forgetRemoved = () =>
    act(async () => {
      const groupId = openId;
      setOpenId('');
      const session = await forgetRemovedGroup(s, ws.book.store, ws.cfg, groupId);
      await history.current.forget(groupId);
      setGs(session);
      await reloadGroups(session);
    });

  const intro = (
    <Alert severity="info" id="groups-intro" action={<MaturityChip id="marmot-groups" />}>
      Grupos Marmot sobre MLS (RFC 9420): forward secrecy y post-compromise security; el relay solo ve texto cifrado y metadatos mínimos. La implementación (marmot-ts) es alpha y no tiene revisión independiente: úsala con esa reserva.
    </Alert>
  );

  if (blocked) {
    return (
      <Stack spacing={2}>
        {intro}
        <Alert severity="error" id="groups-blocked">
          {blocked}
        </Alert>
      </Stack>
    );
  }

  return (
    <Stack spacing={2}>
      {intro}
      {source === 'persona' && (
        <Alert severity="warning" id="groups-relay-warning">
          Este despliegue no define un relay seguro (secureRelays): los grupos usan tus relays. Buzz rechaza los kinds de Marmot (30443/445/10051).
        </Alert>
      )}
      {openError && (
        <Alert severity="error" id="groups-error">
          No se pudo abrir la sesión MLS: {openError}
        </Alert>
      )}
      {!gs && !openError && (
        <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }} role="status">
          <CircularProgress size={20} aria-label="Preparando MLS" />
          <Typography variant="body2">Preparando MLS y verificando la implementación…</Typography>
        </Stack>
      )}
      {gs && (
        <>
          <Card>
            <CardContent>
              <Stack spacing={1}>
                <Typography variant="h6" component="h2">
                  Tu dispositivo en grupos seguros
                </Typography>
                <Typography variant="body2" id="groups-relays">
                  Relay de grupos: {relays.join(', ')}
                </Typography>
                <Typography variant="body2" id="groups-kp-status" role="status">
                  {kp === 'published' ? 'Key package publicado: otros pueden invitarte.' : kp === 'missing' ? 'Sin key package publicado: nadie puede invitarte todavía.' : 'Comprobando tu key package…'}
                </Typography>
                <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap' }} useFlexGap>
                  <Button id="groups-keypackage" variant="outlined" disabled={busy} onClick={() => void publishKeyPackage()}>
                    {kp === 'published' ? 'Renovar key package' : 'Publicar key package'}
                  </Button>
                  <Button id="groups-accept" variant="outlined" disabled={busy} onClick={() => void acceptInvites()}>
                    Aceptar invitaciones pendientes
                  </Button>
                </Stack>
                <Stack direction="row" spacing={1} sx={{ alignItems: 'flex-start', flexWrap: 'wrap', pt: 1 }} useFlexGap>
                  <TextField id="group-device-label" size="small" label="Nombre de este navegador en los grupos (opcional)" value={labelDraft} onChange={(e) => setLabelDraft(e.target.value)} slotProps={{ htmlInput: { maxLength: 64 } }} sx={{ minWidth: 320 }} />
                  <Button id="group-device-label-save" variant="outlined" disabled={busy || labelDraft.trim() === deviceLabel} onClick={() => void saveLabel()}>
                    Guardar nombre
                  </Button>
                </Stack>
                <Typography variant="caption" id="group-device-label-facts" sx={{ color: 'text.secondary' }}>
                  {SECURE_GROUP_TEXTS.label}
                </Typography>
              </Stack>
            </CardContent>
          </Card>

          <Card component="form" id="groups-create" onSubmit={create} aria-labelledby="groups-create-h">
            <CardContent>
              <Stack spacing={2}>
                <Typography variant="h6" component="h2" id="groups-create-h">
                  Nuevo grupo seguro
                </Typography>
                <TextField id="group-name" label="Nombre del grupo" value={name} onChange={(e) => setName(e.target.value)} required />
                <TextField id="group-description" label="Descripción (opcional)" value={description} onChange={(e) => setDescription(e.target.value)} />
                <Button type="submit" variant="contained" disabled={busy || !name.trim()} sx={{ alignSelf: 'flex-start' }}>
                  Crear grupo
                </Button>
              </Stack>
            </CardContent>
          </Card>

          <Card>
            <CardContent>
              <Typography variant="h6" component="h2" id="group-list-h">
                Mis grupos
              </Typography>
              {groups.length === 0 && <Typography variant="body2">Aún no perteneces a ningún grupo seguro.</Typography>}
              <List id="group-list" aria-labelledby="group-list-h">
                {groups.map((g) => (
                  <ListItem key={g.groupId} disablePadding>
                    <ListItemButton selected={g.groupId === openId} onClick={() => setOpenId(g.groupId)}>
                      <ListItemText primary={g.name || 'Grupo sin nombre'} secondary={`Época ${g.epoch} · ${g.members.length} ${g.members.length === 1 ? 'miembro' : 'miembros'} · ${g.admins.includes(s.pubkey) ? 'eres admin' : 'miembro'}${g.restored ? ' · restaurado' : ''}`} />
                    </ListItemButton>
                  </ListItem>
                ))}
              </List>
            </CardContent>
          </Card>

          {current && (
            <Card id="group-detail" aria-labelledby="group-detail-h">
              <CardContent>
                <Stack spacing={2}>
                  <Stack direction="row" spacing={1} sx={{ alignItems: 'center', flexWrap: 'wrap' }} useFlexGap>
                    <Typography variant="h6" component="h2" id="group-detail-h">
                      {current.name || 'Grupo sin nombre'}
                    </Typography>
                    <Chip color="success" size="small" label="cifrado de extremo a extremo (MLS)" />
                  </Stack>
                  <Typography variant="body2" id="group-state" role="status">
                    Época {current.epoch} · {current.members.length} {current.members.length === 1 ? 'miembro' : 'miembros'} · {current.admins.length} {current.admins.length === 1 ? 'admin' : 'admins'}
                  </Typography>
                  {current.restored && !removed && (
                    <Alert
                      severity="warning"
                      id="group-restored"
                      action={
                        <Button color="inherit" disabled={busy} onClick={() => void rejoin()}>
                          Volver a entrar
                        </Button>
                      }
                    >
                      Este grupo se restauró desde el Continuity Vault con la copia de otro dispositivo: puedes leer su historial, pero para escribir este navegador debe entrar otra vez como dispositivo nuevo.
                    </Alert>
                  )}
                  {removed && (
                    <Alert
                      severity="warning"
                      id="group-removed"
                      action={
                        <Button color="inherit" onClick={() => void forgetRemoved()}>
                          Olvidar grupo
                        </Button>
                      }
                    >
                      {standing === 'device-removed'
                        ? 'Quitaron este navegador del grupo: no recibirá sus mensajes nuevos. Tus otros dispositivos siguen en él; para volver, olvida aquí el grupo y pide a uno de ellos o a un admin que lo añada de nuevo.'
                        : 'Ya no eres miembro de este grupo: no recibirás sus mensajes nuevos.'}
                    </Alert>
                  )}

                  <Typography variant="subtitle1" component="h3" id="group-members-h">
                    Miembros
                  </Typography>
                  <Stack direction="row" spacing={1} sx={{ alignItems: 'center', flexWrap: 'wrap' }} useFlexGap>
                    <Button id="group-lookup-names" size="small" disabled={busy} onClick={() => void act(() => lookupGroupMembers(s, current.members))}>
                      Buscar sus perfiles públicos
                    </Button>
                    <AvatarsToggle pubkeys={current.members} shown={avatars} onShow={() => setAvatars(true)} />
                  </Stack>
                  <Typography variant="caption" id="group-lookup-facts" sx={{ color: 'text.secondary' }}>
                    {PUBLIC_PROFILE_TEXTS.groups}
                  </Typography>
                  <List id="group-members" dense aria-labelledby="group-members-h">
                    {current.members.map((m) => (
                      <ListItem
                        key={m}
                        secondaryAction={
                          isAdmin && m !== s.pubkey && !removed && !commitsBlocked ? (
                            <Button size="small" color="error" disabled={busy} aria-label={`Expulsar a ${shortNpub(m)}`} onClick={() => setConfirm({ kind: 'remove', member: m })}>
                              Expulsar
                            </Button>
                          ) : undefined
                        }
                      >
                        <AuthorAvatar pubkey={m} show={avatars} />
                        <ListItemText
                          primary={m === s.pubkey ? `${authorLabel(s, m)} (tú)` : m === ws.cfg.rotationWorker ? `${authorLabel(s, m)} · worker de rotaciones de la organización` : authorLabel(s, m)}
                          secondary={`${current.admins.includes(m) ? 'admin' : 'miembro'}${m === ws.cfg.rotationWorker ? ' · puede descifrar el grupo mientras esté en él; saca a los dispositivos que la organización revoca' : ''}`}
                        />
                      </ListItem>
                    ))}
                  </List>

                  {!removed && !current.restored && <GroupDevices gs={gs} group={current} relays={relays} isAdmin={isAdmin} commitsBlocked={commitsBlocked} busy={busy} act={act} onChanged={() => sync(gs, openId)} reuse={reuse} />}

                  {isAdmin && !removed && (
                    <Stack component="form" id="group-invite" spacing={1} onSubmit={invite}>
                      <TextField id="group-invite-npubs" label="Invitar por npub (una por línea)" multiline minRows={1} value={invitees} onChange={(e) => setInvitees(e.target.value)} required />
                      <Button type="submit" variant="outlined" disabled={busy || !invitees.trim() || commitsBlocked} sx={{ alignSelf: 'flex-start' }}>
                        Invitar
                      </Button>
                    </Stack>
                  )}
                  {commitsBlocked && !removed && (
                    <Typography variant="body2" id="group-commits-blocked">
                      Hay propuestas sin decidir: confírmalas o recházalas antes de invitar, expulsar o cambiar dispositivos (ese commit aplicaría también algunas de ellas).
                    </Typography>
                  )}
                  <GroupProposals gs={gs} group={current} relays={relays} isAdmin={isAdmin} readOnly={removed || !!current.restored} busy={busy} act={act} onChanged={() => sync(gs, openId)} reuse={reuse} />
                  {missingKp.length > 0 && (
                    <Alert severity="warning" id="group-kp-warnings">
                      Sin key package en el relay de grupos, no se pueden invitar: {missingKp.map((p) => shortNpub(p)).join(', ')}. Pídeles que abran «Grupos seguros» y publiquen su key package.
                    </Alert>
                  )}

                  {!!current.pending?.length && (
                    <Alert severity={current.pending.some((p) => p.failed) ? 'warning' : 'info'} id="group-pending">
                      Pendiente de un relay: se reintenta solo en cada actualización del grupo y al volver la conexión. Nada escrito después de un commit pendiente sale antes que él.
                      <Button id="group-pending-retry" size="small" color="inherit" disabled={busy} onClick={() => void retryNow()}>
                        Reintentar ahora
                      </Button>
                      <List dense aria-label="Operaciones pendientes">
                        {current.pending.map((p) => (
                          <ListItem
                            key={p.id}
                            secondaryAction={
                              p.failed ? (
                                <Button size="small" color="inherit" disabled={busy} onClick={() => void discard(p.id)}>
                                  Descartar
                                </Button>
                              ) : undefined
                            }
                          >
                            <ListItemText
                              primary={`${pendingLabel(p)}${p.target ? ` · ${shortNpub(p.target)}` : ''}`}
                              secondary={p.failed ? `Rechazada por los relays: ${p.failed}` : `${p.attempts} ${p.attempts === 1 ? 'intento' : 'intentos'}${p.lastError ? ` · ${p.lastError}` : ''}`}
                            />
                          </ListItem>
                        ))}
                      </List>
                    </Alert>
                  )}

                  <Typography variant="subtitle1" component="h3" id="group-log-h">
                    Mensajes
                  </Typography>
                  <List id="group-log" aria-labelledby="group-log-h" aria-live="polite">
                    {messages.map((m) => (
                      <ListItem key={m.id} alignItems="flex-start">
                        <AuthorAvatar pubkey={m.sender} show={avatars} />
                        <ListItemText
                          primary={
                            m.media?.length ? (
                              <>
                                {m.content && <span style={{ display: 'block' }}>{m.content}</span>}
                                {m.media.map((a) => (
                                  <GroupAttachment key={a.sha256} s={s} gs={gs} groupId={openId} attachment={a} />
                                ))}
                              </>
                            ) : (
                              m.content
                            )
                          }
                          secondary={`${m.sender === s.pubkey ? 'tú' : authorLabel(s, m.sender)} · ${new Date(m.createdAt * 1000).toLocaleString()}${pendingMessages.has(m.id) ? ' · pendiente de enviar' : ''}`}
                        />
                      </ListItem>
                    ))}
                  </List>
                  {messages.some((m) => m.media?.length) && (
                    <Typography variant="caption" id="group-download-facts" sx={{ color: 'text.secondary' }}>
                      {SECURE_GROUP_TEXTS.download}
                    </Typography>
                  )}
                  {!removed && !current.restored && proposalsPending && (
                    <Typography variant="body2" id="group-send-blocked">
                      Hay propuestas sin decidir en el grupo: hasta que un admin las confirme o las rechace no se pueden enviar mensajes ni archivos.
                    </Typography>
                  )}
                  {!removed && !current.restored && (
                    <Stack component="form" id="group-send" spacing={1} onSubmit={send}>
                      <Stack direction="row" spacing={1} sx={{ alignItems: 'flex-start' }}>
                        <TextField id="group-text" label={file ? 'Texto que acompaña al archivo (opcional)' : 'Mensaje al grupo'} value={text} onChange={(e) => setText(e.target.value)} fullWidth required={!file} disabled={proposalsPending} />
                        <Button type="submit" variant="contained" disabled={busy || proposalsPending || (!text.trim() && !file)}>
                          Enviar
                        </Button>
                      </Stack>
                      <Stack direction="row" spacing={1} sx={{ alignItems: 'center', flexWrap: 'wrap' }} useFlexGap>
                        <Button component="label" size="small" variant="outlined" disabled={busy || proposalsPending}>
                          Adjuntar archivo cifrado
                          <input hidden type="file" onChange={(e) => setFile(e.target.files?.[0])} />
                        </Button>
                        {file && <Chip label={file.name} onDelete={() => setFile(undefined)} />}
                      </Stack>
                      {file && (
                        <Typography variant="caption" id="group-media-facts" sx={{ color: 'text.secondary' }}>
                          {SECURE_GROUP_TEXTS.media}
                        </Typography>
                      )}
                    </Stack>
                  )}
                  <Stack direction="row" spacing={1}>
                    <Button id="group-refresh" disabled={busy} onClick={() => void act(() => sync(gs, openId))}>
                      Actualizar
                    </Button>
                    {!removed && !current.restored && (
                      <Button id="group-rotate" disabled={busy} onClick={() => setConfirm({ kind: 'rotate' })}>
                        Rotar mis claves
                      </Button>
                    )}
                    {!removed && (
                      <Button id="group-leave" color="error" disabled={busy} onClick={() => setConfirm({ kind: 'leave' })}>
                        Salir del grupo
                      </Button>
                    )}
                  </Stack>
                </Stack>
              </CardContent>
            </Card>
          )}
        </>
      )}
      <Dialog open={!!confirm} onClose={() => setConfirm(undefined)} aria-labelledby="group-confirm-title">
        <DialogTitle id="group-confirm-title">{confirm ? CONFIRM_TITLES[confirm.kind] : ''}</DialogTitle>
        <DialogContent>
          <DialogContentText>
            {confirm?.kind === 'remove'
              ? `${shortNpub(confirm.member)} dejará de poder descifrar los mensajes nuevos (la época avanza). Lo que ya recibió sigue en su dispositivo. ${SECURE_GROUP_TEXTS.removed}`
              : confirm?.kind === 'rotate'
                ? `${proposalsPending ? `Hay ${current?.pendingProposals} ${current?.pendingProposals === 1 ? 'propuesta pendiente' : 'propuestas pendientes'}. ` : ''}${SECURE_GROUP_TEXTS.rotate}`
                : 'Se publica tu salida y se borra el estado MLS de este grupo en este navegador. Para volver necesitarás otra invitación.'}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfirm(undefined)}>Cancelar</Button>
          <Button color={confirm?.kind === 'rotate' ? 'primary' : 'error'} onClick={runConfirmed}>
            {confirm ? CONFIRM_ACTIONS[confirm.kind] : ''}
          </Button>
        </DialogActions>
      </Dialog>
      {reuse.dialog}
    </Stack>
  );
}
