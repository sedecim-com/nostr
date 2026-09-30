import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from 'react';
import { Alert, Box, Button, Card, CardContent, Chip, Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle, List, ListItem, ListItemButton, ListItemText, Stack, TextField, Typography } from '@mui/material';
import { BlossomClient, prepareBlob, UnsanitizableFileError, uploadToServers } from '@sedecim/blossom-client';
import { blossomServersOf, unsanitizableMessage, uploadTargets } from '../lib/blossom';
import { cappedQuorumNotice, fileKey, SendOperation } from '../lib/outbox';
import type { EventTemplate, NostrEvent } from '@sedecim/nostr-core';
import { channelFilters, channelView, chatMessage, createGroup, deleteEvent, groupAdmins, joinRequest, NIP29, parseGroupMetadata, replyMessage, type ChannelEntry, type GroupMetadata } from '@sedecim/messaging';
import { CHANNEL_DELETION_TEXTS, CHANNEL_MIRROR_TEXTS } from '@sedecim/profiles';
import { canDelete, publishToChannel, reactionToggle, REACTIONS } from '../lib/channels';
import { ChannelReadState, countUnread, MIRROR_REFRESH_MS, MirrorClient, mirrorAvailability, refreshesInBackground, unreadLabel, type MirrorHit, type UnreadCount } from '../lib/mirror';
import { shortNpub } from '../lib/session';
import { sendBlockedReason, useWorkspace } from '../lib/workspace';

interface Imeta {
  url: string;
  sha256: string;
  mime?: string;
}

function imetaOf(evt: NostrEvent): Imeta | undefined {
  const t = evt.tags.find((x) => x[0] === 'imeta');
  if (!t) return undefined;
  const kv = Object.fromEntries(t.slice(1).map((s) => [s.slice(0, s.indexOf(' ')), s.slice(s.indexOf(' ') + 1)]));
  return kv.url && kv.x ? { url: kv.url, sha256: kv.x, ...(kv.m ? { mime: kv.m } : {}) } : undefined;
}

const snippet = (text: string) => (text.length > 80 ? `${text.slice(0, 79)}…` : text);

/** Who and what a reply answers, as far as this browser has it. */
function quoteOf(parent: NostrEvent | undefined, deleted: ReadonlySet<string>): string {
  if (!parent) return 'un mensaje que no está cargado';
  if (deleted.has(parent.id)) return 'un mensaje borrado';
  return `${shortNpub(parent.pubkey)}: «${snippet(parent.content)}»`;
}

/**
 * NIP-29 channels (FR015-02): discover (39000), ask to join (9021), read and write. Not E2EE. FR015-04: reactions
 * (kind 7), replies in threads (NIP-10 `e` markers and `q`) and deletions (9005 for messages, 5 for one's reactions).
 * FR014-04: unread counts and search through the operator's mirror where the deployment has one and the persona's
 * profile allows it.
 */
export function ChannelsView() {
  const ws = useWorkspace();
  const s = ws.session!;
  const config = ws.config!;
  const [channels, setChannels] = useState<GroupMetadata[]>([]);
  const [groupId, setGroupId] = useState('');
  const [newName, setNewName] = useState('');
  const [openId, setOpenId] = useState('');
  // FR015-04: every event of the open channel (messages, reactions, deletions); channelView says what is shown.
  const [events, setEvents] = useState<NostrEvent[]>([]);
  const [admins, setAdmins] = useState<Set<string>>(new Set());
  const [replyTo, setReplyTo] = useState<NostrEvent | undefined>();
  const [toDelete, setToDelete] = useState<NostrEvent | undefined>();
  const [pending, setPending] = useState(false);
  const [text, setText] = useState('');
  const [file, setFile] = useState<File | undefined>();
  const [busy, setBusy] = useState(false);
  const blocked = sendBlockedReason(config);
  const sub = useRef<{ close(): void } | undefined>(undefined);
  const operation = useRef(new SendOperation());
  const opened = useRef('');
  const view = useMemo(() => channelView(events, { groupId: openId, me: s.pubkey, admins }), [events, openId, s.pubkey, admins]);
  const addEvents = (list: NostrEvent[]) =>
    setEvents((cur) => {
      const have = new Set(cur.map((e) => e.id));
      const add = list.filter((e) => !have.has(e.id));
      return add.length ? [...cur, ...add] : cur;
    });

  // FR014-04: the mirror answers with the times of each channel's newest messages; the cursors stay in the vault.
  const mirror = mirrorAvailability(ws.cfg.mirror, config);
  const client = useMemo(() => (mirror.state === 'available' ? new MirrorClient(ws.cfg.mirror!, s.signer) : undefined), [mirror.state, ws.cfg.mirror, s.signer]);
  const readState = useMemo(() => new ChannelReadState(ws.book.store, s.persona.id), [ws.book, s.persona.id]);
  const background = refreshesInBackground(s.persona.custody);
  const [unread, setUnread] = useState<Map<string, UnreadCount>>(new Map());
  const [mirrorError, setMirrorError] = useState('');
  const [query, setQuery] = useState('');
  const [hits, setHits] = useState<MirrorHit[] | undefined>();
  const [searching, setSearching] = useState(false);
  const listed = useRef<GroupMetadata[]>([]);
  const marked = useRef<{ channel: string; until: number } | undefined>(undefined);
  const currentClient = useRef(client);
  currentClient.current = client;

  const refreshUnread = useCallback(
    async (list: GroupMetadata[]) => {
      if (!client || list.length === 0) return;
      try {
        const recent = await client.recent(
          list.map((c) => c.id),
          { kinds: [NIP29.ChatMessage] },
        );
        const counts = countUnread(recent, await readState.cursors([...recent.keys()]));
        // A persona or profile change meanwhile: this answer belongs to the previous one.
        if (currentClient.current !== client) return;
        setUnread(counts);
        setMirrorError('');
      } catch (err) {
        if (currentClient.current === client) setMirrorError((err as Error).message);
      }
    },
    [client, readState],
  );

  // `counts`: also ask the mirror for the unread counts (a signer that may ask to approve each signature waits for «Actualizar»).
  const discover = async (counts = true) => {
    const evts = await s.pool.query(s.persona.relays, [{ kinds: [NIP29.GroupMetadata], limit: 200 }], 5000);
    const byId = new Map<string, GroupMetadata>();
    for (const e of evts.sort((a, b) => a.created_at - b.created_at)) {
      const m = parseGroupMetadata(e);
      if (m && !m.hidden) byId.set(m.id, m);
    }
    const list = [...byId.values()].sort((a, b) => (a.name ?? a.id).localeCompare(b.name ?? b.id));
    setChannels(list);
    listed.current = list;
    if (counts) void refreshUnread(list);
    return list;
  };

  useEffect(() => {
    // Another persona or configuration: its own channels are counted once discovered.
    listed.current = [];
    void discover(background);
    return () => sub.current?.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [s]);

  // FR014-04: the counts refresh while the view is open (and visible) with signers that do not ask for each signature.
  // Another persona or profile (a new session) starts over: its discovery above counts at once.
  useEffect(() => {
    setUnread(new Map());
    setHits(undefined);
    setMirrorError('');
    if (!client || !background) return;
    const timer = setInterval(() => {
      if (!document.hidden) void refreshUnread(listed.current);
    }, MIRROR_REFRESH_MS);
    return () => clearInterval(timer);
  }, [client, background, refreshUnread]);

  // FR014-04: what the open channel shows is read up to its newest message; only this browser's vault learns it.
  useEffect(() => {
    const newest = view.messages.at(-1)?.event.created_at;
    if (!client || !openId || newest === undefined) return;
    // Older messages of the backfill do not move the cursor: one vault write per newer message.
    if (marked.current?.channel === openId && marked.current.until >= newest) return;
    marked.current = { channel: openId, until: newest };
    void readState.markRead(openId, newest).then(() =>
      setUnread((u) => {
        if (!u.get(openId)?.count) return u;
        const next = new Map(u);
        next.set(openId, { count: 0, more: false });
        return next;
      }),
    );
  }, [client, openId, view, readState]);

  const search = async (e: FormEvent) => {
    e.preventDefault();
    if (!client) return;
    if (query.trim().length < 2) return ws.notify('Escribe al menos 2 caracteres para buscar.', 'info');
    setSearching(true);
    try {
      setHits(await client.search(query, { kinds: [NIP29.ChatMessage] }));
    } catch (err) {
      ws.notify((err as Error).message, 'error');
    } finally {
      setSearching(false);
    }
  };

  const open = (id: string) => {
    sub.current?.close();
    opened.current = id;
    setOpenId(id);
    setEvents([]);
    setAdmins(new Set());
    setReplyTo(undefined);
    // FR015-04: messages, and apart the reactions and deletions around them; the admins from the relay-signed state.
    sub.current = s.pool.subscribe(s.persona.relays, channelFilters(id), { onevent: (evt) => addEvents([evt]) });
    void s.pool.query(s.persona.relays, [{ kinds: [NIP29.GroupMetadata, NIP29.GroupAdmins], '#d': [id] }], 5000).then(
      (state) => opened.current === id && setAdmins(groupAdmins(state, id)),
      () => undefined,
    );
  };

  // FR015-04: reactions toggle (kind 7, or kind 5 of one's own) and deletions (9005) go through the outbox.
  const act = async (templates: EventTemplate[], done?: string) => {
    if (pending || blocked) return;
    setPending(true);
    try {
      addEvents(await publishToChannel(s, templates));
      if (done) ws.notify(done, 'info');
    } catch (err) {
      ws.notify((err as Error).message, 'error');
    } finally {
      setPending(false);
    }
  };
  const react = (entry: ChannelEntry, content: string) => act(reactionToggle(openId, entry, content));
  const confirmDelete = () => {
    const target = toDelete;
    setToDelete(undefined);
    if (target) void act([deleteEvent(openId, target.id)], 'Petición de borrado publicada');
  };

  const join = async (id: string) => {
    const rec = await s.engine.submit({ template: joinRequest(id) }, { relays: s.persona.relays, quorum: 1 });
    ws.notify(`Solicitud de unión enviada (${rec.state})`, 'info');
  };

  // NIP-29 create (9007): the relay assigns the id and publishes the metadata (39000) we then discover.
  const create = async (e: FormEvent) => {
    e.preventDefault();
    if (blocked) return ws.notify(blocked, 'error');
    const name = newName.trim();
    const rec = await s.engine.submit({ template: createGroup(name, 'open') }, { relays: s.persona.relays, quorum: 1, wait: true });
    if (rec.state === 'FAILED') return ws.notify(`El relay rechazó el canal: ${rec.failureReason ?? ''}`, 'error');
    setNewName('');
    for (let i = 0; i < 20 && !(await discover(false)).some((c) => c.name === name); i++) await new Promise((r) => setTimeout(r, 500));
  };

  const send = async (e: FormEvent) => {
    e.preventDefault();
    if (!openId || blocked) return;
    setBusy(true);
    try {
      const build = async () => {
        // FR015-04: a reply goes in the thread of the message it answers.
        const tmpl = replyTo ? replyMessage(openId, text, replyTo) : chatMessage(openId, text);
        if (file) {
          // FR018-04: channel images are public to channel members: sanitized (EXIF removed) and stored in Buzz /media.
          if (config.files !== 'relay-plain') throw new Error('Tu perfil exige adjuntos cifrados y los canales NIP-29 no son E2EE: comparte el archivo por mensaje directo.');
          // FR018-05: the user's Blossom servers (kind 10063, primary first), else the relay media server.
          const targets = uploadTargets(ws.cfg, await blossomServersOf(s), false);
          if (targets.length === 0) throw new Error('Este despliegue no tiene servidor de media configurado.');
          const prepared = prepareBlob(new Uint8Array(await file.arrayBuffer()), { sanitize: true, requireSanitizable: config.stripFileMetadata, mimeType: file.type, fileName: file.name });
          const { descriptor: desc } = await uploadToServers(prepared, targets, s.signer);
          tmpl.content = [text, desc.url].filter(Boolean).join('\n');
          (tmpl.tags ??= []).push(['imeta', `url ${desc.url}`, `m ${prepared.mimeType}`, `x ${prepared.sha256}`]);
        }
        return { template: tmpl };
      };
      // FR011-05: «Enviar» again on the same message retries its operation: no other event, no second upload.
      const opId = operation.current.for(JSON.stringify([openId, text, fileKey(file), replyTo?.id ?? '']));
      const rec = await s.engine.submitOnce(opId, build, { relays: s.persona.relays, quorum: config.quorum });
      operation.current.done();
      const capped = cappedQuorumNotice(rec);
      if (capped) ws.notify(capped, 'warning');
      setText('');
      setFile(undefined);
      setReplyTo(undefined);
    } catch (err) {
      ws.notify(err instanceof UnsanitizableFileError ? unsanitizableMessage(err) : (err as Error).message, 'error');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Stack spacing={2}>
      <Alert severity="warning">Los canales de workspace NO son E2EE: el operador del relay puede leer el contenido.</Alert>
      {client && (
        <Card>
          <CardContent>
            <Stack spacing={1}>
              <Typography variant="h6" component="h2">
                Buscar en tus canales
              </Typography>
              <Typography variant="body2" id="channel-mirror-notice">
                {CHANNEL_MIRROR_TEXTS.uses} {CHANNEL_MIRROR_TEXTS.scope}
              </Typography>
              <Stack component="form" direction="row" spacing={1} id="channel-search" onSubmit={(e) => void search(e)}>
                <TextField size="small" id="channel-search-text" label="Texto a buscar" value={query} onChange={(e) => setQuery(e.target.value)} required slotProps={{ htmlInput: { minLength: 2, maxLength: 200 } }} />
                <Button type="submit" disabled={searching}>
                  Buscar
                </Button>
              </Stack>
              {hits && (
                <List dense id="channel-search-results" aria-label="Resultados de la búsqueda">
                  {hits.map((h) => (
                    <ListItem key={h.event.id} disablePadding>
                      <ListItemButton onClick={() => open(h.channel)}>
                        <ListItemText primary={h.event.content} secondary={`#${channels.find((c) => c.id === h.channel)?.name ?? h.channel} · ${shortNpub(h.event.pubkey)} · ${new Date(h.event.created_at * 1000).toLocaleString()}`} />
                      </ListItemButton>
                    </ListItem>
                  ))}
                  {hits.length === 0 && <ListItem>Sin resultados en los canales que puedes leer.</ListItem>}
                </List>
              )}
            </Stack>
          </CardContent>
        </Card>
      )}
      <Box sx={{ display: 'grid', gridTemplateColumns: { md: '280px 1fr' }, gap: 2 }}>
        <Card>
          <CardContent>
            <Typography variant="h6" component="h2">
              Canales
            </Typography>
            <List dense id="channel-list" aria-label="Canales visibles">
              {channels.map((c) => {
                // FR014-04: the open channel is being read; channels the mirror does not answer for have no count.
                const u = c.id === openId ? undefined : unread.get(c.id);
                return (
                  <ListItem key={c.id} disablePadding secondaryAction={<Button size="small" onClick={() => void join(c.id)}>Unirse</Button>}>
                    <ListItemButton selected={openId === c.id} onClick={() => open(c.id)}>
                      <ListItemText
                        primary={c.name ?? c.id}
                        secondary={
                          <>
                            {[c.private ? 'privado' : 'abierto', c.about].filter(Boolean).join(' · ')}
                            {u && u.count > 0 && <Box component="strong" sx={{ color: 'primary.main' }}>{` · ${unreadLabel(u)} sin leer`}</Box>}
                          </>
                        }
                      />
                    </ListItemButton>
                  </ListItem>
                );
              })}
              {channels.length === 0 && <ListItem>Sin canales visibles.</ListItem>}
            </List>
            {mirror.state !== 'hidden' && (
              <Typography variant="body2" id="channel-unread-notice" sx={{ color: 'text.secondary', my: 1 }}>
                {mirror.state === 'disabled' ? mirror.reason : `${CHANNEL_MIRROR_TEXTS.readState}${background ? '' : ' Con un signer externo, los contadores se actualizan al pulsar «Actualizar»: cada consulta al mirror lleva una firma.'}`}
              </Typography>
            )}
            {mirrorError && (
              <Alert severity="warning" sx={{ mb: 1 }}>
                {mirrorError}
              </Alert>
            )}
            <Stack
              component="form"
              direction="row"
              spacing={1}
              id="channel-join"
              onSubmit={(e) => {
                e.preventDefault();
                open(groupId.trim());
              }}
            >
              <TextField size="small" id="group-id" label="ID de canal (#h)" value={groupId} onChange={(e) => setGroupId(e.target.value)} required />
              <Button type="submit">Abrir</Button>
            </Stack>
            <Button size="small" onClick={() => void discover()}>
              Actualizar
            </Button>
            <Stack component="form" direction="row" spacing={1} id="channel-create" onSubmit={(e) => void create(e)} sx={{ mt: 1 }}>
              <TextField size="small" id="new-channel" label="Nuevo canal" value={newName} onChange={(e) => setNewName(e.target.value)} required />
              <Button type="submit">Crear</Button>
            </Stack>
          </CardContent>
        </Card>
        <Card>
          <CardContent>
            <Typography variant="h6" component="h2">
              {openId ? `#${channels.find((c) => c.id === openId)?.name ?? openId}` : 'Elige un canal'}
            </Typography>
            <List id="channel-log" aria-live="polite" dense>
              {view.messages.map((m) => (
                <ListItem key={m.event.id} sx={{ flexDirection: 'column', alignItems: 'stretch' }}>
                  {m.thread && (
                    <Typography variant="caption" sx={{ color: 'text.secondary' }}>
                      {`↪ En respuesta a ${quoteOf(view.byId.get(m.thread.parent), view.deleted)}`}
                    </Typography>
                  )}
                  <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1 }}>
                    <ListItemText primary={m.event.content} secondary={`${shortNpub(m.event.pubkey)} · ${new Date(m.event.created_at * 1000).toLocaleString()}`} />
                    {imetaOf(m.event) && <ChannelImage meta={imetaOf(m.event)!} />}
                  </Box>
                  <Stack direction="row" spacing={0.5} useFlexGap sx={{ flexWrap: 'wrap', alignItems: 'center' }}>
                    {m.reactions.map((r) => (
                      <Chip
                        key={r.content}
                        size="small"
                        label={`${r.content} ${r.count}`}
                        color={r.mine.length ? 'primary' : 'default'}
                        variant={r.mine.length ? 'filled' : 'outlined'}
                        disabled={pending || !!blocked}
                        onClick={() => void react(m, r.content)}
                        aria-label={`${r.content}: ${r.count}. ${r.mine.length ? 'Quitar tu reacción' : 'Reaccionar igual'}`}
                      />
                    ))}
                    {REACTIONS.filter((c) => !m.reactions.some((r) => r.content === c)).map((c) => (
                      <Button key={c} size="small" disabled={pending || !!blocked} onClick={() => void react(m, c)} aria-label={`Reaccionar con ${c}`}>
                        {c}
                      </Button>
                    ))}
                    <Button size="small" onClick={() => setReplyTo(m.event)}>
                      Responder
                    </Button>
                    {canDelete(m.event, s.pubkey, admins) && (
                      <Button size="small" color="error" disabled={pending || !!blocked} onClick={() => setToDelete(m.event)}>
                        Borrar
                      </Button>
                    )}
                  </Stack>
                </ListItem>
              ))}
            </List>
            {openId && (
              <Typography variant="body2" id="channel-collab-notice" sx={{ color: 'text.secondary', mb: 1 }}>
                Las reacciones, respuestas y borrados son eventos firmados que ven los miembros del canal y el operador del relay. {CHANNEL_DELETION_TEXTS.reaction}
              </Typography>
            )}
            {openId && (
              <Stack component="form" spacing={1} id="channel-send" onSubmit={send}>
                {blocked && <Alert severity="error">{blocked}</Alert>}
                {replyTo && (
                  <Alert severity="info" id="channel-reply-to" closeText="Cancelar la respuesta" onClose={() => setReplyTo(undefined)}>
                    Respondiendo a {quoteOf(replyTo, view.deleted)}
                  </Alert>
                )}
                <TextField id="channel-text" label="Mensaje" multiline minRows={2} value={text} onChange={(e) => setText(e.target.value)} required={!file} />
                <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
                  <Button component="label" variant="outlined" disabled={config.files !== 'relay-plain'}>
                    Adjuntar imagen
                    <input hidden type="file" accept="image/*" onChange={(e) => setFile(e.target.files?.[0])} />
                  </Button>
                  {file && <Chip label={file.name} onDelete={() => setFile(undefined)} />}
                  <Button type="submit" variant="contained" disabled={busy || !!blocked}>
                    Enviar
                  </Button>
                </Stack>
              </Stack>
            )}
          </CardContent>
        </Card>
      </Box>
      <Dialog open={!!toDelete} onClose={() => setToDelete(undefined)} aria-labelledby="channel-delete-title">
        <DialogTitle id="channel-delete-title">¿Borrar este mensaje?</DialogTitle>
        <DialogContent>
          <DialogContentText>{CHANNEL_DELETION_TEXTS.message}</DialogContentText>
          <DialogContentText sx={{ mt: 1 }}>{CHANNEL_DELETION_TEXTS.copies}</DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setToDelete(undefined)}>Cancelar</Button>
          <Button color="error" onClick={confirmDelete}>
            Borrar
          </Button>
        </DialogActions>
      </Dialog>
    </Stack>
  );
}

/** Images are fetched (with BUD-01 auth when required) and hash-verified before display; remote previews follow the panel. */
function ChannelImage({ meta }: { meta: Imeta }) {
  const ws = useWorkspace();
  const s = ws.session!;
  const [src, setSrc] = useState<string | undefined>();
  const [error, setError] = useState('');
  const [allowed, setAllowed] = useState(ws.config!.remotePreviews);
  useEffect(() => {
    if (!allowed) return;
    let url: string | undefined;
    const server = new URL(meta.url).origin + new URL(meta.url).pathname.replace(/\/[^/]*$/, '');
    new BlossomClient(server, s.signer)
      .download(meta.sha256, { url: meta.url })
      .then((bytes) => {
        url = URL.createObjectURL(new Blob([bytes.slice().buffer], { type: meta.mime ?? 'application/octet-stream' }));
        setSrc(url);
      })
      .catch((e: Error) => setError(e.message));
    return () => {
      if (url) URL.revokeObjectURL(url);
    };
  }, [allowed, meta, s.signer]);
  if (!allowed) return <Button onClick={() => setAllowed(true)}>Mostrar imagen ({new URL(meta.url).host})</Button>;
  if (error) return <Typography color="error">Imagen no verificada: {error}</Typography>;
  return src ? <Box component="img" src={src} alt="Imagen adjunta al mensaje" sx={{ maxWidth: 240, borderRadius: 1 }} /> : null;
}
