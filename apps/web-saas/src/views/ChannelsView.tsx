import { useEffect, useRef, useState, type FormEvent } from 'react';
import { Alert, Box, Button, Card, CardContent, Chip, List, ListItem, ListItemButton, ListItemText, Stack, TextField, Typography } from '@mui/material';
import { BlossomClient, prepareBlob, UnsanitizableFileError, uploadToServers } from '@sedecim/blossom-client';
import { blossomServersOf, unsanitizableMessage, uploadTargets } from '../lib/blossom';
import { cappedQuorumNotice } from '../lib/outbox';
import type { NostrEvent } from '@sedecim/nostr-core';
import { channelFilter, chatMessage, createGroup, joinRequest, NIP29, parseGroupMetadata, type GroupMetadata } from '@sedecim/messaging';
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

/** NIP-29 channels (FR015-02): discover (39000), ask to join (9021), read and write. Not E2EE. */
export function ChannelsView() {
  const ws = useWorkspace();
  const s = ws.session!;
  const config = ws.config!;
  const [channels, setChannels] = useState<GroupMetadata[]>([]);
  const [groupId, setGroupId] = useState('');
  const [newName, setNewName] = useState('');
  const [openId, setOpenId] = useState('');
  const [messages, setMessages] = useState<NostrEvent[]>([]);
  const [text, setText] = useState('');
  const [file, setFile] = useState<File | undefined>();
  const [busy, setBusy] = useState(false);
  const blocked = sendBlockedReason(config);
  const sub = useRef<{ close(): void } | undefined>(undefined);

  const discover = async () => {
    const evts = await s.pool.query(s.persona.relays, [{ kinds: [NIP29.GroupMetadata], limit: 200 }], 5000);
    const byId = new Map<string, GroupMetadata>();
    for (const e of evts.sort((a, b) => a.created_at - b.created_at)) {
      const m = parseGroupMetadata(e);
      if (m && !m.hidden) byId.set(m.id, m);
    }
    const list = [...byId.values()].sort((a, b) => (a.name ?? a.id).localeCompare(b.name ?? b.id));
    setChannels(list);
    return list;
  };

  useEffect(() => {
    void discover();
    return () => sub.current?.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [s]);

  const open = (id: string) => {
    sub.current?.close();
    setOpenId(id);
    setMessages([]);
    const seen = new Set<string>();
    sub.current = s.pool.subscribe(s.persona.relays, [{ ...channelFilter(id), limit: 100 }], {
      onevent: (evt) => {
        if (evt.kind !== NIP29.ChatMessage || seen.has(evt.id)) return;
        seen.add(evt.id);
        setMessages((m) => [...m, evt].sort((a, b) => a.created_at - b.created_at));
      },
    });
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
    for (let i = 0; i < 20 && !(await discover()).some((c) => c.name === name); i++) await new Promise((r) => setTimeout(r, 500));
  };

  const send = async (e: FormEvent) => {
    e.preventDefault();
    if (!openId || blocked) return;
    setBusy(true);
    try {
      const tmpl = chatMessage(openId, text);
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
      const rec = await s.engine.submit({ template: tmpl }, { relays: s.persona.relays, quorum: config.quorum });
      const capped = cappedQuorumNotice(rec);
      if (capped) ws.notify(capped, 'warning');
      setText('');
      setFile(undefined);
    } catch (err) {
      ws.notify(err instanceof UnsanitizableFileError ? unsanitizableMessage(err) : (err as Error).message, 'error');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Stack spacing={2}>
      <Alert severity="warning">Los canales de workspace NO son E2EE: el operador del relay puede leer el contenido.</Alert>
      <Box sx={{ display: 'grid', gridTemplateColumns: { md: '280px 1fr' }, gap: 2 }}>
        <Card>
          <CardContent>
            <Typography variant="h6" component="h2">
              Canales
            </Typography>
            <List dense id="channel-list" aria-label="Canales visibles">
              {channels.map((c) => (
                <ListItem key={c.id} disablePadding secondaryAction={<Button size="small" onClick={() => void join(c.id)}>Unirse</Button>}>
                  <ListItemButton selected={openId === c.id} onClick={() => open(c.id)}>
                    <ListItemText primary={c.name ?? c.id} secondary={[c.private ? 'privado' : 'abierto', c.about].filter(Boolean).join(' · ')} />
                  </ListItemButton>
                </ListItem>
              ))}
              {channels.length === 0 && <ListItem>Sin canales visibles.</ListItem>}
            </List>
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
              {messages.map((m) => (
                <ListItem key={m.id} alignItems="flex-start">
                  <ListItemText primary={m.content} secondary={`${shortNpub(m.pubkey)} · ${new Date(m.created_at * 1000).toLocaleString()}`} />
                  {imetaOf(m) && <ChannelImage meta={imetaOf(m)!} />}
                </ListItem>
              ))}
            </List>
            {openId && (
              <Stack component="form" spacing={1} id="channel-send" onSubmit={send}>
                {blocked && <Alert severity="error">{blocked}</Alert>}
                <TextField id="channel-text" label="Mensaje" multiline minRows={2} value={text} onChange={(e) => setText(e.target.value)} required={!file} />
                <Stack direction="row" spacing={1} alignItems="center">
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
