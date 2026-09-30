import { useEffect, useRef, useState, type FormEvent } from 'react';
import { Alert, Box, Button, Card, CardContent, Checkbox, Chip, FormControlLabel, List, ListItem, ListItemText, Stack, TextField, Typography } from '@mui/material';
import { downloadFromServers, prepareBlob, UnsanitizableFileError, uploadToServers } from '@sedecim/blossom-client';
import { getTagValue, normalizePubkey } from '@sedecim/nostr-core';
import { BUZZ_PINNED_ADAPTER, DirectMessenger, FeatureDisabledError, FILE_MESSAGE_KIND, wrapOptionsFromFlags, type DirectMessage } from '@sedecim/messaging';
import { blossomServersOf, unsanitizableMessage, uploadTargets } from '../lib/blossom';
import { cappedQuorumNotice, fileKey, SendOperation } from '../lib/outbox';
import { authorLabel, lookupDmCorrespondents } from '../lib/profiles';
import { AuthorAvatar, AvatarsToggle, useProfiles } from './Profile';
import { sendBlockedReason, useWorkspace } from '../lib/workspace';

/** NIP-17 DMs behind the interop-gate flag (FR-017) with client-encrypted attachments (kind 15, FR018-04). */
export function DmView() {
  const ws = useWorkspace();
  const s = ws.session!;
  const config = ws.config!;
  const flags = ws.flags;
  const gateRejected = flags ? !flags.nip17.enabled : false;
  const { nip17, setNip17 } = ws;
  const [to, setTo] = useState('');
  const [text, setText] = useState('');
  const [file, setFile] = useState<File | undefined>();
  const [busy, setBusy] = useState(false);
  const blocked = sendBlockedReason(config);
  const wrapOpts = wrapOptionsFromFlags(flags, BUZZ_PINNED_ADAPTER.wrap);
  const messenger = () => new DirectMessenger(s.signer, { nip17, readReceipts: config.readReceipts }, wrapOpts);
  const { inbox, messages, background } = ws.dm;
  // FR006-04: the public profiles of this persona and of its contacts, and their avatars as the panel allows.
  useProfiles(s);
  const [avatars, setAvatars] = useState(config.remotePreviews);
  // FR011-05: «Enviar» again on the same message retries its operation instead of making another rumor or event.
  const operation = useRef(new SendOperation());

  // ADR 0005: a message shown here counts as read. The inbox sends the read receipt only if the panel allows it,
  // at most once per message; "delivered" receipts go when a message arrives, even in the background (FR009-03).
  const shown = useRef(new Set<string>());
  useEffect(() => {
    for (const m of messages) {
      if (shown.current.has(m.rumor.id)) continue;
      shown.current.add(m.rumor.id);
      void inbox?.markRead(m);
    }
  }, [messages, inbox]);

  // FR006-04: only contacts (keys this persona wrote to) are looked up: asking for someone else who wrote would tell
  // the relays who writes to this persona, which the gift wrap hides.
  useEffect(() => {
    const t = setTimeout(() => void lookupDmCorrespondents(s, messages.map((m) => m.sender)), 300);
    return () => clearTimeout(t);
  }, [s, messages]);

  const send = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      if (blocked) throw new Error(blocked);
      if (!nip17) throw new FeatureDisabledError('nip17');
      const recipient = normalizePubkey(to.trim());
      const opId = operation.current.for(JSON.stringify([recipient, text, fileKey(file)]));
      // FR010-02: each wrap goes to the recipient's DM relays (10050), else their NIP-65 read relays, else ours.
      // FR010-03: discovery also asks the deployment's discovery relays; a retry re-resolves the route (engine router).
      // FR011-05: the message is stored before its wraps are made, under the operation id.
      const route = { pool: s.pool, outbox: s.engine, operations: s.dmOperations, ownRelays: s.persona.relays, discoveryRelays: s.dmDiscovery, quorum: config.quorum };
      const upload = async () => {
        // DM attachments are always encrypted client-side. FR018-05: they go to the user's Blossom servers
        // (kind 10063, primary first) except image-only ones (relay media), else to the deployment blob-store.
        // FR019-03: with stripFileMetadata, an image whose metadata cannot be removed (HEIC, TIFF/RAW, an image
        // format the sanitizer does not know) is refused before anything is uploaded; other documents go as they are.
        const prepared = prepareBlob(new Uint8Array(await file!.arrayBuffer()), { sanitize: true, requireSanitizable: config.stripFileMetadata && 'images', encrypt: true, mimeType: file!.type || 'application/octet-stream', fileName: file!.name });
        const targets = uploadTargets(ws.cfg, await blossomServersOf(s), true);
        if (targets.length === 0) throw new Error('No hay servidor Blossom para adjuntos cifrados: publica tu lista de servidores o configura el blob-store.');
        const { descriptor: desc } = await uploadToServers(prepared, targets, s.signer);
        return { recipients: [recipient], url: desc.url, mimeType: prepared.mimeType, sha256: prepared.sha256, originalSha256: prepared.originalSha256, size: prepared.data.length, encryption: prepared.encryption! };
      };
      // A retry does not upload the file again: the stored message already points to it.
      const { deliveries } = file ? await messenger().sendFileOnce(opId, upload, route) : await messenger().sendDmOnce(opId, { recipients: [recipient], content: text }, route);
      operation.current.done();
      const unrouted = deliveries.find((d) => d.recipient === recipient && d.source !== 'dm-relays');
      const capped = deliveries.map((d) => cappedQuorumNotice(d.record)).find(Boolean);
      const notices = [unrouted && `Destinatario sin relays de DM: se envió a ${unrouted.source === 'nip65-read' ? 'sus relays de lectura (NIP-65)' : 'tus relays'}; la entrega es incierta.`, capped].filter(Boolean);
      if (notices.length) ws.notify(notices.join(' '), 'warning');
      setText('');
      setFile(undefined);
    } catch (err) {
      ws.notify(err instanceof FeatureDisabledError ? 'NIP-17 está deshabilitado (feature flag).' : err instanceof UnsanitizableFileError ? unsanitizableMessage(err) : (err as Error).message, 'error');
    } finally {
      setBusy(false);
    }
  };

  // FR009-03: reads the persona's DM relays again (with NIP-07, the only way messages are read).
  const refresh = async () => {
    if (!inbox) return ws.notify('NIP-17 está deshabilitado (feature flag).', 'error');
    setBusy(true);
    try {
      await inbox.sync();
    } catch (err) {
      ws.notify((err as Error).message, 'error');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Stack spacing={2}>
      <Alert severity="info">NIP-17 cifra el contenido y oculta el remitente al relay, pero no ofrece forward secrecy.</Alert>
      <Card component="form" id="dm-send" onSubmit={send}>
        <CardContent>
          <Stack spacing={2}>
            <FormControlLabel control={<Checkbox id="nip17-flag" checked={nip17} disabled={gateRejected} onChange={(e) => setNip17(e.target.checked)} />} label="Habilitar DMs NIP-17 (feature flag)" />
            <Typography id="nip17-gate" variant="body2" sx={{ color: 'text.secondary' }}>
              {!flags ? 'Sin flags de despliegue (flags.json): NIP-17 queda a criterio de esta sesión.' : flags.nip17.enabled ? `Habilitado por el gate de interoperabilidad contra ${flags.relay} (jitter de gift wrap: ${flags.nip17.timestampJitterSeconds} s).` : `Deshabilitado: el gate de interoperabilidad contra ${flags.relay} no lo aprobó.`}
            </Typography>
            <TextField id="dm-to" label="Destinatario (npub o hex)" value={to} onChange={(e) => setTo(e.target.value)} required />
            <TextField id="dm-text" label="Mensaje" multiline minRows={2} value={text} onChange={(e) => setText(e.target.value)} required={!file} />
            <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
              <Button component="label" variant="outlined">
                Adjuntar archivo cifrado
                <input hidden type="file" onChange={(e) => setFile(e.target.files?.[0])} />
              </Button>
              {file && <Chip label={file.name} onDelete={() => setFile(undefined)} />}
              <Button type="submit" variant="contained" disabled={busy || !!blocked}>
                Enviar
              </Button>
            </Stack>
            {blocked && <Alert severity="error">{blocked}</Alert>}
          </Stack>
        </CardContent>
      </Card>
      <Card>
        <CardContent>
          <Stack direction="row" sx={{ justifyContent: 'space-between', alignItems: 'center' }}>
            <Typography variant="h6" component="h2">
              Recibidos
            </Typography>
            <Button id="dm-refresh" onClick={() => void refresh()} disabled={busy}>
              Actualizar
            </Button>
          </Stack>
          {inbox && (
            <Typography id="dm-inbox-mode" variant="body2" sx={{ color: 'text.secondary' }}>
              {background
                ? 'Los mensajes y los acuses llegan en segundo plano a tus relays de DM (kind 10050), aunque estés en otra sección.'
                : 'Con NIP-07 los mensajes se leen al pulsar «Actualizar»: tu extensión puede pedir permiso para cada descifrado.'}
            </Typography>
          )}
          <AvatarsToggle pubkeys={messages.map((m) => m.sender)} shown={avatars} onShow={() => setAvatars(true)} />
          <List id="dm-log" aria-live="polite">
            {messages.map((m) => (
              <ListItem key={m.rumor.id} alignItems="flex-start">
                <AuthorAvatar pubkey={m.sender} show={avatars} />
                <ListItemText primary={m.kind === FILE_MESSAGE_KIND ? <EncryptedAttachment message={m} /> : m.rumor.content} secondary={`${m.sender === s.pubkey ? 'tú' : authorLabel(s, m.sender)} · ${new Date(m.rumor.created_at * 1000).toLocaleString()}`} />
              </ListItem>
            ))}
          </List>
        </CardContent>
      </Card>
    </Stack>
  );
}

/** Downloads the blob, verifies its hash BEFORE decrypting, then offers it as a local file (spec §13.1). */
function EncryptedAttachment({ message }: { message: DirectMessage }) {
  const ws = useWorkspace();
  const [error, setError] = useState('');
  const url = message.rumor.content;
  const sha = getTagValue(message.rumor, 'x')!;
  const keyHex = getTagValue(message.rumor, 'decryption-key');
  const nonceHex = getTagValue(message.rumor, 'decryption-nonce');
  const mime = getTagValue(message.rumor, 'file-type') ?? 'application/octet-stream';
  const save = async () => {
    try {
      const s = ws.session!;
      const decrypt = keyHex && nonceHex ? { decrypt: { keyHex, nonceHex } } : {};
      // FR018-05 / BUD-03: if the shared URL fails, try the sender's own server list (hash-verified each time).
      const bytes = await downloadFromServers(sha, { url, servers: [] }, s.signer, decrypt)
        .catch(async (err: Error) => {
          const servers = await blossomServersOf(s, message.sender);
          if (servers.length === 0) throw err;
          return downloadFromServers(sha, { servers }, s.signer, decrypt);
        })
        .then((r) => r.data);
      const a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([bytes.slice().buffer], { type: mime }));
      a.download = `adjunto-${sha.slice(0, 8)}`;
      a.click();
      URL.revokeObjectURL(a.href);
    } catch (e) {
      setError((e as Error).message);
    }
  };
  return (
    <Box component="span">
      Adjunto cifrado ({mime}) <Button size="small" onClick={() => void save()}>Descargar y verificar</Button>
      {error && <Typography color="error">{error}</Typography>}
    </Box>
  );
}
