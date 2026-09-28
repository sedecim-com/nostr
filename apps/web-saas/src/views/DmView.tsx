import { useEffect, useState, type FormEvent } from 'react';
import { Alert, Box, Button, Card, CardContent, Checkbox, Chip, FormControlLabel, List, ListItem, ListItemText, Stack, TextField, Typography } from '@mui/material';
import { downloadFromServers, prepareBlob, UnsanitizableFileError, uploadToServers } from '@sedecim/blossom-client';
import { getTagValue, normalizePubkey } from '@sedecim/nostr-core';
import { APP_RECEIPT_KIND, BUZZ_PINNED_ADAPTER, createFileMessage, createReceipt, dmInboxFilter, DirectMessenger, FeatureDisabledError, FILE_MESSAGE_KIND, openDirectMessage, parseReceipt, unwrap, wrapOptionsFromFlags, type DirectMessage } from '@sedecim/messaging';
import { receiptPolicy } from '@sedecim/profiles';
import { blossomServersOf, unsanitizableMessage, uploadTargets } from '../lib/blossom';
import { cappedQuorumNotice } from '../lib/outbox';
import { shortNpub } from '../lib/session';
import { sendBlockedReason, useWorkspace } from '../lib/workspace';

/** NIP-17 DMs behind the interop-gate flag (FR-017) with client-encrypted attachments (kind 15, FR018-04). */
export function DmView() {
  const ws = useWorkspace();
  const s = ws.session!;
  const config = ws.config!;
  const flags = ws.flags;
  const gateRejected = flags ? !flags.nip17.enabled : false;
  const [nip17, setNip17] = useState(flags?.nip17.enabled ?? false);
  const [to, setTo] = useState('');
  const [text, setText] = useState('');
  const [file, setFile] = useState<File | undefined>();
  const [inbox, setInbox] = useState<DirectMessage[]>([]);
  const [busy, setBusy] = useState(false);
  const blocked = sendBlockedReason(config);
  const wrapOpts = wrapOptionsFromFlags(flags, BUZZ_PINNED_ADAPTER.wrap);
  const messenger = () => new DirectMessenger(s.signer, { nip17, readReceipts: config.readReceipts }, wrapOpts);
  const receipts = receiptPolicy(config);
  const sentReceipts = ws.book.store.collection<boolean>(`receipts-${s.persona.id}`);

  useEffect(() => setNip17(flags?.nip17.enabled ?? false), [flags]);

  const send = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      if (blocked) throw new Error(blocked);
      if (!nip17) throw new FeatureDisabledError('nip17');
      const recipient = normalizePubkey(to.trim());
      let msg;
      // FR010-02: each wrap goes to the recipient's DM relays (10050), else their NIP-65 read relays, else ours.
      const route = { pool: s.pool, outbox: s.engine, ownRelays: s.persona.relays, quorum: config.quorum };
      if (file) {
        // DM attachments are always encrypted client-side. FR018-05: they go to the user's Blossom servers
        // (kind 10063, primary first) except image-only ones (relay media), else to the deployment blob-store.
        // FR019-03: with stripFileMetadata, an image whose metadata cannot be removed (HEIC, TIFF/RAW, an image
        // format the sanitizer does not know) is refused before anything is uploaded; other documents go as they are.
        const prepared = prepareBlob(new Uint8Array(await file.arrayBuffer()), { sanitize: true, requireSanitizable: config.stripFileMetadata && 'images', encrypt: true, mimeType: file.type || 'application/octet-stream', fileName: file.name });
        const targets = uploadTargets(ws.cfg, await blossomServersOf(s), true);
        if (targets.length === 0) throw new Error('No hay servidor Blossom para adjuntos cifrados: publica tu lista de servidores o configura el blob-store.');
        const { descriptor: desc } = await uploadToServers(prepared, targets, s.signer);
        msg = await createFileMessage(s.signer, { recipients: [recipient], url: desc.url, mimeType: prepared.mimeType, sha256: prepared.sha256, originalSha256: prepared.originalSha256, size: prepared.data.length, encryption: prepared.encryption! }, wrapOpts);
      }
      const { deliveries } = file ? await messenger().deliver(msg!, route) : await messenger().send({ recipients: [recipient], content: text }, route);
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

  const refresh = async () => {
    const wraps = await s.pool.query(s.persona.relays, [dmInboxFilter(s.pubkey)], 8000);
    const opened: DirectMessage[] = [];
    for (const w of wraps) {
      try {
        if (!nip17) throw new FeatureDisabledError('nip17');
        const u = await unwrap(s.signer, w);
        // FR009-02: receipts from the actual recipient advance our outbox to RECIPIENT_ACKED / READ.
        if (u.rumor.kind === APP_RECEIPT_KIND) {
          const r = parseReceipt(u);
          if (r && r.from !== s.pubkey) await s.engine.applyReceipt(r);
          continue;
        }
        if (u.rumor.kind === 14 || u.rumor.kind === FILE_MESSAGE_KIND) opened.push(await openDirectMessage(s.signer, w));
      } catch {
        /* not for us, or not a message */
      }
    }
    opened.sort((a, b) => a.rumor.created_at - b.rumor.created_at);
    const unique = [...new Map(opened.map((m) => [m.rumor.id, m])).values()];
    setInbox(unique);
    // ADR 0005: gift-wrapped receipts, only as the profile allows and at most once per message.
    for (const m of unique) {
      if (m.sender === s.pubkey) continue;
      for (const type of ['delivered', 'read'] as const) {
        if (!receipts[type] || (await sentReceipts.get(`${type}:${m.rumor.id}`))) continue;
        const r = await createReceipt(s.signer, m.sender, m.rumor.id, type, wrapOpts);
        await s.engine.submit({ event: r.event }, { relays: s.persona.relays, quorum: 1 });
        await sentReceipts.put(`${type}:${m.rumor.id}`, true);
      }
    }
  };

  return (
    <Stack spacing={2}>
      <Alert severity="info">NIP-17 cifra el contenido y oculta el remitente al relay, pero no ofrece forward secrecy.</Alert>
      <Card component="form" id="dm-send" onSubmit={send}>
        <CardContent>
          <Stack spacing={2}>
            <FormControlLabel control={<Checkbox id="nip17-flag" checked={nip17} disabled={gateRejected} onChange={(e) => setNip17(e.target.checked)} />} label="Habilitar DMs NIP-17 (feature flag)" />
            <Typography id="nip17-gate" variant="body2" color="text.secondary">
              {!flags ? 'Sin flags de despliegue (flags.json): NIP-17 queda a criterio de esta sesión.' : flags.nip17.enabled ? `Habilitado por el gate de interoperabilidad contra ${flags.relay} (jitter de gift wrap: ${flags.nip17.timestampJitterSeconds} s).` : `Deshabilitado: el gate de interoperabilidad contra ${flags.relay} no lo aprobó.`}
            </Typography>
            <TextField id="dm-to" label="Destinatario (npub o hex)" value={to} onChange={(e) => setTo(e.target.value)} required />
            <TextField id="dm-text" label="Mensaje" multiline minRows={2} value={text} onChange={(e) => setText(e.target.value)} required={!file} />
            <Stack direction="row" spacing={1} alignItems="center">
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
          <Stack direction="row" justifyContent="space-between" alignItems="center">
            <Typography variant="h6" component="h2">
              Recibidos
            </Typography>
            <Button id="dm-refresh" onClick={() => void refresh()}>
              Actualizar
            </Button>
          </Stack>
          <List id="dm-log" aria-live="polite">
            {inbox.map((m) => (
              <ListItem key={m.rumor.id} alignItems="flex-start">
                <ListItemText primary={m.kind === FILE_MESSAGE_KIND ? <EncryptedAttachment message={m} /> : m.rumor.content} secondary={`${m.sender === s.pubkey ? 'tú' : shortNpub(m.sender)} · ${new Date(m.rumor.created_at * 1000).toLocaleString()}`} />
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
