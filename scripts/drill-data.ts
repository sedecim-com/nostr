/**
 * NFR003-02 restore drill: writes known data into every stateful component of the running stack, and
 * after backup → clean host → restore checks that all of it is back.
 *
 *   npx tsx scripts/drill-data.ts seed   STATE.json   (before scripts/backup.sh)
 *   npx tsx scripts/drill-data.ts verify STATE.json   (after scripts/restore.sh)
 *
 * Components: Buzz events (Postgres `buzz`), mirror (Postgres `sedecim`), Buzz media (SeaweedFS),
 * encrypted attachments (blob-store volume) and the secure relay (SQLite volume).
 * Env: BUZZ_RELAY_URL, MARMOT_RELAY_URL, STACK_INDEXER_URL, STACK_BLOB_URL (same as the interop gate).
 * STATE.json holds a throwaway drill key: it is written with mode 600 and never printed.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import WebSocket from 'ws';
import { bytesToHex, generateSecretKey, getTagValue, hexToBytes, type NostrEvent } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { chatMessage, createGroup, parseGroupMetadata } from '@sedecim/messaging';
import { BlossomClient, prepareBlob } from '@sedecim/blossom-client';
import { nip98Fetch } from '@sedecim/service-kit';
import { tinyPng } from '@sedecim/test-relay';

interface DrillState {
  createdAt: string;
  secretKeyHex: string;
  buzz: { groupId: string; messageId: string; text: string };
  media: { sha256: string; url: string };
  blob: { sha256: string; keyHex: string; nonceHex: string; text: string };
  secureRelay: { eventId: string; text: string };
}

const env = (name: string) => {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required`);
  return v;
};
const RELAY = env('BUZZ_RELAY_URL');
const SECURE = env('MARMOT_RELAY_URL');
const INDEXER = env('STACK_INDEXER_URL');
const BLOBS = env('STACK_BLOB_URL');
const factory = (u: string) => new WebSocket(u) as unknown as WebSocketLike;

async function eventually<T>(what: string, fn: () => Promise<T | undefined>, ms = 90_000): Promise<T> {
  const end = Date.now() + ms;
  let last: unknown;
  while (Date.now() < end) {
    try {
      const v = await fn();
      if (v !== undefined) return v;
    } catch (err) {
      last = err;
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`timeout: ${what}${last ? ` (${(last as Error).message})` : ''}`);
}

const mirrored = (sk: Uint8Array, groupId: string, id: string) =>
  eventually('mirror has the drill message', async () => {
    const res = await nip98Fetch(sk, `${INDEXER}/v1/events?kinds=9&h=${groupId}`);
    return res.status === 200 && res.json.events.some((e: NostrEvent) => e.id === id) ? true : undefined;
  });

async function seed(stateFile: string) {
  const sk = generateSecretKey();
  const signer = new LocalSigner(sk);
  const pool = new RelayPool({ webSocketFactory: factory, signer, authMode: 'auto', authTimeoutMs: 2000 });
  try {
    const stamp = new Date().toISOString();
    // Buzz (Postgres buzz): NIP-29 group + message.
    const create = await signer.signEvent(createGroup(`restore-drill-${Date.now()}`, 'open'));
    const created = await pool.publishTo(create, RELAY);
    if (!created.ok) throw new Error(`Buzz rejected the group: ${created.message}`);
    const groupId = await eventually('group metadata', async () =>
      (await pool.query([RELAY], [{ kinds: [39000], limit: 500 }], 5000)).map(parseGroupMetadata).find((m) => m?.name === getTagValue(create, 'name'))?.id,
    );
    const text = `restore drill ${stamp}`;
    const msg = await signer.signEvent(chatMessage(groupId, text));
    const sent = await pool.publishTo(msg, RELAY);
    if (!sent.ok) throw new Error(`Buzz rejected the message: ${sent.message}`);
    // Mirror (Postgres sedecim): wait until it is there, so the backup contains it.
    await mirrored(sk, groupId, msg.id);

    // Buzz media (SeaweedFS).
    const media = new BlossomClient(`${RELAY.replace(/^ws/, 'http')}/media`, signer);
    const png = await media.upload(prepareBlob(tinyPng(), { sanitize: true, mimeType: 'image/png' }));

    // Encrypted attachment (blob-store volume).
    const blobText = `adjunto del restore drill ${stamp}`;
    const prepared = prepareBlob(new TextEncoder().encode(blobText), { sanitize: false, encrypt: true });
    const blob = await new BlossomClient(BLOBS, signer).upload(prepared);

    // Secure relay (SQLite volume).
    const noteText = `secure relay drill ${stamp}`;
    const note = await signer.signEvent({ kind: 1, content: noteText, tags: [] });
    const stored = await pool.publishTo(note, SECURE);
    if (!stored.ok) throw new Error(`secure relay rejected the note: ${stored.message}`);

    const state: DrillState = {
      createdAt: stamp,
      secretKeyHex: bytesToHex(sk),
      buzz: { groupId, messageId: msg.id, text },
      media: { sha256: png.sha256, url: png.url },
      blob: { sha256: blob.sha256, keyHex: prepared.encryption!.keyHex, nonceHex: prepared.encryption!.nonceHex, text: blobText },
      secureRelay: { eventId: note.id, text: noteText },
    };
    writeFileSync(stateFile, JSON.stringify(state, null, 2) + '\n', { mode: 0o600 });
    console.log(`seeded: buzz message ${msg.id}, media ${png.sha256}, blob ${blob.sha256}, secure note ${note.id}`);
  } finally {
    pool.close();
  }
}

async function verify(stateFile: string) {
  const state = JSON.parse(readFileSync(stateFile, 'utf8')) as DrillState;
  const sk = hexToBytes(state.secretKeyHex);
  const signer = new LocalSigner(sk);
  const pool = new RelayPool({ webSocketFactory: factory, signer, authMode: 'auto', authTimeoutMs: 2000 });
  const failures: string[] = [];
  const check = async (name: string, fn: () => Promise<void>) => {
    try {
      await fn();
      console.log(`ok   ${name}`);
    } catch (err) {
      failures.push(name);
      console.log(`FAIL ${name}: ${(err as Error).message}`);
    }
  };
  try {
    await check('Buzz: seeded group message (Postgres buzz)', async () => {
      const filter = { kinds: [9], '#h': [state.buzz.groupId], limit: 100 };
      const found = await eventually('message on Buzz', async () => (await pool.query([RELAY], [filter], 5000)).find((e) => e.id === state.buzz.messageId), 60_000);
      if (found.content !== state.buzz.text) throw new Error('content differs');
    });
    await check('Mirror: seeded message (Postgres sedecim)', async () => {
      await mirrored(sk, state.buzz.groupId, state.buzz.messageId);
    });
    await check('Buzz media (SeaweedFS)', async () => {
      const media = new BlossomClient(`${RELAY.replace(/^ws/, 'http')}/media`, signer);
      if ((await media.download(state.media.sha256, { url: state.media.url })).length === 0) throw new Error('empty media');
    });
    await check('Encrypted attachment (blob-store)', async () => {
      const data = await new BlossomClient(BLOBS, signer).download(state.blob.sha256, { decrypt: { keyHex: state.blob.keyHex, nonceHex: state.blob.nonceHex } });
      if (new TextDecoder().decode(data) !== state.blob.text) throw new Error('decrypted content differs');
    });
    await check('Secure relay note (SQLite)', async () => {
      const found = (await pool.query([SECURE], [{ ids: [state.secureRelay.eventId] }], 5000)).find((e) => e.id === state.secureRelay.eventId);
      if (!found || found.content !== state.secureRelay.text) throw new Error('note not found');
    });
  } finally {
    pool.close();
  }
  if (failures.length) {
    console.error(`restore drill: ${failures.length} check(s) failed: ${failures.join('; ')}`);
    process.exit(1);
  }
  console.log('restore drill: all seeded data is back');
}

const [mode, stateFile] = process.argv.slice(2);
if ((mode !== 'seed' && mode !== 'verify') || !stateFile) {
  console.error('usage: tsx scripts/drill-data.ts seed|verify STATE.json');
  process.exit(2);
}
await (mode === 'seed' ? seed(stateFile) : verify(stateFile));
