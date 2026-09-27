import { createServer, type Http2Server, type ServerHttp2Stream } from 'node:http2';
import type { AddressInfo } from 'node:net';
import { rename, readFile, writeFile } from 'node:fs/promises';
import type { Pool } from '@sedecim/service-kit';

/**
 * FR023-04: keeps the NIP-42 allowlist of the relays in sync with GET /v1/relay/allowlist.
 * - Buzz: rows of its `pubkey_allowlist` table (read on every NIP-42 AUTH when BUZZ_PUBKEY_ALLOWLIST=true,
 *   no restart needed). Only rows tagged with our note are managed; manual rows are left alone.
 * - secure-relay (nostr-rs-relay): event admission over gRPC (nauthz) by the NIP-42 authenticated pubkey.
 * - Optionally a plain file (one hex pubkey per line) for other relays.
 * A failed fetch keeps the last applied list (never wipes the allowlist on a transient error).
 */

export interface AllowlistSink {
  readonly name: string;
  apply(pubkeys: string[]): Promise<{ added: number; removed: number }>;
}

export const BUZZ_ALLOWLIST_NOTE = 'policy-engine';
const HEX64 = /^[0-9a-f]{64}$/;

export class BuzzAllowlistSink implements AllowlistSink {
  readonly name = 'buzz';
  /** `hosts`: community hosts to manage (Buzz is multi-tenant by Host); empty = every active community. */
  constructor(private readonly pool: Pool, private readonly hosts: string[] = []) {}

  async apply(pubkeys: string[]) {
    const c = await this.pool.connect();
    let added = 0;
    let removed = 0;
    try {
      await c.query('BEGIN');
      const { rows } = this.hosts.length
        ? await c.query("SELECT id FROM communities WHERE deletion_state = 'active' AND archived_at IS NULL AND host = ANY($1)", [this.hosts])
        : await c.query("SELECT id FROM communities WHERE deletion_state = 'active' AND archived_at IS NULL");
      for (const { id } of rows) {
        const ins = await c.query(
          `INSERT INTO pubkey_allowlist (community_id, pubkey, note) SELECT $1, decode(p, 'hex'), $3 FROM unnest($2::text[]) AS p ON CONFLICT DO NOTHING`,
          [id, pubkeys, BUZZ_ALLOWLIST_NOTE],
        );
        const del = await c.query(`DELETE FROM pubkey_allowlist WHERE community_id = $1 AND note = $3 AND NOT (encode(pubkey, 'hex') = ANY($2::text[]))`, [id, pubkeys, BUZZ_ALLOWLIST_NOTE]);
        added += ins.rowCount ?? 0;
        removed += del.rowCount ?? 0;
      }
      await c.query('COMMIT');
    } catch (e) {
      await c.query('ROLLBACK');
      throw e;
    } finally {
      c.release();
    }
    return { added, removed };
  }
}

/** One hex pubkey per line, written atomically and only when it changes. */
export class FileAllowlistSink implements AllowlistSink {
  readonly name = 'file';
  constructor(private readonly path: string) {}

  async apply(pubkeys: string[]) {
    const before = new Set((await readFile(this.path, 'utf8').catch(() => '')).split('\n').filter(Boolean));
    const next = pubkeys.map((p) => `${p}\n`).join('');
    const added = pubkeys.filter((p) => !before.has(p)).length;
    const removed = [...before].filter((p) => !pubkeys.includes(p)).length;
    if (added || removed || before.size !== pubkeys.length) {
      await writeFile(`${this.path}.tmp`, next, { mode: 0o644 });
      await rename(`${this.path}.tmp`, this.path);
    }
    return { added, removed };
  }
}

// --- nauthz gRPC admission (nostr-rs-relay `[grpc] event_admission_server`) --------------------------

function readVarint(b: Uint8Array, o: number): [number, number] {
  let v = 0;
  let shift = 0;
  for (;;) {
    if (o >= b.length || shift > 49) throw new Error('bad varint');
    const x = b[o++]!;
    v += (x & 0x7f) * 2 ** shift;
    if (!(x & 0x80)) return [v, o];
    shift += 7;
  }
}

/** Iterates the fields of a protobuf message: [field number, wire type, value (varint or bytes)]. */
function* protoFields(b: Uint8Array): Generator<[number, number, number | Uint8Array]> {
  let o = 0;
  while (o < b.length) {
    const [key, o1] = readVarint(b, o);
    const field = Math.floor(key / 8);
    const wire = key & 7;
    if (wire === 0) {
      const [v, o2] = readVarint(b, o1);
      o = o2;
      yield [field, wire, v];
    } else if (wire === 2) {
      const [len, o2] = readVarint(b, o1);
      if (o2 + len > b.length) throw new Error('truncated field');
      o = o2 + len;
      yield [field, wire, b.subarray(o2, o)];
    } else if (wire === 1 || wire === 5) {
      o = o1 + (wire === 1 ? 8 : 4);
      if (o > b.length) throw new Error('truncated field');
    } else throw new Error(`unsupported wire type ${wire}`);
  }
}

export interface AdmissionRequest {
  authPubkey?: string;
  eventPubkey?: string;
  kind?: number;
}

export function decodeEventRequest(msg: Uint8Array): AdmissionRequest {
  const out: AdmissionRequest = {};
  for (const [f, w, v] of protoFields(msg)) {
    if (f === 5 && w === 2) out.authPubkey = Buffer.from(v as Uint8Array).toString('hex');
    if (f === 1 && w === 2) {
      for (const [ef, ew, ev] of protoFields(v as Uint8Array)) {
        if (ef === 2 && ew === 2) out.eventPubkey = Buffer.from(ev as Uint8Array).toString('hex');
        if (ef === 4 && ew === 0) out.kind = ev as number;
      }
    }
  }
  return out;
}

function varint(n: number): number[] {
  const out: number[] = [];
  while (n > 0x7f) {
    out.push((n & 0x7f) | 0x80);
    n = Math.floor(n / 128);
  }
  out.push(n);
  return out;
}

/** EventReply { decision = 1; message = 2 } — Decision: 1 PERMIT, 2 DENY. */
export function encodeEventReply(permit: boolean, message?: string): Uint8Array {
  const bytes = [0x08, permit ? 1 : 2];
  if (message) {
    const m = Buffer.from(message);
    bytes.push(0x12, ...varint(m.length), ...m);
  }
  return new Uint8Array(bytes);
}

/**
 * gRPC `nauthz.Authorization/EventAdmit` server (h2c). Permits an event only when the session is NIP-42
 * authenticated by an allowlisted pubkey, whatever the event author (gift wraps and MLS messages are
 * signed by ephemeral keys, so an author whitelist would break them).
 */
export class AdmissionServer {
  private allowed = new Set<string>();
  private server?: Http2Server;
  ready = false;

  set(pubkeys: string[]) {
    this.allowed = new Set(pubkeys);
    this.ready = true;
  }

  decide(r: AdmissionRequest): { permit: boolean; message?: string } {
    if (!r.authPubkey) return { permit: false, message: 'auth-required: NIP-42 authentication required to publish' };
    if (!this.allowed.has(r.authPubkey)) return { permit: false, message: 'restricted: pubkey not in the institutional allowlist' };
    return { permit: true };
  }

  private handle(stream: ServerHttp2Stream, path: string) {
    stream.on('error', () => undefined); // a peer reset must not crash the job
    const trailersOnly = (status: number, message: string) => {
      stream.respond({ ':status': 200, 'content-type': 'application/grpc', 'grpc-status': String(status), 'grpc-message': encodeURIComponent(message) }, { endStream: true });
    };
    if (path !== '/nauthz.Authorization/EventAdmit') {
      stream.resume();
      return trailersOnly(12, 'unimplemented');
    }
    const chunks: Buffer[] = [];
    let size = 0;
    stream.on('data', (c: Buffer) => {
      size += c.length;
      if (size > 1_048_576) stream.close();
      else chunks.push(c);
    });
    stream.on('end', () => {
      try {
        const body = Buffer.concat(chunks);
        if (body.length < 5) throw new Error('short frame');
        if (body[0] !== 0) return trailersOnly(12, 'compression not supported');
        const len = body.readUInt32BE(1);
        if (body.length < 5 + len) throw new Error('truncated frame');
        const d = this.decide(decodeEventRequest(body.subarray(5, 5 + len)));
        const reply = encodeEventReply(d.permit, d.message);
        const frame = Buffer.alloc(5 + reply.length);
        frame.writeUInt32BE(reply.length, 1);
        frame.set(reply, 5);
        stream.respond({ ':status': 200, 'content-type': 'application/grpc' }, { waitForTrailers: true });
        stream.on('wantTrailers', () => stream.sendTrailers({ 'grpc-status': '0' }));
        stream.end(frame);
      } catch (e) {
        trailersOnly(3, (e as Error).message);
      }
    });
  }

  async listen(port = 0, host = '127.0.0.1'): Promise<number> {
    this.server = createServer();
    this.server.on('stream', (stream, headers) => this.handle(stream, String(headers[':path'])));
    await new Promise<void>((r) => this.server!.listen(port, host, () => r()));
    return (this.server.address() as AddressInfo).port;
  }

  async close() {
    await new Promise<void>((r) => (this.server ? this.server.close(() => r()) : r()));
  }
}

export interface AllowlistSyncOptions {
  fetch: () => Promise<string[]>;
  sinks: AllowlistSink[];
  admission?: AdmissionServer;
  /** Service identities (indexer, gateway) always allowlisted so the mirror keeps working. */
  extraPubkeys?: string[];
  intervalMs?: number;
  log?: (msg: string, fields?: Record<string, unknown>) => void;
}

export class AllowlistSync {
  lastSyncAt?: number;
  lastError?: string;
  current: string[] = [];
  private timer?: ReturnType<typeof setInterval>;

  constructor(private readonly opts: AllowlistSyncOptions) {}

  /** Fetches and applies once. On a fetch error nothing is changed (the last list stays in force). */
  async syncOnce(): Promise<string[]> {
    let list: string[];
    try {
      list = [...new Set([...(await this.opts.fetch()), ...(this.opts.extraPubkeys ?? [])])].filter((p) => HEX64.test(p)).sort();
    } catch (e) {
      this.lastError = `fetch: ${(e as Error).message}`;
      this.opts.log?.('allowlist fetch failed, keeping the last list', { error: this.lastError });
      return this.current;
    }
    this.opts.admission?.set(list);
    const errors: string[] = [];
    for (const s of this.opts.sinks) {
      try {
        const r = await s.apply(list);
        if (r.added || r.removed) this.opts.log?.('allowlist applied', { sink: s.name, ...r, total: list.length });
      } catch (e) {
        errors.push(`${s.name}: ${(e as Error).message}`);
      }
    }
    this.current = list;
    this.lastSyncAt = Date.now();
    this.lastError = errors.join('; ') || undefined;
    if (this.lastError) this.opts.log?.('allowlist sink failed', { error: this.lastError });
    return list;
  }

  start() {
    void this.syncOnce();
    this.timer = setInterval(() => void this.syncOnce(), this.opts.intervalMs ?? 30_000);
    this.timer.unref?.();
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
  }
}
