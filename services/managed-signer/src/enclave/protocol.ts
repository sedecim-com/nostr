import { connect, createServer, type ListenOptions, type NetConnectOpts, type Server, type Socket } from 'node:net';
import type { EventTemplate, NostrEvent } from '@sedecim/nostr-core';

/**
 * Parent <-> enclave protocol. Frames are a 4-byte big-endian length followed by UTF-8 JSON; one request per
 * connection. In production the channel is vsock (the enclave has no other I/O): Node has no AF_VSOCK, so a
 * socat bridge on each side maps vsock to a local socket (docs/managed-enclave.md). Tests use a unix socket.
 *
 * No response ever carries key material: the parent only gets public keys, sealed (KMS-encrypted) blobs,
 * signatures/events, NIP-44 results and password-encrypted exports (FR-026).
 */

/** Temporary credentials of the parent's IAM principal, forwarded so the enclave can call KMS via vsock-proxy. */
export interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}

type WithCreds<T> = T & { credentials?: AwsCredentials };

export type EnclaveRequest =
  | { op: 'attest'; nonce: string }
  // `owner` (`${issuer}#${sub}`, as the managed-signer names the key owner) is sealed into the key: export only opens it
  // for a proof of that owner (FR005-09).
  | WithCreds<{ op: 'generate'; owner: string }>
  | WithCreds<{ op: 'import'; owner: string; ncryptsec: string; password: string }>
  | WithCreds<{ op: 'sign'; sealed: string; pubkey: string; template: EventTemplate }>
  | WithCreds<{ op: 'nip44'; sealed: string; pubkey: string; mode: 'encrypt' | 'decrypt'; peer: string; data: string }>
  // `proof` is the owner's Acceso token, verified inside the enclave (FR005-09).
  | WithCreds<{ op: 'export'; sealed: string; pubkey: string; password: string; logN: number; proof: string }>;

export type EnclaveResult =
  | { document: string }
  | { pubkey: string; sealed: string }
  | { event: NostrEvent }
  | { result: string }
  | { ncryptsec: string };

/** `status` is set when the enclave turned the request down on purpose (a 4xx of the caller); absent for its own failures. */
export type EnclaveResponse = ({ ok: true } & EnclaveResult) | { ok: false; error: string; status?: 400 | 401 | 403 };

export const MAX_FRAME = 1 << 20;

export function encodeFrame(msg: unknown): Buffer {
  const body = Buffer.from(JSON.stringify(msg), 'utf8');
  if (body.length > MAX_FRAME) throw new Error('frame too large');
  const head = Buffer.alloc(4);
  head.writeUInt32BE(body.length);
  return Buffer.concat([head, body]);
}

/** Reads one frame from a socket. */
export function readFrame<T>(sock: Socket, timeoutMs = 30_000): Promise<T> {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const done = (err?: Error, v?: T) => {
      clearTimeout(timer);
      sock.off('data', onData).off('error', onError).off('end', onEnd);
      if (err) reject(err);
      else resolve(v as T);
    };
    const onData = (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length < 4) return;
      const n = buf.readUInt32BE(0);
      if (n > MAX_FRAME) return done(new Error('frame too large'));
      if (buf.length < 4 + n) return;
      try {
        done(undefined, JSON.parse(buf.subarray(4, 4 + n).toString('utf8')) as T);
      } catch (err) {
        done(err as Error);
      }
    };
    const onError = (err: Error) => done(err);
    const onEnd = () => done(new Error('connection closed before a full frame'));
    const timer = setTimeout(() => done(new Error('enclave channel timeout')), timeoutMs);
    sock.on('data', onData).on('error', onError).on('end', onEnd);
  });
}

/** How the parent reaches the enclave. */
export interface EnclaveTransport {
  request(req: EnclaveRequest): Promise<EnclaveResponse>;
}

/** Socket transport (unix socket or TCP bridged to vsock by socat). */
export function socketTransport(opts: NetConnectOpts, timeoutMs = 30_000): EnclaveTransport {
  return {
    request(req) {
      return new Promise((resolve, reject) => {
        const sock = connect(opts);
        sock.once('error', reject);
        sock.once('connect', () => {
          readFrame<EnclaveResponse>(sock, timeoutMs).then(resolve, reject).finally(() => sock.destroy());
          sock.write(encodeFrame(req));
        });
      });
    },
  };
}

export interface RequestHandler {
  handle(req: EnclaveRequest): Promise<EnclaveResponse>;
}

/**
 * In-process transport: still serializes through JSON so the boundary is the same as over vsock. Only for
 * tests and the simulated (insecure) mode.
 */
export function inProcessTransport(handler: RequestHandler): EnclaveTransport {
  return { request: async (req) => JSON.parse(JSON.stringify(await handler.handle(JSON.parse(JSON.stringify(req)) as EnclaveRequest))) as EnclaveResponse };
}

/** Enclave-side listener. */
export async function serveEnclave(handler: RequestHandler, listen: ListenOptions): Promise<Server> {
  const server = createServer((sock) => {
    sock.on('error', () => sock.destroy());
    readFrame<EnclaveRequest>(sock)
      .then((req) => handler.handle(req))
      .catch((err: Error) => ({ ok: false as const, error: err.message }))
      .then((res) => sock.end(encodeFrame(res)));
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(listen, () => resolve());
  });
  return server;
}
