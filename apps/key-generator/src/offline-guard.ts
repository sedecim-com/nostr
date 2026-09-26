import net from 'node:net';
import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';

export class OfflineViolation extends Error {
  constructor(what: string) {
    super(`network access attempted in offline mode: ${what}`);
    this.name = 'OfflineViolation';
  }
}

export const attempts: string[] = [];

/**
 * Hard-disables every network primitive in the process (spec §8.2, FR-003). Any attempt throws and is
 * recorded, so tests and users can verify the generator makes zero connections.
 */
export function enforceOffline(): void {
  const block = (what: string) =>
    function blocked(): never {
      attempts.push(what);
      throw new OfflineViolation(what);
    };
  net.Socket.prototype.connect = block('net.Socket.connect') as never;
  (net as { connect: unknown }).connect = block('net.connect');
  (net as { createConnection: unknown }).createConnection = block('net.createConnection');
  (tls as { connect: unknown }).connect = block('tls.connect');
  for (const fn of ['lookup', 'resolve', 'resolve4', 'resolve6', 'resolveAny'] as const) (dns as Record<string, unknown>)[fn] = block(`dns.${fn}`);
  (dns.promises as Record<string, unknown>).lookup = block('dns.promises.lookup');
  (http as { request: unknown }).request = block('http.request');
  (http as { get: unknown }).get = block('http.get');
  (https as { request: unknown }).request = block('https.request');
  (https as { get: unknown }).get = block('https.get');
  (globalThis as { fetch: unknown }).fetch = block('fetch');
  (globalThis as { WebSocket: unknown }).WebSocket = block('WebSocket');
}
