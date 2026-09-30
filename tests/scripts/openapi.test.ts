/**
 * OPS-14: the OpenAPI documents of the services (docs/openapi, scripts/openapi.ts). They are generated from the routes
 * each service registers, so a route nobody documented, or a document that no longer matches the code, fails here and
 * in the CI `docs` job.
 */
import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

interface Operation {
  operationId: string;
  summary: string;
  parameters?: Array<{ name: string; in: string; required: boolean }>;
  security: Array<Record<string, string[]>>;
  responses: Record<string, { content?: Record<string, { schema: { $ref: string } }> }>;
}
interface OpenApi {
  openapi: string;
  info: { title: string; version: string };
  servers: Array<{ url: string }>;
  paths: Record<string, Record<string, Operation>>;
  components: { securitySchemes: Record<string, unknown> };
}

const root = new URL('../..', import.meta.url).pathname;
const dir = join(root, 'docs/openapi');
const docs = new Map(
  readdirSync(dir)
    .filter((f) => f.endsWith('.json'))
    .map((f) => [f.replace(/\.json$/, ''), JSON.parse(readFileSync(join(dir, f), 'utf8')) as OpenApi]),
);
const op = (service: string, path: string, method: string) => docs.get(service)!.paths[path]![method]!;

describe('OpenAPI of the services (OPS-14)', () => {
  it('matches the routes each service registers, every one with its summary', () => {
    const out = spawnSync(join(root, 'node_modules/.bin/tsx'), ['scripts/openapi.ts', '--check'], { cwd: root, encoding: 'utf8' });
    expect(out.status, out.stderr).toBe(0);
    expect(out.stdout).toMatch(/openapi ok: 9 servicios/);
  }, 60_000);

  it('declares for every operation its summary, authentication, path parameters and errors', () => {
    expect([...docs.keys()].sort()).toEqual(['blob-store', 'continuity-vault', 'identity-service', 'indexer', 'managed-signer', 'notification-gateway', 'policy-engine', 'relay-allowlist', 'rotation-worker']);
    for (const [service, d] of docs) {
      expect(d.openapi).toBe('3.1.0');
      expect(d.info.title).toBe(service);
      expect(d.servers).toHaveLength(1);
      const schemes = Object.keys(d.components.securitySchemes);
      const ids = new Set<string>();
      for (const [path, ops] of Object.entries(d.paths)) {
        for (const [method, o] of Object.entries(ops)) {
          const where = `${service} ${method.toUpperCase()} ${path}`;
          expect(o.summary, where).toMatch(/\S/);
          expect(ids.has(o.operationId), where).toBe(false);
          ids.add(o.operationId);
          for (const alt of o.security) for (const s of Object.keys(alt)) expect(schemes, where).toContain(s);
          expect((o.parameters ?? []).map((p) => p.name), where).toEqual([...path.matchAll(/\{([^}]+)\}/g)].map((m) => m[1]));
          expect(o.responses['4XX']?.content?.['application/json']?.schema.$ref, where).toBe('#/components/schemas/Error');
        }
      }
    }
  });

  it('says how each sensitive route authenticates', () => {
    expect(op('policy-engine', '/v1/evaluate', 'post').security).toEqual([{ serviceToken: [] }]);
    expect(op('policy-engine', '/v1/subjects', 'get').security).toEqual([{ nip98: [] }]);
    expect(op('policy-engine', '/v1/rotations', 'get').security).toEqual([{ nip98: [] }, { serviceToken: [] }]);
    // The managed-signer authenticates in its handlers: the document names the tokens it takes.
    expect(op('managed-signer', '/v1/keys/{id}/sign', 'post').security).toEqual([{ acceso: [] }, { deviceSession: [] }]);
    expect(op('managed-signer', '/v1/device-sessions', 'post').security).toEqual([{ acceso: [] }]);
    expect(op('managed-signer', '/v1/devices/{id}/revoke', 'post').security).toEqual([{ revocationToken: [] }]);
    expect(op('continuity-vault', '/v1/archives/{id}', 'put').security).toEqual([{ nip98: [] }, { acceso: [] }]);
    // NIP-98 optional: anonymous reads of public data, or signed reads.
    expect(op('indexer', '/v1/events', 'get').security).toEqual([{}, { nip98: [] }]);
    expect(op('blob-store', '/upload', 'put').security).toEqual([{ blossom: [] }]);
    expect(op('policy-engine', '/health', 'get').security).toEqual([]);
  });
});
