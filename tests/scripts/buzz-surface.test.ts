import { afterEach, describe, expect, it } from 'vitest';
import { createServer, type IncomingHttpHeaders, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { readFileSync } from 'node:fs';
import { ROUTES, edgeViolations, probe, relayViolations, surfaceTable, type SurfaceRoute } from '../../scripts/buzz-surface-routes';

const root = new URL('../../', import.meta.url);
const read = (path: string) => readFileSync(new URL(path, root), 'utf8');
const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
/** `/git/{owner}/{repo}/info/refs` as a pattern over any concrete path. */
const asPattern = (path: string) => path.split(/\{[^}]+\}/).map(esc).join('[^\\s"/?]+');
const matches = (route: SurfaceRoute, method: string, path: string) => route.method === method && new RegExp(`^${asPattern(route.path)}$`).test(path);

let server: Server | undefined;
afterEach(() => new Promise<void>((resolve) => (server ? server.close(() => resolve()) : resolve())));
/** What the stand-in received, to check the probe asks the way a client would and sends no credentials. */
let seen: { method: string; url: string; body: string; headers: IncomingHttpHeaders }[] = [];
/** A stand-in for the relay or the edge: `answer` decides status and body for each request. */
async function serve(answer: (method: string, path: string, route?: SurfaceRoute) => [number, string]): Promise<string> {
  seen = [];
  server = createServer((req, res) => {
    let body = '';
    req.on('data', (chunk: Buffer) => (body += chunk.toString()));
    req.on('end', () => {
      const path = new URL(req.url ?? '/', 'http://x').pathname;
      const route = ROUTES.find((x) => matches(x, req.method ?? 'GET', path));
      seen.push({ method: req.method ?? 'GET', url: req.url ?? '/', body, headers: req.headers });
      const [status, text] = answer(req.method ?? 'GET', path, route);
      res.writeHead(status, { 'content-type': 'text/plain' });
      res.end(req.method === 'HEAD' ? undefined : text);
    });
  });
  await new Promise<void>((resolve) => server!.listen(0, '127.0.0.1', resolve));
  return `http://127.0.0.1:${(server!.address() as AddressInfo).port}`;
}
/**
 * The relay as configured here, as the pinned image answered it in CI: public routes answer, the rest ask for credentials,
 * what is off does not exist, and the operator API, with no RELAY_OPERATOR_API_ORIGIN, refuses with a generic 500.
 */
const buzz = (method: string, path: string, route?: SurfaceRoute): [number, string] =>
  !route || route.exposure === 'disabled'
    ? [404, '{"error":"not found"}']
    : route.unconfigured
      ? [route.unconfigured, '{"error":"internal server error"}']
      : route.exposure === 'public'
        ? [200, '{}']
        : [401, '{"error":"auth required"}'];

describe('Buzz attack surface (SEC-12)', () => {
  it('has a route table without duplicates, where only / and /media are forwarded by the edge', () => {
    const keys = ROUTES.map((x) => `${x.method} ${x.path}`);
    expect(new Set(keys).size).toBe(keys.length);
    const forwarded = ROUTES.filter((x) => x.edge === 'allow').map((x) => `${x.method} ${x.path}`);
    expect(forwarded).toEqual(['GET /', 'PUT /media/upload', 'GET /media/{sha256_ext}', 'HEAD /media/{sha256_ext}']);
    // Nothing that needs an operator key, git, the admin API or a secret is forwarded.
    for (const x of ROUTES.filter((y) => ['operator', 'internal', 'disabled'].includes(y.exposure))) expect(x.edge).toBe('deny');
    // The one server error a route may answer is the refusal of the operator API that is not configured.
    expect(ROUTES.filter((x) => x.unconfigured).map((x) => [x.group, x.unconfigured])).toEqual(Array(9).fill(['operator', 500]));
    expect(ROUTES.filter((x) => x.group === 'operator')).toHaveLength(9);
  });

  describe('the relay, probed without credentials', () => {
    it('passes when public routes answer and the rest ask for credentials or do not exist', async () => {
      const url = await serve(buzz);
      const results = await probe(url);
      expect(results).toHaveLength(ROUTES.length);
      expect(relayViolations(results)).toEqual([]);
      // Each route was asked with its own method and a concrete path, no credentials sent.
      expect(results.find((p) => p.route.path === '/git/{owner}/{repo}/git-receive-pack')?.url).toMatch(/\/git\/x\/x\/git-receive-pack$/);
      expect(results.find((p) => p.route.path === '/media/{sha256_ext}' && p.route.method === 'GET')?.url).toMatch(/\/media\/a{64}\.png$/);
    });

    it('asks with ids, queries and bodies a handler accepts, so that what answers is the authentication, and sends no credentials', async () => {
      const zero = '00000000-0000-4000-8000-000000000000';
      await probe(await serve(buzz));
      const asked = (method: string, path: string) => seen.find((x) => x.method === method && new URL(x.url, 'http://x').pathname === path)!;
      expect(asked('GET', `/workflows/${zero}/runs`)).toBeDefined();
      expect(asked('GET', `/workflows/${zero}/runs/${zero}/approvals`)).toBeDefined();
      expect(asked('POST', `/hooks/${zero}`)).toBeDefined();
      expect(asked('GET', `/huddle/${zero}/audio`)).toBeDefined();
      expect(new URL(asked('GET', '/operator/communities').url, 'http://x').searchParams.get('owner_pubkey')).toMatch(/^[0-9a-f]{64}$/);
      expect(new URL(asked('GET', '/operator/communities/availability').url, 'http://x').searchParams.get('host')).toBe('probe.invalid');
      expect(JSON.parse(asked('POST', '/_mesh/demo/echo').body)).toEqual({ community_id: zero, session_id: zero, payload: 'x' });
      // The rest of the POSTs carry an empty JSON object; uploads and reads carry nothing.
      expect(asked('POST', '/events').body).toBe('{}');
      expect(asked('PUT', '/media/upload').body).toBe('');
      for (const x of seen) expect([x.headers.authorization, x.headers.cookie], `${x.method} ${x.url}`).toEqual([undefined, undefined]);
    });

    it('accepts the 500 that the operator routes answer while the operator API is not configured, and no other server error', async () => {
      const results = await probe(await serve(buzz));
      const operator = results.filter((p) => p.route.group === 'operator');
      expect(operator).toHaveLength(9);
      expect(operator.map((p) => p.status)).toEqual(Array(9).fill(500));
      expect(relayViolations(results)).toEqual([]);
    });

    it('fails another server error from an operator route, and a 500 from any route that does not document it', async () => {
      const url = await serve((m, p, route) => (route?.path === '/operator/communities/delete' ? [502, 'bad gateway'] : route?.path === '/events' ? [500, 'boom'] : buzz(m, p, route)));
      expect(relayViolations(await probe(url))).toEqual([
        'POST /events: 500, a server error for a request without credentials',
        'POST /operator/communities/delete: 502, a server error for a request without credentials',
      ]);
    });

    it('fails a route that is off here when it answers something other than the 404 of a path that does not exist', async () => {
      const url = await serve((m, p, route) => (route?.path === '/api/admin/v1/communities' ? [401, '{"error":"auth required"}'] : route?.path === '/_mesh/demo/echo' ? [422, 'bad body'] : buzz(m, p, route)));
      expect(relayViolations(await probe(url))).toEqual([
        'POST /_mesh/demo/echo: 422, a route that is off here should answer 404',
        'GET /api/admin/v1/communities: 401, a route that is off here should answer 404',
      ]);
    });

    it('fails a route that needs credentials and answers 2xx without them', async () => {
      const url = await serve((m, p, route) => (route?.path === '/operator/communities' && m === 'GET' ? [200, '[]'] : buzz(m, p, route)));
      expect(relayViolations(await probe(url))).toEqual(['GET /operator/communities: 200 without credentials, but it is operator']);
    });

    it('fails a route that answers 3xx or 5xx without credentials', async () => {
      const url = await serve((m, p, route) => (route?.path === '/events' ? [500, 'boom'] : route?.path === '/query' ? [302, ''] : buzz(m, p, route)));
      const bad = relayViolations(await probe(url));
      expect(bad).toContain('POST /events: 500, a server error for a request without credentials');
      expect(bad).toContain('POST /query: 302 without credentials, but it is authenticated');
    });

    it('lets public routes answer any client error', async () => {
      const url = await serve((m, p, route) => (route?.group === 'invites' && route.exposure === 'public' ? [403, 'no'] : buzz(m, p, route)));
      expect(relayViolations(await probe(url))).toEqual([]);
    });

    it('fails a path that no route has when it answers', async () => {
      const url = await serve((m, p, route) => (p === '/zz-surface-probe' ? [200, 'hello'] : buzz(m, p, route)));
      expect(relayViolations(await probe(url))).toEqual(['GET /zz-surface-probe: 200 without credentials, but it is disabled', 'POST /zz-surface-probe: 200 without credentials, but it is disabled']);
    });
  });

  describe('through the public edge', () => {
    const edge = (method: string, path: string, route?: SurfaceRoute): [number, string] => (route?.edge === 'allow' ? buzz(method, path, route) : [404, 'not found\n']);

    it('passes when only the allowed routes reach Buzz and the rest get the edge 404', async () => {
      expect(edgeViolations(await probe(await serve(edge)))).toEqual([]);
    });

    it('fails a route the edge lets through to Buzz, even when Buzz answers 404 itself', async () => {
      const url = await serve((m, p, route) => (route?.path === '/git/{owner}/{repo}/info/refs' ? [404, '{"error":"no such repo"}'] : route?.path === '/operator/communities' && m === 'POST' ? [401, '{}'] : edge(m, p, route)));
      expect(edgeViolations(await probe(url))).toEqual([
        'POST /operator/communities: 401, the edge should answer its own 404',
        'GET /git/{owner}/{repo}/info/refs: 404, the edge should answer its own 404',
      ]);
    });

    it('fails an edge that denies what clients use', async () => {
      const url = await serve((m, p, route) => (route?.path === '/media/upload' ? [404, 'not found\n'] : edge(m, p, route)));
      expect(edgeViolations(await probe(url))).toEqual(['PUT /media/upload: the edge denies a route clients use']);
    });
  });

  describe('the edge configuration', () => {
    it('nginx forwards to the relay only / and /media/, and answers 404 itself to the rest', () => {
      const block = read('deploy/k8s/base/files/core-server.conf')
        .split(/\n(?=server \{)/)
        .find((b) => b.includes('-relay\\.;'));
      expect(block).toBeDefined();
      const locations = [...block!.matchAll(/location\s+(=\s+)?(\S+)\s*\{([^}]*)\}/g)].map((m) => ({
        exact: Boolean(m[1]),
        path: m[2],
        proxied: /proxy_pass\s+http:\/\/relay:3000;/.test(m[3]!),
        returns404: /return 404 'not found\\n';/.test(m[3]!),
      }));
      expect(locations).toEqual([
        { exact: true, path: '/', proxied: true, returns404: false },
        { exact: true, path: '/media', proxied: false, returns404: true },
        { exact: false, path: '/media/', proxied: true, returns404: false },
        { exact: false, path: '/', proxied: false, returns404: true },
      ]);
      expect(block!.match(/proxy_pass/g)).toHaveLength(2);
    });

    it('Caddy forwards to the relay only / and /media/*, and answers 404 itself to the rest', () => {
      const block = /^relay\.\{\$DOMAIN\} \{\n([\s\S]*?)\n\}/m.exec(read('infra/caddy/Caddyfile'))?.[1];
      expect(block).toBeDefined();
      expect(block).toContain('@buzz_public {\n\t\tpath /\n\t\tpath /media/*\n\t}');
      expect(block).toContain('handle @buzz_public {\n\t\treverse_proxy relay:3000\n\t}');
      expect(block).toContain('handle {\n\t\trespond "not found" 404\n\t}');
      expect(block!.match(/reverse_proxy/g)).toHaveLength(1);
    });

    it('compose publishes only the public port of the relay, not the health or metrics ones', () => {
      const relay = /\n {2}relay:\n([\s\S]*?)(?=\n {2}[a-z][a-z-]*:\n)/.exec(read('docker-compose.yml'))?.[1] ?? '';
      expect(relay.match(/^ {4}ports:.*$/gm)).toEqual(['    ports: ["${RELAY_PORT:-3000}:3000"]']);
    });

    it('scripts/edge-check.sh asks for every route the edge denies', () => {
      const script = read('scripts/edge-check.sh');
      for (const x of ROUTES.filter((y) => y.edge === 'deny' && y.group !== 'control')) {
        const pattern = asPattern(x.path);
        const re = x.method === 'GET' ? new RegExp(`(^|[\\s"])(GET )?${pattern}([\\s"?]|$)`, 'm') : new RegExp(`${x.method} ${pattern}`);
        expect(script, `${x.method} ${x.path}`).toMatch(re);
      }
    });
  });

  describe('the inventory', () => {
    it('embeds the route table generated from the code', () => {
      expect(read('docs/security/buzz-attack-surface.md')).toContain(`<!-- routes:start -->\n${surfaceTable()}\n<!-- routes:end -->`);
    });

    it('names the pin it was reviewed for', () => {
      const pin = /^BUZZ_COMMIT=(\w+)$/m.exec(read('infra/buzz/PIN'))?.[1] ?? '';
      expect(pin).toMatch(/^[0-9a-f]{40}$/);
      expect(
        read('docs/security/buzz-attack-surface.md'),
        `infra/buzz/PIN moved to ${pin.slice(0, 7)}: reread the Buzz router for new routes, update the routes of scripts/buzz-surface-routes.ts and the pin in docs/security/buzz-attack-surface.md`,
      ).toContain(`commit \`${pin.slice(0, 7)}\``);
    });
  });

  describe('CI', () => {
    const ci = read('.github/workflows/ci.yml');
    const job = (name: string) => new RegExp(`\\n {2}${name}:\\n([\\s\\S]*?)(?=\\n {2}[a-z][a-z-]*:\\n|$)`).exec(ci)?.[1] ?? '';

    it('probes the pinned relay in the stack job and keeps the report', () => {
      expect(job('stack')).toContain('npx tsx scripts/buzz-surface.ts --relay http://localhost:3000 --out buzz-surface-report.json');
      // Once in the step that writes it and once in the artifact that keeps it.
      expect(job('stack').match(/buzz-surface-report\.json/g)).toHaveLength(2);
    });

    it('checks the real edge config in the deploy-config job, and lints the script', () => {
      expect(job('deploy-config')).toContain('bash scripts/edge-check.sh');
      expect(job('deploy-config')).toMatch(/shellcheck -x [^\n]*scripts\/edge-check\.sh/);
    });
  });
});
