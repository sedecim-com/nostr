// SEC-12: the HTTP and WebSocket routes of the pinned Buzz relay and what an unauthenticated client gets from them.
// The table is the source of truth behind docs/security/buzz-attack-surface.md (its route table is generated from here
// and tests/scripts/buzz-surface.test.ts keeps both in step), scripts/buzz-surface.ts probes it and scripts/edge-check.sh
// checks what the public edge forwards. Routes are read from the upstream router (crates/buzz-relay/src/router.rs, commit
// 12dbb11); the probe is what says what the pinned image really does.

export type Exposure = 'public' | 'authenticated' | 'operator' | 'internal' | 'disabled';

export interface SurfaceRoute {
  method: string;
  /** As Buzz registers it. `{x}` segments are probed with a fixed value. */
  path: string;
  group: string;
  /** What a request needs in this deployment: nothing, NIP-98/BUD-01/a secret, an operator key, localhost, or a flag we leave off. */
  exposure: Exposure;
  /** Whether the public edge forwards it. Only the WebSocket/NIP-11 at `/` and the media under `/media/` are forwarded. */
  edge: 'allow' | 'deny';
  /** Spanish, it is rendered into the inventory. */
  note: string;
  /** Query string of the probe, for the routes whose handler rejects a request without it before it looks at credentials. */
  query?: string;
  /** JSON body of the probe when `{}` is rejected as malformed before the handler reaches its own checks. */
  body?: string;
  /**
   * The status the pinned Buzz answers, before it looks at credentials, when the feature the route needs is not configured
   * here (the operator API without RELAY_OPERATOR_API_ORIGIN answers a generic 500). The request is refused and nothing runs:
   * the only server error a route may answer.
   */
  unconfigured?: number;
}

type Extra = Pick<SurfaceRoute, 'query' | 'body' | 'unconfigured'>;
const r = (method: string, path: string, group: string, exposure: Exposure, edge: 'allow' | 'deny', note: string, extra: Extra = {}): SurfaceRoute => ({ method, path, group, exposure, edge, note, ...extra });

const ZERO_UUID = '00000000-0000-4000-8000-000000000000';
/** A query and a body a handler accepts, so that what answers is its authentication and not the parsing in front of it. */
const OPERATOR = { unconfigured: 500 } satisfies Extra;
const OWNER_QUERY = `owner_pubkey=${'0'.repeat(64)}`;
const DEMO_BODY = JSON.stringify({ community_id: ZERO_UUID, session_id: ZERO_UUID, payload: 'x' });

export const ROUTES: SurfaceRoute[] = [
  r('GET', '/', 'websocket', 'public', 'allow', 'WebSocket (NIP-01, NIP-42) y documento NIP-11'),
  r('GET', '/info', 'websocket', 'public', 'deny', 'información del relay'),
  r('GET', '/.well-known/nostr.json', 'websocket', 'public', 'deny', 'nombres NIP-05'),
  r('GET', '/health', 'health', 'public', 'deny', 'sonda; el stack sondea el puerto de salud'),
  r('GET', '/_liveness', 'health', 'public', 'deny', 'sonda'),
  r('GET', '/_readiness', 'health', 'public', 'deny', 'sonda'),
  r('POST', '/events', 'bridge', 'authenticated', 'deny', 'puente HTTP para publicar (NIP-98); los clientes usan el WebSocket'),
  r('POST', '/query', 'bridge', 'authenticated', 'deny', 'puente HTTP para leer (NIP-98)'),
  r('POST', '/count', 'bridge', 'authenticated', 'deny', 'puente HTTP para contar (NIP-98)'),
  r('POST', '/gifs/search', 'gifs', 'authenticated', 'deny', 'proxy a un proveedor de GIF de terceros (NIP-98); necesita su clave de API, que no ponemos'),
  r('POST', '/gifs/share', 'gifs', 'authenticated', 'deny', 'el mismo proxy'),
  r('GET', '/workflows/{workflow_id}/runs', 'workflows', 'authenticated', 'deny', 'ejecuciones de un workflow'),
  r('GET', '/workflows/{workflow_id}/runs/{run_id}/approvals', 'workflows', 'authenticated', 'deny', 'aprobaciones de una ejecución'),
  r('POST', '/hooks/{id}', 'workflows', 'authenticated', 'deny', 'webhook de workflow, autenticado por un secreto y no por NIP-98'),
  r('GET', '/operator/communities', 'operator', 'operator', 'deny', 'lista las comunidades de la clave de operador (NIP-98); exige RELAY_OPERATOR_PUBKEYS', { ...OPERATOR, query: OWNER_QUERY }),
  r('POST', '/operator/communities', 'operator', 'operator', 'deny', 'provisiona una comunidad (scripts/buzz-provision-community.ts)', OPERATOR),
  r('POST', '/operator/listener/pubkeys', 'operator', 'operator', 'deny', 'registra las claves que sigue un listener de operador', OPERATOR),
  r('DELETE', '/operator/listener/pubkeys', 'operator', 'operator', 'deny', 'las retira', OPERATOR),
  r('POST', '/operator/communities/archive', 'operator', 'operator', 'deny', 'archiva una comunidad', OPERATOR),
  r('POST', '/operator/communities/unarchive', 'operator', 'operator', 'deny', 'la desarchiva', OPERATOR),
  r('POST', '/operator/communities/delete', 'operator', 'operator', 'deny', 'la borra', OPERATOR),
  r('GET', '/operator/communities/availability', 'operator', 'operator', 'deny', 'comprueba si un host está libre', { ...OPERATOR, query: 'host=probe.invalid' }),
  r('POST', '/operator/communities/transfer', 'operator', 'operator', 'deny', 'transfiere la propiedad', OPERATOR),
  r('POST', '/api/invites', 'invites', 'authenticated', 'deny', 'crea una invitación (dueño o admin)'),
  r('GET', '/api/join-policy', 'invites', 'public', 'deny', 'política que debe aceptar quien se une'),
  r('GET', '/api/join-policy/terms', 'invites', 'public', 'deny', 'página de términos de servicio'),
  r('GET', '/api/join-policy/privacy', 'invites', 'public', 'deny', 'página de política de privacidad'),
  r('POST', '/api/invites/accept-policy', 'invites', 'authenticated', 'deny', 'acepta la política'),
  r('POST', '/api/invites/claim', 'invites', 'public', 'deny', 'canjea una invitación (fuera de la puerta de membresía; exige una invitación válida)'),
  r('GET', '/moderation/reports', 'moderation', 'authenticated', 'deny', 'cola de moderación (NIP-98 y autorización de moderador)'),
  r('GET', '/moderation/audit', 'moderation', 'authenticated', 'deny', 'auditoría de moderación'),
  r('GET', '/moderation/restricted', 'moderation', 'authenticated', 'deny', 'contenido restringido'),
  r('POST', '/_mesh/demo/echo', 'mesh', 'disabled', 'deny', 'solo de banco de pruebas: 404 salvo con BUZZ_MESH y BUZZ_MESH_DEMO_ECHO', { body: DEMO_BODY }),
  r('GET', '/huddle/{channel_id}/audio', 'huddle', 'authenticated', 'deny', 'WebSocket de audio de los huddles'),
  r('PUT', '/upload', 'media', 'authenticated', 'deny', 'subida Blossom en la raíz (BUD-02); los clientes usan /media/upload'),
  r('PUT', '/media/upload', 'media', 'authenticated', 'allow', 'subida Blossom'),
  r('GET', '/media/{sha256_ext}', 'media', 'authenticated', 'allow', 'descarga Blossom; Buzz pide autorización BUD-01 también para descargar'),
  r('HEAD', '/media/{sha256_ext}', 'media', 'authenticated', 'allow', 'comprobación de existencia Blossom'),
  r('GET', '/git/{owner}/{repo}/info/refs', 'git', 'authenticated', 'deny', 'git smart HTTP (Buzz aloja repositorios); nuestro producto no lo usa'),
  r('POST', '/git/{owner}/{repo}/git-upload-pack', 'git', 'authenticated', 'deny', 'git fetch'),
  r('POST', '/git/{owner}/{repo}/git-receive-pack', 'git', 'authenticated', 'deny', 'git push'),
  r('POST', '/internal/git/policy', 'git', 'internal', 'deny', 'comprobación de política del hook pre-receive, solo desde localhost'),
  r('GET', '/api/admin/v1/communities', 'admin', 'disabled', 'deny', 'API de administración, montada solo con BUZZ_ADMIN_HOST, que no ponemos'),
  // Controls: a path no route has must not answer either.
  r('GET', '/zz-surface-probe', 'control', 'disabled', 'deny', 'ruta inexistente'),
  r('POST', '/zz-surface-probe', 'control', 'disabled', 'deny', 'ruta inexistente'),
];

const EXPOSURE_ES: Record<Exposure, string> = {
  public: 'nada (pública)',
  authenticated: 'credenciales (NIP-98, BUD-01 o un secreto)',
  operator: 'clave de operador',
  internal: 'solo localhost',
  disabled: 'apagada por configuración',
};

/** The route table of docs/security/buzz-attack-surface.md, between its routes markers. Controls are not routes. */
export function surfaceTable(routes: SurfaceRoute[] = ROUTES): string {
  const asks = (x: SurfaceRoute) => (x.unconfigured ? `${EXPOSURE_ES[x.exposure]}; sin configurar responde ${x.unconfigured}` : EXPOSURE_ES[x.exposure]);
  const rows = routes
    .filter((x) => x.group !== 'control')
    .map((x) => `| \`${x.method} ${x.path}\` | ${x.group} | ${asks(x)} | ${x.edge === 'allow' ? 'sí' : 'no (404 del edge)'} | ${x.note} |`);
  return ['| Ruta | Grupo | Qué pide sin credenciales | ¿La reenvía el edge? | Nota |', '|---|---|---|---|---|', ...rows].join('\n');
}

export interface Probed {
  route: SurfaceRoute;
  url: string;
  status: number;
  body: string;
}

const SHA256 = 'a'.repeat(64);
// Path parameters that are ids: Buzz answers 400 to anything that does not parse as one, before it asks who is calling.
const UUID_PARAMS = new Set(['workflow_id', 'run_id', 'id', 'channel_id']);
const fill = (path: string) => path.replace(/\{([^}]+)\}/g, (_m, name: string) => (name === 'sha256_ext' ? `${SHA256}.png` : UUID_PARAMS.has(name) ? ZERO_UUID : 'x'));

/**
 * One request per route, with no credentials, no redirects followed and no side effects a rejection does not stop.
 * Ids, queries and bodies are well formed, so that what answers is the authentication and not the parsing in front of it.
 */
export async function probe(base: string, routes: SurfaceRoute[] = ROUTES, fetchFn: typeof fetch = fetch): Promise<Probed[]> {
  const out: Probed[] = [];
  for (const route of routes) {
    const url = new URL(fill(route.path) + (route.query ? `?${route.query}` : ''), base).toString();
    const body = route.body ?? (route.method === 'POST' ? '{}' : undefined);
    const res = await fetchFn(url, {
      method: route.method,
      redirect: 'manual',
      headers: { accept: 'application/json', ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
      ...(body === undefined ? {} : { body }),
      signal: AbortSignal.timeout(10_000),
    });
    out.push({ route, url, status: res.status, body: route.method === 'HEAD' ? '' : (await res.text()).slice(0, 200) });
  }
  return out;
}

/**
 * What the relay itself must never do for a client without credentials: fail (5xx, but for the refusal a route documents
 * for what is not configured), answer a route that needs them with anything but a client error, or answer a route that is
 * off here with anything but the 404 of a path that does not exist. Public routes may answer anything below 500.
 */
export function relayViolations(results: Probed[]): string[] {
  const bad: string[] = [];
  for (const { route, status } of results) {
    const label = `${route.method} ${route.path}`;
    if (status >= 500) {
      if (status !== route.unconfigured) bad.push(`${label}: ${status}, a server error for a request without credentials`);
    } else if (route.exposure !== 'public' && status < 400) bad.push(`${label}: ${status} without credentials, but it is ${route.exposure}`);
    else if (route.exposure === 'disabled' && status !== 404) bad.push(`${label}: ${status}, a route that is off here should answer 404`);
  }
  return bad;
}

/** Through the public edge: only the allowed routes reach Buzz; every other one gets the edge's own 404 ("not found"). */
export const isEdgeDenial = (p: Probed): boolean => p.status === 404 && p.body.trim() === 'not found';

export function edgeViolations(results: Probed[]): string[] {
  const bad: string[] = [];
  for (const p of results) {
    if (p.route.method === 'HEAD') continue; // no body to tell the edge's 404 from Buzz's
    const label = `${p.route.method} ${p.route.path}`;
    if (p.route.edge === 'deny' && !isEdgeDenial(p)) bad.push(`${label}: ${p.status}, the edge should answer its own 404`);
    if (p.route.edge === 'allow' && isEdgeDenial(p)) bad.push(`${label}: the edge denies a route clients use`);
  }
  return bad;
}
