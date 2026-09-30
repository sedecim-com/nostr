/**
 * OPS-14: the OpenAPI 3.1 document of each service, generated from the routes it registers (service-kit `describe()`)
 * plus the summary and authentication of each route, defined here. Services without a service-kit API (blob-store, the
 * health endpoints of rotation-worker and relay-allowlist) list their routes here.
 *
 *   npx tsx scripts/openapi.ts           (writes docs/openapi/<service>.json and docs/openapi/README.md)
 *   npx tsx scripts/openapi.ts --check   (CI: fails if they are stale, if a route has no summary or a summary no route)
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createContinuityVaultApi, MemoryArchiveRepository, MemoryObjectStore } from '@sedecim/continuity-vault';
import { createIdentityApi, MemoryIdentityRepository } from '@sedecim/identity-service';
import { createIndexerApi, MemoryEventRepository } from '@sedecim/indexer';
import { createManagedSignerApi, ManagedSigner, MemoryVault } from '@sedecim/managed-signer';
import { createNotificationApi, generateVapidKeys, type NotificationGateway } from '@sedecim/notification-gateway';
import { createPolicyApi, PolicyEngine } from '@sedecim/policy-engine';
import type { AuthMode } from '@sedecim/service-kit';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const OUT = join(ROOT, 'docs/openapi');

/** Security schemes: NIP-98 (Nostr HTTP auth) and the bearer tokens each service accepts. */
const SCHEMES = {
  nip98: { type: 'http', scheme: 'Nostr', description: 'NIP-98: `Authorization: Nostr <evento kind 27235 en base64>`, firmado para esta URL y este método.' },
  serviceToken: { type: 'http', scheme: 'bearer', description: 'Token de servicio a servicio (p. ej. `POLICY_SERVICE_TOKENS`).' },
  acceso: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT', description: 'Token de ID del login de Acceso (Cognito, ADR 0008).' },
  deviceSession: { type: 'http', scheme: 'bearer', description: 'Sesión de dispositivo del managed-signer (`sds_…`, FR024-03).' },
  revocationToken: { type: 'http', scheme: 'bearer', description: 'Token de revocación (`MANAGED_SIGNER_REVOCATION_TOKENS`), solo para revocar dispositivos.' },
  blossom: { type: 'http', scheme: 'Nostr', description: 'Blossom BUD-02: `Authorization: Nostr <evento kind 24242 en base64>` con `t` y `x` (sha256).' },
} as const;
type Scheme = keyof typeof SCHEMES;

interface RouteDoc {
  summary: string;
  /** Alternatives accepted (each one a scheme, or 'none'), when the handler authenticates instead of the route. */
  security?: Array<Scheme | 'none'>;
}
interface Route {
  method: string;
  path: string;
  auth: AuthMode;
}
interface ServiceDoc {
  description: string;
  /** Where it answers in the local compose stack. */
  server: { url: string; description: string };
  /** What `nip98-or-token` accepts besides NIP-98 in this service. */
  token?: Scheme;
  routes: () => Route[];
  docs: Record<string, RouteDoc>;
}

const ERROR = { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } };
const local = (port: number) => ({ url: `http://localhost:${port}`, description: 'Stack de docker compose en local' });
const internal = (host: string, port: number) => ({ url: `http://${host}:${port}`, description: 'Red interna del compose: sin puerto en el host' });

const HEALTH = { 'GET /health': { summary: 'Salud del servicio.' } };
const ACCESO_OR_SESSION: Array<Scheme | 'none'> = ['acceso', 'deviceSession'];
/** IR-2026-10-03: routes that take a recent sign-in with the Acceso password, never a device session. */
const RECENT_ACCESO: Array<Scheme | 'none'> = ['acceso'];
const RECENT =
  ' Solo con un login de Acceso de los últimos minutos (`MANAGED_SIGNER_REAUTH_MAX_AGE_S`, 300 s por defecto), nunca con una sesión de dispositivo; si no, 401 con `WWW-Authenticate: Bearer error="insufficient_user_authentication"` (RFC 9470, IR-2026-10-03).';

const SERVICES: Record<string, ServiceDoc> = {
  'policy-engine': {
    server: local(8083),
    description: 'Modo institucional (spec §16): personas, recursos, dispositivos, revocación, auditoría y retención. docs/institutional.md.',
    token: 'serviceToken',
    routes: () => createPolicyApi(new PolicyEngine(), { name: 'policy-engine', adminPubkeys: [] }).describe(),
    docs: {
      ...HEALTH,
      'GET /v1/subjects': { summary: 'Personas de la organización (admin).' },
      'PUT /v1/subjects/:pubkey': { summary: 'Roles y atributos de una persona; nunca cambia su revocación (FR023-09).' },
      'POST /v1/subjects/:pubkey/revoke': { summary: 'Revoca a la persona y sus dispositivos; devuelve las rotaciones MLS que quedan pendientes.' },
      'POST /v1/subjects/:pubkey/reactivate': { summary: 'Reactiva a una persona revocada; sus dispositivos siguen revocados.' },
      'GET /v1/resources': { summary: 'Recursos (workspace, channel, group) con sus reglas y miembros.' },
      'PUT /v1/resources/:id': { summary: 'Crea o cambia un recurso, sus reglas y sus miembros.' },
      'GET /v1/devices': { summary: 'Dispositivos, todos o los de un dueño (`owner`).' },
      'POST /v1/devices': { summary: 'Registra un dispositivo (`unverified` o `registered`; `attested` solo con WebAuthn).' },
      'POST /v1/devices/:id/revoke': { summary: 'Revoca un dispositivo; devuelve las rotaciones MLS que deja pendientes.' },
      'POST /v1/devices/:id/webauthn/options': { summary: 'Opciones para registrar una passkey en el dispositivo (FR023-07).' },
      'POST /v1/devices/:id/webauthn/register': { summary: 'Verifica la passkey y deja el dispositivo `attested`.' },
      'POST /v1/sessions': { summary: 'Abre una sesión de política para el dueño que firma (NIP-98).' },
      'POST /v1/evaluate': { summary: 'Decide si una persona puede leer, publicar, administrar o invitar en un recurso.' },
      'GET /v1/relay/allowlist': { summary: 'Allowlist NIP-42 de los relays: personas activas con un dispositivo sin revocar (FR023-04).' },
      'GET /v1/relay/grants': { summary: 'Quién puede publicar en cada canal y grupo, para la admisión por `h` de los relays y la membresía NIP-29 de Buzz (FR023-10).' },
      'GET /v1/rotations': { summary: 'Rotaciones MLS pendientes o hechas (FR024-02).' },
      'POST /v1/rotations/:id/done': { summary: 'Marca una rotación como hecha.' },
      'GET /v1/audit': { summary: 'Auditoría append-only de lo que hacen los admins, más nueva primero.' },
      'GET /v1/access-log': { summary: 'Decisiones de acceso, más nueva primero; se guardan `retentionDays` días (FR023-12).' },
      'GET /v1/revocations': { summary: 'Revocaciones de dispositivo desde un cursor, más antigua primero (FR024-04).' },
      'GET /v1/directory': { summary: 'Directorio organizacional: cargo y unidad por npub (FR023-06).' },
      'PUT /v1/directory/:pubkey': { summary: 'Cargo y unidad de una persona.' },
      'DELETE /v1/directory/:pubkey': { summary: 'Quita una entrada del directorio.' },
      'GET /v1/retention': { summary: 'Retención y legal hold de cada recurso, con el aviso de su alcance (FR023-08).' },
      'PUT /v1/retention/:resourceId': { summary: 'Fija la retención o el legal hold de un recurso; 409 en un grupo MLS (FR023-12).' },
    },
  },
  'managed-signer': {
    server: local(8084),
    description: 'Custodia gestionada de llaves Nostr en KMS (FR005): firma y NIP-44 con sesiones de dispositivo revocables. docs/managed-enclave.md.',
    routes: () => createManagedSignerApi(new ManagedSigner(new MemoryVault()), { name: 'managed-signer' }).describe(),
    docs: {
      'GET /health': { summary: 'Salud del servicio.', security: ['none'] },
      'POST /v1/device-sessions': { summary: 'Abre una sesión de dispositivo (`sds_…`, 12 h) con el login de Acceso; nunca desde otra sesión (FR024-03).', security: ['acceso'] },
      'GET /v1/device-sessions': { summary: 'Sesiones de dispositivo del usuario (FR005-11).', security: ACCESO_OR_SESSION },
      'DELETE /v1/device-sessions/:id': { summary: 'Cierra una sesión: con el login de Acceso, o la propia sesión.', security: ACCESO_OR_SESSION },
      'DELETE /v1/device-sessions': { summary: `Cierra las demás sesiones del usuario y deja fuera sus otros logins de Acceso anteriores a ese momento (IR-2026-10-11).${RECENT}`, security: RECENT_ACCESO },
      'POST /v1/devices/:id/revoke': { summary: 'Revoca un dispositivo: borra sus sesiones y rechaza las nuevas (FR024-03/04).', security: ['revocationToken'] },
      'GET /v1/keys': { summary: 'Llaves gestionadas del usuario.', security: ACCESO_OR_SESSION },
      'GET /v1/keys/closed': { summary: 'Llaves que salieron de la custodia gestionada y cuándo se destruye cada una (FR026-04).', security: ACCESO_OR_SESSION },
      'POST /v1/keys': { summary: 'Crea una llave gestionada.', security: ACCESO_OR_SESSION },
      'GET /v1/enclave/attestation': { summary: 'Documento de attestation del enclave para el nonce del cliente (`nonce`, base64url de 16 a 64 bytes): el cliente lo verifica antes de sellar secretos hacia la llave RSA que trae (FR005-10). 404 si las llaves no están en un enclave.', security: ACCESO_OR_SESSION },
      'POST /v1/keys/import': { summary: 'Importa una llave existente a custodia gestionada: `ncryptsec` y `password`, o `sealed_secrets`, los dos sellados por el cliente hacia el enclave (FR005-10).', security: ACCESO_OR_SESSION },
      'GET /v1/keys/:id': { summary: 'Describe una llave: pubkey y estado.', security: ACCESO_OR_SESSION },
      'POST /v1/keys/:id/sign': { summary: 'Firma un evento Nostr con la llave.', security: ACCESO_OR_SESSION },
      'POST /v1/keys/:id/nip44/encrypt': { summary: 'Cifra con NIP-44 para un destinatario.', security: ACCESO_OR_SESSION },
      'POST /v1/keys/:id/nip44/decrypt': { summary: 'Descifra con NIP-44 de un remitente.', security: ACCESO_OR_SESSION },
      'POST /v1/keys/:id/export': { summary: `Exporta la llave cifrada con una contraseña (NIP-49) para pasar a custodia propia: \`password\`, o \`sealed_password\` sellada por el cliente hacia el enclave (FR005-10).${RECENT}`, security: RECENT_ACCESO },
      'POST /v1/keys/:id/confirm-migration': { summary: `Confirma la migración con una prueba firmada por la llave exportada.${RECENT}`, security: RECENT_ACCESO },
      'DELETE /v1/keys/:id': { summary: `Programa el borrado de la llave (\`destroy_after\`).${RECENT}`, security: RECENT_ACCESO },
      'POST /v1/keys/:id/cancel': { summary: `Cancela la custodia sin migrar (derecho ARCO), confirmada con la npub de la llave (\`destroy_after\`, FR026-04).${RECENT}`, security: RECENT_ACCESO },
      'GET /v1/keys/:id/usage': { summary: 'Operaciones de la llave, cada una con su dispositivo (FR005-11); también después de que saliera de la custodia, hasta que se destruye (IR-2026-10-03).', security: ACCESO_OR_SESSION },
    },
  },
  'identity-service': {
    server: local(8082),
    description: 'Cuentas SaaS: personas, vínculos entre personas, login de Acceso asociado y backups cifrados en el cliente.',
    token: 'acceso',
    routes: () => createIdentityApi(new MemoryIdentityRepository(), { name: 'identity-service' }).describe(),
    docs: {
      ...HEALTH,
      'POST /v1/accounts': { summary: 'Crea la cuenta de la pubkey que firma.' },
      'GET /v1/accounts/me': { summary: 'La cuenta de quien firma, con sus personas.' },
      'POST /v1/accounts/me/personas': { summary: 'Añade una persona a la cuenta.' },
      'DELETE /v1/accounts/me/personas/:pubkey': { summary: 'Quita una persona de la cuenta.' },
      'POST /v1/links': { summary: 'Publica un vínculo entre dos personas con su visibilidad.' },
      'GET /v1/links/public/:pubkey': { summary: 'Vínculos públicos de una persona.' },
      'GET /v1/links/visible/:pubkey': { summary: 'Vínculos de una persona que quien firma puede ver.' },
      'PUT /v1/personas/:pubkey/key-metadata': { summary: 'Metadatos de custodia de la llave de una persona, sin material secreto.' },
      'POST /v1/accounts/me/external-logins': { summary: 'Asocia el login de Acceso a la cuenta; el token prueba quién lo controla y no se guarda (ADR 0008).' },
      'GET /v1/accounts/me/external-logins': { summary: 'Logins de Acceso asociados a la cuenta.' },
      'DELETE /v1/accounts/me/external-logins/:provider': { summary: 'Quita un login de Acceso de la cuenta.' },
      'POST /v1/backups': { summary: 'Guarda un backup cifrado en el cliente; el servicio no puede abrirlo.' },
      'GET /v1/backups': { summary: 'Backups de la cuenta (metadatos).' },
      'GET /v1/backups/:id': { summary: 'Descarga un backup.' },
      'DELETE /v1/backups': { summary: 'Borra todos los backups de la cuenta.' },
      'DELETE /v1/backups/:id': { summary: 'Borra un backup.' },
      'GET /v1/accounts/me/audit': { summary: 'Auditoría de la cuenta.' },
    },
  },
  'continuity-vault': {
    server: local(8088),
    description: 'Continuity Vault (ADR 0011): sobres de archivo sellados en cada dispositivo; el operador ve cuentas, tamaños y fechas, nunca contenido ni llaves.',
    token: 'acceso',
    routes: () => createContinuityVaultApi(new MemoryArchiveRepository(), new MemoryObjectStore(), { name: 'continuity-vault' }).describe(),
    docs: {
      ...HEALTH,
      'PUT /v1/archives/:id': { summary: 'Guarda o reemplaza un sobre sellado.' },
      'GET /v1/archives': { summary: 'Sobres de la cuenta: id, tamaño y fechas.' },
      'GET /v1/archives/:id': { summary: 'Descarga un sobre.' },
      'DELETE /v1/archives': { summary: 'Borra todos los sobres y la cuenta.' },
      'DELETE /v1/archives/:id': { summary: 'Borra un sobre.' },
      'GET /v1/usage': { summary: 'Uso de la cuenta y la retención que aplica.' },
      'PUT /v1/retention': { summary: 'Días que el vault guarda cada sobre desde su última escritura (VAULT-05).' },
    },
  },
  indexer: {
    server: local(8081),
    description: 'Mirror e índice de los relays: lecturas, no leídos y búsqueda; en modo institucional, filtrados por la política (FR023-05).',
    routes: () => createIndexerApi(new MemoryEventRepository(), { name: 'indexer' }).describe(),
    docs: {
      'GET /health': { summary: 'Salud del servicio y estadísticas del mirror.' },
      'GET /v1/events': { summary: 'Eventos del mirror por filtro; con política, solo los que quien firma puede leer.' },
      'GET /v1/events/:id': { summary: 'Un evento del mirror por id.' },
      'GET /v1/channels/:h/summary': { summary: 'Resumen de un canal: último mensaje y conteos.' },
      'GET /v1/unread': { summary: 'No leídos por canal de quien firma (FR014-03).' },
      'GET /v1/unread/recent': { summary: 'Hora de los mensajes más recientes de cada canal que quien firma puede leer, sin los suyos ni los borrados: el cliente cuenta sus no leídos con un cursor que no envía (FR014-04).' },
      'PUT /v1/read-cursor': { summary: 'Marca hasta dónde leyó quien firma en un canal.' },
      'GET /v1/search': { summary: 'Búsqueda en mensajes en claro de los canales que quien firma puede leer (nunca gift wraps).' },
    },
  },
  'notification-gateway': {
    server: local(8086),
    description: 'Notificaciones push opacas (ADR 0010): observa los relays que puede observar sin leer DMs.',
    routes: () => createNotificationApi({} as NotificationGateway, { name: 'notification-gateway', vapid: generateVapidKeys() }).describe(),
    docs: {
      ...HEALTH,
      'GET /v1/vapid': { summary: 'Llave pública VAPID (`applicationServerKey`) para suscribirse.' },
      'GET /v1/relays': { summary: 'Relays que el gateway puede observar sin leer DMs de nadie (OPS-06).' },
      'POST /v1/subscriptions': { summary: 'Registra una suscripción Web Push para las personas de quien firma.' },
      'DELETE /v1/subscriptions': { summary: 'Borra una suscripción.' },
    },
  },
  'blob-store': {
    server: local(8085),
    description: 'Servidor Blossom agnóstico al contenido para adjuntos cifrados en el cliente (BUD-01/02).',
    routes: () => [
      { method: 'GET', path: '/health', auth: 'none' },
      { method: 'PUT', path: '/upload', auth: 'none' },
      { method: 'GET', path: '/:sha256', auth: 'none' },
      { method: 'HEAD', path: '/:sha256', auth: 'none' },
      { method: 'DELETE', path: '/:sha256', auth: 'none' },
    ],
    docs: {
      ...HEALTH,
      'PUT /upload': { summary: 'Sube un blob (BUD-02); la autorización lleva su sha256 en `x`.', security: ['blossom'] },
      'GET /:sha256': { summary: 'Descarga un blob por su sha256 (BUD-01), con extensión opcional.' },
      'HEAD /:sha256': { summary: 'Si el blob existe, con su tamaño y tipo.' },
      'DELETE /:sha256': { summary: 'Borra un blob que subió quien firma (BUD-02 `delete`).', security: ['blossom'] },
    },
  },
  'rotation-worker': {
    server: internal('rotation-worker', 8089),
    description: 'Worker de rotaciones (FR024-05): une grupos, saca a los revocados con commits MLS y lleva las revocaciones al managed-signer.',
    routes: () => [{ method: 'GET', path: '/health', auth: 'none' }],
    docs: { 'GET /health': { summary: 'Estado del último ciclo: errores por paso, grupos, rotaciones y revocaciones.' } },
  },
  'relay-allowlist': {
    server: internal('relay-allowlist', 8087),
    description: 'Sincronía de los relays con el policy-engine: allowlist NIP-42 (FR023-04) y permisos de publicar por recurso (FR023-10), también como membresía NIP-29 en Buzz. La admisión de eventos del relay seguro es gRPC (`nauthz.Authorization/EventAdmit`, puerto 50051), fuera de este documento.',
    routes: () => [{ method: 'GET', path: '/health', auth: 'none' }],
    docs: { 'GET /health': { summary: 'Última sincronización: personas, permisos por recurso, membresía de Buzz y último error.' } },
  },
};

function security(auth: AuthMode, token: Scheme | undefined, doc: RouteDoc) {
  const alt = (s: Scheme | 'none') => (s === 'none' ? {} : { [s]: [] });
  if (doc.security) return doc.security.map(alt);
  switch (auth) {
    case 'none':
      return [];
    case 'nip98':
      return [{ nip98: [] }];
    case 'nip98-optional':
      return [{}, { nip98: [] }];
    case 'bearer':
      return [{ serviceToken: [] }];
    case 'nip98-or-token':
      if (!token) throw new Error('nip98-or-token without a token scheme for this service');
      return [{ nip98: [] }, { [token]: [] }];
  }
}

const openapiPath = (p: string) => p.replace(/:([a-zA-Z_][a-zA-Z0-9_]*)/g, '{$1}');
const operationId = (method: string, p: string) =>
  method.toLowerCase() + p.split('/').filter(Boolean).map((s) => s.replace(/^:/, 'by-').replace(/[^a-zA-Z0-9]+(.)?/g, (_m, c: string | undefined) => (c ? c.toUpperCase() : '')).replace(/^./, (c) => c.toUpperCase())).join('');

function document(name: string, svc: ServiceDoc, version: string, problems: string[]) {
  const routes = svc.routes();
  const keys = new Set(routes.map((r) => `${r.method} ${r.path}`));
  for (const k of Object.keys(svc.docs)) if (!keys.has(k)) problems.push(`${name}: summary for a route that does not exist: ${k}`);
  const used = new Set<string>();
  const paths: Record<string, Record<string, unknown>> = {};
  for (const r of routes) {
    const key = `${r.method} ${r.path}`;
    const doc = svc.docs[key];
    if (!doc) {
      problems.push(`${name}: route without a summary: ${key} (add it in scripts/openapi.ts)`);
      continue;
    }
    const sec = security(r.auth, svc.token, doc);
    for (const alt of sec) for (const s of Object.keys(alt)) used.add(s);
    const params = [...r.path.matchAll(/:([a-zA-Z_][a-zA-Z0-9_]*)/g)].map((m) => ({ name: m[1], in: 'path', required: true, schema: { type: 'string' } }));
    (paths[openapiPath(r.path)] ??= {})[r.method.toLowerCase()] = {
      operationId: operationId(r.method, r.path),
      summary: doc.summary,
      ...(params.length ? { parameters: params } : {}),
      security: sec,
      responses: {
        '2XX': { description: 'Respuesta correcta (JSON salvo los blobs de Blossom).' },
        '4XX': { description: 'Petición rechazada: 400, 401, 403, 404, 409, 413 o 429 (con `Retry-After`).', content: ERROR },
        '5XX': { description: 'Error interno.', content: ERROR },
      },
    };
  }
  return {
    openapi: '3.1.0',
    info: { title: name, version, description: svc.description, license: { name: 'Apache-2.0', identifier: 'Apache-2.0' } },
    servers: [svc.server],
    paths,
    components: {
      schemas: { Error: { type: 'object', properties: { error: { type: 'string' } }, required: ['error'] } },
      securitySchemes: Object.fromEntries([...used].sort().map((s) => [s, SCHEMES[s as Scheme]])),
    },
  };
}

const check = process.argv.includes('--check');
const problems: string[] = [];
const files: Record<string, string> = {};
const index: string[] = [];
for (const [name, svc] of Object.entries(SERVICES)) {
  const dir = name === 'relay-allowlist' ? 'policy-engine' : name;
  const version = (JSON.parse(readFileSync(join(ROOT, 'services', dir, 'package.json'), 'utf8')) as { version: string }).version;
  const doc = document(name, svc, version, problems);
  files[`${name}.json`] = `${JSON.stringify(doc, null, 2)}\n`;
  index.push(`| [${name}](${name}.json) | ${Object.values(doc.paths).reduce((n, ops) => n + Object.keys(ops).length, 0)} | ${svc.description} |`);
}
files['README.md'] = [
  '# OpenAPI de los servicios',
  '',
  '> Generado por `npx tsx scripts/openapi.ts` (OPS-14) desde las rutas que registra cada servicio; no se edita a mano. El job `docs` de CI falla si no está al día o si una ruta no tiene resumen.',
  '',
  '| Servicio | Operaciones | Qué hace |',
  '|---|---|---|',
  ...index,
  '',
].join('\n');

if (problems.length) {
  for (const p of problems) console.error(p);
  process.exit(1);
}
if (check) {
  const stale = Object.entries(files).filter(([f, c]) => {
    try {
      return readFileSync(join(OUT, f), 'utf8') !== c;
    } catch {
      return true;
    }
  });
  for (const [f] of stale) console.error(`docs/openapi/${f} no está al día: npx tsx scripts/openapi.ts`);
  if (stale.length) process.exit(1);
  console.log(`openapi ok: ${Object.keys(SERVICES).length} servicios`);
} else {
  mkdirSync(OUT, { recursive: true });
  for (const [f, c] of Object.entries(files)) writeFileSync(join(OUT, f), c);
  console.log(`openapi: ${Object.keys(SERVICES).length} servicios en docs/openapi`);
}
process.exit(0);
