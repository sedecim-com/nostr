/**
 * Browser E2E for the admin console (OPS-07). Run with: npm run test:browser
 * Serves the Vite build like nginx does (per-request CSP nonce) on http://localhost (WebAuthn needs a
 * domain RP id) against the real policy-engine (FR023-13: its API and engine in process, memory repository,
 * WebAuthn verification included), the real identity-service, and a test relay for the NIP-46 bunker sign-in.
 */
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { extname, join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { chromium, type Browser, type BrowserContext, type Page } from 'playwright';
import WebSocket from 'ws';
import { finalizeEvent, generateSecretKey, getPublicKey, nip98, npubEncode, nsecEncode, toUnsigned } from '@sedecim/nostr-core';
import { LocalSigner, Nip46Bunker } from '@sedecim/signer';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { TestRelay } from '@sedecim/test-relay';
import { nip98Fetch } from '@sedecim/service-kit';
import { createIdentityApi, MemoryIdentityRepository } from '@sedecim/identity-service';
import { createPolicyApi, DEFAULT_ACCESS_LOG_RETENTION_DAYS, GROUP_RETENTION_REFUSED, MemoryPolicyRepository, PolicyEngine, RETENTION_NOTICE } from '@sedecim/policy-engine';

const dist = new URL('../../apps/admin-console/dist/', import.meta.url).pathname;
const types: Record<string, string> = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml' };
let failures = 0;
const assert = (c: unknown, m: string) => {
  if (!c) {
    failures++;
    console.error(`not ok - ${m}`);
    throw new Error(`ASSERTION FAILED: ${m}`);
  }
  console.log(`ok - ${m}`);
};
const factory = (u: string) => new WebSocket(u) as unknown as WebSocketLike;
const until = async (fn: () => boolean | Promise<boolean>, what: string, ms = 10_000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await fn()) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`timeout waiting for ${what}`);
};

// --- keys
const adminSk = generateSecretKey();
const adminPk = getPublicKey(adminSk);
const outsiderSk = generateSecretKey();
const outsiderPk = getPublicKey(outsiderSk);
// FR023-11: a person of the organisation, no admin, who registers the passkey on their own device.
const memberSk = generateSecretKey();
const memberPk = getPublicKey(memberSk);
const aliceSk = generateSecretKey();
const alicePk = getPublicKey(aliceSk);
const aliceAltSk = generateSecretKey();
const aliceAltPk = getPublicKey(aliceAltSk);
const bobPk = getPublicKey(generateSecretKey());

// --- static server with the same nonce substitution and CSP as infra/web/nginx.conf
const server = createServer(async (req, res) => {
  const p = (req.url ?? '/').split('?')[0]!;
  const file = join(dist, p === '/' || !extname(p) ? 'index.html' : p);
  try {
    let body: Buffer | string = await readFile(file);
    const headers: Record<string, string> = { 'content-type': types[extname(file)] ?? 'application/octet-stream' };
    if (file.endsWith('index.html')) {
      const nonce = randomBytes(16).toString('hex');
      body = body.toString('utf8').replaceAll('__NONCE__', nonce);
      headers['content-security-policy'] = `default-src 'self'; connect-src 'self' ws: wss: http://localhost:* http://127.0.0.1:* https:; img-src 'self' data:; style-src 'self' 'nonce-${nonce}'; script-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`;
    }
    res.writeHead(200, headers).end(body);
  } catch {
    res.writeHead(404).end();
  }
});
await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
const base = `http://localhost:${(server.address() as AddressInfo).port}`;

// --- backends
// FR023-13: the real policy-engine. WebAuthn: the console's origin, RP id localhost, `none` attestation accepted.
const engine = new PolicyEngine(new MemoryPolicyRepository(), Date.now, { rpId: 'localhost', rpName: 'Acceso Nostr', origins: [base] });
// Older entries so the audit table has several pages.
for (let i = 0; i < 45; i++) await engine.repo.appendAudit({ at: Date.now() - 5_000_000 + i, actor: 'seed', action: i % 2 ? 'seed.even' : 'seed.odd', target: `seed-${i}` });
const policy = createPolicyApi(engine, { name: 'policy-e2e', adminPubkeys: [adminPk], corsOrigins: [base] });
const policyUrl = await policy.listen();
// What the engine holds, read back through its own API (never through the console).
const subjectOf = async (pk: string) => (await engine.listSubjects()).find((x) => x.pubkey === pk);
const resourceOf = async (id: string) => (await engine.listResources()).find((x) => x.id === id);
const directoryOf = async (pk: string) => (await engine.listDirectory()).find((x) => x.pubkey === pk);
const retentionOf = async (id: string) => (await engine.listRetention()).find((x) => x.resourceId === id);
const auditLog = () => engine.listAudit({ limit: 1000 });
const identityRepo = new MemoryIdentityRepository();
const identity = createIdentityApi(identityRepo, { name: 'identity-e2e', corsOrigins: [base] });
const identityUrl = await identity.listen();
const relay = new TestRelay({ host: '127.0.0.1' });
await relay.start();

// Alice publicly links a second persona (FR-007), so the identity lookup has something to show.
const acc = await nip98Fetch(aliceSk, `${identityUrl}/v1/accounts`, 'POST', { custody_mode: 'local' });
const personasUrl = `${identityUrl}/v1/accounts/me/personas`;
const proof = finalizeEvent(toUnsigned({ kind: nip98.HTTP_AUTH_KIND, content: '', tags: [['u', personasUrl], ['account', acc.json.account_id]] }, aliceAltPk), aliceAltSk);
await nip98Fetch(aliceSk, personasUrl, 'POST', { pubkey: aliceAltPk, proof });
const link = await nip98Fetch(aliceSk, `${identityUrl}/v1/links`, 'POST', { from: alicePk, to: aliceAltPk, visibility: 'public', confirm: true });

const config = { policyEngineUrl: policyUrl, identityServiceUrl: identityUrl, devLocalKey: true };
const browser: Browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
const errors: string[] = [];
const policyRequests: Array<{ method: string; url: string; auth?: string }> = [];
const newContext = async (o: { bypassCSP?: boolean } = {}) => {
  const ctx = await browser.newContext(o);
  await ctx.route('**/config.json', (r) => r.fulfill({ contentType: 'application/json', body: JSON.stringify(config) }));
  return ctx;
};
const watch = (page: Page) => {
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('console', (m) => /Content Security Policy/i.test(m.text()) && errors.push(m.text()));
  if (process.env.DEBUG_E2E) page.on('console', (m) => console.log('[browser]', m.type(), m.text()));
  page.on('request', (r) => r.url().startsWith(policyUrl) && policyRequests.push({ method: r.method(), url: r.url(), ...(r.headers().authorization ? { auth: r.headers().authorization } : {}) }));
};
// FR023-11: «Dispositivos» is also a part of «Mis dispositivos»: that one is matched whole, the rest by what they contain.
const tab = (p: Page, name: string) => p.getByRole('tab', { name, exact: name === 'Dispositivos' }).click();
const signInLocal = async (p: Page, sk: Uint8Array) => {
  await p.fill('#dev-nsec', nsecEncode(sk));
  await p.getByRole('button', { name: 'Entrar con llave local' }).click();
};
const row = (p: Page, attr: string, value: string) => p.locator(`tr[data-${attr}="${value}"]`);

const contexts: BrowserContext[] = [];
const bunkerPool = new RelayPool({ webSocketFactory: factory, signer: new LocalSigner(generateSecretKey()) });
try {
  assert(link.status === 201, 'fixture: identity-service holds a public link for Alice');

  // --- the policy-engine enforces NIP-98 and the admin allowlist
  const noAuth = await fetch(`${policyUrl}/v1/subjects`);
  assert(noAuth.status === 401, 'request without NIP-98 is rejected (401)');
  const wrongUrlEvt = finalizeEvent(toUnsigned(nip98.buildHttpAuthTemplate(`${policyUrl}/v1/resources`, 'GET'), adminPk), adminSk);
  const wrongUrl = await fetch(`${policyUrl}/v1/subjects`, { headers: { authorization: nip98.encodeAuthHeader(wrongUrlEvt) } });
  assert(wrongUrl.status === 401, 'NIP-98 event signed for another URL is rejected (401)');
  const tamperedBody = finalizeEvent(toUnsigned(nip98.buildHttpAuthTemplate(`${policyUrl}/v1/subjects/${bobPk}`, 'PUT', JSON.stringify({ roles: ['a'] })), adminPk), adminSk);
  const tampered = await fetch(`${policyUrl}/v1/subjects/${bobPk}`, { method: 'PUT', headers: { authorization: nip98.encodeAuthHeader(tamperedBody), 'content-type': 'application/json' }, body: JSON.stringify({ roles: ['admin'] }) });
  assert(tampered.status === 401, 'NIP-98 payload hash must match the body (401)');
  assert((await nip98Fetch(outsiderSk, `${policyUrl}/v1/subjects`)).status === 403, 'valid NIP-98 from a non-admin key is refused (403)');
  assert((await nip98Fetch(adminSk, `${policyUrl}/v1/subjects`)).status === 200, 'valid NIP-98 from the admin key is accepted');

  // --- sign-in
  const ctx = await newContext();
  contexts.push(ctx);
  const page = await ctx.newPage();
  watch(page);
  await page.goto(base);
  await page.getByRole('heading', { name: 'Consola de administración' }).waitFor();
  assert(await page.getByRole('button', { name: 'Entrar con extensión NIP-07' }).isDisabled(), 'NIP-07 button disabled without an extension');
  assert(await page.getByText('Solo desarrollo').isVisible(), 'local key sign-in is labeled as development only');
  // FR023-11: a key that is not an admin opens its own devices only, without any admin screen.
  await signInLocal(page, outsiderSk);
  await page.locator('#member-identity').waitFor();
  await page.getByText('No tienes dispositivos registrados a tu nombre').waitFor();
  assert((await page.textContent('#member-identity'))?.includes('sin permisos de administración') && (await page.getByRole('tab').count()) === 0 && (await page.locator('#admin-identity').count()) === 0, 'a non-admin key opens only its own devices, not the console');
  await page.getByRole('button', { name: 'Cerrar sesión' }).click();
  await page.locator('#dev-nsec').waitFor();
  await signInLocal(page, adminSk);
  await page.locator('#admin-identity').waitFor();
  assert((await page.textContent('#admin-identity'))?.includes('Llave local (solo desarrollo)'), 'admin signed in with the local dev key (labeled in the header)');

  // --- personas: create, edit
  await page.getByRole('button', { name: 'Nueva persona' }).click();
  await page.fill('#subject-pubkey', npubEncode(alicePk));
  await page.fill('#subject-roles', 'staff, legal');
  await page.fill('#subject-attributes', 'clearance=secret\nunit=ops|legal');
  await page.getByRole('button', { name: 'Guardar' }).click();
  await row(page, 'pubkey', alicePk).waitFor();
  const alice = await subjectOf(alicePk);
  assert(alice?.roles.join() === 'staff,legal' && alice.attributes.clearance === 'secret' && (alice.attributes.unit as string[]).join() === 'ops,legal', 'subject created with roles and (multi-valued) attributes from an npub');
  await row(page, 'pubkey', alicePk).getByRole('button', { name: 'Editar' }).click();
  assert(await page.locator('#subject-pubkey').isDisabled(), 'the pubkey of an existing subject is not editable');
  await page.fill('#subject-roles', 'staff');
  await page.getByRole('button', { name: 'Guardar' }).click();
  await until(async () => (await subjectOf(alicePk))?.roles.join() === 'staff', 'subject edit');
  assert(true, 'subject roles edited');

  // --- resources: validation, create a group with Alice as member
  await tab(page, 'Recursos y políticas');
  await page.getByRole('button', { name: 'Nuevo recurso' }).click();
  await page.fill('#resource-id', 'grupo-a');
  await page.selectOption('#resource-kind', 'group');
  await page.selectOption('#resource-sensitivity', 'confidential');
  await page.fill('#resource-rules', '[{ "actions": ["fly"] }]');
  await page.getByRole('button', { name: 'Guardar' }).click();
  await page.getByText('regla 0: "actions"').waitFor();
  assert(!(await resourceOf('grupo-a')), 'invalid rules are rejected before calling the API');
  await page.fill('#resource-rules', '[{ "actions": ["read", "publish"], "anyRole": ["staff"], "minDeviceTrust": "registered" }]');
  await page.fill('#resource-members', npubEncode(alicePk));
  await page.getByRole('button', { name: 'Guardar' }).click();
  await row(page, 'resource', 'grupo-a').waitFor();
  const res = await resourceOf('grupo-a');
  assert(res?.kind === 'group' && res.sensitivity === 'confidential' && res.rules[0]?.anyRole?.[0] === 'staff' && res.members?.[0] === alicePk, 'resource saved with kind, sensitivity, rules and members');
  await page.getByRole('button', { name: 'Nuevo recurso' }).click();
  await page.fill('#resource-id', 'canal-general');
  await page.getByRole('button', { name: 'Guardar' }).click();
  await row(page, 'resource', 'canal-general').waitFor();
  assert((await resourceOf('canal-general'))?.members === undefined, 'resource without members omits the field');

  // --- devices: register, passkey through Chromium's virtual authenticator, revoke → rotations
  const cdp = await ctx.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  await tab(page, 'Dispositivos');
  await page.fill('#device-owner', npubEncode(alicePk));
  await page.getByRole('button', { name: 'Buscar dispositivos' }).click();
  await page.getByText('Sin dispositivos.').waitFor();
  await page.getByRole('button', { name: 'Registrar dispositivo' }).click();
  await page.locator('#devices-notice').waitFor();
  const [d1] = await engine.listDevices();
  assert(d1?.ownerPubkey === alicePk && d1.trust === 'registered', 'device registered for the owner');
  await row(page, 'device', d1!.id).getByText('Registrado').waitFor();
  await row(page, 'device', d1!.id).getByRole('button', { name: 'Registrar passkey' }).click();
  await page.getByText('Passkey registrada').waitFor({ timeout: 15_000 });
  await row(page, 'device', d1!.id).getByText('Atestiguado (passkey)').waitFor();
  const creds = (await cdp.send('WebAuthn.getCredentials', { authenticatorId })).credentials;
  const attested = await engine.getDevice(d1!.id);
  assert(attested?.trust === 'attested' && creds.length === 1 && attested.credentialId === Buffer.from(creds[0]!.credentialId, 'base64').toString('base64url'), 'passkey: options → navigator.credentials.create → register, verified by the policy-engine; device attested with that credential');
  await page.getByRole('button', { name: 'Registrar dispositivo' }).click();
  await until(async () => (await engine.listDevices()).length === 2, 'second device');
  const d2 = (await engine.listDevices()).find((d) => d.id !== d1!.id)!;
  await row(page, 'device', d2.id).getByRole('button', { name: 'Revocar' }).click();
  await page.fill('#revoke-reason', 'perdido');
  await page.getByRole('button', { name: 'Revocar dispositivo' }).click();
  await page.locator('#device-revoke-result').waitFor();
  assert((await page.textContent('#device-revoke-result'))?.includes('Grupo grupo-a'), 'revoking a device shows the MLS rotations it queued');
  assert((await engine.getDevice(d2.id))?.revokedAt !== undefined && (await auditLog()).some((a) => a.action === 'device.revoke' && a.details?.reason === 'perdido'), 'device revoked with the given reason');
  await row(page, 'device', d2.id).getByText(/Revocado/).waitFor();

  // --- pending rotations: mark done
  await tab(page, 'Rotaciones pendientes');
  const [rot] = await engine.listRotations('pending');
  await row(page, 'rotation', rot!.id).getByRole('button', { name: 'Marcar como hecha' }).click();
  await page.getByText('No hay rotaciones pendientes.').waitFor();
  assert((await engine.listRotations()).find((r) => r.id === rot!.id)?.status === 'done', 'rotation marked done');

  // --- revoke a subject: confirm dialog explains MLS consequences, rotations shown
  await tab(page, 'Personas');
  await row(page, 'pubkey', alicePk).getByRole('button', { name: 'Revocar' }).click();
  const dialog = page.getByRole('dialog', { name: 'Revocar persona' });
  await dialog.waitFor();
  assert((await dialog.textContent())?.includes('grupo MLS') && (await dialog.textContent())?.includes('rotar la clave'), 'revoke confirmation explains the MLS rotation consequences');
  await dialog.getByRole('button', { name: 'Revocar persona' }).click();
  await page.locator('#subject-revoke-result').waitFor();
  assert((await page.textContent('#subject-revoke-result'))?.includes('Grupo grupo-a'), 'subject revocation shows the returned rotations');
  await row(page, 'pubkey', alicePk).getByText('Revocada').waitFor();
  assert((await subjectOf(alicePk))?.suspended === true && (await engine.getDevice(d1!.id))?.revokedAt !== undefined && !(await resourceOf('grupo-a'))?.members?.includes(alicePk), 'subject suspended, devices revoked, removed from members');
  await tab(page, 'Rotaciones pendientes');
  await page.locator('tr[data-rotation]').first().waitFor();
  assert((await page.locator('tr[data-rotation]').count()) === 1, 'the new rotation is listed as pending');

  // --- FR023-09: editing a revoked subject does not reactivate it; reactivating is explicit and audited
  await tab(page, 'Personas');
  await row(page, 'pubkey', alicePk).getByRole('button', { name: 'Editar' }).click();
  await page.getByText('Esta persona está revocada').waitFor();
  await page.getByRole('button', { name: 'Cancelar' }).click();
  await row(page, 'pubkey', alicePk).getByRole('button', { name: 'Reactivar' }).click();
  const reactivateDialog = page.getByRole('dialog', { name: 'Reactivar persona' });
  await reactivateDialog.waitFor();
  assert((await reactivateDialog.textContent())?.includes('siguen revocados'), 'the reactivation dialog says devices stay revoked');
  await reactivateDialog.getByRole('button', { name: 'Reactivar persona' }).click();
  await row(page, 'pubkey', alicePk).getByText('Activa').waitFor();
  assert(!(await subjectOf(alicePk))?.suspended && (await auditLog()).some((a) => a.action === 'subject.reactivate' && a.target === alicePk), 'subject reactivated explicitly, with its own audit entry');

  // --- directory
  await tab(page, 'Directorio');
  assert((await page.textContent('#directory-notice'))?.includes('nunca se publica'), 'directory states it is never published');
  await page.fill('#dir-pubkey', npubEncode(bobPk));
  await page.fill('#dir-title', 'Jefe de sistemas');
  await page.fill('#dir-unit', 'TI');
  await page.getByRole('button', { name: 'Guardar entrada' }).click();
  await row(page, 'directory', bobPk).waitFor();
  const entry = await directoryOf(bobPk);
  assert(entry?.title === 'Jefe de sistemas' && entry.unit === 'TI', 'directory entry saved');
  await row(page, 'directory', bobPk).getByRole('button', { name: 'Editar' }).click();
  await page.fill('#dir-unit', 'Seguridad');
  await page.getByRole('button', { name: 'Guardar entrada' }).click();
  await row(page, 'directory', bobPk).getByText('Seguridad').waitFor();
  await row(page, 'directory', bobPk).getByRole('button', { name: 'Borrar' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Borrar' }).click();
  await page.getByText('El directorio está vacío.').waitFor();
  assert(!(await directoryOf(bobPk)), 'directory entry edited and deleted');

  // --- retention: API notice shown prominently, per-resource days and legal hold
  await tab(page, 'Retención');
  await page.locator('#retention-notice').waitFor();
  assert((await page.textContent('#retention-notice'))?.includes(RETENTION_NOTICE), 'retention shows the API notice text');
  await row(page, 'retention', 'canal-general').getByRole('button', { name: 'Editar' }).click();
  await page.fill('#retention-days', '30');
  await page.check('#retention-hold');
  await page.getByRole('button', { name: 'Guardar' }).click();
  await row(page, 'retention', 'canal-general').getByText('Retención legal activa').waitFor();
  const kept = await retentionOf('canal-general');
  assert(kept?.days === 30 && kept.legalHold === true, 'retention days and legal hold saved');
  await row(page, 'retention', 'canal-general').getByRole('button', { name: 'Editar' }).click();
  await page.fill('#retention-days', '');
  await page.getByRole('button', { name: 'Guardar' }).click();
  await row(page, 'retention', 'canal-general').getByText('Sin límite').waitFor();
  const unlimited = await retentionOf('canal-general');
  assert(unlimited?.days === null && unlimited.legalHold === true, 'empty days means no automatic deletion (null); the hold stays');
  // FR023-12: an MLS group has no copy for a retention or a hold to act on; the console says so and offers no edit.
  await row(page, 'retention', 'grupo-a').getByText('No aplica (grupo MLS)').waitFor();
  assert((await row(page, 'retention', 'grupo-a').getByRole('button', { name: 'Editar' }).count()) === 0 && !(await retentionOf('grupo-a')), 'a group takes no retention policy');
  const refused = await nip98Fetch(adminSk, `${policyUrl}/v1/retention/grupo-a`, 'PUT', { days: null, legalHold: true });
  assert(refused.status === 409 && refused.json.error === GROUP_RETENTION_REFUSED, 'the policy-engine refuses a hold on a group');

  // --- audit: server pagination (limit/before), client-side filters
  await tab(page, 'Auditoría');
  await until(async () => (await page.locator('#audit-rows tr[data-action]').count()) === 20, 'audit page 1');
  const page1 = await page.locator('#audit-rows tr[data-action]').allTextContents();
  assert(page1[0]?.includes('retention.set'), 'audit newest first');
  await page.getByRole('button', { name: 'Anteriores' }).click();
  await page.getByText('Página 2').waitFor();
  await until(async () => (await page.locator('#audit-rows tr[data-action]').first().textContent()) !== page1[0], 'audit page 2');
  const page2 = await page.locator('#audit-rows tr[data-action]').allTextContents();
  assert(page2.length === 20 && !page2.some((r) => page1.includes(r)), 'second page holds older, different entries');
  assert(policyRequests.some((r) => /\/v1\/audit\?limit=20&before=\d+$/.test(r.url)), 'pagination uses limit and before');
  await page.fill('#audit-action', 'seed.even');
  const filtered = await page.locator('#audit-rows tr[data-action]').evaluateAll((rs) => rs.map((r) => r.getAttribute('data-action')));
  assert(filtered.length > 0 && filtered.length < 20 && filtered.every((a) => a === 'seed.even'), 'client-side filter by action');
  await page.fill('#audit-action', '');
  await page.fill('#audit-actor', 'seed');
  assert((await page.locator('#audit-rows tr[data-action]').count()) === 20, 'client-side filter by actor');
  await page.getByRole('button', { name: 'Más recientes' }).click();
  await page.getByText('Página 1').waitFor();

  // --- FR023-12: access decisions, apart from the audit, with a retention of their own
  for (let i = 0; i < 25; i++) await engine.repo.appendAccess({ at: Date.now() - 4_000_000 + i, pubkey: bobPk, resourceId: 'canal-general', action: 'read', allow: false });
  await engine.evaluate({ pubkey: alicePk, resourceId: 'grupo-a', action: 'read' });
  assert(!(await auditLog()).some((a) => a.action === 'policy.evaluate'), 'decisions are not in the audit');
  await tab(page, 'Accesos');
  await until(async () => (await page.locator('#access-rows tr[data-resource]').count()) === 20, 'access page 1');
  assert((await page.locator('#access-rows tr[data-resource]').first().getAttribute('data-resource')) === 'grupo-a', 'access decisions newest first');
  assert((await page.textContent('#access-scope'))?.includes(`Se guardan ${DEFAULT_ACCESS_LOG_RETENTION_DAYS} días`), 'the access log states its retention');
  await page.getByRole('button', { name: 'Anteriores' }).click();
  await page.getByText('Página 2').waitFor();
  await until(async () => (await page.locator('#access-rows tr[data-resource]').count()) >= 6, 'access page 2');
  await page.fill('#access-resource', 'grupo-a');
  await page.getByRole('button', { name: 'Filtrar' }).click();
  await page.getByText('Página 1').waitFor();
  await until(async () => (await page.locator('#access-rows tr[data-resource]').count()) >= 1 && (await page.locator('#access-rows tr[data-resource="canal-general"]').count()) === 0, 'access filtered by resource');
  assert(policyRequests.some((r) => /\/v1\/access-log\?limit=20&resource=grupo-a$/.test(r.url)), 'the resource filter is applied by the server');
  await page.getByRole('button', { name: 'Ver todos' }).click();
  await until(async () => (await page.locator('#access-rows tr[data-resource]').count()) === 20, 'access unfiltered again');

  // --- identity-service: visible links lookup (no admin listing exists there)
  await tab(page, 'Vínculos de identidad');
  await page.fill('#identity-pubkey', npubEncode(alicePk));
  await page.getByRole('button', { name: 'Consultar vínculos' }).click();
  await page.locator('#identity-links').getByText('Público').waitFor();
  assert(true, 'identity lookup shows the public link through NIP-98');

  // every browser request to the policy-engine carried a NIP-98 header for its exact URL and method
  assert(policyRequests.length > 20, `browser called the policy-engine (${policyRequests.length} requests)`);
  const signedBy = (r: (typeof policyRequests)[number]) => {
    if (!r.auth?.startsWith('Nostr ')) return undefined;
    const evt = JSON.parse(Buffer.from(r.auth.slice(6), 'base64').toString('utf8')) as { pubkey: string; tags: string[][] };
    return evt.tags.find((t) => t[0] === 'u')?.[1] === r.url && evt.tags.find((t) => t[0] === 'method')?.[1] === r.method ? evt.pubkey : undefined;
  };
  const bad = policyRequests.filter((r) => signedBy(r) === undefined);
  assert(bad.length === 0, `every request carries a NIP-98 Authorization for its URL and method (${bad.map((r) => r.url).join(', ')})`);
  const outsiderCalls = policyRequests.filter((r) => signedBy(r) !== adminPk);
  const outsiderUrls = [`${policyUrl}/v1/subjects`, `${policyUrl}/v1/devices?owner=${outsiderPk}`];
  assert(outsiderCalls.every((r) => signedBy(r) === outsiderPk && r.method === 'GET' && outsiderUrls.includes(r.url)) && outsiderUrls.every((u) => outsiderCalls.some((r) => r.url === u)), 'besides the admin, only the outsider signed: the refused admin check and the read of its own devices');
  assert((await auditLog()).filter((a) => a.actor !== 'seed').every((a) => a.actor === adminPk), 'every change the policy-engine audited was made by the admin key');

  await page.getByRole('button', { name: 'Cerrar sesión' }).click();
  await page.locator('#dev-nsec').waitFor();
  assert((await page.inputValue('#dev-nsec')) === '', 'sign-out returns to the sign-in screen without keeping the key');

  // --- FR023-11: the person registers the passkey on their own device (their browser's authenticator, signed with their
  // own key), and every session they open asks that authenticator for an assertion
  const memberDevice = await engine.registerDevice(adminPk, memberPk);
  const memberCtx = await newContext();
  contexts.push(memberCtx);
  const member = await memberCtx.newPage();
  watch(member);
  const memberCdp = await memberCtx.newCDPSession(member);
  await memberCdp.send('WebAuthn.enable');
  const memberAuthenticator = (await memberCdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } })).authenticatorId;
  await member.goto(base);
  await signInLocal(member, memberSk);
  await member.locator('#member-identity').waitFor();
  await row(member, 'own-device', memberDevice.id).getByRole('button', { name: 'Registrar passkey' }).click();
  await member.locator('#my-devices-notice').waitFor({ timeout: 15_000 });
  await row(member, 'own-device', memberDevice.id).getByText('Atestiguado (passkey)').waitFor();
  const memberCreds = (await memberCdp.send('WebAuthn.getCredentials', { authenticatorId: memberAuthenticator })).credentials;
  const memberAttested = await engine.getDevice(memberDevice.id);
  assert(
    memberAttested?.trust === 'attested' && memberCreds.length === 1 && memberAttested.credentialId === Buffer.from(memberCreds[0]!.credentialId, 'base64').toString('base64url') && (await auditLog()).some((a) => a.action === 'device.attest' && a.actor === memberPk && a.target === memberDevice.id),
    'FR023-11: the person registers the passkey on their own device, with their own key',
  );
  assert((await nip98Fetch(memberSk, `${policyUrl}/v1/sessions`, 'POST', { deviceId: memberDevice.id })).status === 403, 'FR023-11: from then on a session without the assertion of that passkey is refused');
  const memberTokens: string[] = [];
  for (const n of [1, 2]) {
    const [opened] = await Promise.all([
      member.waitForResponse((r) => r.url() === `${policyUrl}/v1/sessions` && r.request().method() === 'POST'),
      row(member, 'own-device', memberDevice.id).getByRole('button', { name: 'Abrir sesión con passkey' }).click(),
    ]);
    const body = (await opened.json()) as { token: string; deviceId: string; asserted: boolean };
    assert(opened.status() === 201 && body.asserted && body.deviceId === memberDevice.id, `FR023-11: session ${n} opened with an assertion of the passkey (navigator.credentials.get)`);
    memberTokens.push(body.token);
  }
  await member.locator('#my-session').waitFor();
  assert(memberTokens[0] !== memberTokens[1] && (await Promise.all(memberTokens.map((t) => engine.sessionValid(t)))).every(Boolean), 'FR023-11: each session asked for its own assertion and is bound to the device');
  await engine.revokeDevice(adminPk, memberDevice.id, 'perdido');
  assert((await Promise.all(memberTokens.map((t) => engine.sessionValid(t)))).every((v) => !v), 'FR023-11: revoking the device ends the sessions opened with its passkey');

  // --- NIP-07 extension sign-in (window.nostr injected; signing happens in Node)
  const extCtx = await newContext();
  contexts.push(extCtx);
  const ext = await extCtx.newPage();
  watch(ext);
  const adminSigner = new LocalSigner(adminSk);
  await ext.exposeFunction('__e2eSign', async (t: string) => JSON.stringify(await adminSigner.signEvent(JSON.parse(t))));
  // A string, not a function: tsx's keepNames helpers do not exist in the page.
  await ext.addInitScript(`window.nostr = { getPublicKey: async () => ${JSON.stringify(adminPk)}, signEvent: async (t) => JSON.parse(await window.__e2eSign(JSON.stringify(t))) };`);
  await ext.goto(base);
  await ext.getByRole('button', { name: 'Entrar con extensión NIP-07' }).click();
  await ext.locator('#admin-identity').waitFor();
  assert((await ext.textContent('#admin-identity'))?.includes('Extensión NIP-07'), 'admin signs in with a NIP-07 extension');

  // --- NIP-46 bunker sign-in (only kind 27235 is requested and allowed)
  const bunker = new Nip46Bunker(new LocalSigner(adminSk), bunkerPool, [relay.url], { allowedKinds: [27235] });
  const bunkerUrl = await bunker.start();
  const remoteCtx = await newContext();
  contexts.push(remoteCtx);
  const remote = await remoteCtx.newPage();
  watch(remote);
  await remote.goto(base);
  await remote.fill('#bunker-url', bunkerUrl);
  await remote.getByRole('button', { name: 'Conectar bunker' }).click();
  await remote.locator('#admin-identity').waitFor({ timeout: 20_000 });
  assert((await remote.textContent('#admin-identity'))?.includes('Bunker NIP-46'), 'admin signs in through a NIP-46 bunker');
  await remote.getByRole('tab', { name: 'Recursos y políticas' }).click();
  await row(remote, 'resource', 'grupo-a').waitFor({ timeout: 15_000 });
  assert(true, 'requests signed remotely by the bunker are accepted');
  bunker.stop();

  // --- accessibility (NFR009-01): axe-core on every screen and the main dialogs
  const a11yCtx = await newContext({ bypassCSP: true });
  contexts.push(a11yCtx);
  const a11y = await a11yCtx.newPage();
  a11y.on('pageerror', (e) => errors.push(e.message));
  const axePath = createRequire(import.meta.url).resolve('axe-core/axe.min.js');
  const audit = async (label: string) => {
    await a11y.addScriptTag({ path: axePath });
    const v = await a11y.evaluate(async () => (await (window as unknown as { axe: { run(): Promise<{ violations: Array<{ id: string; impact: string; nodes: unknown[] }> }> } }).axe.run()).violations.filter((x) => x.impact === 'serious' || x.impact === 'critical').map((x) => `${x.id}(${x.nodes.length}: ${(x.nodes as Array<{ target: string[]; failureSummary?: string }>).map((n) => `${n.target.join(' ')} ${n.failureSummary ?? ''}`.replace(/\s+/g, ' ').slice(0, 220)).join(' | ')})`));
    assert(v.length === 0, `axe: no serious/critical violations on ${label} (${v.join(', ')})`);
    const dup = await a11y.evaluate(() => {
      const seen = new Map<string, number>();
      for (const el of document.querySelectorAll('[id]')) seen.set(el.id, (seen.get(el.id) ?? 0) + 1);
      return [...seen].filter(([, n]) => n > 1).map(([id]) => id);
    });
    assert(dup.length === 0, `no duplicate ids on ${label} (${dup.join(', ')})`);
  };
  // axe must not run during the dialog fade-in (half-transparent text fails contrast).
  const dialogShown = () => a11y.waitForFunction(() => [...document.querySelectorAll('.MuiDialog-container')].every((e) => getComputedStyle(e).opacity === '1'));
  await a11y.goto(base);
  await a11y.locator('#dev-nsec').waitFor();
  await audit('sign-in');
  await signInLocal(a11y, adminSk);
  await a11y.locator('#admin-identity').waitFor();
  await row(a11y, 'pubkey', alicePk).waitFor();
  await audit('Personas');
  await a11y.getByRole('button', { name: 'Nueva persona' }).click();
  await a11y.locator('#subject-pubkey').waitFor();
  await dialogShown();
  await audit('Personas: dialog');
  await a11y.keyboard.press('Escape');
  await a11y.getByRole('dialog').waitFor({ state: 'detached' });
  await a11y.getByRole('tab', { name: 'Recursos y políticas' }).click();
  await row(a11y, 'resource', 'grupo-a').waitFor();
  await audit('Recursos');
  await row(a11y, 'resource', 'grupo-a').getByRole('button', { name: 'Editar' }).click();
  await a11y.locator('#resource-rules').waitFor();
  await dialogShown();
  await audit('Recursos: dialog');
  await a11y.keyboard.press('Escape');
  await a11y.getByRole('dialog').waitFor({ state: 'detached' });
  await a11y.getByRole('tab', { name: 'Dispositivos', exact: true }).click();
  await a11y.fill('#device-owner', alicePk);
  await a11y.getByRole('button', { name: 'Buscar dispositivos' }).click();
  await row(a11y, 'device', d1!.id).waitFor();
  await audit('Dispositivos');
  for (const [name, ready] of [
    ['Rotaciones pendientes', 'tr[data-rotation]'],
    ['Directorio', '#directory-notice'],
    ['Retención', '#retention-notice'],
    ['Auditoría', '#audit-rows tr[data-action]'],
    ['Accesos', '#access-rows tr[data-resource]'],
    ['Vínculos de identidad', '#identity-pubkey'],
    ['Mis dispositivos', '#my-devices table'],
  ] as const) {
    await a11y.getByRole('tab', { name }).click();
    await a11y.locator(ready).first().waitFor();
    await audit(name);
  }
  // FR023-11: what a key without admin rights opens (the person's device, attested and revoked above).
  await a11y.getByRole('button', { name: 'Cerrar sesión' }).click();
  await signInLocal(a11y, memberSk);
  await row(a11y, 'own-device', memberDevice.id).waitFor();
  await audit('Mis dispositivos, sin permisos de administración');

  assert(errors.length === 0, `no page errors or CSP violations (${errors.join(' | ')})`);
} finally {
  for (const c of contexts) await c.close().catch(() => undefined);
  await browser.close();
  bunkerPool.close();
  server.close();
  await policy.close();
  await identity.close();
  await relay.stop();
}
if (failures) process.exit(1);
