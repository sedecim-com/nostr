/**
 * Browser E2E for the Acceso Nostr web client (sprint S2). Run with: npm run test:browser
 * Serves the Vite build like nginx does (per-request CSP nonce) against an in-process relay, Blossom
 * servers, identity-service and a simulated Acceso (Cognito) endpoint.
 */
import { createServer } from 'node:http';
import { createSign, generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { extname, join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { chromium, type Page, type Route } from 'playwright';
import WebSocket from 'ws';
import { verifyEvent as ntVerifyEvent } from 'nostr-tools';
import type { VaultExport } from '@sedecim/continuity';
import { bytesToHex, finalizeEvent, generateSecretKey, getPublicKey, getTagValue, nip19, npubEncode, toUnsigned } from '@sedecim/nostr-core';
import { LocalSigner, Nip46Bunker } from '@sedecim/signer';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { heicWithGps, TestBlossomServer, TestRelay, tinyPng } from '@sedecim/test-relay';
import { APP_RECEIPT_KIND, buildProfile, chatMessage, createDirectMessage, createReceipt, dmInboxFilter, FILE_MESSAGE_KIND, openDirectMessage, unwrap } from '@sedecim/messaging';
import { BlossomClient } from '@sedecim/blossom-client';
import { CognitoVerifier, createIdentityApi, MemoryIdentityRepository } from '@sedecim/identity-service';
import { createManagedSignerApi, ManagedSigner, MemoryVault } from '@sedecim/managed-signer';
import { backupFile, generateKey } from '@sedecim/key-generator';
import { managedConsentVersion } from '@sedecim/profiles';
import { createNotificationApi, generateVapidKeys, NotificationGateway, createWebPushSender } from '@sedecim/notification-gateway';
import { createContinuityVaultApi, MemoryArchiveRepository, MemoryObjectStore } from '@sedecim/continuity-vault';
import { createPolicyApi, PolicyEngine } from '@sedecim/policy-engine';
import { HttpPolicySource, managedSignerSink, RevocationPropagator } from '@sedecim/rotation-worker';

const dist = new URL('../../apps/web-saas/dist/', import.meta.url).pathname;
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
const PASS = 'contraseña-local-larga';

// --- backends
const relay = new TestRelay({ requireAuth: true, pGatedKinds: [1059], host: '127.0.0.1' });
await relay.start();
// Bob's DM inbox relay (kind 10050): the web must route his wraps here (FR010-02).
const bobRelay = new TestRelay({ requireAuth: true, pGatedKinds: [1059], host: '127.0.0.1' });
await bobRelay.start();
const media = new TestBlossomServer(); // Buzz /media: plain images, downloads need BUD-01 auth
media.requireGetAuth = true;
media.cors = true;
await media.start();
const blobs = new TestBlossomServer(); // blob-store: client-encrypted attachments
blobs.cors = true;
await blobs.start();
const userBlobs = new TestBlossomServer(); // a Blossom server of the user's own kind 10063 list (FR018-05)
userBlobs.cors = true;
await userBlobs.start();

// Acceso (Cognito) simulated with a real RS256 key; identity-service verifies against its JWKS.
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const cognito = { region: 'us-east-1', userPoolId: 'us-east-1_E2E', userPoolClientId: 'acceso-web', authFlowType: 'USER_PASSWORD_AUTH' as const };
const iss = `https://cognito-idp.${cognito.region}.amazonaws.com/${cognito.userPoolId}`;
const jwt = (claims: Record<string, unknown>) => {
  const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const body = `${enc({ alg: 'RS256', kid: 'e2e' })}.${enc({ iss, sub: 'acceso-user-1', iat: now, exp: now + 3600, ...claims })}`;
  return `${body}.${createSign('RSA-SHA256').update(body).sign(privateKey).toString('base64url')}`;
};
const identityRepo = new MemoryIdentityRepository();

// Static server with the same nonce substitution as infra/web/nginx.conf.
const server = createServer(async (req, res) => {
  const p = (req.url ?? '/').split('?')[0]!;
  const file = join(dist, p === '/' || !extname(p) ? 'index.html' : p);
  try {
    let body: Buffer | string = await readFile(file);
    const headers: Record<string, string> = { 'content-type': types[extname(file)] ?? 'application/octet-stream' };
    if (file.endsWith('index.html')) {
      const nonce = randomBytes(16).toString('hex');
      body = body.toString('utf8').replaceAll('__NONCE__', nonce);
      headers['content-security-policy'] = `default-src 'self'; connect-src 'self' ws: wss: http://localhost:* http://127.0.0.1:* https:; img-src 'self' data: blob:; style-src 'self' 'nonce-${nonce}'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'`;
    }
    res.writeHead(200, headers).end(body);
  } catch {
    res.writeHead(404).end();
  }
});
await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
const identity = createIdentityApi(identityRepo, {
  name: 'identity-e2e',
  corsOrigins: [base],
  cognito: new CognitoVerifier({ region: cognito.region, userPoolId: cognito.userPoolId, clientId: cognito.userPoolClientId, fetch: (async () => new Response(JSON.stringify({ keys: [{ ...publicKey.export({ format: 'jwk' }), kid: 'e2e', alg: 'RS256' }] }))) as typeof fetch }),
});
const identityUrl = await identity.listen();
// Custodial managed-signer (SaaS only, ADR 0009): authorized by the same simulated Acceso tokens.
const managedCore = new ManagedSigner(new MemoryVault());
// FR024-03: the rotation worker (FR024-05) sends the organisation's device revocations with this token.
const REVOCATION_TOKEN = 'revocation-token-e2e-0123456789';
const managed = createManagedSignerApi(managedCore, {
  name: 'managed-e2e',
  corsOrigins: [base],
  // FR005-11: as a strict deployment runs it: keys only through device sessions, never the bare Acceso token.
  requireDeviceSession: true,
  revocationTokens: { [REVOCATION_TOKEN]: 'rotation-worker' },
  cognito: new CognitoVerifier({ region: cognito.region, userPoolId: cognito.userPoolId, clientId: cognito.userPoolClientId, fetch: (async () => new Response(JSON.stringify({ keys: [{ ...publicKey.export({ format: 'jwk' }), kid: 'e2e', alg: 'RS256' }] }))) as typeof fetch }),
});
const managedUrl = await managed.listen();
// FR024-03: the organisation's policy-engine, and what its rotation worker service runs (FR024-05): the revocation feed
// sent to the managed-signer.
const orgPolicy = new PolicyEngine();
const orgAdmin = getPublicKey(generateSecretKey());
const POLICY_TOKEN = 'policy-token-e2e-0123456789';
const policyApi = createPolicyApi(orgPolicy, { name: 'policy-e2e', adminPubkeys: [orgAdmin], bearerTokens: { [POLICY_TOKEN]: 'rotation-worker' } });
const policyUrl = await policyApi.listen();
const propagator = new RevocationPropagator({
  feed: new HttpPolicySource({ baseUrl: policyUrl, signer: new LocalSigner(generateSecretKey()), bearer: POLICY_TOKEN }),
  sinks: [managedSignerSink({ baseUrl: managedUrl, token: REVOCATION_TOKEN })],
});
// Opaque push gateway (ADR 0010): the web only offers the opt-in control; nothing registers unless clicked. OPS-06: it
// authenticates with its own identity, as deployed, and checks with a canary whether it can see activity on the relay.
const vapid = generateVapidKeys();
const gatewayCore = new NotificationGateway({ pool: new RelayPool({ webSocketFactory: factory, signer: new LocalSigner(generateSecretKey()), authMode: 'auto' }), sender: createWebPushSender({ vapid, subject: 'mailto:e2e@example.org' }), relays: [{ public: relay.url }] });
const gateway = createNotificationApi(gatewayCore, { name: 'notification-e2e', corsOrigins: [base], vapid });
const gatewayUrl = await gateway.listen();
const gatewayProbe = await gatewayCore.probeRelays(3000);
// VAULT-02: the Continuity Vault, with its storage in reach of the test to check what the operator holds.
const vaultRepo = new MemoryArchiveRepository();
const vaultObjects = new MemoryObjectStore();
const continuity = createContinuityVaultApi(vaultRepo, vaultObjects, { name: 'vault-e2e', corsOrigins: [base] });
const continuityUrl = await continuity.listen();
const selfHosted = { mode: 'self-hosted', relays: [relay.url], buzzMedia: media.url, blobStore: blobs.url, identityService: identityUrl, notificationGateway: gatewayUrl, continuityVault: continuityUrl };

const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
const context = await browser.newContext();
await context.route('**/config.json', (r) => r.fulfill({ contentType: 'application/json', body: JSON.stringify(selfHosted) }));
const page = await context.newPage();
// E2E_CPU_THROTTLE=6 emulates a slow CI runner (surfaces races such as ephemeral NIP-46 responses).
if (process.env.E2E_CPU_THROTTLE) await (await context.newCDPSession(page)).send('Emulation.setCPUThrottlingRate', { rate: Number(process.env.E2E_CPU_THROTTLE) });
const errors: string[] = [];
const external: string[] = [];
const outbound: string[] = [];
page.on('pageerror', (e) => errors.push(e.message));
if (process.env.DEBUG_E2E) page.on('console', (m) => console.log('[browser]', m.type(), m.text()));
page.on('console', (m) => /Content Security Policy/i.test(m.text()) && errors.push(m.text()));
page.on('request', (r) => {
  // blob:/data: URLs are in-memory objects of this page (e.g. decrypted images), not network requests.
  const u = new URL(r.url());
  if (u.protocol !== 'blob:' && u.protocol !== 'data:' && u.hostname !== '127.0.0.1') external.push(r.url());
  outbound.push(`${r.url()} ${r.postData() ?? ''} ${JSON.stringify(r.headers())}`);
});
page.on('websocket', (ws) => ws.on('framesent', (f) => outbound.push(String(f.payload))));

const tab = (p: Page, name: string) => p.getByRole('tab', { name }).click();
const fill = (p: Page, id: string, v: string) => p.fill(`#${id}`, v);

const pools: RelayPool[] = [];
try {
  // --- vault (DEC-05 / FR001-04): IndexedDB, password-protected
  await page.goto(base);
  await page.getByText('Crear almacén').waitFor();
  await fill(page, 'local-pass', PASS);
  await page.getByRole('button', { name: 'Crear almacén' }).click();
  await page.getByRole('button', { name: 'Crear persona' }).waitFor();
  assert((await page.textContent('#sending-as'))?.includes('Sin identidad activa'), 'workspace opens after creating the vault');

  // --- persona with a KNOWN key so we can prove it never leaves the browser (FR001-05)
  const knownSk = generateSecretKey();
  const knownNsec = nip19.nsecEncode(knownSk);
  await page.getByLabel('Importar nsec / ncryptsec').check();
  await fill(page, 'persona-label', 'Trabajo');
  await fill(page, 'secret-input', knownNsec);
  await fill(page, 'relays', relay.url);
  await page.getByRole('button', { name: 'Crear persona' }).click();
  await page.waitForFunction(() => document.querySelector('#sending-as')?.textContent?.includes('Enviando como Trabajo'));
  assert(true, 'banner "Enviando como…" names the active persona (FR006-02)');
  assert((await page.textContent('#sending-as'))?.endsWith('· Llave local (navegador) · red directa · sin vínculo'), 'the banner also says custody, network and link level (FR007-05)');
  assert((await page.textContent('#custody-facts'))?.includes('NO puede firmar'), 'custody facts are disclosed');
  assert((await page.locator('#cloud-backup').count()) === 0, 'no cloud backup is offered when the deployment does not configure backupVault (FR027-03)');
  const webPub = getPublicKey(knownSk);
  await page.waitForTimeout(500);
  const probe = new RelayPool({ webSocketFactory: factory, signer: new LocalSigner(generateSecretKey()) });
  pools.push(probe);
  const ownList = (await probe.query([relay.url], [{ kinds: [10050], authors: [webPub] }], 3000))[0];
  assert(ownList?.tags.some((t) => t[0] === 'relay' && t[1] === relay.url), 'onboarding publishes the persona DM relay list (kind 10050, FR017-04)');

  // --- channels: discovery (39000), read, write (FR015-02, FR-014/015)
  const other = new LocalSigner(generateSecretKey());
  const pool = new RelayPool({ webSocketFactory: factory, signer: other });
  pools.push(pool);
  const relayKey = generateSecretKey();
  relay.inject(finalizeEvent(toUnsigned({ kind: 39000, content: '', tags: [['d', 'general'], ['name', 'General'], ['about', 'Canal de pruebas']] }, getPublicKey(relayKey)), relayKey));
  await pool.publishTo(await other.signEvent(chatMessage('general', 'hola desde desktop')), relay.url);
  await tab(page, 'Canales');
  await page.locator('#channel-list').getByText('General').click();
  await page.locator('#channel-log').getByText('hola desde desktop').waitFor({ timeout: 10_000 });
  assert(true, 'channel discovered from kind 39000 and messages from another client are shown');
  await fill(page, 'channel-text', 'hola desde la web');
  await page.locator('#channel-send').getByRole('button', { name: 'Enviar' }).click();
  await page.locator('#channel-log').getByText('hola desde la web').waitFor({ timeout: 10_000 });
  const fromOther = await pool.query([relay.url], [{ kinds: [9], '#h': ['general'] }], 3000);
  assert(fromOther.some((e) => e.content === 'hola desde la web'), 'message sent from the web is visible to other clients (FR-015)');
  await page.locator('#channel-list').getByRole('button', { name: 'Unirse' }).first().click();
  await page.waitForTimeout(500);
  assert((await pool.query([relay.url], [{ kinds: [9021], '#h': ['general'] }], 3000)).some((e) => e.pubkey === webPub), 'join request (kind 9021) published (FR015-02)');

  // --- channel image: sanitized, stored in Buzz /media, fetched with auth and hash-verified (FR018-04)
  await page.locator('#channel-send input[type=file]').setInputFiles({ name: 'foto.png', mimeType: 'image/png', buffer: Buffer.from(tinyPng()) });
  await fill(page, 'channel-text', 'con imagen');
  await page.locator('#channel-send').getByRole('button', { name: 'Enviar' }).click();
  await page.locator('#channel-log img').waitFor({ timeout: 10_000 }).catch(async (e) => {
    console.log('media blobs', media.blobs.size, 'alerts:', await page.locator('.MuiAlert-message').allTextContents());
    throw e;
  });
  assert(media.blobs.size === 1, 'channel image uploaded to the relay media server');
  const imgMsg = (await pool.query([relay.url], [{ kinds: [9], '#h': ['general'] }], 3000)).find((e) => e.content.startsWith('con imagen'));
  assert(imgMsg?.tags.some((t) => t[0] === 'imeta' && t.some((x) => x.startsWith('x '))), 'channel image message carries an imeta tag with the hash');

  // --- outbox
  await tab(page, 'Entrega');
  await page.locator('#outbox-rows td', { hasText: 'REPLICATED' }).first().waitFor({ timeout: 10_000 });
  assert(true, 'outbox shows REPLICATED state');
  // VAULT-04: the convenience profile copies each send to the Continuity Vault best-effort, a state of its own.
  await page.locator('#outbox-rows td.outbox-vault', { hasText: 'CONTINUITY_BACKED_UP' }).first().waitFor({ timeout: 10_000 });
  assert(vaultRepo.rows().length > 0, 'each send is copied to the Continuity Vault (CONTINUITY_BACKED_UP beside the relay ACK), before any manual push (VAULT-04)');
  await page.locator('#relay-health-rows tr', { hasText: 'OK' }).first().waitFor({ timeout: 10_000 });
  assert((await page.locator('.relay-degraded').count()) === 0, 'relay health: a healthy relay is shown as OK with its P95 (NFR004-02)');
  // A slow relay is surfaced as degraded with its P95, not hidden behind silent retries (NFR004-02).
  relay.faults.okDelayMs = 2300;
  await tab(page, 'Canales');
  await page.locator('#channel-list').getByText('General').click();
  await fill(page, 'channel-text', 'mensaje lento');
  await page.locator('#channel-send').getByRole('button', { name: 'Enviar' }).click();
  await tab(page, 'Entrega');
  await page.locator('.relay-degraded').first().waitFor({ timeout: 15_000 });
  relay.faults.okDelayMs = 0;
  assert(/degradado · P95 \d+ ms/.test((await page.locator('.relay-degraded').first().textContent()) ?? ''), 'a relay with P95 above 2 s shows a "degradado · P95" chip');
  assert(await page.locator('#relay-degraded-alert').isVisible(), 'the degradation is announced above the outbox');

  // --- NIP-17 DM + encrypted attachment, enabled by the gate flags (FR-017, FR018-04)
  const bobKey = generateSecretKey();
  const bob = new LocalSigner(bobKey);
  const bobPool = new RelayPool({ webSocketFactory: factory, signer: bob });
  pools.push(bobPool);
  await bobPool.publishTo(await bob.signEvent({ kind: 10050, content: '', tags: [['relay', bobRelay.url]] }), relay.url);
  // FR006-04: Bob's public profile, which the web shows once Bob is a contact (someone it wrote to).
  await bobPool.publishTo(await bob.signEvent(buildProfile({ name: 'Bob del escritorio' })), relay.url);
  await tab(page, 'Mensajes directos');
  assert(await page.isChecked('#nip17-flag'), 'NIP-17 enabled from flags.json generated by the interop gate (FR-017)');
  assert((await page.textContent('#nip17-gate'))?.includes('gate de interoperabilidad'), 'flag source is shown to the user');
  await fill(page, 'dm-to', npubEncode(getPublicKey(bobKey)));
  await fill(page, 'dm-text', 'dm desde la web');
  await page.locator('#dm-send').getByRole('button', { name: 'Enviar' }).click();
  await page.waitForFunction(() => (document.querySelector('#dm-text') as HTMLTextAreaElement).value === '');
  const secretDoc = Buffer.from('documento confidencial');
  await page.locator('#dm-send input[type=file]').setInputFiles({ name: 'doc.txt', mimeType: 'text/plain', buffer: secretDoc });
  await page.locator('#dm-send').getByRole('button', { name: 'Enviar' }).click();
  let gotText = false;
  let fileRumor: Awaited<ReturnType<typeof openDirectMessage>>['rumor'] | undefined;
  for (let i = 0; i < 40 && !(gotText && fileRumor); i++) {
    await new Promise((r) => setTimeout(r, 250));
    for (const w of await bobPool.query([bobRelay.url], [dmInboxFilter(getPublicKey(bobKey))], 2000)) {
      const m = await openDirectMessage(bob, w).catch(() => undefined);
      if (m?.rumor.content === 'dm desde la web') gotText = true;
      if (m?.kind === FILE_MESSAGE_KIND) fileRumor = m.rumor;
    }
  }
  assert(gotText, 'NIP-17 DM routed to the recipient DM relay (10050) and readable by an independent client (FR010-02)');
  assert((await bobPool.query([relay.url], [dmInboxFilter(getPublicKey(bobKey))], 2000)).length === 0, 'the recipient wrap is not left on the sender relays');
  if (!fileRumor) console.log('blob-store blobs', blobs.blobs.size, 'alerts:', await page.locator('.MuiAlert-message').allTextContents());
  assert(fileRumor && ![...blobs.blobs.values()].some((b) => Buffer.from(b.data).includes(secretDoc)), 'DM attachment stored encrypted in the blob-store');
  const plain = await new BlossomClient(blobs.url, bob).download(getTagValue(fileRumor!, 'x')!, { url: fileRumor!.content, decrypt: { keyHex: getTagValue(fileRumor!, 'decryption-key')!, nonceHex: getTagValue(fileRumor!, 'decryption-nonce')! } });
  assert(Buffer.from(plain).equals(secretDoc), 'recipient decrypts the attachment after hash verification (kind 15)');

  // --- FR019-03: the profile strips file metadata, so a HEIC with GPS attached to a DM is refused before any upload
  const storedBlobs = () => blobs.blobs.size + userBlobs.blobs.size + media.blobs.size;
  const storedBeforeHeic = storedBlobs();
  await page.locator('#dm-send input[type=file]').setInputFiles({ name: 'IMG_0042.HEIC', mimeType: 'image/heic', buffer: Buffer.from(heicWithGps()) });
  await page.locator('#dm-send').getByRole('button', { name: 'Enviar' }).click();
  const heicRefusal = page.locator('.MuiAlert-message', { hasText: 'HEIC/HEIF/AVIF' });
  await heicRefusal.waitFor({ timeout: 10_000 });
  assert(storedBlobs() === storedBeforeHeic, 'a HEIC with GPS attached to a DM is refused before any upload (FR019-03)');
  assert((await heicRefusal.textContent())?.includes('JPEG, PNG o WebP'), 'the refusal tells the user how to share the image');

  // --- FR018-05: the user's Blossom server list (kind 10063) drives uploads; ciphertext skips image-only media
  await tab(page, 'Personas');
  await page.locator('#blossom-servers').waitFor();
  await page.waitForFunction(() => !(document.querySelector('#blossom-servers') as HTMLTextAreaElement).disabled);
  await fill(page, 'blossom-servers', `${media.url}\n${userBlobs.url}`);
  assert((await page.textContent('#blossom-encrypted-route'))?.includes(new URL(userBlobs.url).host) && !(await page.textContent('#blossom-encrypted-route'))?.includes(new URL(media.url).host), 'encrypted attachments route skips the image-only relay media server');
  await page.click('#blossom-publish');
  let serverList: string[] = [];
  for (let i = 0; i < 20 && serverList.length === 0; i++) {
    await new Promise((r) => setTimeout(r, 250));
    const evt = (await probe.query([relay.url], [{ kinds: [10063], authors: [webPub] }], 2000))[0];
    serverList = evt ? evt.tags.filter((t) => t[0] === 'server').map((t) => t[1]!) : [];
  }
  assert(serverList.join(',') === `${media.url},${userBlobs.url}`, 'the web publishes the user Blossom server list (kind 10063, BUD-03)');

  // --- FR006-04: Trabajo (a linked identity: no extra step) publishes its public profile, the avatar uploaded without
  // its metadata to its first Blossom server; other clients read the kind 0 and the channel shows the name next to the npub.
  await page.waitForFunction(() => {
    const el = document.querySelector('#profile-name') as HTMLInputElement | null;
    return !!el && !el.disabled;
  });
  assert((await page.locator('#profile-pseudonymous').count()) === 0, 'a linked identity gets no pseudonymous warning (FR006-04)');
  await fill(page, 'profile-name', 'Ana del trabajo');
  await page.locator('#profile-avatar-file').setInputFiles({ name: 'avatar.png', mimeType: 'image/png', buffer: Buffer.from(tinyPng('foto en casa')) });
  await page.waitForFunction(() => (document.querySelector('#profile-picture') as HTMLInputElement).value.startsWith('http'), undefined, { timeout: 10_000 });
  const avatarUrl = await page.inputValue('#profile-picture');
  assert(avatarUrl.startsWith(media.url) && ![...media.blobs.values()].some((b) => Buffer.from(b.data).includes(Buffer.from('foto en casa'))), 'the avatar goes to the persona’s first Blossom server without its metadata (FR006-04)');
  await page.locator('#profile-publish').click();
  let profileEvent: { content: string } | undefined;
  for (let i = 0; i < 40 && !profileEvent; i++) {
    await new Promise((r) => setTimeout(r, 250));
    profileEvent = (await probe.query([relay.url], [{ kinds: [0], authors: [webPub] }], 2000))[0];
  }
  const published = JSON.parse(profileEvent?.content ?? '{}') as { name?: string; picture?: string };
  assert(published.name === 'Ana del trabajo' && published.picture === avatarUrl, 'the public profile (kind 0), signed with the persona key, reaches its relay and another client reads it (FR006-04)');
  await tab(page, 'Canales');
  await page.locator('#channel-list').getByText('General').click();
  await page.locator('#channel-log').getByText(`Ana del trabajo · ${npubEncode(webPub).slice(0, 12)}`, { exact: false }).first().waitFor({ timeout: 10_000 });
  assert(true, 'the channel shows the author’s public name next to the npub (FR006-04)');

  await tab(page, 'Mensajes directos');
  await fill(page, 'dm-to', npubEncode(getPublicKey(bobKey)));
  await page.locator('#dm-send input[type=file]').setInputFiles({ name: 'otro.txt', mimeType: 'text/plain', buffer: Buffer.from('segundo adjunto') });
  const mediaBefore = media.blobs.size;
  await page.locator('#dm-send').getByRole('button', { name: 'Enviar' }).click();
  for (let i = 0; i < 40 && userBlobs.blobs.size === 0; i++) await new Promise((r) => setTimeout(r, 250));
  assert(userBlobs.blobs.size === 1 && media.blobs.size === mediaBefore, 'with a kind 10063 list the encrypted attachment goes to the user server, never to the image-only media');

  // --- FR009-03: the web reads its own DM relays (its kind 10050) in the background, from any view
  assert((await page.textContent('#dm-inbox-mode'))?.includes('segundo plano'), 'the DM view says messages and receipts arrive in the background (FR009-03)');
  let webDmRumor: string | undefined;
  for (const w of await bobPool.query([bobRelay.url], [dmInboxFilter(getPublicKey(bobKey))], 2000)) {
    const m = await openDirectMessage(bob, w).catch(() => undefined);
    if (m?.rumor.content === 'dm desde la web') webDmRumor = m.rumor.id;
  }
  // Bob answers on the web persona's DM relay while the user is on another view: nobody clicks «Actualizar».
  await tab(page, 'Entrega');
  const ack = await createReceipt(bob, webPub, webDmRumor!, 'delivered');
  await bobPool.publishTo(ack.event, relay.url);
  await page.locator('#outbox-rows td', { hasText: 'RECIPIENT_ACKED' }).first().waitFor({ timeout: 10_000 });
  assert(true, 'a delivered receipt reaches the web in the background and moves the DM to RECIPIENT_ACKED (FR009-02, FR009-03)');

  // --- a DM that arrives while the user is elsewhere is counted on the tab and shown without refreshing
  const toWeb = await createDirectMessage(bob, { recipients: [webPub], content: 'hola web, soy bob' });
  for (const w of toWeb.wraps) await bobPool.publishTo(w.event, relay.url);
  await page.getByRole('tab', { name: 'Mensajes directos · 1 nuevo' }).waitFor({ timeout: 10_000 });
  assert(true, 'a DM received in the background is counted on the Mensajes directos tab (FR009-03)');
  await tab(page, 'Mensajes directos');
  await page.locator('#dm-log').getByText('hola web, soy bob').waitFor({ timeout: 5_000 });
  assert(!(await page.getByRole('tab', { name: /nuevo/ }).count()), 'the DM is shown without «Actualizar», and the count clears');
  await page.locator('#dm-log').getByText(`Bob del escritorio · ${npubEncode(getPublicKey(bobKey)).slice(0, 12)}`, { exact: false }).first().waitFor({ timeout: 10_000 });
  assert(true, 'a DM from a contact shows the sender’s public name next to the npub (FR006-04)');

  // --- receipts per profile (ADR 0005): convenience sends "delivered", never "read"; FR009-03: to the sender's DM relays
  const receiptsFor = async (url: string) => {
    const out: string[] = [];
    for (const w of await bobPool.query([url], [dmInboxFilter(getPublicKey(bobKey))], 2000)) {
      const m = await unwrap(bob, w).catch(() => undefined);
      if (m?.rumor.kind === APP_RECEIPT_KIND && getTagValue(m.rumor, 'e') === toWeb.rumor.id) out.push(getTagValue(m.rumor, 'receipt')!);
    }
    return out;
  };
  let receipts: string[] = [];
  for (let i = 0; i < 20 && receipts.length === 0; i++) {
    await new Promise((r) => setTimeout(r, 250));
    receipts = await receiptsFor(bobRelay.url);
  }
  assert(receipts.includes('delivered') && !receipts.includes('read'), `delivered receipt sent, read receipt not sent (${receipts.join(',')})`);
  assert((await receiptsFor(relay.url)).length === 0, "the receipt goes to the sender's DM relay (10050), not to the web's own relays (FR009-03)");

  // --- VAULT-02/03/07: the Continuity Vault card says what the operator sees, seals the persona's history (the
  // channel, DMs both ways, the ledger) in this browser with its archive key and opens it again; the vault holds no
  // text, event or npub. A clean browser with nothing but the backup file and an empty relay gets it all back.
  await tab(page, 'Personas');
  assert((await page.textContent('#vault-facts'))?.includes('El operador sí ve tu cuenta del vault'), 'the vault card says what its operator sees before anything is uploaded (VAULT-07)');
  assert((await page.textContent('#backup-facts'))?.includes('llave de archivo del Continuity Vault'), 'the backup says it carries the archive key (VAULT-02)');
  assert((await page.textContent('#vault-policy'))?.includes('best-effort'), 'the vault card says each send is copied best-effort (VAULT-04)');
  await page.locator('#vault-push').click();
  await page.waitForFunction(() => document.querySelector('#vault-status')?.textContent?.includes('operaciones'), undefined, { timeout: 30_000 });
  const pushStatus = (await page.textContent('#vault-status')) ?? '';
  const pushed = /(\d+) eventos nuevos \((\d+) ya estaban\), 0 mensajes de grupo nuevos, ledger de (\d+) operaciones\./.exec(pushStatus);
  // The canonical events of the persona: those its sends already copied (VAULT-04) are kept, the rest uploaded.
  const pushedEvents = Number(pushed?.[1] ?? 0) + Number(pushed?.[2] ?? 0);
  const operations = Number(pushed?.[3] ?? 0);
  assert(Number(pushed?.[1] ?? 0) >= 1 && Number(pushed?.[2] ?? 0) >= 3 && operations >= 5, `the push seals the persona's canonical events and its ledger, finding its sends already copied (VAULT-03/04: ${pushStatus})`);
  let vaultHeld = JSON.stringify(vaultRepo.rows());
  for await (const k of vaultObjects.list()) vaultHeld += new TextDecoder().decode((await vaultObjects.get(k))!);
  const archives = vaultRepo.rows().length;
  // Besides the canonical events and the ledger, the copies of what was sent to others (Bob's wraps and receipts).
  assert(archives > pushedEvents + 1 && vaultRepo.rows().every((r) => !r.owner.includes(webPub)), `one archive per event plus the ledger and the copies of what went to others, under a vault account that is not the npub (${archives})`);
  assert(!['dm desde la web', 'hola web, soy bob', 'hola desde la web', 'mensaje lento', 'Canal de pruebas', webPub, 'REPLICATED', relay.url].some((t) => vaultHeld.includes(t)), 'the vault holds no text, event, npub or relay of the history (sealed in the browser)');
  await page.locator('#vault-verify').click();
  await page.waitForFunction((n) => document.querySelector('#vault-status')?.textContent?.includes(`${n} de ${n} archivos se abren`), archives, { timeout: 15_000 });
  assert(true, 'every archive opens again with the archive key of this browser');

  // The persona's backup file (its key and its archive key), a relay that lost everything and a clean browser.
  await fill(page, 'backup-pass', 'contraseña-del-backup');
  const [download] = await Promise.all([page.waitForEvent('download'), page.locator('#export-backup').click()]);
  const backupBytes = await readFile((await download.path())!);
  const emptyRelay = new TestRelay({ requireAuth: true, pGatedKinds: [1059], host: '127.0.0.1' });
  await emptyRelay.start();
  const cleanCtx = await browser.newContext();
  try {
    await cleanCtx.route('**/config.json', (r) => r.fulfill({ contentType: 'application/json', body: JSON.stringify({ ...selfHosted, relays: [emptyRelay.url] }) }));
    const clean = await cleanCtx.newPage();
    clean.on('pageerror', (e) => errors.push(`restored browser: ${e.message}`));
    await clean.goto(base);
    await clean.getByText('Crear almacén').waitFor();
    await fill(clean, 'local-pass', PASS);
    await clean.getByRole('button', { name: 'Crear almacén' }).click();
    await clean.getByRole('button', { name: 'Crear persona' }).waitFor();
    await fill(clean, 'persona-label', 'Restaurada');
    await clean.getByLabel('Importar archivo de backup (generador offline o esta web)').check();
    await clean.locator('#backup-file').setInputFiles({ name: 'backup.json', mimeType: 'application/json', buffer: backupBytes });
    await fill(clean, 'import-backup-pass', 'contraseña-del-backup');
    await fill(clean, 'relays', emptyRelay.url);
    await clean.getByRole('button', { name: 'Crear persona' }).click();
    await clean.waitForFunction(() => document.querySelector('#sending-as')?.textContent?.includes('Enviando como Restaurada'), undefined, { timeout: 20_000 });
    await tab(clean, 'Personas');
    await clean.locator('#vault-restore').click();
    await clean.waitForFunction(() => document.querySelector('#vault-status')?.textContent?.startsWith('Restaurado desde el vault'), undefined, { timeout: 30_000 });
    const restoreStatus = (await clean.textContent('#vault-status')) ?? '';
    const back = /(\d+) eventos verificados, (\d+) publicados otra vez en tus relays \((\d+) mensajes cifrados para otras personas siguen en el vault\);/.exec(restoreStatus);
    const verified = Number(back?.[1] ?? -1);
    const republished = Number(back?.[2] ?? -1);
    const forOthers = Number(back?.[3] ?? -1);
    // Every event the push found comes back, plus the copies of sends the relay no longer had (an older 10050 list).
    assert(republished >= pushedEvents && verified === republished + forOthers && forOthers >= 1 && restoreStatus.includes(`ledger: ${operations} operaciones añadidas`) && !/rechazados|no se abren/.test(restoreStatus), `a clean browser with the backup restores every event and the ledger from the vault, and keeps what went to others there (VAULT-03/04: ${restoreStatus})`);
    // (The restored browser's own new receipts to Bob may land there: his DM relay list is not on the empty relay.)
    const sentToBob = bobRelay.query([{ kinds: [1059], '#p': [getPublicKey(bobKey)] }]).map((e) => e.id);
    assert(sentToBob.length >= 2 && !emptyRelay.query([{ kinds: [1059], '#p': [getPublicKey(bobKey)] }]).some((e) => sentToBob.includes(e.id)), "the gift wraps sent to Bob, copied to the vault, are not republished on the persona's relays (VAULT-04)");
    const ids = (events: Array<{ id: string }>) => events.map((e) => e.id).sort().join();
    assert(ids(emptyRelay.query([{ kinds: [9], '#h': ['general'] }])) === ids(relay.query([{ kinds: [9], '#h': ['general'] }])), 'the empty relay holds the whole channel again, messages of other clients included');
    const wrapsFor = (r: TestRelay) => r.query([{ kinds: [1059], '#p': [webPub] }]);
    assert(wrapsFor(relay).length >= 4 && wrapsFor(relay).every((w) => wrapsFor(emptyRelay).some((x) => x.id === w.id)), 'and every gift wrap of the persona: DMs received and its own copies of those it sent');
    await tab(clean, 'Canales');
    await clean.locator('#channel-list').getByText('General').click();
    for (const t of ['hola desde desktop', 'hola desde la web', 'mensaje lento']) await clean.locator('#channel-log').getByText(t).waitFor({ timeout: 10_000 });
    assert(true, 'the restored browser reads the channel as before (NIP-29)');
    await tab(clean, 'Mensajes directos');
    for (const t of ['dm desde la web', 'hola web, soy bob']) await clean.locator('#dm-log').getByText(t, { exact: true }).waitFor({ timeout: 10_000 });
    assert(true, 'and the DMs in both directions (NIP-17, its own copy of the sent one included)');
    await tab(clean, 'Entrega');
    await clean.locator('#outbox-rows td', { hasText: 'RECIPIENT_ACKED' }).first().waitFor({ timeout: 10_000 });
    // The view lists the latest 50 operations.
    assert((await clean.locator('#outbox-rows tr').count()) >= Math.min(50, operations + 1), 'and the delivery ledger, with the acknowledged DM, next to its own new operations');
  } finally {
    await cleanCtx.close();
    await emptyRelay.stop();
  }

  // --- VAULT-05: the persona chooses how long the vault keeps its archives, takes them out in an open format any
  // Nostr client reads, and deletes them (the vault account with them).
  await tab(page, 'Personas');
  assert((await page.textContent('#vault-facts'))?.includes('hasta que vence su plazo'), 'the vault card says how long the archives are kept (VAULT-05)');
  await page.locator('#vault-retention').click();
  await page.getByRole('option', { name: '90 días' }).click();
  await page.waitForFunction(() => document.querySelector('#vault-status')?.textContent?.includes('conserva cada archivo 90 días'), undefined, { timeout: 15_000 });
  const vaultOwner = vaultRepo.rows()[0]!.owner;
  assert((await vaultRepo.retention(vaultOwner)) === 90, 'the vault keeps the retention the persona chose (VAULT-05)');
  const [vaultDownload] = await Promise.all([page.waitForEvent('download'), page.locator('#vault-export').click()]);
  const bundle = JSON.parse(await readFile((await vaultDownload.path())!, 'utf8')) as VaultExport;
  await page.waitForFunction(() => document.querySelector('#vault-status')?.textContent?.startsWith('Exportado'), undefined, { timeout: 30_000 });
  const bundleText = JSON.stringify(bundle);
  assert(
    vaultDownload.suggestedFilename() === 'acceso-nostr-vault-Trabajo.json' && bundle.format === 'sedecim-vault-export' && bundle.pubkey === webPub && bundle.events.length >= pushedEvents && bundle.events.every((e) => ntVerifyEvent({ ...e })) && bundle.ledger.length >= operations,
    `the export is an open JSON of the persona's signed events (verified by another Nostr implementation) and its ledger (VAULT-05, NFR-008: ${bundle.events.length} events, ${bundle.ledger.length} operations)`,
  );
  assert(bundle.events.some((e) => e.kind === 9 && e.content === 'hola desde la web') && !bundleText.includes('"mls"') && !bundleText.includes(bytesToHex(knownSk)), 'the export carries the channel messages as they were signed, and neither MLS state nor keys');
  await page.locator('#vault-delete').click();
  await page.locator('#vault-delete-title').waitFor();
  assert((await page.textContent('[role="dialog"]'))?.includes('las copias de seguridad del operador pueden conservar'), 'deleting says what the operator backups may still keep (VAULT-05)');
  const deletedAt = Date.now();
  await page.locator('#vault-delete-confirm').click();
  await page.waitForFunction(() => document.querySelector('#vault-status')?.textContent?.startsWith('Se borraron'), undefined, { timeout: 15_000 });
  const deleteStatus = (await page.textContent('#vault-status')) ?? '';
  // A best-effort copy of a send after the deletion would open the account again: only rows from before are checked.
  assert(
    vaultRepo.rows().every((r) => r.owner !== vaultOwner || Date.parse(r.createdAt) >= deletedAt) && (await vaultRepo.retention(vaultOwner)) === null && deleteStatus.includes('La copia automática sigue encendida'),
    `deleting removes every archive of the persona and its vault account, and says new sends are still copied while best-effort is on (VAULT-05: ${deleteStatus})`,
  );

  // --- panel applies and persists per persona (PANEL-02/03)
  await tab(page, 'Soberanía y privacidad');
  // PANEL-05: custody is a fact of the persona, shown but not chosen, and the panel explains stripFileMetadata.
  assert((await page.textContent('#cfg-custody')) === 'local' && (await page.isDisabled('#cfg-custody')), 'the panel shows the real custody (a key in this browser) and does not let it change (PANEL-05)');
  assert((await page.textContent('#panel-disclosures'))?.includes('Se quitan los metadatos (EXIF, ubicación, datos del dispositivo)'), 'the panel explains what stripFileMetadata does (PANEL-05)');
  // PANEL-07: the panel says how mature the configuration is, from the same catalog as the CLI and the README.
  assert((await page.textContent('#panel-maturity'))?.includes('Early release'), 'the panel shows the maturity of the configuration (PANEL-07)');
  await page.locator('#cfg-remotePreviews').uncheck();
  await page.locator('#panel-save').click();
  await page.getByText('Configuración aplicada a esta persona').waitFor();
  await page.locator('#cfg-network').click();
  await page.getByRole('option', { name: 'tor-only' }).click();
  assert((await page.textContent('#panel-issues'))?.includes('Tor-only no puede garantizarse desde un navegador'), 'panel blocks Tor-only in the browser');
  assert((await page.textContent('#panel-maturity'))?.includes('Experimental'), 'a Tor-only configuration is Experimental (PANEL-07)');
  assert(await page.isDisabled('#panel-save'), 'a blocking configuration cannot be applied');
  await page.getByRole('button', { name: 'Descartar cambios' }).click();
  // FR010-04: a quorum above the persona's relays (one here) is refused instead of being capped in silence.
  await fill(page, 'cfg-quorum', '3');
  assert((await page.textContent('#panel-issues'))?.includes('El quorum (3) supera los relays de esta persona (1)'), 'panel refuses a quorum above the persona relays (FR010-04)');
  assert(await page.isDisabled('#panel-save'), 'a quorum its relays cannot meet cannot be applied');
  await page.getByRole('button', { name: 'Descartar cambios' }).click();
  await page.getByRole('button', { name: 'Bloquear' }).click();
  await fill(page, 'local-pass', 'contraseña-incorrecta');
  await page.getByRole('button', { name: 'Desbloquear' }).click();
  await page.getByText('wrong passphrase').waitFor();
  assert(true, 'wrong local password is rejected');
  await fill(page, 'local-pass', PASS);
  await page.getByRole('button', { name: 'Desbloquear' }).click();
  await page.waitForFunction(() => document.querySelector('#sending-as')?.textContent?.includes('Enviando como Trabajo'));
  await tab(page, 'Soberanía y privacidad');
  assert(!(await page.isChecked('#cfg-remotePreviews')), 'panel configuration persisted encrypted in the vault (PANEL-03)');
  await tab(page, 'Canales');
  await page.locator('#channel-list').getByText('General').click();
  await page.getByRole('button', { name: /Mostrar imagen/ }).waitFor({ timeout: 10_000 });
  assert(true, 'remote previews off: images wait for an explicit click (PANEL-02)');

  // --- PANEL-05: the profile is validated before the persona exists; a browser cannot be Tor-only
  await tab(page, 'Personas');
  await page.locator('#persona-preset').click();
  await page.getByRole('option', { name: 'sovereign-tor', exact: true }).click();
  await fill(page, 'persona-label', 'Tor en el navegador');
  await page.getByLabel('Crear llave local nueva (la nsec no sale del navegador)').check();
  await page.getByRole('button', { name: 'Crear persona' }).click();
  await page.locator('.MuiAlert-message', { hasText: 'Tor-only no puede garantizarse desde un navegador' }).waitFor({ timeout: 10_000 });
  assert((await page.getByText('Tor en el navegador ·').count()) === 0, 'a Tor-only persona is refused before it is created (PANEL-05)');
  await page.locator('#persona-preset').click();
  await page.getByRole('option', { name: 'convenience', exact: true }).click();

  // --- second persona and switching (FR006-02)
  await tab(page, 'Personas');
  await fill(page, 'persona-label', 'Personal');
  await page.getByLabel('Crear llave local nueva (la nsec no sale del navegador)').check();
  await page.getByRole('button', { name: 'Crear persona' }).click();
  await page.waitForFunction(() => document.querySelector('#sending-as')?.textContent?.includes('Enviando como Personal'));
  await page.locator('#persona-select').click();
  await page.getByRole('option', { name: /Trabajo/ }).click();
  await page.waitForFunction(() => document.querySelector('#sending-as')?.textContent?.includes('Enviando como Trabajo'));
  assert(true, 'switching persona changes the sending identity');

  // --- import the offline key generator's backup: the npub is verified on decryption (FR002-03)
  const offline = generateKey({ password: 'clave-del-generador', logN: 14 });
  await tab(page, 'Personas');
  await fill(page, 'persona-label', 'Offline');
  await page.getByLabel('Importar archivo de backup (generador offline o esta web)').check();
  await page.locator('#backup-file').setInputFiles({ name: 'backup.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(backupFile(offline, 14))) });
  assert((await page.textContent('#backup-npub'))?.includes(offline.npub), 'the backup npub is shown before asking for the password');
  await fill(page, 'import-backup-pass', 'incorrecta');
  await page.getByRole('button', { name: 'Crear persona' }).click();
  await page.getByText(/wrong passphrase|corrupted/i).waitFor({ timeout: 20_000 });
  await fill(page, 'import-backup-pass', 'clave-del-generador');
  await page.getByRole('button', { name: 'Crear persona' }).click();
  await page.waitForFunction(() => document.querySelector('#sending-as')?.textContent?.includes('Enviando como Offline'), undefined, { timeout: 20_000 });
  await page.getByRole('button', { name: 'Mostrar QR de mi npub' }).click();
  assert(await page.getByRole('img', { name: 'Código QR de tu npub' }).isVisible(), 'imported persona can show its npub as a QR (FR003-03)');
  assert(await page.getByRole('img', { name: 'Código QR de tu npub' }).locator('path').count() === 1, 'QR drawn as a single SVG path, no external resources');

  // --- remote signer via client-initiated nostrconnect:// (FR004-03/04): the nsec never reaches the browser
  const remoteUser = new LocalSigner(generateSecretKey());
  const bunkerPool = new RelayPool({ webSocketFactory: factory, signer: new LocalSigner(generateSecretKey()) });
  pools.push(bunkerPool);
  const bunker = new Nip46Bunker(remoteUser, bunkerPool, [relay.url], { allowedKinds: [5, 7, 9, 13, 9007, 9021, 10050, 22242, 24242, 27235] });
  await bunker.start();
  await tab(page, 'Personas');
  await fill(page, 'persona-label', 'Remota');
  await page.getByLabel('Signer remoto (NIP-46)').check();
  assert((await page.textContent('#nip46-permissions'))?.includes('Firmar: Mensajes de canal (NIP-29)'), 'requested NIP-46 permissions are listed before connecting (FR004-04)');
  await page.getByRole('button', { name: 'Generar código de conexión' }).click();
  const uri = await page.inputValue('#nostrconnect-uri');
  assert(await page.getByRole('img', { name: 'Código QR de conexión nostrconnect' }).isVisible(), 'the nostrconnect offer is also shown as a QR');
  assert(uri.startsWith('nostrconnect://') && uri.includes('perms='), 'web shows a nostrconnect:// offer with its permissions');
  await bunker.acceptNostrConnect(uri);
  await page.waitForFunction(() => document.querySelector('#sending-as')?.textContent?.includes('Enviando como Remota'), undefined, { timeout: 15_000 });
  await tab(page, 'Canales');
  await page.locator('#channel-list').getByText('General').click();
  await fill(page, 'channel-text', 'firmado por el signer remoto');
  await page.locator('#channel-send').getByRole('button', { name: 'Enviar' }).click();
  const remoteMsg = await (async () => {
    for (let i = 0; i < 40; i++) {
      const e = (await pool.query([relay.url], [{ kinds: [9], '#h': ['general'] }], 2000)).find((x) => x.content === 'firmado por el signer remoto');
      if (e) return e;
      await new Promise((r) => setTimeout(r, 250));
    }
  })();
  assert(remoteMsg?.pubkey === (await remoteUser.getPublicKey()), 'channel message signed through the remote signer (FR004-03)');
  bunker.stop();

  // --- linking personas explains the consequences first (FR007-03)
  await page.locator('#persona-select').click();
  await page.getByRole('option', { name: /Trabajo/ }).click();
  await page.waitForFunction(() => document.querySelector('#sending-as')?.textContent?.includes('Enviando como Trabajo'));
  await tab(page, 'Personas');
  await page.locator('#link-target').click();
  await page.getByRole('option', { name: /^Personal/ }).click();
  await page.getByLabel('Selectivo (solo las personas que elijas)').check();
  await fill(page, 'link-audience', npubEncode(getPublicKey(bobKey)));
  await page.getByRole('button', { name: 'Vincular…' }).click();
  assert((await page.getByRole('dialog').textContent())?.includes('la desanonimización no se puede deshacer'), 'link dialog explains the de-anonymization before confirming');
  const accountBefore = await identityRepo.personaByPubkey(webPub);
  assert(!accountBefore, 'nothing is sent to the identity service before confirming');
  await page.getByRole('button', { name: 'Entiendo las consecuencias, vincular' }).click();
  await page.getByText('Personas vinculadas (selective)').waitFor({ timeout: 10_000 });
  const acct = (await identityRepo.personaByPubkey(webPub))!.accountId;
  const personasOf = await identityRepo.personasOf(acct);
  const links = await identityRepo.linksOf(personasOf.map((p) => p.personaId));
  assert(personasOf.length === 2 && links.length === 1 && links[0]!.visibility === 'selective' && links[0]!.audience[0] === getPublicKey(bobKey), 'identity service registered both personas (with proof of key control) and a selective link');
  await page.waitForFunction(() => document.querySelector('#sending-as')?.textContent?.endsWith('· vínculo selectivo'));
  assert(true, 'after linking, the banner shows the link level (FR007-05)');
  await page.locator('#persona-select').click();
  await page.getByRole('option', { name: /^Personal/ }).click();
  await page.waitForFunction(() => document.querySelector('#sending-as')?.textContent?.includes('Enviando como Personal'));
  assert((await page.textContent('#sending-as'))?.endsWith('· vínculo selectivo'), 'the other persona of the link shows it too (FR007-05)');
  await page.locator('#persona-select').click();
  await page.getByRole('option', { name: /Trabajo/ }).click();
  await page.waitForFunction(() => document.querySelector('#sending-as')?.textContent?.includes('Enviando como Trabajo'));

  // --- panel: per-dimension indicators backed by statements (PANEL-04)
  await tab(page, 'Soberanía y privacidad');
  await page.locator('#dim-privacidad-operador-h').click();
  assert((await page.locator('#dim-privacidad-operador').textContent())?.includes('ver consecuencia'), 'each dimension lists the statements that move it, linked to their disclosure');

  // --- ADR 0010 / OPS-06: push only where the gateway sees activity without reading DMs; never for sovereign/Tor personas
  assert(gatewayProbe.length === 1 && !gatewayProbe[0]!.observable, `the gateway's canary does not reach it on a relay that delivers gift wraps only to their recipient (${gatewayProbe[0]?.reason})`);
  await page.locator('#notifications-unobservable').waitFor();
  assert((await page.locator('#notifications-toggle').count()) === 0 && (await page.textContent('#notifications-unobservable'))?.includes('sin acceso a tus DMs'), 'so the web offers no push switch, and says why (OPS-06)');
  await page.locator('#preset').click();
  await page.getByRole('option', { name: 'sovereign', exact: true }).click();
  await page.locator('#panel-save').click();
  await page.locator('#notifications-off').waitFor();
  assert((await page.locator('#notifications-toggle').count()) === 0 && (await page.textContent('#notifications-off'))?.includes('no usa notificaciones push'), 'sovereign persona: no push switch, with an explanation');
  // Where the gateway can watch the relay (here it says so), the control is offered: opt-in and opaque.
  const observableRelays = `${gatewayUrl}/v1/relays`;
  await page.route(observableRelays, (r) => r.fulfill({ contentType: 'application/json', headers: { 'access-control-allow-origin': base }, body: JSON.stringify({ relays: [{ relay: relay.url, observable: true, checkedAt: Date.now() }] }) }));
  await page.locator('#preset').click();
  await page.getByRole('option', { name: 'convenience', exact: true }).click();
  await page.locator('#panel-save').click();
  await page.locator('#notifications-toggle:not([disabled])').waitFor();
  assert(!(await page.isChecked('#notifications-toggle')), 'the Notificaciones control is offered where the gateway can watch the relay, and off by default (opt-in)');
  assert((await page.textContent('#notifications-control'))?.includes('no incluye contenido, remitente ni número de mensajes'), 'the control explains that pushes are opaque');
  await page.unroute(observableRelays);
  await page.locator('#preset').click();
  await page.getByRole('option', { name: 'sovereign', exact: true }).click();
  await page.locator('#panel-save').click();
  await page.locator('#notifications-off').waitFor();
  assert(gatewayCore.size === 0, 'nothing was registered with the notification gateway');
  const swScope = await page.evaluate(async () => {
    const r = await navigator.serviceWorker.register('./sw.js', { scope: './push/e2e/' });
    const scope = r.scope;
    await r.unregister();
    return scope;
  });
  assert(swScope === `${base}/push/e2e/`, 'the push service worker registers under a per-persona scope within the CSP (script-src self)');

  // --- a deployment whose gate rejected NIP-17 blocks it
  const gated = await context.newPage();
  await gated.route('**/flags.json', (r) => r.fulfill({ contentType: 'application/json', body: JSON.stringify({ nip17: { enabled: false, timestampJitterSeconds: null }, relay: 'buzz@test', source: 'test', generatedAt: '' }) }));
  await gated.goto(base);
  await fill(gated, 'local-pass', PASS);
  await gated.getByRole('button', { name: 'Desbloquear' }).click();
  await tab(gated, 'Mensajes directos');
  assert(await gated.isDisabled('#nip17-flag'), 'NIP-17 cannot be enabled when the gate rejected it');
  await gated.close();

  // --- FR001-05: the nsec never left the browser, and IndexedDB holds no plaintext key
  const leaks = outbound.filter((o) => o.includes(knownNsec) || o.includes(bytesToHex(knownSk)));
  assert(leaks.length === 0 && outbound.length > 20, `no request or WebSocket frame carries the nsec (${outbound.length} inspected)`);
  const idb = await page.evaluate(async () => {
    const db: IDBDatabase = await new Promise((res, rej) => {
      const r = indexedDB.open('acceso-nostr');
      r.onsuccess = () => res(r.result);
      r.onerror = () => rej(r.error);
    });
    const all: ArrayBuffer[] = await new Promise((res) => {
      const r = db.transaction('kv').objectStore('kv').getAll();
      r.onsuccess = () => res(r.result as ArrayBuffer[]);
    });
    db.close();
    return all.map((b) => Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, '0')).join('')).join('|');
  });
  assert(idb.length > 0 && !idb.includes(bytesToHex(knownSk)) && !idb.includes(Buffer.from(knownNsec).toString('hex')), 'IndexedDB contains only sealed records');

  assert(errors.length === 0, `no page errors or CSP violations (${errors.join('; ')})`);
  assert(external.length === 0, `self-hosted mode makes no requests to third-party hosts (${external.join(', ')})`);

  // --- accessibility (NFR009-01): axe-core, no serious or critical violations on each view
  const a11yCtx = await browser.newContext({ bypassCSP: true });
  await a11yCtx.route('**/config.json', (r) => r.fulfill({ contentType: 'application/json', body: JSON.stringify(selfHosted) }));
  const a11y = await a11yCtx.newPage();
  const axePath = createRequire(import.meta.url).resolve('axe-core/axe.min.js');
  const audit = async (label: string) => {
    await a11y.addScriptTag({ path: axePath });
    const v = await a11y.evaluate(async () => (await (window as unknown as { axe: { run(): Promise<{ violations: Array<{ id: string; impact: string; nodes: unknown[] }> }> } }).axe.run()).violations.filter((x) => x.impact === 'serious' || x.impact === 'critical').map((x) => `${x.id}(${x.nodes.length}: ${(x.nodes as Array<{ target: string[]; failureSummary?: string }>).map((n) => `${n.target.join(' ')} ${n.failureSummary ?? ''}`.replace(/\s+/g, ' ').slice(0, 220)).join(' | ')})`));
    assert(v.length === 0, `axe: no serious/critical violations on ${label} (${v.join(', ')})`);
    // axe rates duplicate ids as minor, but they break label/aria wiring and tests (found once in Personas).
    const dup = await a11y.evaluate(() => {
      const seen = new Map<string, number>();
      for (const el of document.querySelectorAll('[id]')) seen.set(el.id, (seen.get(el.id) ?? 0) + 1);
      return [...seen].filter(([, n]) => n > 1).map(([id]) => id);
    });
    assert(dup.length === 0, `no duplicate ids on ${label} (${dup.join(', ')})`);
  };
  await a11y.goto(base);
  await a11y.getByText('Crear almacén').waitFor();
  await audit('vault gate');
  await a11y.fill('#local-pass', PASS);
  await a11y.getByRole('button', { name: 'Crear almacén' }).click();
  await a11y.getByRole('button', { name: 'Crear persona' }).click();
  await a11y.waitForFunction(() => document.querySelector('#sending-as')?.textContent?.includes('Enviando como'));
  for (const t of ['Personas', 'Canales', 'Mensajes directos', 'Grupos seguros', 'Entrega', 'Soberanía y privacidad']) {
    await tab(a11y, t);
    await a11y.waitForTimeout(300);
    await audit(t);
  }
  await a11yCtx.close();

  // --- SaaS mode (ADR 0008): Acceso login first, then optional linking of a persona
  const saasCtx = await browser.newContext();
  const managedTerms = { url: 'https://legal.example/custodia-gestionada', version: '2026-10' };
  const saasConfig = { ...selfHosted, mode: 'saas', cognito, managedSigner: managedUrl, managedTerms, backupVault: identityUrl, organizationDevices: true };
  await saasCtx.route('**/config.json', (r) => r.fulfill({ contentType: 'application/json', body: JSON.stringify(saasConfig) }));
  const cognitoCalls: string[] = [];
  const accesoRoute = async (r: Route) => {
    const target = r.request().headers()['x-amz-target'] ?? '';
    cognitoCalls.push(target);
    if (target.endsWith('InitiateAuth')) {
      const { AuthParameters } = JSON.parse(r.request().postData() ?? '{}');
      if (AuthParameters?.PASSWORD !== 'acceso-pass') return r.fulfill({ status: 400, contentType: 'application/x-amz-json-1.1', body: JSON.stringify({ __type: 'NotAuthorizedException', message: 'Incorrect username or password.' }) });
      // Like Cognito, both tokens of a sign-in carry when it happened and its own id (IR-2026-10-03, IR-2026-10-11).
      const signIn = { auth_time: Math.floor(Date.now() / 1000), origin_jti: randomUUID() };
      return r.fulfill({
        contentType: 'application/x-amz-json-1.1',
        body: JSON.stringify({ AuthenticationResult: { IdToken: jwt({ token_use: 'id', aud: cognito.userPoolClientId, 'cognito:username': 'ana', ...signIn }), AccessToken: jwt({ token_use: 'access', client_id: cognito.userPoolClientId, username: 'ana', ...signIn }), RefreshToken: 'refresh', ExpiresIn: 3600, TokenType: 'Bearer' }, ChallengeParameters: {} }),
      });
    }
    return r.fulfill({ status: 400, contentType: 'application/x-amz-json-1.1', body: JSON.stringify({ __type: 'InvalidParameterException', message: `unexpected ${target}` }) });
  };
  await saasCtx.route(`https://cognito-idp.${cognito.region}.amazonaws.com/**`, accesoRoute);
  const saas = await saasCtx.newPage();
  saas.on('pageerror', (e) => errors.push(e.message));
  await saas.goto(base);
  await saas.getByRole('button', { name: 'Entrar con Acceso' }).waitFor();
  assert(!(await saas.getByText('Crear almacén').isVisible()), 'SaaS mode requires the Acceso login before any identity');
  // FR005-08: with managed custody on offer, the login never claims that the key stays in this browser.
  const loginText = (await saas.locator('main').textContent()) ?? '';
  assert(!loginText.includes('no sale de este navegador') && loginText.includes('con la custodia gestionada (opcional), la guarda la plataforma'), 'the Acceso login does not promise that the key never leaves the browser when managed custody exists (FR005-08)');
  await saas.fill('#acceso-user', 'ana');
  await saas.fill('#acceso-pass', 'mala');
  await saas.getByRole('button', { name: 'Entrar con Acceso' }).click();
  await saas.getByText('Incorrect username or password.').waitFor();
  await saas.fill('#acceso-pass', 'acceso-pass');
  await saas.getByRole('button', { name: 'Entrar con Acceso' }).click();
  await saas.getByText('Crear almacén').waitFor({ timeout: 15_000 });
  assert(cognitoCalls.some((c) => c.endsWith('InitiateAuth')), 'Acceso login goes to the configured Cognito user pool');
  await saas.fill('#local-pass', PASS);
  await saas.getByRole('button', { name: 'Crear almacén' }).click();
  const saasSk = generateSecretKey();
  await saas.getByLabel('Importar nsec / ncryptsec').check();
  await saas.fill('#secret-input', nip19.nsecEncode(saasSk));
  await saas.getByRole('button', { name: 'Crear persona' }).click();
  await saas.waitForFunction(() => document.querySelector('#sending-as')?.textContent?.includes('Enviando como'));
  assert(await saas.getByText('Acceso: ana').isVisible(), 'Acceso user is shown next to the persona');
  const account = async () => (await identityRepo.personaByPubkey(getPublicKey(saasSk)))?.accountId;
  assert(!(await account()), 'no account is created before the user consents to linking');
  await saas.getByLabel(/Vincular esta persona con mi cuenta de Acceso/).check();
  await saas.getByRole('button', { name: 'Vincular', exact: true }).click();
  await saas.getByText('Cuenta de Acceso vinculada a esta persona').waitFor({ timeout: 10_000 });
  const logins = await identityRepo.externalLoginsOf((await account())!);
  assert(logins.length === 1 && logins[0]!.subject === 'acceso-user-1' && logins[0]!.issuer === iss, 'identity-service verified the Cognito token and linked it to the persona account');

  // --- encrypted cloud backup (FR027-03): only ciphertext is uploaded; a new device restores it with the
  // Acceso login and the backup password.
  assert(await saas.locator('#cloud-backup-facts').isVisible(), 'the cloud backup explains who holds the decryption password');
  await saas.fill('#backup-pass', 'nube-segura-123');
  await saas.locator('#cloud-backup').click();
  await saas.getByText('Copia cifrada guardada en la nube').waitFor({ timeout: 20_000 });
  const stored = await identityRepo.getBackup((await account())!, 'latest');
  assert(stored && stored.format === 'acceso-nostr-key-backup' && stored.npub === npubEncode(getPublicKey(saasSk)), 'the vault stores the encrypted web backup under the persona account');
  assert(!stored!.envelope.includes(bytesToHex(saasSk)) && !stored!.envelope.includes(nip19.nsecEncode(saasSk)) && !stored!.envelope.includes('nube-segura-123'), 'the stored backup holds no plaintext key and no password');
  const deviceCtx = await browser.newContext();
  await deviceCtx.route('**/config.json', (r) => r.fulfill({ contentType: 'application/json', body: JSON.stringify(saasConfig) }));
  await deviceCtx.route(`https://cognito-idp.${cognito.region}.amazonaws.com/**`, accesoRoute);
  const device = await deviceCtx.newPage();
  device.on('pageerror', (e) => errors.push(e.message));
  await device.goto(base);
  await device.fill('#acceso-user', 'ana');
  await device.fill('#acceso-pass', 'acceso-pass');
  await device.getByRole('button', { name: 'Entrar con Acceso' }).click();
  await device.getByText('Crear almacén').waitFor({ timeout: 15_000 });
  await device.fill('#local-pass', PASS);
  await device.getByRole('button', { name: 'Crear almacén' }).click();
  await device.fill('#persona-label', 'Restaurada');
  await device.getByLabel('Importar archivo de backup (generador offline o esta web)').check();
  await device.locator('#cloud-restore').click();
  await device.locator('#backup-npub').waitFor({ timeout: 10_000 });
  assert((await device.textContent('#backup-npub'))?.includes(npubEncode(getPublicKey(saasSk))), 'a new device downloads the backup with the Acceso login and shows its npub');
  await device.fill('#import-backup-pass', 'nube-segura-123');
  await device.getByRole('button', { name: 'Crear persona' }).click();
  await device.waitForFunction(() => document.querySelector('#sending-as')?.textContent?.includes('Enviando como Restaurada'), undefined, { timeout: 20_000 });
  assert((await device.getByRole('heading', { name: /^Restaurada · / }).textContent())?.includes(npubEncode(getPublicKey(saasSk)).slice(0, 12)), 'the restored persona has the same npub (decrypted in the browser with the backup password)');
  await deviceCtx.close();

  // --- managed custody: explicit opt-in (FR005-07), signatures authorized by the Acceso token (FR005-04)
  await saas.fill('#persona-label', 'Gestionada');
  await saas.getByLabel('Llave gestionada por la plataforma (custodial, opcional)').check();
  assert((await saas.getByRole('alert').filter({ hasText: 'capacidad técnica de firmar' }).count()) > 0, 'managed custody shows the custodial disclosure before creating');
  assert(await saas.getByRole('button', { name: 'Crear persona' }).isDisabled(), 'managed custody is never created without explicit consent');
  assert((await saas.textContent('#managed-decryption'))?.includes('se cifran y descifran en el servidor de firma'), 'the opt-in warns that DMs are decrypted on the server (FR005-08)');
  assert((await saas.getAttribute('#managed-terms', 'href')) === managedTerms.url, 'the opt-in links the published terms of the managed custody (FR005-08)');
  await saas.locator('#managed-consent').check();
  await saas.getByRole('button', { name: 'Crear persona' }).click();
  await saas.waitForFunction(() => document.querySelector('#sending-as')?.textContent?.includes('Enviando como Gestionada'), undefined, { timeout: 15_000 });
  const owner = `${iss}#acceso-user-1`;
  const managedKey = (await managedCore.list(owner))[0];
  assert(managedKey && (await saas.textContent('#sending-as'))?.includes('custodial'), 'managed key created for the Acceso user and flagged as custodial');
  assert(managedKey!.consentVersion === managedConsentVersion(managedTerms.version) && typeof managedKey!.consentAt === 'number', `the managed-signer recorded the consent with its version (${managedKey!.consentVersion}) (FR005-08)`);
  await tab(saas, 'Canales');
  await saas.locator('#channel-list').getByText('General').click();
  await saas.fill('#channel-text', 'firmado por la custodia gestionada');
  await saas.locator('#channel-send').getByRole('button', { name: 'Enviar' }).click();
  const managedMsg = await (async () => {
    for (let i = 0; i < 40; i++) {
      const e = (await pool.query([relay.url], [{ kinds: [9], '#h': ['general'] }], 2000)).find((x) => x.content === 'firmado por la custodia gestionada');
      if (e) return e;
      await new Promise((r) => setTimeout(r, 250));
    }
  })();
  assert(managedMsg?.pubkey === managedKey!.pubkey, 'channel message signed by the managed signer with the Acceso token');
  assert((await managedCore.usageOf(managedKey!.keyId, owner)).some((u) => u.action === 'sign' && u.principal === owner), 'each managed signature is audited under the Acceso user');
  const signedFrom = (await managedCore.usageOf(managedKey!.keyId, owner)).filter((u) => u.action === 'sign').map((u) => u.deviceId);
  assert(signedFrom.length > 0 && signedFrom.every((d) => d?.startsWith('web-')), 'the web signs through a device session of this browser, never with the bare Acceso token (FR005-11)');

  // --- FR005-11: the usage log and the sessions of the managed key; a new browser recovers the persona with the login
  const channelMessage = async (text: string, tries = 60) => {
    for (let i = 0; i < tries; i++) {
      const e = (await pool.query([relay.url], [{ kinds: [9], '#h': ['general'] }], 2000)).find((x) => x.content === text);
      if (e) return e;
      await new Promise((r) => setTimeout(r, 250));
    }
  };
  await tab(saas, 'Personas');
  await saas.locator('#managed-usage').getByText('Firma · kind 9').first().waitFor({ timeout: 15_000 });
  assert((await saas.locator('#managed-usage').textContent())?.includes('este navegador') && (await saas.locator('#managed-sessions li').count()) === 1 && (await saas.locator('#managed-sessions').textContent())?.includes('(este navegador)'), 'the managed persona shows its usage log (signed from this browser) and its one session (FR005-11)');
  const recCtx = await browser.newContext();
  await recCtx.route('**/config.json', (r) => r.fulfill({ contentType: 'application/json', body: JSON.stringify(saasConfig) }));
  await recCtx.route(`https://cognito-idp.${cognito.region}.amazonaws.com/**`, accesoRoute);
  const rec = await recCtx.newPage();
  rec.on('pageerror', (e) => errors.push(`recovered: ${e.message}`));
  await rec.goto(base);
  await rec.fill('#acceso-user', 'ana');
  await rec.fill('#acceso-pass', 'acceso-pass');
  await rec.getByRole('button', { name: 'Entrar con Acceso' }).click();
  await rec.getByText('Crear almacén').waitFor({ timeout: 15_000 });
  await rec.fill('#local-pass', PASS);
  await rec.getByRole('button', { name: 'Crear almacén' }).click();
  await rec.fill('#persona-label', 'Gestionada recuperada');
  await rec.getByLabel('Recuperar mi persona gestionada (con este login de Acceso)').check();
  assert(await rec.getByRole('button', { name: 'Recuperar persona' }).isDisabled(), 'nothing is recovered before a key is chosen');
  await rec.locator('#managed-recovery-search').click();
  await rec.locator('#managed-recovery').getByText(npubEncode(managedKey!.pubkey).slice(0, 12)).waitFor({ timeout: 15_000 });
  await rec.getByRole('button', { name: 'Recuperar persona' }).click();
  await rec.waitForFunction(() => document.querySelector('#sending-as')?.textContent?.includes('Enviando como Gestionada recuperada'), undefined, { timeout: 20_000 });
  assert((await rec.getByRole('heading', { name: /^Gestionada recuperada · / }).textContent())?.includes(npubEncode(managedKey!.pubkey).slice(0, 12)) && (await managedCore.list(owner)).length === 1, 'a new browser reopens the same managed key with the Acceso login: same npub, no new key (FR005-11)');
  await tab(rec, 'Canales');
  await rec.locator('#channel-list').getByText('General').click();
  await rec.fill('#channel-text', 'desde el navegador recuperado');
  await rec.locator('#channel-send').getByRole('button', { name: 'Enviar' }).click();
  assert((await channelMessage('desde el navegador recuperado'))?.pubkey === managedKey!.pubkey, 'the recovered persona signs with its managed key');
  await tab(rec, 'Personas');
  await rec.locator('#managed-sessions li').nth(1).waitFor({ timeout: 15_000 });
  assert((await rec.locator('#managed-sessions li').count()) === 2 && (await rec.locator('#managed-usage').textContent())?.includes('este navegador'), 'the new browser sees both sessions and its own signature in the usage log');
  // IR-2026-10-03/-11: closing the others asks for the Acceso password again (a wrong one changes nothing).
  assert(await rec.locator('#managed-close-others').isDisabled(), 'closing the other sessions waits for the Acceso password');
  await rec.fill('#sessions-reauth', 'mala');
  await rec.locator('#managed-close-others').click();
  await rec.locator('#managed-activity').getByText('Incorrect username or password.').waitFor({ timeout: 15_000 });
  assert((await managedCore.listDeviceSessions(owner)).length === 2, 'a wrong Acceso password closes nothing');
  await rec.fill('#sessions-reauth', 'acceso-pass');
  await rec.locator('#managed-close-others').click();
  await rec.waitForFunction(() => document.querySelectorAll('#managed-sessions li').length === 1, undefined, { timeout: 15_000 });
  assert((await managedCore.listDeviceSessions(owner)).length === 1, 'the user closes the other browser’s session from the new one (FR005-11)');

  // --- FR024-03: this browser signs as the device the organisation registered for it; revoking that device, sent to
  // the managed-signer by the rotation worker, turns it away, also when it tries to open another session with the login.
  const orgDevice = await orgPolicy.registerDevice(orgAdmin, managedKey!.pubkey, 'registered');
  await rec.fill('#managed-org-device', orgDevice.id);
  await rec.getByRole('button', { name: 'Vincular este navegador' }).click();
  await rec.locator('#managed-org-bound').waitFor({ timeout: 15_000 });
  await rec.locator('#managed-sessions').getByText(`${orgDevice.id} (este navegador)`).waitFor({ timeout: 15_000 });
  assert((await managedCore.listDeviceSessions(owner)).map((x) => x.deviceId).join() === orgDevice.id, 'binding closes the old session of this browser and opens one as the organisation’s device');
  await tab(rec, 'Canales');
  await rec.locator('#channel-list').getByText('General').click();
  await rec.fill('#channel-text', 'como dispositivo de la organización');
  await rec.locator('#channel-send').getByRole('button', { name: 'Enviar' }).click();
  assert((await channelMessage('como dispositivo de la organización'))?.pubkey === managedKey!.pubkey && (await managedCore.usageOf(managedKey!.keyId, owner)).some((u) => u.action === 'sign' && u.deviceId === orgDevice.id), 'the managed-signer records the signature under the organisation’s device id');
  await orgPolicy.revokeDevice(orgAdmin, orgDevice.id, 'perdido');
  assert((await propagator.runOnce()).join() === orgDevice.id, 'the rotation worker’s feed sends the revocation to the managed-signer');
  await rec.fill('#channel-text', 'después de la revocación');
  await rec.locator('#channel-send').getByRole('button', { name: 'Enviar' }).click();
  await tab(rec, 'Personas');
  await rec.locator('#managed-activity-refresh').click();
  await rec.locator('#managed-activity').getByText(/Tu organización revocó este dispositivo/).waitFor({ timeout: 15_000 });
  assert(!(await channelMessage('después de la revocación', 4)) && (await managedCore.listDeviceSessions(owner)).length === 0, 'the revoked browser signs nothing more and cannot open another session with the login; the web says why');
  await recCtx.close();
  // IR-2026-10-11: the first browser signed in before the other one closed its sessions, so its login opens no other
  // session (not even refreshed) until the password is typed again; then it signs again.
  await tab(saas, 'Canales');
  await saas.locator('#channel-list').getByText('General').click();
  await saas.fill('#channel-text', 'después de cerrar mi sesión');
  await saas.locator('#channel-send').getByRole('button', { name: 'Enviar' }).click();
  assert(!(await channelMessage('después de cerrar mi sesión', 4)), 'a login older than the closing of the other sessions signs nothing (IR-2026-10-11)');
  await tab(saas, 'Personas');
  await saas.locator('#managed-cut-off').waitFor({ timeout: 15_000 });
  await saas.fill('#sessions-reauth', 'acceso-pass');
  await saas.locator('#managed-sign-in-again').click();
  await saas.locator('#managed-cut-off').waitFor({ state: 'detached', timeout: 15_000 });
  await tab(saas, 'Canales');
  await saas.locator('#channel-list').getByText('General').click();
  await saas.fill('#channel-text', 'después de volver a entrar');
  await saas.locator('#channel-send').getByRole('button', { name: 'Enviar' }).click();
  assert((await channelMessage('después de volver a entrar'))?.pubkey === managedKey!.pubkey, 'with the Acceso password typed again, the first browser opens another session and signs; the device the organisation revoked was only the other browser’s (FR024-03)');

  // --- migration back to local custody with verification (FR026-03)
  await tab(saas, 'Personas');
  await saas.fill('#migration-pass', 'exportacion-segura-123');
  // IR-2026-10-03: exporting asks for the Acceso password again; deleting right after does not ask twice.
  assert(await saas.getByRole('button', { name: 'Exportar y verificar' }).isDisabled(), 'the export waits for the Acceso password');
  await saas.fill('#migration-reauth', 'acceso-pass');
  await saas.getByRole('button', { name: 'Exportar y verificar' }).click();
  await saas.getByText('Tu llave ya vive en este navegador').waitFor({ timeout: 60_000 });
  // The banner follows the persona reload that the success message can precede.
  await saas.waitForFunction(() => document.querySelector('#sending-as')?.textContent?.includes('Llave local (navegador)'), undefined, { timeout: 10_000 }).catch(() => undefined);
  assert((await saas.textContent('#sending-as'))?.includes('Llave local (navegador)'), 'after verified export the persona signs locally');
  await saas.getByRole('button', { name: 'Borrar la copia gestionada' }).click();
  await saas.locator('#migration-done').waitFor({ timeout: 10_000 });
  assert((await managedCore.list(owner)).length === 0, 'managed copy deleted only after the verified migration (destroyed after the retention window)');
  await saasCtx.close();
} finally {
  for (const p of pools) p.close();
  await browser.close();
  server.close();
  await identity.close();
  await managed.close();
  await policyApi.close();
  gatewayCore.stop();
  await gateway.close();
  await continuity.close();
  await media.stop();
  await blobs.stop();
  await userBlobs.stop();
  await relay.stop();
  await bobRelay.stop();
}
if (failures) process.exit(1);
