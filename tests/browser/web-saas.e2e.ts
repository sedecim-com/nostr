/**
 * Browser E2E for the Acceso Nostr web client (sprint S2). Run with: npm run test:browser
 * Serves the Vite build like nginx does (per-request CSP nonce) against an in-process relay, Blossom
 * servers, identity-service and a simulated Acceso (Cognito) endpoint.
 */
import { createServer } from 'node:http';
import { createSign, generateKeyPairSync, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { extname, join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { chromium, type Page, type Route } from 'playwright';
import WebSocket from 'ws';
import { bytesToHex, finalizeEvent, generateSecretKey, getPublicKey, getTagValue, nip19, npubEncode, toUnsigned } from '@sedecim/nostr-core';
import { LocalSigner, Nip46Bunker } from '@sedecim/signer';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { TestBlossomServer, TestRelay, tinyPng } from '@sedecim/test-relay';
import { APP_RECEIPT_KIND, chatMessage, createDirectMessage, createReceipt, dmInboxFilter, FILE_MESSAGE_KIND, openDirectMessage, unwrap } from '@sedecim/messaging';
import { BlossomClient } from '@sedecim/blossom-client';
import { CognitoVerifier, createIdentityApi, MemoryIdentityRepository } from '@sedecim/identity-service';
import { createManagedSignerApi, ManagedSigner, MemoryVault } from '@sedecim/managed-signer';
import { backupFile, generateKey } from '@sedecim/key-generator';
import { createNotificationApi, generateVapidKeys, NotificationGateway, createWebPushSender } from '@sedecim/notification-gateway';

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
const managed = createManagedSignerApi(managedCore, {
  name: 'managed-e2e',
  corsOrigins: [base],
  cognito: new CognitoVerifier({ region: cognito.region, userPoolId: cognito.userPoolId, clientId: cognito.userPoolClientId, fetch: (async () => new Response(JSON.stringify({ keys: [{ ...publicKey.export({ format: 'jwk' }), kid: 'e2e', alg: 'RS256' }] }))) as typeof fetch }),
});
const managedUrl = await managed.listen();
// Opaque push gateway (ADR 0010): the web only offers the opt-in control; nothing registers unless clicked.
const vapid = generateVapidKeys();
const gatewayCore = new NotificationGateway({ pool: new RelayPool({ webSocketFactory: factory }), sender: createWebPushSender({ vapid, subject: 'mailto:e2e@example.org' }), relays: [{ public: relay.url }] });
const gateway = createNotificationApi(gatewayCore, { name: 'notification-e2e', corsOrigins: [base], vapid });
const gatewayUrl = await gateway.listen();
const selfHosted = { mode: 'self-hosted', relays: [relay.url], buzzMedia: media.url, blobStore: blobs.url, identityService: identityUrl, notificationGateway: gatewayUrl };

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

  // --- NIP-17 DM + encrypted attachment, enabled by the gate flags (FR-017, FR018-04)
  const bobKey = generateSecretKey();
  const bob = new LocalSigner(bobKey);
  const bobPool = new RelayPool({ webSocketFactory: factory, signer: bob });
  pools.push(bobPool);
  await bobPool.publishTo(await bob.signEvent({ kind: 10050, content: '', tags: [['relay', bobRelay.url]] }), relay.url);
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

  // --- incoming receipt advances the web outbox (FR009-02)
  let webDmRumor: string | undefined;
  for (const w of await bobPool.query([bobRelay.url], [dmInboxFilter(getPublicKey(bobKey))], 2000)) {
    const m = await openDirectMessage(bob, w).catch(() => undefined);
    if (m?.rumor.content === 'dm desde la web') webDmRumor = m.rumor.id;
  }
  const ack = await createReceipt(bob, webPub, webDmRumor!, 'delivered');
  await bobPool.publishTo(ack.event, relay.url);
  await page.getByRole('button', { name: 'Actualizar' }).click();
  await tab(page, 'Entrega');
  await page.locator('#outbox-rows td', { hasText: 'RECIPIENT_ACKED' }).first().waitFor({ timeout: 10_000 });
  assert(true, 'a delivered receipt from the recipient moves the DM to RECIPIENT_ACKED');
  await tab(page, 'Mensajes directos');

  // --- receipts per profile (ADR 0005): convenience sends "delivered", never "read"
  const toWeb = await createDirectMessage(bob, { recipients: [webPub], content: 'hola web, soy bob' });
  for (const w of toWeb.wraps) await bobPool.publishTo(w.event, relay.url);
  await page.getByRole('button', { name: 'Actualizar' }).click();
  await page.locator('#dm-log').getByText('hola web, soy bob').waitFor({ timeout: 10_000 });
  let receipts: string[] = [];
  for (let i = 0; i < 20 && receipts.length === 0; i++) {
    await new Promise((r) => setTimeout(r, 250));
    receipts = [];
    for (const w of await bobPool.query([relay.url], [dmInboxFilter(getPublicKey(bobKey))], 2000)) {
      const m = await unwrap(bob, w).catch(() => undefined);
      if (m?.rumor.kind === APP_RECEIPT_KIND && getTagValue(m.rumor, 'e') === toWeb.rumor.id) receipts.push(getTagValue(m.rumor, 'receipt')!);
    }
  }
  assert(receipts.includes('delivered') && !receipts.includes('read'), `delivered receipt sent, read receipt not sent (${receipts.join(',')})`);

  // --- panel applies and persists per persona (PANEL-02/03)
  await tab(page, 'Soberanía y privacidad');
  await page.locator('#cfg-remotePreviews').uncheck();
  await page.locator('#panel-save').click();
  await page.getByText('Configuración aplicada a esta persona').waitFor();
  await page.locator('#cfg-network').click();
  await page.getByRole('option', { name: 'tor-only' }).click();
  assert((await page.textContent('#panel-issues'))?.includes('Tor-only no puede garantizarse desde un navegador'), 'panel blocks Tor-only in the browser');
  assert(await page.isDisabled('#panel-save'), 'a blocking configuration cannot be applied');
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
  await page.locator('input[type=file][accept="application/json,.json"]').setInputFiles({ name: 'backup.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(backupFile(offline, 14))) });
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

  // --- panel: per-dimension indicators backed by statements (PANEL-04)
  await tab(page, 'Soberanía y privacidad');
  await page.locator('#dim-privacidad-operador-h').click();
  assert((await page.locator('#dim-privacidad-operador').textContent())?.includes('ver consecuencia'), 'each dimension lists the statements that move it, linked to their disclosure');

  // --- ADR 0010 / OPS-06: opt-in opaque push, never offered to sovereign/Tor personas
  await page.locator('#notifications-toggle').waitFor();
  assert(!(await page.isChecked('#notifications-toggle')), 'the Notificaciones control is offered (gateway configured) and off by default (opt-in)');
  assert((await page.textContent('#notifications-control'))?.includes('no incluye contenido, remitente ni número de mensajes'), 'the control explains that pushes are opaque');
  await page.locator('#preset').click();
  await page.getByRole('option', { name: 'sovereign', exact: true }).click();
  await page.locator('#panel-save').click();
  await page.locator('#notifications-off').waitFor();
  assert((await page.locator('#notifications-toggle').count()) === 0 && (await page.textContent('#notifications-off'))?.includes('no usa notificaciones push'), 'sovereign persona: no push switch, with an explanation');
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
  for (const t of ['Personas', 'Canales', 'Mensajes directos', 'Entrega', 'Soberanía y privacidad']) {
    await tab(a11y, t);
    await a11y.waitForTimeout(300);
    await audit(t);
  }
  await a11yCtx.close();

  // --- SaaS mode (ADR 0008): Acceso login first, then optional linking of a persona
  const saasCtx = await browser.newContext();
  const saasConfig = { ...selfHosted, mode: 'saas', cognito, managedSigner: managedUrl, backupVault: identityUrl };
  await saasCtx.route('**/config.json', (r) => r.fulfill({ contentType: 'application/json', body: JSON.stringify(saasConfig) }));
  const cognitoCalls: string[] = [];
  const accesoRoute = async (r: Route) => {
    const target = r.request().headers()['x-amz-target'] ?? '';
    cognitoCalls.push(target);
    if (target.endsWith('InitiateAuth')) {
      const { AuthParameters } = JSON.parse(r.request().postData() ?? '{}');
      if (AuthParameters?.PASSWORD !== 'acceso-pass') return r.fulfill({ status: 400, contentType: 'application/x-amz-json-1.1', body: JSON.stringify({ __type: 'NotAuthorizedException', message: 'Incorrect username or password.' }) });
      return r.fulfill({
        contentType: 'application/x-amz-json-1.1',
        body: JSON.stringify({ AuthenticationResult: { IdToken: jwt({ token_use: 'id', aud: cognito.userPoolClientId, 'cognito:username': 'ana' }), AccessToken: jwt({ token_use: 'access', client_id: cognito.userPoolClientId, username: 'ana' }), RefreshToken: 'refresh', ExpiresIn: 3600, TokenType: 'Bearer' }, ChallengeParameters: {} }),
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
  await saas.locator('#managed-consent').check();
  await saas.getByRole('button', { name: 'Crear persona' }).click();
  await saas.waitForFunction(() => document.querySelector('#sending-as')?.textContent?.includes('Enviando como Gestionada'), undefined, { timeout: 15_000 });
  const owner = `${iss}#acceso-user-1`;
  const managedKey = (await managedCore.list(owner))[0];
  assert(managedKey && (await saas.textContent('#sending-as'))?.includes('custodial'), 'managed key created for the Acceso user and flagged as custodial');
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

  // --- migration back to local custody with verification (FR026-03)
  await tab(saas, 'Personas');
  await saas.fill('#migration-pass', 'exportacion-segura-123');
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
  gatewayCore.stop();
  await gateway.close();
  await media.stop();
  await blobs.stop();
  await relay.stop();
  await bobRelay.stop();
}
if (failures) process.exit(1);
