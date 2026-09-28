/**
 * SEC-05: leaks through WebRTC and remote previews in the web client. Run with: npm run test:browser
 *
 * For each sensitive profile available in a browser (private-resilient, sovereign; tor-only is refused
 * on the web), a persona receives and sends channel messages and DMs that contain links, Markdown/HTML
 * images and an imeta image attachment pointing at canary hosts. Every request of the browser context
 * is intercepted: anything that is not the local app/relay is recorded and aborted. The test asserts:
 *  - no request to any canary URL (no link previews, no remote image loads) while the profile keeps
 *    remote previews off;
 *  - WebRTC is unavailable in the app page (no RTCPeerConnection, so no ICE candidates can be gathered).
 * Negative controls: clicking "Mostrar imagen" must produce a recorded canary request (the interception
 * sees remote loads), and a page without the app must gather ICE candidates (the probe works).
 */
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { extname, join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { chromium, type Browser, type Page } from 'playwright';
import WebSocket from 'ws';
import { bytesToHex, finalizeEvent, generateSecretKey, getPublicKey, nip19, toUnsigned } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { TestBlossomServer, TestRelay } from '@sedecim/test-relay';
import { chatMessage, createDirectMessage } from '@sedecim/messaging';
import { preset, type PresetName } from '@sedecim/profiles';

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
const CANARY = /leak-canary-[a-z0-9-]+\.example/;
const IMG_SHA = bytesToHex(randomBytes(32));
const canaryText = (who: string) =>
  `${who}: mira https://leak-canary-link.example/articulo?utm=1 y www.leak-canary-www.example ` +
  `![foto](https://leak-canary-md.example/foto.png) <img src="https://leak-canary-html.example/x.png"> ` +
  `https://leak-canary-og.example/video.mp4`;

const relay = new TestRelay({ requireAuth: true, pGatedKinds: [1059], host: '127.0.0.1' });
await relay.start();
// private-resilient asks for a quorum of 2, and a persona is only created with that many relays (PANEL-05).
const second = new TestRelay({ requireAuth: true, pGatedKinds: [1059], host: '127.0.0.1' });
await second.start();
const media = new TestBlossomServer();
media.cors = true;
await media.start();
const blobs = new TestBlossomServer();
blobs.cors = true;
await blobs.start();

// Static server with the same nonce substitution as infra/web/nginx.conf (img-src allows https: there too).
const server = createServer(async (req, res) => {
  const p = (req.url ?? '/').split('?')[0]!;
  const file = join(dist, p === '/' || !extname(p) ? 'index.html' : p);
  try {
    let body: Buffer | string = await readFile(file);
    const headers: Record<string, string> = { 'content-type': types[extname(file)] ?? 'application/octet-stream' };
    if (file.endsWith('index.html')) {
      const nonce = randomBytes(16).toString('hex');
      body = body.toString('utf8').replaceAll('__NONCE__', nonce);
      headers['content-security-policy'] = `default-src 'self'; connect-src 'self' ws: wss: http://localhost:* http://127.0.0.1:* https:; img-src 'self' data: blob: https: http://localhost:* http://127.0.0.1:*; style-src 'self' 'nonce-${nonce}'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'`;
    }
    res.writeHead(200, headers).end(body);
  } catch {
    res.writeHead(404).end();
  }
});
await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
const selfHosted = { mode: 'self-hosted', relays: [relay.url], buzzMedia: media.url, blobStore: blobs.url };

const browser: Browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
const pools: RelayPool[] = [];
const tab = (p: Page, name: string) => p.getByRole('tab', { name }).click();

/** Gathers ICE candidates for 3 s in the given page; `unavailable` when RTCPeerConnection is gone. */
const iceProbe = (p: Page) =>
  p.evaluate(async () => {
    const w = window as unknown as Record<string, unknown>;
    const Ctor = w.RTCPeerConnection as (new (c: RTCConfiguration) => RTCPeerConnection) | undefined;
    if (typeof Ctor !== 'function') return { available: false, candidates: [] as string[] };
    const pc = new Ctor({ iceServers: [{ urls: 'stun:leak-canary-stun.example:3478' }] });
    const candidates: string[] = [];
    pc.onicecandidate = (e) => {
      if (e.candidate?.candidate) candidates.push(e.candidate.candidate);
    };
    pc.createDataChannel('probe');
    await pc.setLocalDescription(await pc.createOffer());
    await new Promise((r) => setTimeout(r, 3000));
    pc.close();
    return { available: true, candidates };
  });

async function scenario(presetName: PresetName) {
  assert(preset(presetName).remotePreviews === false, `${presetName}: the profile keeps remote previews off`);
  const context = await browser.newContext();
  const remote: string[] = [];
  const errors: string[] = [];
  // Catch-all first; the config.json route registered after it takes precedence for that URL.
  await context.route('**/*', (route) => {
    const u = new URL(route.request().url());
    if (u.hostname === '127.0.0.1') return route.continue();
    remote.push(route.request().url());
    return route.abort('blockedbyclient');
  });
  await context.route('**/config.json', (r) => r.fulfill({ contentType: 'application/json', body: JSON.stringify(selfHosted) }));
  const page = await context.newPage();
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('websocket', (ws) => {
    if (new URL(ws.url()).hostname !== '127.0.0.1') remote.push(ws.url());
  });
  page.on('request', (r) => {
    // Requests the route may not see (service workers, prefetch): recorded as well.
    const u = new URL(r.url());
    if (u.protocol.startsWith('http') && u.hostname !== '127.0.0.1' && !remote.includes(r.url())) remote.push(r.url());
  });

  // --- vault + persona with a known key in the sensitive profile
  await page.goto(base);
  await page.getByText('Crear almacén').waitFor();
  await page.fill('#local-pass', PASS);
  await page.getByRole('button', { name: 'Crear almacén' }).click();
  await page.getByRole('button', { name: 'Crear persona' }).waitFor();
  const sk = generateSecretKey();
  const webPub = getPublicKey(sk);
  await page.locator('#persona-preset').click();
  await page.getByRole('option', { name: presetName, exact: true }).click();
  await page.getByLabel('Importar nsec / ncryptsec').check();
  await page.fill('#persona-label', `Sensible ${presetName}`);
  await page.fill('#secret-input', nip19.nsecEncode(sk));
  await page.fill('#relays', preset(presetName).quorum > 1 ? `${relay.url}\n${second.url}` : relay.url);
  await page.getByRole('button', { name: 'Crear persona' }).click();
  await page.waitForFunction((label) => document.querySelector('#sending-as')?.textContent?.includes(`Enviando como ${label}`), `Sensible ${presetName}`);
  await tab(page, 'Soberanía y privacidad');
  assert(!(await page.isChecked('#cfg-remotePreviews')), `${presetName}: panel shows remote previews off`);

  // --- WebRTC is not available in the app page (SEC-05)
  const rtc = await iceProbe(page);
  const globals = await page.evaluate(() => ['RTCPeerConnection', 'webkitRTCPeerConnection', 'RTCDataChannel', 'RTCSessionDescription'].filter((n) => typeof (window as unknown as Record<string, unknown>)[n] !== 'undefined'));
  assert(!rtc.available && rtc.candidates.length === 0 && globals.length === 0, `${presetName}: no RTCPeerConnection in the app, zero ICE candidates (${globals.join(',') || 'none exposed'})`);
  const reassigned = await page.evaluate(() => {
    try {
      (window as unknown as Record<string, unknown>).RTCPeerConnection = function Fake() {};
    } catch {
      /* strict-mode TypeError: also fine */
    }
    return typeof (window as unknown as Record<string, unknown>).RTCPeerConnection;
  });
  assert(reassigned === 'undefined', `${presetName}: the WebRTC guard cannot be undone from page script`);

  // --- channel: incoming and outgoing messages with links and remote images
  const group = `leaks-${presetName}`;
  const relayKey = generateSecretKey();
  relay.inject(finalizeEvent(toUnsigned({ kind: 39000, content: '', tags: [['d', group], ['name', `Fugas ${presetName}`]] }, getPublicKey(relayKey)), relayKey));
  const other = new LocalSigner(generateSecretKey());
  const pool = new RelayPool({ webSocketFactory: factory, signer: other });
  pools.push(pool);
  await pool.publishTo(await other.signEvent(chatMessage(group, canaryText('otro cliente'))), relay.url);
  const plain = chatMessage(group, 'adjunto remoto');
  const withImage = { ...plain, tags: [...(plain.tags ?? []), ['imeta', `url https://leak-canary-imeta.example/${IMG_SHA}.png`, `x ${IMG_SHA}`, 'm image/png']] };
  await pool.publishTo(await other.signEvent(withImage), relay.url);
  await tab(page, 'Canales');
  await page.locator('#channel-list').getByText(`Fugas ${presetName}`).click();
  await page.locator('#channel-log').getByText('otro cliente: mira').waitFor({ timeout: 10_000 });
  await page.getByRole('button', { name: /Mostrar imagen/ }).waitFor({ timeout: 10_000 });
  await page.fill('#channel-text', canaryText('yo'));
  await page.locator('#channel-send').getByRole('button', { name: 'Enviar' }).click();
  await page.locator('#channel-log').getByText('yo: mira').waitFor({ timeout: 10_000 });

  // --- DM with the same content (NIP-17)
  const bob = new LocalSigner(generateSecretKey());
  const bobPool = new RelayPool({ webSocketFactory: factory, signer: bob });
  pools.push(bobPool);
  const dm = await createDirectMessage(bob, { recipients: [webPub], content: canaryText('bob') });
  for (const w of dm.wraps) await bobPool.publishTo(w.event, relay.url);
  await tab(page, 'Mensajes directos');
  await page.locator('#dm-refresh').click();
  await page.locator('#dm-log').getByText('bob: mira').waitFor({ timeout: 10_000 });

  await page.waitForTimeout(1500); // give any preview/image loader time to fire
  const leaked = remote.filter((u) => CANARY.test(u));
  assert(leaked.length === 0, `${presetName}: no request to linked or embedded URLs (no previews, no remote images) (${leaked.join(', ')})`);
  assert(remote.length === 0, `${presetName}: no request to any host other than the local app and relay (${remote.join(', ')})`);
  assert(errors.length === 0, `${presetName}: no page errors (${errors.join('; ')})`);

  // --- negative control: an explicit click loads the image, and the interception records it
  await tab(page, 'Canales');
  await page.locator('#channel-list').getByText(`Fugas ${presetName}`).click();
  await page.getByRole('button', { name: /Mostrar imagen/ }).click();
  for (let i = 0; i < 40 && !remote.some((u) => u.includes('leak-canary-imeta.example')); i++) await page.waitForTimeout(100);
  assert(remote.some((u) => u.includes('leak-canary-imeta.example')), `${presetName}: negative control - the explicit "Mostrar imagen" request is detected by the interception`);
  await context.close();
}

try {
  // Negative control for the ICE probe: a page without the app does gather candidates in this browser.
  const bare = await browser.newContext();
  const barePage = await bare.newPage();
  const control = await iceProbe(barePage);
  assert(control.available && control.candidates.length > 0, `negative control - without the guard Chromium gathers ICE candidates (${control.candidates.length})`);
  await bare.close();

  for (const name of ['private-resilient', 'sovereign'] as const) await scenario(name);
} finally {
  for (const p of pools) p.close();
  await browser.close();
  server.close();
  await media.stop();
  await blobs.stop();
  await relay.stop();
  await second.stop();
}
if (failures) process.exit(1);
