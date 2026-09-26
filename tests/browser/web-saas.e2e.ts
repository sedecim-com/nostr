/**
 * Browser E2E for the SaaS web client (FR-015, FR-028). Run with: npm run test:browser
 * Requires Playwright (browsers preinstalled in CI images or `npx playwright install chromium`).
 */
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { chromium } from 'playwright';
import WebSocket from 'ws';
import { generateSecretKey, getPublicKey, npubEncode } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { TestRelay } from '@sedecim/test-relay';
import { chatMessage, openDirectMessage, dmInboxFilter } from '@sedecim/messaging';

const root = new URL('../../apps/web-saas/public/', import.meta.url).pathname;
const types: Record<string, string> = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.map': 'application/json' };
const assert = (c: unknown, m: string) => {
  if (!c) throw new Error(`ASSERTION FAILED: ${m}`);
  console.log(`ok - ${m}`);
};

const relay = new TestRelay({ requireAuth: true, pGatedKinds: [1059], host: '127.0.0.1' });
await relay.start();
const server = createServer(async (req, res) => {
  const path = join(root, req.url === '/' ? 'index.html' : req.url!.split('?')[0]!);
  try {
    res.writeHead(200, { 'content-type': types[extname(path)] ?? 'application/octet-stream' });
    res.end(await readFile(path));
  } catch {
    res.writeHead(404).end();
  }
});
await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
const page = await browser.newPage();
const errors: string[] = [];
page.on('pageerror', (e) => errors.push(e.message));
const external: string[] = [];
page.on('request', (r) => {
  const u = new URL(r.url());
  if (u.hostname !== '127.0.0.1') external.push(r.url());
});

try {
  await page.goto(base);
  await page.fill('#local-pass', 'contraseña-local');
  await page.fill('#relays', relay.url);
  await page.click('#unlock-form button[type=submit]');
  await page.waitForSelector('#identity-status:has-text("Identidad activa")', { timeout: 30_000 });
  const sendingAs = await page.textContent('#sending-as');
  assert(sendingAs?.startsWith('Enviando como npub1'), `composer shows sending identity: ${sendingAs}`);
  assert((await page.textContent('#custody-facts'))?.includes('NO puede firmar'), 'custody facts are disclosed');

  // another client (e.g. Buzz Desktop) writes to the same relay; the web app reads it
  const other = new LocalSigner(generateSecretKey());
  const pool = new RelayPool({ webSocketFactory: (u) => new WebSocket(u) as unknown as WebSocketLike, signer: other });
  await pool.publishTo(await other.signEvent(chatMessage('general', 'hola desde desktop')), relay.url);

  await page.click('[data-tab=channel]');
  await page.fill('#group-id', 'general');
  await page.click('#channel-join button');
  await page.waitForSelector('#channel-log li:has-text("hola desde desktop")', { timeout: 10_000 });
  assert(true, 'web app shows messages written by another client (FR-014)');

  await page.fill('#channel-text', 'hola desde la web');
  await page.click('#channel-send button');
  await page.waitForSelector('#channel-log li:has-text("hola desde la web")', { timeout: 10_000 });
  const fromOther = await pool.query([relay.url], [{ kinds: [9], '#h': ['general'] }], 3000);
  assert(fromOther.some((e) => e.content === 'hola desde la web'), 'message sent from the web app is visible to other clients on the same relay (FR-015)');

  await page.click('[data-tab=outbox]');
  await page.waitForSelector('#outbox-rows td:has-text("REPLICATED")', { timeout: 10_000 });
  assert(true, 'outbox shows REPLICATED state');

  // NIP-17 gated by flag, then enabled
  const bobKey = generateSecretKey();
  const bob = new LocalSigner(bobKey);
  const bobPool = new RelayPool({ webSocketFactory: (u) => new WebSocket(u) as unknown as WebSocketLike, signer: bob });
  await page.click('[data-tab=dm]');
  await page.fill('#dm-to', npubEncode(getPublicKey(bobKey)));
  await page.fill('#dm-text', 'dm desde la web');
  let dialogMsg = '';
  page.once('dialog', (dlg) => {
    dialogMsg = dlg.message();
    void dlg.dismiss();
  });
  await page.click('#dm-send button');
  await page.waitForTimeout(300);
  assert(dialogMsg.includes('deshabilitado'), 'NIP-17 is blocked while the feature flag is off (FR-017)');
  await page.check('#nip17-flag');
  await page.click('#dm-send button');
  let got = false;
  for (let i = 0; i < 40 && !got; i++) {
    await new Promise((r) => setTimeout(r, 250));
    const wraps = await bobPool.query([relay.url], [dmInboxFilter(getPublicKey(bobKey))], 2000);
    for (const w of wraps) if ((await openDirectMessage(bob, w).catch(() => undefined))?.rumor.content === 'dm desde la web') got = true;
  }
  assert(got, 'NIP-17 DM sent from the web is readable by an independent client');

  await page.click('[data-tab=panel]');
  await page.selectOption('#preset', 'sovereign-tor');
  assert((await page.textContent('#panel-issues'))?.includes('Tor-only no puede garantizarse desde un navegador'), 'panel blocks Tor-only in the browser');
  await page.selectOption('#cfg-custody', 'managed');
  assert((await page.textContent('#panel-disclosures'))?.includes('capacidad técnica de firmar'), 'managed custody disclosure shown (FR-028)');

  assert(errors.length === 0, `no page errors (${errors.join('; ')})`);
  assert(external.length === 0, `no requests to third-party hosts (${external.join(', ')})`);
  pool.close();
  bobPool.close();
} finally {
  await browser.close();
  server.close();
  await relay.stop();
}
