/**
 * FR015-03: the Acceso Nostr web against a real Buzz relay — create a channel, join one, send, read.
 * Env: BUZZ_RELAY_URL (required) and STACK_WEB_URL (the compose web, served by nginx with the real CSP);
 * without STACK_WEB_URL the Vite build is served locally. Run: npx tsx tests/browser/web-buzz.e2e.ts
 */
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { chromium } from 'playwright';
import WebSocket from 'ws';
import { generateSecretKey, getTagValue } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { chatMessage, createGroup, parseGroupMetadata } from '@sedecim/messaging';

const RELAY = process.env.BUZZ_RELAY_URL;
if (!RELAY) {
  console.log('skip - BUZZ_RELAY_URL not set');
  process.exit(0);
}
const assert = (c: unknown, m: string) => {
  if (!c) throw new Error(`ASSERTION FAILED: ${m}`);
  console.log(`ok - ${m}`);
};
const eventually = async <T>(fn: () => Promise<T | undefined>, ms: number): Promise<T | undefined> => {
  for (const end = Date.now() + ms; Date.now() < end; await new Promise((r) => setTimeout(r, 500))) {
    const v = await fn().catch(() => undefined);
    if (v) return v;
  }
  return undefined;
};

let base = process.env.STACK_WEB_URL;
let server: ReturnType<typeof createServer> | undefined;
if (!base) {
  const dist = new URL('../../apps/web-saas/dist/', import.meta.url).pathname;
  server = createServer(async (req, res) => {
    const p = (req.url ?? '/').split('?')[0]!;
    try {
      const file = join(dist, p === '/' || !extname(p) ? 'index.html' : p);
      res.writeHead(200, { 'content-type': file.endsWith('.js') ? 'text/javascript' : file.endsWith('.html') ? 'text/html' : 'application/json' }).end(await readFile(file));
    } catch {
      res.writeHead(404).end();
    }
  });
  await new Promise<void>((r) => server!.listen(0, '127.0.0.1', () => r()));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

const other = new LocalSigner(generateSecretKey());
const pool = new RelayPool({ webSocketFactory: (u) => new WebSocket(u) as unknown as WebSocketLike, signer: other, authMode: 'auto', authTimeoutMs: 1500 });
const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
const ctx = await browser.newContext();
await ctx.route('**/config.json', (r) => r.fulfill({ contentType: 'application/json', body: JSON.stringify({ mode: 'self-hosted', relays: [RELAY] }) }));
const page = await ctx.newPage();
const errors: string[] = [];
page.on('pageerror', (e) => errors.push(e.message));
page.on('console', (m) => /Content Security Policy/i.test(m.text()) && errors.push(m.text()));
const stamp = Date.now();
try {
  await page.goto(base);
  await page.fill('#local-pass', 'contraseña-e2e-buzz');
  await page.getByRole('button', { name: 'Crear almacén' }).click();
  await page.getByRole('button', { name: 'Crear persona' }).click();
  await page.waitForFunction(() => document.querySelector('#sending-as')?.textContent?.includes('Enviando como'));
  await page.getByRole('tab', { name: 'Canales' }).click();

  // create from the web: Buzz assigns the id and publishes 39000
  const webName = `web-e2e-${stamp}`;
  await page.fill('#new-channel', webName);
  await page.locator('#channel-create').getByRole('button', { name: 'Crear' }).click();
  await page.locator('#channel-list').getByText(webName).waitFor({ timeout: 20_000 });
  assert(true, 'channel created from the web appears from Buzz metadata (39000)');
  await page.locator('#channel-list').getByText(webName).click();
  await page.fill('#channel-text', 'hola buzz desde la web');
  await page.locator('#channel-send').getByRole('button', { name: 'Enviar' }).click();
  const webMeta = (await pool.query([RELAY], [{ kinds: [39000], limit: 500 }], 5000)).map(parseGroupMetadata).find((m) => m?.name === webName);
  const seen = await eventually(async () => (await pool.query([RELAY], [{ kinds: [9], '#h': [webMeta!.id] }], 4000)).find((e) => e.content === 'hola buzz desde la web'), 20_000);
  assert(seen, 'message sent from the web is readable by another Nostr client through Buzz');

  // join a channel created by someone else, then write and read there
  const create = await other.signEvent(createGroup(`otro-${stamp}`, 'open'));
  assert((await pool.publishTo(create, RELAY)).ok, 'another client creates an open channel');
  const meta = await eventually(async () => (await pool.query([RELAY], [{ kinds: [39000], limit: 500 }], 5000)).map(parseGroupMetadata).find((m) => m?.name === getTagValue(create, 'name')), 20_000);
  await pool.publishTo(await other.signEvent(chatMessage(meta!.id, 'bienvenida desde otro cliente')), RELAY);
  await page.locator('#channel-list').getByRole('button', { name: 'Actualizar' }).click().catch(() => page.getByRole('button', { name: 'Actualizar' }).click());
  const row = page.locator('#channel-list li', { hasText: `otro-${stamp}` });
  await row.waitFor({ timeout: 20_000 });
  await row.getByRole('button', { name: 'Unirse' }).click();
  await row.getByText(`otro-${stamp}`).click();
  await page.locator('#channel-log').getByText('bienvenida desde otro cliente').waitFor({ timeout: 20_000 });
  assert(true, 'web reads messages of a joined channel from Buzz');
  await page.fill('#channel-text', 'gracias, ya me uní');
  await page.locator('#channel-send').getByRole('button', { name: 'Enviar' }).click();
  const reply = await eventually(async () => (await pool.query([RELAY], [{ kinds: [9], '#h': [meta!.id] }], 4000)).find((e) => e.content === 'gracias, ya me uní'), 20_000);
  assert(reply, 'web writes in the joined channel and the other client reads it');
  assert(errors.length === 0, `no page errors or CSP violations (${errors.join('; ')})`);
} finally {
  pool.close();
  await browser.close();
  server?.close();
}
