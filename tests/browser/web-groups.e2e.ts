/**
 * Browser E2E for high-security groups in the web (FR025-07). Run with: npm run test:browser
 * Two browser contexts (Alice, Bob) against in-process relays: a general relay (the persona relays, like
 * Buzz) and the secondary secure relay (NIP-42, gift wraps readable only by their recipient) configured
 * as `secureRelays`. Alice creates a Marmot/MLS group, invites Bob, both chat, Alice removes Bob and Bob
 * can no longer read; reloads restore the encrypted MLS state from the vault.
 */
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { extname, join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { chromium, type BrowserContext, type Page } from 'playwright';
import { bytesToHex, generateSecretKey, getPublicKey, nip19, npubEncode } from '@sedecim/nostr-core';
import { TestRelay } from '@sedecim/test-relay';

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
const PASS = 'contraseña-local-larga';
const MARMOT_KINDS = [30443, 443, 444, 445, 10051];

const relay = new TestRelay({ requireAuth: true, pGatedKinds: [1059], host: '127.0.0.1' });
await relay.start();
const secure = new TestRelay({ requireAuth: true, pGatedKinds: [1059], host: '127.0.0.1' });
await secure.start();

// Static server with the same nonce substitution and CSP as infra/web/nginx.conf.
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
const config = { mode: 'self-hosted', relays: [relay.url], secureRelays: [secure.url] };

const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
const errors: string[] = [];

async function newUser(name: string, opts: { bypassCSP?: boolean } = {}): Promise<{ ctx: BrowserContext; page: Page; sk: Uint8Array; pubkey: string }> {
  const ctx = await browser.newContext(opts.bypassCSP ? { bypassCSP: true } : {});
  await ctx.route('**/config.json', (r) => r.fulfill({ contentType: 'application/json', body: JSON.stringify(config) }));
  const page = await ctx.newPage();
  page.on('pageerror', (e) => errors.push(`${name}: ${e.message}`));
  page.on('console', (m) => /Content Security Policy/i.test(m.text()) && errors.push(`${name}: ${m.text()}`));
  if (process.env.DEBUG_E2E) page.on('console', (m) => console.log(`[${name}]`, m.type(), m.text()));
  const sk = generateSecretKey();
  await page.goto(base);
  await page.getByText('Crear almacén').waitFor();
  await page.fill('#local-pass', PASS);
  await page.getByRole('button', { name: 'Crear almacén' }).click();
  await page.getByLabel('Importar nsec / ncryptsec').check();
  await page.fill('#persona-label', name);
  await page.fill('#secret-input', nip19.nsecEncode(sk));
  await page.fill('#relays', relay.url);
  await page.getByRole('button', { name: 'Crear persona' }).click();
  await page.waitForFunction((n) => document.querySelector('#sending-as')?.textContent?.includes(`Enviando como ${n}`), name);
  return { ctx, page, sk, pubkey: getPublicKey(sk) };
}

const openGroups = async (p: Page) => {
  await p.getByRole('tab', { name: 'Grupos seguros' }).click();
  // The first session per page runs the MLS removal self-test before opening (fail closed).
  await p.locator('#groups-accept').waitFor({ timeout: 30_000 });
};
const unlock = async (p: Page, name: string) => {
  await p.getByRole('button', { name: 'Desbloquear' }).waitFor();
  await p.fill('#local-pass', PASS);
  await p.getByRole('button', { name: 'Desbloquear' }).click();
  await p.waitForFunction((n) => document.querySelector('#sending-as')?.textContent?.includes(`Enviando como ${n}`), name);
};
const logHas = (p: Page, text: string, timeout = 20_000) => p.locator('#group-log').getByText(text, { exact: true }).waitFor({ timeout });
const stateText = async (p: Page) => (await p.textContent('#group-state')) ?? '';
const waitState = (p: Page, re: RegExp, timeout = 20_000) => p.waitForFunction((src) => new RegExp(src).test(document.querySelector('#group-state')?.textContent ?? ''), re.source, { timeout });
const idbHex = (p: Page) =>
  p.evaluate(async () => {
    const db: IDBDatabase = await new Promise((res, rej) => {
      const r = indexedDB.open('acceso-nostr');
      r.onsuccess = () => res(r.result);
      r.onerror = () => rej(r.error);
    });
    const [keys, values] = await Promise.all(
      ['getAllKeys', 'getAll'].map(
        (m) =>
          new Promise<unknown[]>((res) => {
            const r = (db.transaction('kv').objectStore('kv') as unknown as Record<string, () => IDBRequest<unknown[]>>)[m]!();
            r.onsuccess = () => res(r.result);
          }),
      ),
    );
    db.close();
    return { keys: (keys as string[]).map(String), hex: (values as ArrayBuffer[]).map((b) => Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, '0')).join('')).join('|'), localStorage: Object.keys(localStorage) };
  });
const hex = (s: string) => Buffer.from(s).toString('hex');

try {
  const alice = await newUser('Alice');
  const bob = await newUser('Bob');

  // --- Bob makes himself invitable: key package (kind 30443) on the secure relay only
  await openGroups(bob.page);
  assert((await bob.page.textContent('#groups-relays'))?.includes(secure.url), 'groups use the secure relay configured by the deployment (ADR 0006)');
  assert((await bob.page.textContent('#groups-kp-status'))?.includes('Sin key package'), 'a persona without a key package is told nobody can invite it yet');
  await bob.page.locator('#groups-keypackage').click();
  await bob.page.locator('#groups-kp-status').getByText(/^Key package publicado:/).waitFor({ timeout: 20_000 });
  assert(secure.query([{ kinds: [30443, 443], authors: [bob.pubkey] }]).length >= 1, 'Bob key package published to the secure relay');

  // --- Alice creates a group
  await openGroups(alice.page);
  assert((await alice.page.locator('#groups-relay-warning').count()) === 0, 'no relay warning when secureRelays is configured');
  await alice.page.fill('#group-name', 'Redacción');
  await alice.page.fill('#group-description', 'Equipo de investigación');
  await alice.page.locator('#groups-create').getByRole('button', { name: 'Crear grupo' }).click();
  await alice.page.locator('#group-detail').waitFor({ timeout: 20_000 });
  assert(await alice.page.locator('#group-detail').getByText('cifrado de extremo a extremo (MLS)').isVisible(), 'the open group shows the MLS end-to-end badge');
  assert(/Época 0 · 1 miembro · 1 admin/.test(await stateText(alice.page)), `new group: epoch 0, one member, one admin (${await stateText(alice.page)})`);

  // --- invite: a member without key package is warned, Bob is added
  const nobody = npubEncode(getPublicKey(generateSecretKey()));
  await alice.page.fill('#group-invite-npubs', nobody);
  await alice.page.locator('#group-invite').getByRole('button', { name: 'Invitar' }).click();
  await alice.page.locator('#group-kp-warnings').waitFor({ timeout: 20_000 });
  assert((await alice.page.textContent('#group-kp-warnings'))?.includes('Sin key package'), 'inviting someone without a key package shows a warning instead of failing silently');
  await alice.page.fill('#group-invite-npubs', npubEncode(bob.pubkey));
  await alice.page.locator('#group-invite').getByRole('button', { name: 'Invitar' }).click();
  await waitState(alice.page, /Época 1 · 2 miembros/);
  assert(true, 'Bob added by key package: epoch 1, two members');
  assert((await alice.page.locator('#group-kp-warnings').count()) === 0, 'the key package warning clears once everyone could be invited');

  // --- Bob accepts the gift-wrapped Welcome
  await bob.page.locator('#groups-accept').click();
  await bob.page.locator('#group-detail').waitFor({ timeout: 20_000 });
  await waitState(bob.page, /Época 1 · 2 miembros/);
  assert((await bob.page.textContent('#group-detail-h')) === 'Redacción', 'Bob joined "Redacción" from the Welcome');
  assert((await bob.page.locator('#group-invite').count()) === 0 && (await bob.page.getByRole('button', { name: /^Expulsar a/ }).count()) === 0, 'a non-admin member gets no invite or remove controls');

  // --- chat both ways (kind 445 through marmot-ts)
  await alice.page.fill('#group-text', 'hola bob');
  await alice.page.locator('#group-send').getByRole('button', { name: 'Enviar' }).click();
  await logHas(alice.page, 'hola bob');
  await logHas(bob.page, 'hola bob');
  assert(true, 'Bob receives and decrypts Alice message');
  await bob.page.fill('#group-text', 'hola alice');
  await bob.page.locator('#group-send').getByRole('button', { name: 'Enviar' }).click();
  await logHas(alice.page, 'hola alice');
  assert(true, 'Alice receives and decrypts Bob message');
  const groupEvents = secure.query([{ kinds: [445] }]);
  assert(groupEvents.length >= 3 && groupEvents.every((e) => e.tags.some((t) => t[0] === 'h') && !e.content.includes('hola') && e.pubkey !== alice.pubkey && e.pubkey !== bob.pubkey), `secure relay only stores kind 445 ciphertext with ephemeral signers (${groupEvents.length} events)`);
  assert(relay.received.every((e) => !MARMOT_KINDS.includes(e.kind)), 'no Marmot kind was sent to the general relay');

  // --- Bob reloads: MLS state restored from the vault and still decrypts
  await bob.page.reload();
  await unlock(bob.page, 'Bob');
  await openGroups(bob.page);
  await bob.page.locator('#group-list').getByText('Redacción').click();
  await logHas(bob.page, 'hola bob');
  await logHas(bob.page, 'hola alice');
  assert(true, 'after a reload Bob sees the group and its history (sealed in the vault)');
  await alice.page.fill('#group-text', 'después de recargar');
  await alice.page.locator('#group-send').getByRole('button', { name: 'Enviar' }).click();
  await logHas(bob.page, 'después de recargar');
  assert(true, 'the restored MLS state decrypts new messages');

  // --- Alice removes Bob; Bob cannot read later messages
  await alice.page.getByRole('button', { name: /^Expulsar a/ }).click();
  await alice.page.getByRole('dialog').getByRole('button', { name: 'Expulsar' }).click();
  await waitState(alice.page, /Época 2 · 1 miembro/);
  assert(true, 'after the removal the epoch advances and one member remains');
  await alice.page.fill('#group-text', 'secreto posterior');
  await alice.page.locator('#group-send').getByRole('button', { name: 'Enviar' }).click();
  await logHas(alice.page, 'secreto posterior');
  await bob.page.locator('#group-removed').waitFor({ timeout: 20_000 });
  assert(true, 'Bob is told he is no longer a member');
  await bob.page.waitForTimeout(5000); // at least one more poll of the secure relay
  await bob.page.locator('#group-refresh').click().catch(() => undefined);
  await bob.page.waitForTimeout(1500);
  assert((await bob.page.locator('#group-log').getByText('secreto posterior').count()) === 0, 'the removed member cannot decrypt messages sent after the removal');
  assert((await bob.page.locator('#group-send').count()) === 0, 'the removed member has no composer');
  await bob.page.locator('#group-removed').getByRole('button', { name: 'Olvidar grupo' }).click();
  await bob.page.locator('#group-detail').waitFor({ state: 'detached', timeout: 20_000 });
  // The detail closes first; the list refreshes once the MLS session has been reopened without the group.
  await bob.page.locator('#group-list').getByText('Redacción').waitFor({ state: 'detached', timeout: 20_000 }).catch(() => undefined);
  assert((await bob.page.locator('#group-list').getByText('Redacción').count()) === 0, 'the removed member can forget the group locally');

  // --- Alice reloads: admin state (epoch, members) and history restored
  await alice.page.reload();
  await unlock(alice.page, 'Alice');
  await openGroups(alice.page);
  await alice.page.locator('#group-list').getByText('Redacción').click();
  await waitState(alice.page, /Época 2 · 1 miembro · 1 admin/);
  await logHas(alice.page, 'secreto posterior');
  await alice.page.fill('#group-text', 'sigo aquí');
  await alice.page.locator('#group-send').getByRole('button', { name: 'Enviar' }).click();
  await logHas(alice.page, 'sigo aquí');
  assert(true, 'after a reload Alice keeps epoch, members, history and can keep sending');

  // --- MLS state only sealed in IndexedDB, never in localStorage or in clear
  for (const [who, u] of [['Alice', alice], ['Bob', bob]] as const) {
    const dump = await idbHex(u.page);
    const ns = who === 'Alice' ? '-groups:' : '-keypackages:'; // Bob forgot the group after his removal
    assert(dump.keys.some((k) => k.startsWith('mls-') && k.includes(ns)), `${who}: MLS state stored in the vault (per-persona mls-*${ns.slice(0, -1)} collection)`);
    assert(!dump.hex.includes(hex('hola bob')) && !dump.hex.includes(hex('Redacción')) && !dump.hex.includes(bytesToHex(u.sk)), `${who}: IndexedDB holds no plaintext message, group name or key`);
    assert(dump.localStorage.length === 0, `${who}: nothing in localStorage (${dump.localStorage.join(', ')})`);
  }

  assert(errors.length === 0, `no page errors or CSP violations (${errors.join('; ')})`);
  await alice.ctx.close();
  await bob.ctx.close();

  // --- accessibility (NFR009-01): axe on the groups view, empty and with an open group
  const a11y = await newUser('Auditoría', { bypassCSP: true });
  const axePath = createRequire(import.meta.url).resolve('axe-core/axe.min.js');
  const audit = async (label: string) => {
    await a11y.page.addScriptTag({ path: axePath });
    const v = await a11y.page.evaluate(async () => (await (window as unknown as { axe: { run(): Promise<{ violations: Array<{ id: string; impact: string; nodes: unknown[] }> }> } }).axe.run()).violations.filter((x) => x.impact === 'serious' || x.impact === 'critical').map((x) => `${x.id}(${x.nodes.length}: ${(x.nodes as Array<{ target: string[]; failureSummary?: string }>).map((n) => `${n.target.join(' ')} ${n.failureSummary ?? ''}`.replace(/\s+/g, ' ').slice(0, 220)).join(' | ')})`));
    assert(v.length === 0, `axe: no serious/critical violations on ${label} (${v.join(', ')})`);
    const dup = await a11y.page.evaluate(() => {
      const seen = new Map<string, number>();
      for (const el of document.querySelectorAll('[id]')) seen.set(el.id, (seen.get(el.id) ?? 0) + 1);
      return [...seen].filter(([, n]) => n > 1).map(([id]) => id);
    });
    assert(dup.length === 0, `no duplicate ids on ${label} (${dup.join(', ')})`);
  };
  await openGroups(a11y.page);
  await audit('Grupos seguros (vacío)');
  await a11y.page.fill('#group-name', 'Auditoría');
  await a11y.page.locator('#groups-create').getByRole('button', { name: 'Crear grupo' }).click();
  await a11y.page.locator('#group-detail').waitFor({ timeout: 20_000 });
  await a11y.page.fill('#group-invite-npubs', nobody);
  await a11y.page.locator('#group-invite').getByRole('button', { name: 'Invitar' }).click();
  await a11y.page.locator('#group-kp-warnings').waitFor({ timeout: 20_000 });
  await audit('Grupos seguros (grupo abierto)');
  await a11y.page.locator('#group-leave').click();
  await a11y.page.getByRole('dialog').waitFor();
  await a11y.page.waitForTimeout(600); // let the dialog fade-in finish (axe reads mid-transition colours)
  await audit('Grupos seguros (confirmar salida)');
  await a11y.page.getByRole('dialog').getByRole('button', { name: 'Salir' }).click();
  await a11y.page.locator('#group-detail').waitFor({ state: 'detached', timeout: 20_000 });
  assert((await a11y.page.locator('#group-list').getByText('Auditoría').count()) === 0, 'leaving a group removes it from the list and its local state');
  await a11y.ctx.close();
} finally {
  await browser.close();
  server.close();
  await relay.stop();
  await secure.stop();
}
if (failures) process.exit(1);
