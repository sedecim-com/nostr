/**
 * Browser E2E of the air-gapped key generator (FR003-05). Run with: npm run test:keygen-html
 * Builds apps/key-generator/dist/keygen.html, opens it from file:// with every network request aborted
 * and the context offline, generates a key and checks the ncryptsec decrypts to the shown npub.
 */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { chromium } from 'playwright';
import { getPublicKey, nip19, nip49 } from '@sedecim/nostr-core';

let failures = 0;
const assert = (c: unknown, m: string) => {
  if (!c) {
    failures++;
    console.error(`not ok - ${m}`);
    throw new Error(`ASSERTION FAILED: ${m}`);
  }
  console.log(`ok - ${m}`);
};

const root = new URL('../../', import.meta.url).pathname;
execFileSync(process.execPath, [`${root}apps/key-generator/build-html.mjs`], { stdio: 'inherit' });
const file = `${root}apps/key-generator/dist/keygen.html`;
const html = readFileSync(file);
const [sum] = readFileSync(`${file}.sha256`, 'utf8').split(/\s+/);
assert(createHash('sha256').update(html).digest('hex') === sum, 'keygen.html matches its .sha256 checksum');

const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
try {
  const context = await browser.newContext({ acceptDownloads: true });
  const requests: string[] = [];
  // Everything except the page file itself is aborted (and recorded as a failure below).
  await context.route('**/*', (route) => {
    if (route.request().url() === pathToFileURL(file).href) return route.continue();
    requests.push(route.request().url());
    return route.abort();
  });
  await context.setOffline(true);
  const page = await context.newPage();
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('console', (m) => /Content Security Policy|Refused to/i.test(m.text()) && errors.push(m.text()));
  page.on('request', (r) => !r.url().startsWith('file:') && !r.url().startsWith('blob:') && requests.push(r.url()));

  await page.goto(pathToFileURL(file).href);
  await page.waitForSelector('html[data-ready="1"]', { timeout: 10_000 });
  assert(errors.length === 0, `inline script and style run under the hashed CSP (${errors.join(' | ')})`);

  // The CSP itself blocks network APIs even if the page tried.
  const probe = await page.evaluate(async () => {
    const r: string[] = [];
    try {
      await fetch('https://example.com/');
      r.push('fetch-allowed');
    } catch {
      r.push('fetch-blocked');
    }
    try {
      new WebSocket('wss://relay.example.com');
      r.push('ws-created');
    } catch {
      r.push('ws-blocked');
    }
    return r;
  });
  assert(probe[0] === 'fetch-blocked', 'fetch is blocked from the page');
  errors.length = 0; // the probe above intentionally produced CSP violations

  const pass = 'una contraseña larga de prueba';
  await page.fill('#pw', 'corta');
  await page.fill('#pw2', 'corta');
  await page.click('#generate');
  assert(/al menos 12/.test((await page.textContent('#error')) ?? ''), 'rejects a short passphrase');
  await page.fill('#pw', pass);
  await page.fill('#pw2', pass);
  await page.selectOption('#logn', '16');
  await page.click('#generate');
  await page.waitForSelector('#result:not([hidden])', { timeout: 60_000 });
  const npub = (await page.textContent('#npub'))!.trim();
  const ncryptsec = (await page.textContent('#ncryptsec'))!.trim();
  assert(/^npub1/.test(npub) && /^ncryptsec1/.test(ncryptsec), 'shows npub and ncryptsec');
  assert((await page.inputValue('#pw')) === '', 'passphrase fields are cleared after generating');
  assert(!(await page.content()).includes('nsec1'), 'the page never shows an nsec');

  const { secretKey, logn } = nip49.decryptKey(ncryptsec, pass);
  assert(logn === 16, 'ncryptsec uses the selected scrypt cost');
  assert(nip19.npubEncode(getPublicKey(secretKey)) === npub, 'the produced ncryptsec decrypts with the passphrase to the shown npub');
  let wrong = false;
  try {
    nip49.decryptKey(ncryptsec, 'otra contraseña');
  } catch {
    wrong = true;
  }
  assert(wrong, 'a wrong passphrase does not decrypt the ncryptsec');

  assert((await page.locator('#sheet svg').count()) === 2, 'printable sheet contains the npub and ncryptsec QR codes');
  assert((await page.textContent('#sheet-ncryptsec'))?.trim() === ncryptsec, 'sheet prints the same ncryptsec');
  assert(/Cómo recuperar/.test((await page.textContent('#sheet')) ?? ''), 'sheet includes recovery instructions');
  assert(/Autoprueba: derivación correcta, firma BIP-340 correcta/.test((await page.textContent('#selftest')) ?? ''), 'self-test result is shown');

  const [download] = await Promise.all([page.waitForEvent('download'), page.click('#download')]);
  const backup = JSON.parse(readFileSync((await download.path())!, 'utf8'));
  assert(backup.format === 'sedecim-offline-key' && backup.npub === npub && backup.ncryptsec === ncryptsec && backup.kdf.logN === 16, 'downloads a sedecim-offline-key backup of the same key');

  await page.emulateMedia({ media: 'print' });
  assert(!(await page.locator('#form').isVisible()) && (await page.locator('#sheet svg').first().isVisible()), 'print media shows only the backup sheet');

  assert(errors.length === 0, `no CSP violations or page errors during generation (${errors.join(' | ')})`);
  assert(requests.length === 0, `no network request was attempted (${requests.join(', ')})`);
  await context.close();
} finally {
  await browser.close();
}
if (failures) process.exit(1);
