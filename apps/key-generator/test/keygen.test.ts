import { describe, expect, it } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as nt from 'nostr-tools';
import { getPublicKey, nip19, nip49 } from '@sedecim/nostr-core';
import { generateKey, backupFile, verifyBackup } from '../src/generate';
import { backupQrSvgs, backupSheetBody, backupSheetHtml } from '../src/backup-sheet';

const cli = new URL('../src/cli.ts', import.meta.url).pathname;
const tsx = new URL('../../../node_modules/.bin/tsx', import.meta.url).pathname;

describe('offline key generator (FR-003)', () => {
  it('generates, self-tests and produces a verifiable NIP-49 backup', () => {
    const k = generateKey({ password: 'contraseña muy larga', logN: 4 });
    expect(k.selfTest.ok).toBe(true);
    expect(k.nsec).toBeUndefined();
    const file = backupFile(k, 4);
    expect(verifyBackup(file, 'contraseña muy larga')).toEqual({ ok: true, npub: k.npub });
    expect(() => verifyBackup(file, 'otra')).toThrow();
  });

  it('runs with every network primitive disabled and makes no connection', () => {
    const dir = mkdtempSync(join(tmpdir(), 'keygen-'));
    const pw = join(dir, 'pw');
    writeFileSync(pw, 'una contraseña larga y segura\n');
    const out = join(dir, 'backup.json');
    const res = spawnSync(tsx, [cli, '--out', out, '--password-file', pw, '--logn', '4'], { encoding: 'utf8' });
    expect(res.status, res.stderr).toBe(0);
    expect(res.stdout).toMatch(/npub:\s+npub1/);
    expect(res.stdout).not.toMatch(/nsec1/);
    const file = JSON.parse(readFileSync(out, 'utf8'));
    expect(file.ncryptsec).toMatch(/^ncryptsec1/);
    const verify = execFileSync(tsx, [cli, 'verify', out, '--password-file', pw], { encoding: 'utf8' });
    expect(verify).toContain('OK: backup válido');
  });

  it('--qr writes self-contained SVG QR codes and --print a local backup sheet (FR003-03/04)', () => {
    const dir = mkdtempSync(join(tmpdir(), 'keygen-qr-'));
    const pw = join(dir, 'pw');
    writeFileSync(pw, 'una contraseña larga y segura\n');
    const qrDir = join(dir, 'qr');
    const sheet = join(dir, 'backup.html');
    const res = spawnSync(tsx, [cli, '--qr', qrDir, '--print', sheet, '--password-file', pw, '--logn', '4'], { encoding: 'utf8' });
    expect(res.status, res.stderr).toBe(0);
    const npub = /npub:\s+(npub1\w+)/.exec(res.stdout)![1]!;
    for (const name of ['npub.svg', 'ncryptsec.svg']) {
      const svg = readFileSync(join(qrDir, name), 'utf8');
      expect(svg).toMatch(/^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg" viewBox="0 0 \d+ \d+"/);
      expect(svg).not.toMatch(/href|<script|<style|<image|url\(/i);
    }
    const html = readFileSync(sheet, 'utf8');
    expect(html).not.toMatch(/https?:\/\//);
    expect(html).not.toMatch(/<script|<link|<img|<iframe|@import|url\(|src=|href=/i);
    const csp = /<meta http-equiv="Content-Security-Policy" content="([^"]+)">/.exec(html)![1]!;
    expect(csp).toMatch(/^default-src 'none'; style-src 'sha256-[A-Za-z0-9+/=]+'; img-src 'none'; base-uri 'none'; form-action 'none'$/);
    const css = /<style>([\s\S]*?)<\/style>/.exec(html)![1]!;
    expect(csp).toContain(`'sha256-${createHash('sha256').update(css).digest('base64')}'`);
    expect(html.match(/<svg viewBox=/g)).toHaveLength(2);
    expect(html).toContain(npub);
    const ncryptsec = /id="sheet-ncryptsec">(ncryptsec1\w+)</.exec(html)![1]!;
    expect(nip19.npubEncode(getPublicKey(nip49.decryptKey(ncryptsec, 'una contraseña larga y segura').secretKey))).toBe(npub);
    expect(html).toMatch(/Cómo recuperar la identidad/);
    expect(html).toMatch(/Creada el \d+ de \w+ de 20\d\d/);
    expect(html).not.toMatch(/nsec1/);
    // Never overwrite an existing file.
    const again = spawnSync(tsx, [cli, '--print', sheet, '--password-file', pw, '--logn', '4'], { encoding: 'utf8' });
    expect(again.status).toBe(1);
    expect(again.stderr).toContain('ya existe');
  });

  it('backup sheet is escaped, needs valid bech32 and names both QR codes', async () => {
    const k = generateKey({ password: 'contraseña muy larga', logN: 4 });
    const input = { npub: k.npub, ncryptsec: k.ncryptsec!, createdAt: '2026-11-02T10:00:00.000Z' };
    const body = backupSheetBody(input);
    expect(body).toContain('2 de noviembre de 2026');
    expect(body).toContain('aria-label="Código QR del npub (clave pública)"');
    expect(() => backupSheetBody({ ...input, npub: '<script>' })).toThrow(/invalid npub/);
    const qr = backupQrSvgs(input);
    expect(qr.ncryptsec.length).toBeGreaterThan(qr.npub.length);
    const html = await backupSheetHtml(input, () => 'AAAA');
    expect(html).toContain("style-src 'sha256-AAAA'");
  });

  it('builds a single-file air-gapped HTML with a hash-pinned CSP and checksum (FR003-05)', () => {
    const out = mkdtempSync(join(tmpdir(), 'keygen-html-'));
    execFileSync(process.execPath, [new URL('../build-html.mjs', import.meta.url).pathname, '--outdir', out], { encoding: 'utf8' });
    const html = readFileSync(join(out, 'keygen.html'), 'utf8');
    expect(readFileSync(join(out, 'keygen.html.sha256'), 'utf8')).toBe(`${createHash('sha256').update(html).digest('hex')}  keygen.html\n`);
    const csp = /<meta http-equiv="Content-Security-Policy" content="([^"]+)">/.exec(html)![1]!;
    expect(csp.split('; ')[0]).toBe("default-src 'none'");
    expect(csp).toContain("connect-src 'none'");
    expect(csp).not.toMatch(/unsafe|\*|https?:|data:|blob:/);
    const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]!);
    expect(scripts).toHaveLength(1);
    expect(csp).toContain(`script-src 'sha256-${createHash('sha256').update(scripts[0]!).digest('base64')}'`);
    const css = /<style>([\s\S]*?)<\/style>/.exec(html)![1]!;
    expect(csp).toContain(`style-src 'sha256-${createHash('sha256').update(css).digest('base64')}'`);
    // No resource can be loaded: no src/href attributes, no CSS url(), no imports; the only URL-looking
    // string is the SVG namespace identifier inside the QR library (never fetched).
    const markup = html.replace(scripts[0]!, '');
    expect(markup).not.toMatch(/\s(src|href|action)=|<link|<img|<iframe|<object|@import|url\(/i);
    expect([...html.matchAll(/https?:\/\/[^\s"'`)]+/g)].map((m) => m[0])).toEqual(['http://www.w3.org/2000/svg']);
    expect(html.indexOf('Content-Security-Policy')).toBeLessThan(html.indexOf('<style>'));
  });

  it('requires explicit acknowledgement before printing the nsec', () => {
    const res = spawnSync(tsx, [cli, '--show-nsec'], { encoding: 'utf8' });
    expect(res.status).toBe(2);
    expect(res.stderr).toContain('ADVERTENCIA');
  });

  it('service-key prints a self-tested hex key for a service .env only when acknowledged (OPS-03)', () => {
    expect(spawnSync(tsx, [cli, 'service-key'], { encoding: 'utf8' }).status).toBe(2);
    const out = execFileSync(tsx, [cli, 'service-key', '--i-understand'], { encoding: 'utf8' });
    const secret = /^secret_hex=([0-9a-f]{64})$/m.exec(out)![1]!;
    const pubkey = /^pubkey_hex=([0-9a-f]{64})$/m.exec(out)![1]!;
    expect(nt.getPublicKey(Uint8Array.from(Buffer.from(secret, 'hex')))).toBe(pubkey);
    expect(out).toContain(`npub=${nt.nip19.npubEncode(pubkey)}`);
  });

  it('offline guard blocks sockets, DNS and fetch inside the process', () => {
    const script = `
      import { enforceOffline, attempts } from ${JSON.stringify(new URL('../src/offline-guard.ts', import.meta.url).pathname)};
      import net from 'node:net'; import dns from 'node:dns';
      enforceOffline();
      const r = [];
      for (const f of [() => net.connect(80, 'example.com'), () => dns.lookup('example.com', () => {}), () => fetch('https://example.com')]) {
        try { f(); r.push('allowed'); } catch (e) { r.push(e.name); }
      }
      console.log(JSON.stringify({ r, attempts }));`;
    const dir = mkdtempSync(join(tmpdir(), 'guard-'));
    const f = join(dir, 'probe.ts');
    writeFileSync(f, script);
    const out = JSON.parse(execFileSync(tsx, [f], { encoding: 'utf8' }));
    expect(out.r).toEqual(['OfflineViolation', 'OfflineViolation', 'OfflineViolation']);
    expect(out.attempts).toEqual(['net.connect', 'dns.lookup', 'fetch']);
  });
});
