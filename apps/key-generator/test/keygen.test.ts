import { describe, expect, it } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as nt from 'nostr-tools';
import { generateKey, backupFile, verifyBackup } from '../src/generate';

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
