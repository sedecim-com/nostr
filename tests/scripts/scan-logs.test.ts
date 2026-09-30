/**
 * NFR006-03: scripts/scan-logs.sh fails when a service log contains a secret (gitleaks rules or a known
 * value from .env) and passes on a clean log. The gitleaks half runs when the binary is available
 * (GITLEAKS=/absolute/path or `gitleaks` in PATH), as in CI.
 */
import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { bytesToHex, generateSecretKey, getPublicKey, nsecEncode, randomBytes } from '@sedecim/nostr-core';

const root = new URL('../..', import.meta.url).pathname;
const gitleaks = process.env.GITLEAKS ?? 'gitleaks';
const hasGitleaks = spawnSync(gitleaks, ['version'], { encoding: 'utf8' }).status === 0;

function scan(files: Record<string, string>, args: string[] = []) {
  const dir = mkdtempSync(join(tmpdir(), 'scan-logs-'));
  for (const [name, content] of Object.entries(files)) writeFileSync(join(dir, name), content);
  const res = spawnSync('sh', [join(root, 'scripts/scan-logs.sh'), ...args, join(dir, 'compose.log'), join(dir, '.env')], {
    encoding: 'utf8',
    env: { ...process.env, ...(hasGitleaks ? { GITLEAKS: gitleaks } : {}) },
  });
  return { status: res.status, out: res.stdout + res.stderr };
}

// Generated at run time like scripts/init-env.sh does (and the repository scan has nothing to flag).
const password = bytesToHex(randomBytes(24));
const env = [
  `POSTGRES_PASSWORD=${password}`,
  'BUZZ_RELAY_PRIVATE_KEY=' + 'ab'.repeat(32),
  'POLICY_SERVICE_TOKENS=tok-abcdefgh1234:ops,short:x',
  'RELAY_OWNER_PUBKEY=' + 'cd'.repeat(32),
  'RELAY_URL=ws://localhost:3000',
].join('\n');
const clean = 'relay-1  | INFO listening on 0.0.0.0:3000\nindexer-1 | {"level":"info","msg":"mirror started","pubkey":"' + 'cd'.repeat(32) + '"}\n';
const noGitleaks = hasGitleaks ? [] : ['--no-gitleaks'];

describe('scripts/scan-logs.sh (NFR006-03)', () => {
  it('passes on a clean log (public keys are not secrets)', () => {
    const r = scan({ 'compose.log': clean, '.env': env }, noGitleaks);
    expect(r.status, r.out).toBe(0);
    expect(r.out).toMatch(/canary: 3 secret values checked/);
  });

  it('fails when a value from .env appears, printing only its name', () => {
    const r = scan({ 'compose.log': clean + `identity-1 | connecting to postgres://buzz:${password}@postgres/sedecim\n`, '.env': env }, noGitleaks);
    expect(r.status).toBe(1);
    expect(r.out).toMatch(/LEAK: the value of POSTGRES_PASSWORD appears/);
    expect(r.out).not.toContain(password);
  });

  it('checks service tokens one by one', () => {
    const r = scan({ 'compose.log': clean + 'policy-1 | bad token tok-abcdefgh1234\n', '.env': env }, noGitleaks);
    expect(r.status).toBe(1);
    expect(r.out).toMatch(/LEAK: the value of POLICY_SERVICE_TOKENS/);
  });

  it('refuses an empty log (nothing collected is not "clean")', () => {
    expect(scan({ 'compose.log': '', '.env': env }, noGitleaks).status).toBe(2);
  });

  it.skipIf(!hasGitleaks)('fails on a Nostr secret key found by the gitleaks rules (not in .env)', () => {
    const sk = generateSecretKey();
    const r = scan({ 'compose.log': clean + `web-1 | debug key ${nsecEncode(sk)} for ${getPublicKey(sk)}\n`, '.env': env });
    expect(r.status, r.out).toBe(1);
    expect(r.out).toMatch(/gitleaks found secrets/);
    expect(r.out).not.toContain(nsecEncode(sk));
  });

  it.skipIf(!hasGitleaks)('does not take the bkey field of the Buzz relay logs for a credential, and still reports anything else on that line', () => {
    const value = bytesToHex(randomBytes(32));
    const line = (field: string, message = 'stored') => `relay-1  | {"timestamp":"2026-09-30T22:49:00.000000Z","level":"INFO","message":"${message}","${field}":"${value}","target":"buzz_relay::media"}\n`;
    const bkey = scan({ 'compose.log': clean + line('bkey'), '.env': env });
    expect(bkey.status, bkey.out).toBe(0);
    // Only the text of that field: the same value under another name is still a finding, and so is a secret key on the same line.
    expect(scan({ 'compose.log': clean + line('api_key'), '.env': env }).status).toBe(1);
    const sk = nsecEncode(generateSecretKey());
    const withNsec = scan({ 'compose.log': clean + line('bkey', `leaked ${sk}`), '.env': env });
    expect(withNsec.status, withNsec.out).toBe(1);
    expect(withNsec.out).toMatch(/RuleID:\s+nostr-nsec/);
  });

  it.skipIf(!hasGitleaks)('says which rule, line and service each finding comes from, with the value redacted', () => {
    const sk = generateSecretKey();
    const log = clean + 'relay-1  | INFO client connected\n' + `rotation-worker-1  | debug ${nsecEncode(sk)}\n`;
    const r = scan({ 'compose.log': log, '.env': env });
    expect(r.status, r.out).toBe(1);
    expect(r.out).toMatch(/RuleID:\s+nostr-nsec/);
    expect(r.out).toMatch(/finding on line 4, written by rotation-worker-1/);
    expect(r.out).toMatch(/REDACTED/);
    expect(r.out).not.toContain(nsecEncode(sk));
    expect(r.out).not.toContain(nsecEncode(sk).slice(5, 25));
  });
});
