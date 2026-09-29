/**
 * NFR006-04: the CI `stack` job also runs the optional profiles (managed, push, institutional, tor) and scans their
 * logs. scripts/stack-profiles.sh turns them on with secrets the scan knows, sends canary credentials, and fails when
 * a service of the stack wrote nothing to the collected log.
 */
import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { getPublicKey, hexToBytes } from '@sedecim/nostr-core';

const root = new URL('../..', import.meta.url).pathname;
const script = join(root, 'scripts/stack-profiles.sh');
const read = (p: string) => readFileSync(join(root, p), 'utf8');
const run = (args: string[], env: NodeJS.ProcessEnv = {}) => {
  const r = spawnSync('sh', [script, ...args], { encoding: 'utf8', env: { ...process.env, ...env } });
  return { status: r.status, out: r.stdout + r.stderr };
};
const value = (env: string, name: string) => new RegExp(`^${name}=(.*)$`, 'm').exec(env)?.[1];

function envFile(content: string) {
  const dir = mkdtempSync(join(tmpdir(), 'stack-profiles-'));
  const file = join(dir, '.env');
  writeFileSync(file, content);
  return { dir, file };
}

describe('scripts/stack-profiles.sh configure', () => {
  it('turns the four profiles on with generated secrets and the allowlist token among the service tokens', () => {
    const { file } = envFile('POSTGRES_PASSWORD=abc\nPOLICY_SERVICE_TOKENS=ops-token-123:ops\nMANAGED_SIGNER_KEK=\n');
    expect(run(['configure', file]).status).toBe(0);
    const env = readFileSync(file, 'utf8');
    expect(value(env, 'COMPOSE_PROFILES')).toBe('managed,push,institutional,tor');
    expect(value(env, 'MANAGED_SIGNER_KEK')).toMatch(/^[0-9a-f]{64}$/);
    expect(value(env, 'NOTIFY_NSEC')).toMatch(/^[0-9a-f]{64}$/);
    expect(value(env, 'NOTIFY_VAPID_PRIVATE_KEY')).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const token = value(env, 'RELAY_ALLOWLIST_POLICY_TOKEN')!;
    expect(token).toMatch(/^[0-9a-f]{48}$/);
    // FR024-05: the rotation worker's own service token, and its revocation token for the managed-signer.
    const worker = value(env, 'ROTATION_WORKER_POLICY_TOKEN')!;
    expect(worker).toMatch(/^[0-9a-f]{48}$/);
    expect(value(env, 'POLICY_SERVICE_TOKENS')).toBe(`ops-token-123:ops,${token}:relay-allowlist,${worker}:rotation-worker`);
    const revocation = value(env, 'ROTATION_MANAGED_SIGNER_TOKEN')!;
    expect(revocation).toMatch(/^[0-9a-f]{48}$/);
    expect(value(env, 'MANAGED_SIGNER_REVOCATION_TOKENS')).toBe(`${revocation}:rotation-worker`);
    expect(value(env, 'ROTATION_MANAGED_SIGNER_URL')).toBe('http://managed-signer:8084');
    // A placeholder Acceso pool: the signer starts and nobody can sign in.
    expect(value(env, 'COGNITO_USER_POOL_ID')).toBe('us-east-1_stackci');
    expect(value(env, 'POSTGRES_PASSWORD')).toBe('abc');
    // FR023-13: an admin key of the policy-engine for the institutional check, and a fast allowlist sync.
    const admin = value(env, 'POLICY_ADMIN_SECRET_KEY')!;
    expect(admin).toMatch(/^[0-9a-f]{64}$/);
    expect(value(env, 'POLICY_ADMIN_PUBKEYS')).toBe(getPublicKey(hexToBytes(admin)));
    expect(value(env, 'ALLOWLIST_SYNC_INTERVAL_MS')).toBe('2000');
  });

  it('lets the institutional secure relay admit the rotation worker (FR024-05)', () => {
    const sk = 'cd'.repeat(32);
    const { file } = envFile(`ROTATION_WORKER_NSEC=${sk}\nALLOWLIST_EXTRA_PUBKEYS=${'ef'.repeat(32)}\n`);
    expect(run(['configure', file]).status).toBe(0);
    run(['configure', file]);
    expect(value(readFileSync(file, 'utf8'), 'ALLOWLIST_EXTRA_PUBKEYS')).toBe(`${'ef'.repeat(32)},${getPublicKey(hexToBytes(sk))}`);
  });

  it('is idempotent and keeps what was already set, other profiles included', () => {
    const { file } = envFile('COMPOSE_PROFILES=scale\nMANAGED_SIGNER_KEK=' + 'ab'.repeat(32) + '\n');
    run(['configure', file]);
    const first = readFileSync(file, 'utf8');
    run(['configure', file]);
    const second = readFileSync(file, 'utf8');
    expect(value(second, 'COMPOSE_PROFILES')).toBe('scale,managed,push,institutional,tor');
    expect(value(second, 'MANAGED_SIGNER_KEK')).toBe('ab'.repeat(32));
    for (const name of ['NOTIFY_NSEC', 'NOTIFY_VAPID_PRIVATE_KEY', 'RELAY_ALLOWLIST_POLICY_TOKEN', 'POLICY_SERVICE_TOKENS', 'POLICY_ADMIN_SECRET_KEY', 'POLICY_ADMIN_PUBKEYS', 'ROTATION_WORKER_POLICY_TOKEN', 'ROTATION_MANAGED_SIGNER_TOKEN', 'MANAGED_SIGNER_REVOCATION_TOKENS']) expect(value(second, name), name).toBe(value(first, name));
    expect(value(second, 'POLICY_SERVICE_TOKENS')!.split(',')).toHaveLength(2);
    expect(value(second, 'MANAGED_SIGNER_REVOCATION_TOKENS')!.split(',')).toHaveLength(1);
    expect(value(second, 'POLICY_ADMIN_PUBKEYS')!.split(',')).toHaveLength(1);
  });

  it('every secret it generates, and the canary, is one the log scan checks (NFR006-03)', () => {
    const { dir, file } = envFile('POLICY_SERVICE_TOKENS=\n');
    run(['configure', file]);
    writeFileSync(file, readFileSync(file, 'utf8') + 'STACK_CANARY_TOKEN=' + 'c4'.repeat(24) + '\n');
    const env = readFileSync(file, 'utf8');
    const names = ['MANAGED_SIGNER_KEK', 'NOTIFY_NSEC', 'NOTIFY_VAPID_PRIVATE_KEY', 'RELAY_ALLOWLIST_POLICY_TOKEN', 'POLICY_ADMIN_SECRET_KEY', 'ROTATION_WORKER_POLICY_TOKEN', 'ROTATION_MANAGED_SIGNER_TOKEN', 'STACK_CANARY_TOKEN'];
    const log = join(dir, 'compose.log');
    writeFileSync(log, names.map((n) => `managed-signer-1  | leaked ${value(env, n)}`).join('\n') + '\n');
    const scan = spawnSync('sh', [join(root, 'scripts/scan-logs.sh'), '--no-gitleaks', log, file], { encoding: 'utf8' });
    expect(scan.status).toBe(1);
    for (const n of names) expect(scan.stdout, n).toContain(`LEAK: the value of ${n} appears`);
  });
});

describe('scripts/stack-profiles.sh logged', () => {
  // `docker compose config --services`, as the stack with the profiles on answers it.
  function fakeDocker() {
    const dir = mkdtempSync(join(tmpdir(), 'fake-docker-'));
    writeFileSync(join(dir, 'docker'), '#!/bin/sh\nprintf "relay\\nmanaged-signer\\ntor\\n"\n');
    chmodSync(join(dir, 'docker'), 0o755);
    return { PATH: `${dir}:${process.env.PATH}` };
  }

  it('fails naming each service that wrote nothing to the log, and passes when all did', () => {
    const { dir } = envFile('');
    const log = join(dir, 'compose.log');
    writeFileSync(log, 'relay-1  | listening\ntor-1  | Tor 0.4.9.13 running on Linux\n');
    const partial = run(['logged', log], fakeDocker());
    expect(partial.status).toBe(1);
    expect(partial.out).toContain('managed-signer wrote nothing');
    expect(partial.out).not.toContain('relay wrote nothing');
    writeFileSync(log, readFileSync(log, 'utf8') + 'managed-signer-1  | {"msg":"metrics listening"}\n');
    expect(run(['logged', log], fakeDocker()).status).toBe(0);
  });
});

describe('the CI stack job runs and scans the optional profiles (NFR006-04)', () => {
  const ci = read('.github/workflows/ci.yml');
  const stack = ci.slice(ci.indexOf('\n  stack:'));
  it('configures the profiles, sends the canaries, requires every service in the log and scans it', () => {
    const steps = [
      'sh scripts/stack-profiles.sh configure',
      'sh scripts/wait-stack.sh',
      // FR023-13: the institutional check restarts the secure relay with event admission, then runs its test.
      'SECURE_RELAY_CONFIG=./infra/secure-relay/config.institutional.toml docker compose up -d secure-relay',
      'npx vitest run tests/interop/institutional.interop.test.ts',
      'sh scripts/stack-profiles.sh exercise',
      'docker compose logs --no-color > compose.log',
      'sh scripts/stack-profiles.sh logged compose.log',
      'sh scripts/scan-logs.sh compose.log .env',
    ];
    const at = steps.map((s) => stack.indexOf(s));
    expect(at.every((i) => i > 0), steps.filter((_, i) => at[i]! < 0).join(', ')).toBe(true);
    expect([...at].sort((a, b) => a - b)).toEqual(at);
  });

  it('waits for the services of the profiles that are on', () => {
    const wait = read('scripts/wait-stack.sh');
    for (const p of ['managed', 'push', 'institutional', 'tor']) expect(wait).toContain(`if has ${p}; then wait_for`);
  });

  it('shellchecks both scripts', () => {
    expect(ci).toMatch(/shellcheck -x [^\n]*scripts\/stack-profiles\.sh[^\n]*scripts\/wait-stack\.sh/);
  });
});
