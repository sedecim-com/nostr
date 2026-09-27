/**
 * NFR001-03: scripts/rds-failover-test.sh against a fake `aws` CLI (no AWS here). The fake flips the primary
 * AZ on reboot --force-failover and takes the "database" down for ~2 s; the script must measure that gap.
 */
import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const root = new URL('../..', import.meta.url).pathname;
const script = join(root, 'scripts/rds-failover-test.sh');

const FAKE_AWS = `#!/usr/bin/env bash
# Fake aws CLI for the failover drill. State lives in $FAKE_STATE.
set -eu
args="$*"
case "$args" in
  *"describe-db-instances"*)
    if [ -e "$FAKE_STATE/failed-over" ] && [ -z "\${FAKE_NO_FLIP:-}" ]; then printf 'available\\tTrue\\tus-east-1b\\tus-east-1a\\n'
    else printf 'available\\tTrue\\tus-east-1a\\tus-east-1b\\n'; fi ;;
  *"reboot-db-instance"*"--force-failover"*)
    touch "$FAKE_STATE/failed-over" "$FAKE_STATE/down"
    echo "$args" >> "$FAKE_STATE/calls"
    ( sleep 2; rm -f "$FAKE_STATE/down" ) > /dev/null 2>&1 &
    echo '{}' ;;
  *"wait db-instance-available"*) sleep 1 ;;
  *"describe-events"*) printf '2026-09-27T00:00:00Z\\tMulti-AZ instance failover started.\\n' ;;
  *) echo "fake aws: unexpected $args" >&2; exit 3 ;;
esac
`;

function fakeEnv(extra: Record<string, string> = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'fake-aws-'));
  writeFileSync(join(dir, 'aws'), FAKE_AWS);
  chmodSync(join(dir, 'aws'), 0o755);
  return { dir, env: { ...process.env, PATH: `${dir}:${process.env.PATH}`, FAKE_STATE: dir, ...extra } };
}

const run = (args: string[], env: NodeJS.ProcessEnv) => spawnSync('bash', [script, ...args], { encoding: 'utf8', env, timeout: 60_000 });

describe('scripts/rds-failover-test.sh', () => {
  it('dry-run prints the plan without calling AWS', () => {
    const { dir, env } = fakeEnv();
    const r = run(['--db-instance-id', 'acceso-nostr-stage-postgres', '--health-url', 'https://example.invalid/health'], env);
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toMatch(/reboot-db-instance --db-instance-identifier acceso-nostr-stage-postgres --force-failover/);
    expect(r.stdout).toMatch(/dry-run/);
    expect(() => readFileSync(join(dir, 'calls'))).toThrow();
  });

  it('validates its arguments', () => {
    const { env } = fakeEnv();
    expect(run(['--health-url', 'x'], env).stderr).toMatch(/--db-instance-id/);
    expect(run(['--db-instance-id', 'x'], env).stderr).toMatch(/una sonda/);
    expect(run(['--db-instance-id', 'x', '--psql', '--health-url', 'y'], env).stderr).toMatch(/una sonda/);
  });

  it('forces the failover, measures the downtime and checks the AZ change', () => {
    const { dir, env } = fakeEnv();
    const report = join(dir, 'report.json');
    const r = run(['--db-instance-id', 'db1', '--probe-cmd', `test ! -e ${dir}/down`, '--max-downtime', '30', '--timeout', '40', '--report', report, '--yes'], env);
    expect(r.status, r.stdout + r.stderr).toBe(0);
    expect(r.stdout).toMatch(/us-east-1a -> us-east-1b/);
    expect(readFileSync(join(dir, 'calls'), 'utf8')).toMatch(/--db-instance-identifier db1 --force-failover/);
    const rep = JSON.parse(readFileSync(report, 'utf8')) as { downtime_ms: number; passed: boolean; az_after: string };
    expect(rep.passed).toBe(true);
    expect(rep.az_after).toBe('us-east-1b');
    expect(rep.downtime_ms).toBeGreaterThanOrEqual(1000);
    expect(rep.downtime_ms).toBeLessThan(10_000);
  });

  it('fails when the primary does not move or the downtime exceeds the limit', () => {
    const { dir, env } = fakeEnv({ FAKE_NO_FLIP: '1' });
    const r = run(['--db-instance-id', 'db1', '--probe-cmd', `test ! -e ${dir}/down`, '--max-downtime', '1', '--timeout', '40', '--yes'], env);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/sigue en us-east-1a/);
    expect(r.stderr).toMatch(/caída de \d+ ms > 1s/);
  });
});
