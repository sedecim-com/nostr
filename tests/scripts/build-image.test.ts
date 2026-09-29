import { describe, expect, it } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const root = new URL('../..', import.meta.url).pathname;
const SERVICES = ['indexer', 'identity-service', 'policy-engine', 'blob-store', 'managed-signer', 'notification-gateway', 'continuity-vault', 'web', 'tor'];

const dryRun = (service: string, env: Record<string, string> = {}) =>
  spawnSync('sh', [join(root, 'scripts/build-image.sh'), service, 'out.tar'], {
    cwd: root,
    encoding: 'utf8',
    env: { ...process.env, DRY_RUN: '1', SOURCE_DATE_EPOCH: '1700000000', IMAGE_VERSION: 'v1.2.3', IMAGE_REVISION: 'deadbeef', ...env },
  });

/** "a b c" → map of flag → values, plus the positional context (last argument). */
function parse(stdout: string) {
  const args = stdout.trim().split('\n');
  const flags: Record<string, string[]> = {};
  const context = args.pop() ?? '';
  while (args.length) {
    const arg = args.shift() ?? '';
    const eq = arg.indexOf('=');
    if (eq > 0) (flags[arg.slice(0, eq)] ??= []).push(arg.slice(eq + 1));
    else if (args.length && !args[0]?.startsWith('--')) (flags[arg] ??= []).push(args.shift() ?? '');
    else (flags[arg] ??= []).push('');
  }
  return { flags, context };
}

describe('scripts/build-image.sh (NFR010-03)', () => {
  it('builds every service with the same context / target / SERVICE as docker-compose.yml', () => {
    const compose = readFileSync(join(root, 'docker-compose.yml'), 'utf8');
    for (const service of SERVICES) {
      const r = dryRun(service);
      expect(r.status, r.stderr).toBe(0);
      const { flags, context } = parse(r.stdout);
      const target = flags['--target']?.[0];
      const arg = flags['--build-arg']?.find((a) => a.startsWith('SERVICE='));
      const expected =
        service === 'tor' ? 'build: { context: ./infra/tor }' : service === 'web' ? 'build: { context: ., target: web }' : `build: { context: ., target: service, args: { SERVICE: ${service} } }`;
      expect(compose, service).toContain(expected);
      expect(context).toBe(service === 'tor' ? 'infra/tor' : '.');
      expect(target).toBe(service === 'tor' ? undefined : service === 'web' ? 'web' : 'service');
      expect(arg).toBe(service === 'tor' || service === 'web' ? undefined : `SERVICE=${service}`);
    }
  });

  it('is deterministic: fixed platform, no cache, no embedded attestations, commit timestamp, rewrite-timestamp', () => {
    const { flags } = parse(dryRun('indexer', { IMAGE_NAME: 'ghcr.io/o/nostr-indexer:v1.2.3' }).stdout);
    expect(flags['--platform']).toEqual(['linux/amd64']);
    expect(flags['--no-cache']).toEqual(['']);
    expect(flags['--provenance']).toEqual(['false']);
    expect(flags['--sbom']).toEqual(['false']);
    expect(flags['--build-arg']).toContain('SOURCE_DATE_EPOCH=1700000000');
    expect(flags['--output']).toEqual(['type=oci,dest=out.tar,rewrite-timestamp=true,name=ghcr.io/o/nostr-indexer:v1.2.3']);
    expect(flags['--label']).toEqual([
      'org.opencontainers.image.source=https://github.com/sedecim-com/nostr',
      'org.opencontainers.image.revision=deadbeef',
      'org.opencontainers.image.version=v1.2.3',
      'org.opencontainers.image.licenses=Apache-2.0',
    ]);
    // Without SOURCE_DATE_EPOCH it takes the committer time of HEAD.
    const ct = execFileSync('git', ['log', '-1', '--format=%ct'], { cwd: root, encoding: 'utf8' }).trim();
    const noEpoch = spawnSync('sh', [join(root, 'scripts/build-image.sh'), 'tor', 'x.tar'], { cwd: root, encoding: 'utf8', env: { ...process.env, DRY_RUN: '1', SOURCE_DATE_EPOCH: '' } });
    expect(noEpoch.stdout).toContain(`SOURCE_DATE_EPOCH=${ct}`);
  });

  it('rejects unknown services and missing arguments', () => {
    expect(dryRun('relay').status).toBe(2);
    expect(spawnSync('sh', [join(root, 'scripts/build-image.sh'), 'indexer'], { cwd: root, encoding: 'utf8' }).status).toBe(2);
  });

  it('release.yml and reproducible-images.yml build exactly these services through the script', () => {
    for (const wf of ['release.yml', 'reproducible-images.yml']) {
      const text = readFileSync(join(root, '.github/workflows', wf), 'utf8');
      expect(text, wf).toContain(`name: [${SERVICES.join(', ')}]`);
      expect(text, wf).toContain('sh scripts/build-image.sh "$NAME"');
      expect(text, wf).not.toContain('docker/build-push-action');
    }
    const script = readFileSync(join(root, 'scripts/build-image.sh'), 'utf8');
    expect(script).toContain(`SERVICES="${SERVICES.join(' ')}"`);
    expect(script).toMatch(/BUILDKIT_IMAGE=moby\/buildkit:v[\d.]+@sha256:[0-9a-f]{64}/);
  });

  it('Dockerfiles pin the frontend and every base image by digest, and every apk package by version', () => {
    for (const file of ['Dockerfile', 'infra/tor/Dockerfile']) {
      const text = readFileSync(join(root, file), 'utf8');
      expect(text.split('\n')[0], file).toMatch(/^# syntax=docker\/dockerfile:[\d.]+@sha256:[0-9a-f]{64}$/);
      const args = Object.fromEntries([...text.matchAll(/^ARG (\w+)=(\S+)$/gm)].map((m) => [m[1], m[2]]));
      for (const [, image = ''] of text.matchAll(/^FROM (\S+)/gm)) {
        const ref = image.replace(/^\$\{(\w+)\}$/, (_, a: string) => args[a] ?? image);
        const stage = /^[a-z-]+$/.test(ref) && new RegExp(`AS ${ref}$`, 'm').test(text);
        if (!stage) expect(ref, `${file}: ${image}`).toMatch(/^[\w./-]+:[\w.-]+@sha256:[0-9a-f]{64}$/);
      }
      const apk = /apk add --no-cache((?:[^\n]*\\\n)*[^\n]*)/.exec(text);
      if (apk) {
        const pkgs = (apk[1] ?? '').replace(/\\\n/g, ' ').split('&&')[0]!.trim().split(/\s+/);
        expect(pkgs.length).toBeGreaterThan(0);
        for (const p of pkgs) expect(p, file).toMatch(/^[a-z0-9-]+=\d[\w.]*-r\d+$/);
      }
    }
  });
});

describe('scripts/image-diff.sh (NFR010-03)', () => {
  /** Minimal OCI archive: one layer with the given files (name → [content, mtime]) and a config. */
  function ociArchive(dir: string, name: string, files: Record<string, [string, number]>, created: string) {
    const base = join(dir, name);
    const blobs = join(base, 'blobs/sha256');
    mkdirSync(blobs, { recursive: true });
    const put = (data: Buffer) => {
      const d = createHash('sha256').update(data).digest('hex');
      writeFileSync(join(blobs, d), data);
      return { digest: `sha256:${d}`, size: data.length };
    };
    const tree = join(dir, `${name}-tree`);
    mkdirSync(tree);
    for (const [f, [content, mtime]] of Object.entries(files)) {
      writeFileSync(join(tree, f), content);
      execFileSync('touch', ['-d', `@${mtime}`, join(tree, f)]);
    }
    const layerPath = join(dir, `${name}-layer.tar`);
    execFileSync('tar', ['--sort=name', '--owner=0', '--group=0', '-cf', layerPath, '-C', tree, '.']);
    const layer = put(readFileSync(layerPath));
    const config = put(Buffer.from(JSON.stringify({ architecture: 'amd64', os: 'linux', created, rootfs: { type: 'layers', diff_ids: [layer.digest] } })));
    const manifest = put(
      Buffer.from(
        JSON.stringify({
          schemaVersion: 2,
          mediaType: 'application/vnd.oci.image.manifest.v1+json',
          config: { mediaType: 'application/vnd.oci.image.config.v1+json', ...config },
          layers: [{ mediaType: 'application/vnd.oci.image.layer.v1.tar', ...layer }],
        }),
      ),
    );
    writeFileSync(join(base, 'index.json'), JSON.stringify({ schemaVersion: 2, manifests: [{ mediaType: 'application/vnd.oci.image.manifest.v1+json', ...manifest }] }));
    writeFileSync(join(base, 'oci-layout'), '{"imageLayoutVersion":"1.0.0"}');
    const out = join(dir, `${name}.tar`);
    execFileSync('tar', ['-cf', out, '-C', base, '.']);
    return out;
  }

  it('points at the config field and the layer files that differ', () => {
    const dir = mkdtempSync(join(tmpdir(), 'image-diff-'));
    const a = ociArchive(dir, 'a', { 'same.txt': ['x', 1_700_000_000], 'app.js': ['v1', 1_700_000_000] }, '2023-11-14T22:13:20Z');
    const b = ociArchive(dir, 'b', { 'same.txt': ['x', 1_700_000_000], 'app.js': ['v2', 1_800_000_000] }, '2027-01-15T08:00:00Z');
    const r = spawnSync('sh', [join(root, 'scripts/image-diff.sh'), a, b], { cwd: root, encoding: 'utf8' });
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toMatch(/-\s+"created": "2023-11-14T22:13:20Z"/);
    expect(r.stdout).toMatch(/\+\s+"created": "2027-01-15T08:00:00Z"/);
    expect(r.stdout).toMatch(/== capa 1: sha256:/);
    expect(r.stdout).toMatch(/\+.*\.\/app\.js/);
    expect(r.stdout).toMatch(/Files .*app\.js and .*app\.js differ/);
    expect(r.stdout).not.toMatch(/same\.txt differ/);
    expect(spawnSync('sh', [join(root, 'scripts/image-diff.sh'), a], { encoding: 'utf8' }).status).toBe(2);
  });
});
