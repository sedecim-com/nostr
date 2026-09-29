import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
// @ts-expect-error plain ESM script without types
import { checkImage, installedPackages } from '../../scripts/image-sbom-check.mjs';

const root = new URL('../..', import.meta.url).pathname;
/** A component as syft writes it in CycloneDX: purl and the path it was found at. */
const npm = (name: string, version: string, path: string) => ({
  name,
  version,
  purl: `pkg:npm/${name.replace('@', '%40')}@${version}`,
  properties: [
    { name: 'syft:package:foundBy', value: 'javascript-package-cataloger' },
    { name: 'syft:location:0:path', value: path },
  ],
});
const sbom = {
  components: [
    npm('tsx', '4.23.15', '/app/node_modules/tsx/package.json'),
    npm('@scope/lib', '1.0.0', '/app/node_modules/@scope/lib/package.json'),
    npm('nested', '2.0.0', '/app/node_modules/tsx/node_modules/nested/package.json'),
    // Not installed packages of the app: a subpath export, the lock itself, a workspace, npm of the base image.
    npm('@aws-amplify/analytics/kinesis', 'UNKNOWN', '/app/node_modules/@aws-amplify/analytics/kinesis/package.json'),
    npm('vitest', '5.0.1', '/app/package-lock.json'),
    npm('@sedecim/profiles', '0.1.0', '/app/packages/profiles/package.json'),
    npm('@npmcli/agent', '3.0.0', '/usr/local/lib/node_modules/npm/node_modules/@npmcli/agent/package.json'),
    { name: 'musl', version: '1.2.5-r10', purl: 'pkg:apk/alpine/musl@1.2.5-r10', properties: [{ name: 'syft:location:0:path', value: '/lib/apk/db/installed' }] },
  ],
};

// NFR010-04: the SBOM of each image, and no devDependency in its runtime.
describe('what the image carries under /app', () => {
  it('takes the installed npm packages, by their package-lock path, and nothing else', () => {
    expect(Object.fromEntries(installedPackages(sbom))).toEqual({
      'node_modules/tsx': 'tsx@4.23.15',
      'node_modules/@scope/lib': '@scope/lib@1.0.0',
      'node_modules/tsx/node_modules/nested': 'nested@2.0.0',
    });
  });

  it('fails on a dev-only package and on one the lock does not have there; optional and devOptional ones pass', () => {
    const lock = {
      packages: {
        'node_modules/tsx': { version: '4.23.15' },
        'node_modules/@scope/lib': { version: '1.0.0', dev: true },
        'node_modules/tsx/node_modules/nested': { version: '2.0.0', devOptional: true },
      },
    };
    expect(checkImage(sbom, lock)).toEqual({ problems: ['@scope/lib@1.0.0 en /app/node_modules/@scope/lib es solo de desarrollo (devDependency)'], checked: 3 });
    const { 'node_modules/tsx/node_modules/nested': _nested, ...partial } = lock.packages;
    expect(checkImage(sbom, { packages: { ...partial, 'node_modules/@scope/lib': { version: '1.0.0' } } }).problems).toEqual([
      'nested@2.0.0 en /app/node_modules/tsx/node_modules/nested no está en package-lock.json',
    ]);
  });

  it('the CLI exits 1 with the list, 0 when clean, 2 without a file', () => {
    const dir = mkdtempSync(join(tmpdir(), 'image-sbom-'));
    writeFileSync(join(dir, 'sbom.json'), JSON.stringify(sbom));
    writeFileSync(join(dir, 'dev.json'), JSON.stringify({ packages: { 'node_modules/tsx': {}, 'node_modules/@scope/lib': { dev: true }, 'node_modules/tsx/node_modules/nested': {} } }));
    writeFileSync(join(dir, 'prod.json'), JSON.stringify({ packages: { 'node_modules/tsx': {}, 'node_modules/@scope/lib': {}, 'node_modules/tsx/node_modules/nested': {} } }));
    const run = (...args: string[]) => spawnSync(process.execPath, [join(root, 'scripts/image-sbom-check.mjs'), ...args], { encoding: 'utf8' });
    const bad = run(join(dir, 'sbom.json'), '--lock', join(dir, 'dev.json'));
    expect(bad.status).toBe(1);
    expect(bad.stderr).toContain('@scope/lib@1.0.0 en /app/node_modules/@scope/lib es solo de desarrollo');
    const good = run(join(dir, 'sbom.json'), '--lock', join(dir, 'prod.json'));
    expect(good.status, good.stderr).toBe(0);
    expect(good.stdout).toContain('3 paquetes npm en /app, ninguno de desarrollo');
    expect(run().status).toBe(2);
  });
});

describe('images without devDependencies, and their SBOM in CI and in the release', () => {
  it('the service image copies the app from an install without devDependencies; tsx, which runs it, is a dependency', () => {
    const docker = readFileSync(join(root, 'Dockerfile'), 'utf8');
    const stage = (name: string) => docker.split(/^FROM /m).find((s) => new RegExp(` AS ${name}\\n`).test(s)) ?? '';
    expect(stage('prod-deps')).toContain('RUN npm ci --omit=dev --ignore-scripts');
    expect(stage('service')).toContain('COPY --from=prod-deps /app /app');
    expect(stage('service')).not.toContain('--from=deps');
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    expect(pkg.dependencies.tsx).toBeDefined();
    expect(pkg.devDependencies.tsx).toBeUndefined();
    expect(JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8')).packages['node_modules/tsx'].dev).toBeUndefined();
  });

  it('reproducible-images.yml and release.yml make and check the SBOM of every image; the release attests it, and the Buzz one', () => {
    for (const wf of ['release.yml', 'reproducible-images.yml']) {
      const text = readFileSync(join(root, '.github/workflows', wf), 'utf8');
      expect(text, wf).toMatch(/sh scripts\/image-sbom\.sh oci-archive:\S+ "sbom-\$NAME\.cdx\.json"\n\s+node scripts\/image-sbom-check\.mjs "sbom-\$NAME\.cdx\.json"/);
    }
    const release = readFileSync(join(root, '.github/workflows/release.yml'), 'utf8');
    expect(release).toContain('sbom-path: sbom-${{ matrix.name }}.cdx.json');
    expect(release).not.toContain('matrix.sbom');
    expect(release).toContain('sh scripts/image-sbom.sh "registry:$buzz" sbom-buzz.cdx.json');
    expect(release).toContain('sbom-path: release/sbom-buzz.cdx.json');
    const verify = readFileSync(join(root, 'scripts/verify-release.sh'), 'utf8');
    expect(verify).toContain('--predicate-type https://cyclonedx.org/bom');
    expect(verify).toContain('buzz-image.txt');
  });

  it('image-sbom.sh pins syft by version and checksum, and rejects a source that is not an image', () => {
    const script = readFileSync(join(root, 'scripts/image-sbom.sh'), 'utf8');
    expect(script).toMatch(/^SYFT_VERSION=\d+\.\d+\.\d+$/m);
    expect(script).toMatch(/^SYFT_SHA256=[0-9a-f]{64}$/m);
    for (const args of [[], ['dir:.', 'out.json'], ['registry:ghcr.io/block/buzz:latest', 'out.json'], ['oci-archive:image.tar']]) {
      expect(spawnSync('sh', [join(root, 'scripts/image-sbom.sh'), ...args], { encoding: 'utf8' }).status, args.join(' ')).toBe(2);
    }
  });
});
