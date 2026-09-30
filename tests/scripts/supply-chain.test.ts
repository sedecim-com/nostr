/**
 * OPS-13: supply-chain hygiene of CI and deployments. Actions pinned by commit SHA, third-party images by
 * digest (compose, CI services, Kubernetes and the ECR mirror), every downloaded tool checked against its
 * published checksum, Dependabot watching what it can update, and npm audit and CodeQL as gates.
 */
import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const root = new URL('../..', import.meta.url).pathname;
const read = (p: string) => readFileSync(join(root, p), 'utf8');
const workflows = readdirSync(join(root, '.github/workflows')).filter((f) => f.endsWith('.yml'));
const DIGEST = /@sha256:[0-9a-f]{64}\b/;

describe('supply chain (OPS-13)', () => {
  it('every action is pinned by commit SHA, with the version it is in a comment', () => {
    for (const wf of workflows) {
      for (const [line, ref] of read(`.github/workflows/${wf}`).matchAll(/uses:\s*(\S+)[^\n]*/g)) {
        if (ref!.startsWith('./')) continue; // a workflow of this repository
        expect(line, wf).toMatch(/@[0-9a-f]{40} # v\d+(\.\d+)*$/);
      }
    }
  });

  it('every third-party image is pinned by digest: compose, CI services, Kubernetes and the ECR mirror', () => {
    for (const file of ['docker-compose.yml', 'compose.tls.yml', ...workflows.map((w) => `.github/workflows/${w}`)]) {
      for (const [line] of read(file).matchAll(/^\s+image:\s*(\S+).*$/gm)) {
        if (/\$\{\{/.test(line)) continue; // an input of the workflow (buzz-upstream.yml, pinned by digest there)
        expect(line, file).toMatch(DIGEST);
      }
    }
    for (const file of ['deploy/k8s/base/kustomization.yaml', 'deploy/monitoring/kustomization.yaml']) {
      const images = read(file).split(/^images:\n/m)[1]!.split(/^\S/m)[0]!;
      for (const entry of images.split(/^\s+- name: /m).slice(1)) {
        if (entry.startsWith('acceso-nostr-')) continue; // built from this repository
        expect(entry, `${file}: ${entry.split('\n')[0]}`).toMatch(/digest: sha256:[0-9a-f]{64}/);
      }
    }
    const mirror = read('deploy/k8s/scripts/mirror-ecr-deps.sh');
    for (const [, src] of mirror.matchAll(/^\s+"([^|"]+)\|/gm)) if (!src!.includes('BUZZ_IMAGE')) expect(src, 'mirror-ecr-deps.sh').toMatch(DIGEST);
  });

  it('every downloaded tool is checked against its published checksum before it runs', () => {
    for (const wf of workflows) {
      const text = read(`.github/workflows/${wf}`);
      for (const [, out] of text.matchAll(/curl [^\n]*-o (\S+) "https:\/\/github\.com\/[^"]+\/releases\/download\/[^"]+"/g)) {
        expect(text, `${wf}: ${out}`).toMatch(new RegExp(`echo "\\$\\{\\w+_SHA256\\}  ${out!.replace('.', '\\.')}" \\| sha256sum -c -`));
      }
      for (const [, name] of text.matchAll(/^\s+(\w+)_SHA256: ([0-9a-f]*)$/gm)) expect(text, `${wf}: ${name}_SHA256`).toMatch(new RegExp(`${name}_SHA256: [0-9a-f]{64}$`, 'm'));
    }
  });

  it('Dependabot watches the actions, npm, both Dockerfiles and the compose images', () => {
    const cfg = read('.github/dependabot.yml');
    const updates = cfg.split(/^\s+- package-ecosystem: /m).slice(1).map((u) => `${u.split('\n')[0]} ${/directory: (\S+)/.exec(u)?.[1]}`);
    expect(updates).toEqual(expect.arrayContaining(['npm /', 'github-actions /', 'docker /', 'docker /infra/tor', 'docker-compose /']));
    // Buzz follows buzz-upstream.yml (ADR 0003). Dependabot names images without their registry: an ignore
    // written as ghcr.io/block/buzz matches nothing.
    expect(cfg).toMatch(/^\s+- dependency-name: block\/buzz$/m);
    expect(cfg).not.toMatch(/dependency-name: \S*\.\S+\//);
  });

  it('npm audit gates CI, and CodeQL gates the release', () => {
    const ci = read('.github/workflows/ci.yml');
    expect(ci).toContain('npm audit --omit=dev --audit-level=high');
    expect(ci).toContain('npm audit --audit-level=critical');
    const release = read('.github/workflows/release.yml');
    expect(release).toMatch(/node scripts\/release-gate\.mjs all /);
    expect(release).toMatch(/dod:[\s\S]*?security-events: read/);
    expect(read('scripts/release-gate.mjs')).toMatch(/codeql: \(\) => checkCodeql\(/);
  });
});
