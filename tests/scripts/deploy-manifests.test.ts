/**
 * NFR001-01 / NFR001-02: the Kubernetes manifests and the monitoring config stay in sync with
 * docker-compose.yml (pins, copied config files, service list, probed endpoints).
 * With kubectl in PATH (or KUBECTL=/path) the stage overlay is also rendered and checked.
 */
import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const root = new URL('../..', import.meta.url).pathname;
const read = (p: string) => readFileSync(join(root, p), 'utf8');

const compose = read('docker-compose.yml');
const base = read('deploy/k8s/base/kustomization.yaml');
const pinImage = /^BUZZ_IMAGE=(.+)$/m.exec(read('infra/buzz/PIN'))![1]!;

/** digest of an `images` entry in a kustomization. */
function kustomizeImage(kustomization: string, name: string) {
  const m = new RegExp(`- name: ${name}\\n\\s+newName: (\\S+)\\n\\s+digest: (sha256:[0-9a-f]{64})`).exec(kustomization);
  return m ? `${m[1]}@${m[2]}` : undefined;
}
const composeDefault = (variable: string) => new RegExp(`\\$\\{${variable}:-([^}]+)\\}`).exec(compose)?.[1];

describe('deploy/k8s pins (same images as docker-compose.yml)', () => {
  it('Buzz is pinned by the digest of infra/buzz/PIN', () => {
    expect(pinImage).toMatch(/@sha256:[0-9a-f]{64}$/);
    expect(kustomizeImage(base, 'buzz')).toBe(pinImage);
    expect(composeDefault('BUZZ_IMAGE')).toBe(pinImage);
  });

  it('SeaweedFS and the secure relay use the compose digests', () => {
    expect(kustomizeImage(base, 'seaweedfs')).toBe(composeDefault('SEAWEEDFS_IMAGE'));
    expect(kustomizeImage(base, 'secure-relay')).toBe(composeDefault('SECURE_RELAY_IMAGE'));
  });

  it('the ECR mirror copies exactly the pinned digests', () => {
    const mirror = read('deploy/k8s/scripts/mirror-ecr-deps.sh');
    for (const name of ['seaweedfs', 'secure-relay']) expect(mirror).toContain(kustomizeImage(base, name)!);
    // Buzz comes straight from infra/buzz/PIN.
    expect(mirror).toContain('infra/buzz/PIN');
  });
});

describe('deploy/k8s copies of the compose config files', () => {
  it('are identical to their sources', () => {
    expect(read('deploy/k8s/base/files/01-platform-db.sh')).toBe(read('infra/postgres/01-platform-db.sh'));
    expect(read('deploy/k8s/base/files/secure-relay.config.toml')).toBe(read('infra/secure-relay/config.toml'));
    expect(JSON.parse(read('deploy/k8s/base/files/web-config.json'))).toEqual(JSON.parse(read('infra/web/config.json')));
  });

  it('the stage secure relay config only changes relay_url', () => {
    const strip = (s: string) => s.replace(/^relay_url = .*$/m, '');
    expect(strip(read('deploy/k8s/overlays/stage/files/secure-relay.config.toml'))).toBe(strip(read('infra/secure-relay/config.toml')));
    expect(read('deploy/k8s/overlays/stage/files/secure-relay.config.toml')).toMatch(/^relay_url = "wss:\/\/nostr-stage-secure\.ai\.acce\.so\/"$/m);
  });
});

describe('every compose service has a Kubernetes workload', () => {
  const manifests = [
    ...readdirSync(join(root, 'deploy/k8s/base')).filter((f) => f.endsWith('.yaml')).map((f) => read(`deploy/k8s/base/${f}`)),
    read('deploy/k8s/components/managed-signer/managed-signer.yaml'),
  ].join('\n---\n');
  const servicesBlock = compose.slice(compose.indexOf('\nservices:\n'), compose.indexOf('\nvolumes:\n'));
  const services = [...servicesBlock.matchAll(/^ {2}([a-z][a-z0-9-]*):$/gm)].map((m) => m[1]!);

  it('reads the compose service list', () => {
    expect(services).toEqual(expect.arrayContaining(['relay', 'postgres', 'indexer', 'managed-signer', 'web']));
  });

  it.each(services.filter((s) => s !== 'tor'))('%s', (service) => {
    expect(manifests).toMatch(new RegExp(`kind: (Deployment|StatefulSet|Job)\\nmetadata:\\n  name: ${service}\\n`));
  });

  it('secrets never live in the manifests (only secretKeyRef to acceso-nostr-secrets)', () => {
    expect(manifests).not.toMatch(/kind: Secret\b/);
    expect(manifests).not.toMatch(/PASSWORD\n\s+value:/);
  });
});

describe('monitoring probes every HTTP service (NFR001-02)', () => {
  const prometheus = read('deploy/monitoring/prometheus/prometheus.yml');
  it.each(['relay', 'secure-relay', 'indexer', 'identity-service', 'policy-engine', 'blob-store', 'web', 'managed-signer', 'edge'])('%s', (service) => {
    expect(prometheus).toMatch(new RegExp(`labels: \\{ service: ${service}, module: http_`));
  });
});

const kubectl = process.env.KUBECTL ?? 'kubectl';
const hasKubectl = spawnSync(kubectl, ['version', '--client'], { encoding: 'utf8' }).status === 0;

describe.skipIf(!hasKubectl)('kubectl kustomize deploy/k8s/overlays/stage', () => {
  const out = spawnSync(kubectl, ['kustomize', join(root, 'deploy/k8s/overlays/stage')], { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });

  it('renders', () => {
    expect(out.status, out.stderr).toBe(0);
  });

  it('pulls every image from the Sedecim ECR and keeps the Buzz digest', () => {
    const images = [...out.stdout.matchAll(/image: (\S+)/g)].map((m) => m[1]!);
    expect(images.length).toBeGreaterThan(10);
    for (const image of images) expect(image).toMatch(/^212568716371\.dkr\.ecr\.us-east-1\.amazonaws\.com\/acceso-nostr-/);
    expect(images).toContain(`212568716371.dkr.ecr.us-east-1.amazonaws.com/acceso-nostr-buzz@${pinImage.split('@')[1]}`);
  });

  it('exposes only the edge, on the NodePort registered in Terraform', () => {
    expect([...out.stdout.matchAll(/type: NodePort/g)]).toHaveLength(1);
    expect(out.stdout).toMatch(/nodePort: 31810/);
    expect(read('deploy/terraform/modules/acceso-nostr/variables.tf')).toMatch(/default\s+= 31810/);
  });

  it('runs every pod as non-root without privilege escalation', () => {
    const pods = out.stdout.split('\n---\n').filter((d) => /^kind: (Deployment|StatefulSet|Job)$/m.test(d));
    expect(pods.length).toBeGreaterThan(10);
    for (const doc of pods) {
      expect(doc, doc.slice(0, 200)).toMatch(/runAsNonRoot: true/);
      expect(doc).toMatch(/allowPrivilegeEscalation: false/);
      expect(doc).not.toMatch(/allowPrivilegeEscalation: true/);
    }
  });
});
