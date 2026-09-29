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
    expect(JSON.parse(read('deploy/k8s/base/files/admin-config.json'))).toEqual(JSON.parse(read('infra/web/admin-config.json')));
    expect(read('deploy/k8s/components/institutional/files/secure-relay.config.toml')).toBe(read('infra/secure-relay/config.institutional.toml'));
  });

  it('the institutional secure relay config only adds the gRPC event admission (FR023-04)', () => {
    const inst = read('infra/secure-relay/config.institutional.toml');
    expect(inst.startsWith(read('infra/secure-relay/config.toml'))).toBe(true);
    expect(inst).toMatch(/^\[grpc\]\nevent_admission_server = "http:\/\/relay-allowlist:50051"$/m);
  });

  it('the stage admin console never allows the development key and points at the stage APIs', () => {
    const stage = JSON.parse(read('deploy/k8s/overlays/stage/files/admin-config.json')) as Record<string, unknown>;
    expect(stage.devLocalKey).not.toBe(true);
    expect(JSON.parse(read('infra/web/admin-config.json')).devLocalKey).not.toBe(true);
    expect(stage.policyEngineUrl).toBe('https://nostr-stage-policy.ai.acce.so');
    expect(stage.identityServiceUrl).toBe('https://nostr-stage-id.ai.acce.so');
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
    read('deploy/k8s/components/notification-gateway/notification-gateway.yaml'),
    read('deploy/k8s/components/continuity-vault/continuity-vault.yaml'),
    read('deploy/k8s/components/institutional/relay-allowlist.yaml'),
  ].join('\n---\n');
  const servicesBlock = compose.slice(compose.indexOf('\nservices:\n'), compose.indexOf('\nvolumes:\n'));
  const services = [...servicesBlock.matchAll(/^ {2}([a-z][a-z0-9-]*):$/gm)].map((m) => m[1]!);

  it('indexer-2 is only another replica of the indexer image', () => {
    expect(compose).toMatch(/\n  indexer-2:\n[\s\S]*?profiles: \[scale\][\s\S]*?SERVICE: indexer[\s\S]*?<<: \*indexer-env/);
  });

  it('reads the compose service list', () => {
    expect(services).toEqual(expect.arrayContaining(['relay', 'postgres', 'indexer', 'managed-signer', 'web']));
  });

  // indexer-2 is a second compose replica of `indexer` (NFR005-01); Kubernetes scales it with `replicas`.
  // tor and secure-relay-onion are the compose-only Sovereign Tor profile (docs/sovereign-tor.md).
  it.each(services.filter((s) => !['tor', 'secure-relay-onion', 'indexer-2'].includes(s)))('%s', (service) => {
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

describe('monitoring kustomization ships every rules file, test and dashboard (NFR004-02)', () => {
  const k = read('deploy/monitoring/kustomization.yaml');
  const rules = readdirSync(join(root, 'deploy/monitoring/prometheus/rules')).filter((f) => f.endsWith('.rules.yml'));
  const dashboards = readdirSync(join(root, 'deploy/monitoring/grafana/dashboards')).filter((f) => f.endsWith('.json'));
  it.each(rules)('%s', (f) => {
    expect(k).toContain(`- ${f}=prometheus/rules/${f}`);
    expect(readdirSync(join(root, 'deploy/monitoring/prometheus/tests'))).toContain(f.replace('.rules.yml', '.test.yml'));
  });
  it.each(dashboards)('%s', (f) => {
    expect(k).toContain(`- ${f}=grafana/dashboards/${f}`);
    const d = JSON.parse(read(`deploy/monitoring/grafana/dashboards/${f}`)) as { uid: string; panels: Array<{ id: number }> };
    expect(new Set(d.panels.map((p) => p.id)).size).toBe(d.panels.length);
  });
  it('scrapes the Nostr metrics exporter', () => {
    expect(read('deploy/monitoring/prometheus/prometheus.yml')).toMatch(/job_name: nostr-metrics\n[\s\S]*?targets: \['indexer:9464'\]/);
    expect(read('deploy/k8s/base/indexer.yaml')).toMatch(/name: METRICS_PORT\n\s+value: "9464"/);
  });
  // FR011-06: the only exporter (the indexer) has no outbox, so an outbox rule or panel could never show a problem.
  it('neither alerts on nor charts outbox metrics that no deployed process exports', () => {
    for (const f of rules) expect(read(`deploy/monitoring/prometheus/rules/${f}`), f).not.toMatch(/nostr_outbox_|outbox:/);
    for (const f of dashboards) expect(read(`deploy/monitoring/grafana/dashboards/${f}`), f).not.toMatch(/nostr_outbox_|outbox:/);
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

  it('uses RDS with verified TLS instead of the in-cluster Postgres (NFR001-03)', () => {
    const docs = out.stdout.split('\n---\n');
    expect(docs.some((d) => /^kind: StatefulSet$/m.test(d) && /^  name: postgres$/m.test(d))).toBe(false);
    expect(out.stdout).toMatch(/POSTGRES_URL_QUERY: \?sslmode=verify-full&sslrootcert=\/etc\/rds-ca\/rds-ca-us-east-1\.pem/);
    const withDb = docs.filter((d) => /name: DATABASE_URL/.test(d));
    expect(withDb.length).toBe(5);
    for (const d of withDb) {
      expect(d).toMatch(/@\$\(POSTGRES_HOST\):5432\/\$\((PLATFORM_DB|POSTGRES_DB)\)\$\(POSTGRES_URL_QUERY\)/);
      expect(d).toMatch(/mountPath: \/etc\/rds-ca/);
    }
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
