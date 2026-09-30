/**
 * FR020-06: the sovereign CLI as a service of the compose `tor` profile, `docker compose run --rm sovereign …` with
 * TOR_SOCKS=tor:9050. What docker-compose.yml, the Dockerfile and the scripts say about it, the CLI run with the
 * environment and the secret files the service gives it, the file selection of its image run on a fixture tree, and
 * the sandbox checks of the tor-profile job against configurations they must reject. Without Docker: the compose job
 * validates the model, and the tor-profile job builds the image and runs the service against the real onion services.
 */
import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, readlinkSync, symlinkSync, writeFileSync } from 'node:fs';
import { builtinModules } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { parse } from 'yaml';
// @ts-expect-error plain ESM script without types
import { inspectChecks, insideChecks } from '../../scripts/sovereign-sandbox.mjs';

type Check = { ok: boolean; what: string };
type Service = Record<string, unknown> & { environment?: Record<string, string>; networks?: unknown; volumes?: unknown };
type Compose = { services: Record<string, Service>; volumes: Record<string, unknown>; networks: Record<string, unknown>; secrets: Record<string, unknown> };

const root = new URL('../..', import.meta.url).pathname;
const read = (p: string) => readFileSync(join(root, p), 'utf8');
const compose = parse(read('docker-compose.yml'), { merge: true }) as Compose;
const sovereign = compose.services.sovereign!;
const dockerfile = read('Dockerfile');
const SECRET_VARS = ['SOVEREIGN_PASSPHRASE', 'SOVEREIGN_BACKUP_PASSWORD', 'SOVEREIGN_POLICY_BEARER', 'SOVEREIGN_REVOCATION_TOKEN'];

/** One stage of the Dockerfile, from its FROM to the next FROM. */
function stage(name: string): string {
  const start = dockerfile.search(new RegExp(`^FROM \\S+ AS ${name}$`, 'm'));
  if (start < 0) return '';
  const rest = dockerfile.slice(start);
  const next = rest.slice(1).search(/^FROM /m);
  return next < 0 ? rest : rest.slice(0, next + 1);
}

/** The CLI as the image runs it (node --import tsx), with only the environment given. */
function cli(args: string[], env: Record<string, string>) {
  const clean = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('SOVEREIGN_') && k !== 'TOR_SOCKS'));
  return spawnSync(process.execPath, ['--import', 'tsx', join(root, 'apps/sovereign-client/src/cli.ts'), ...args], { cwd: root, encoding: 'utf8', env: { ...clean, ...env } });
}
const onion = `servicerelay${'a'.repeat(44)}.onion`;
const failed = (checks: Check[]) => checks.filter((c) => !c.ok).map((c) => c.what.replace(/ \(found: .*\)$/, ''));

describe('the sovereign CLI as a service of the compose tor profile (FR020-06)', () => {
  it('is `docker compose run --rm sovereign …` with TOR_SOCKS=tor:9050: a one-off container of the tor profile', () => {
    expect(sovereign.profiles).toEqual(['tor']);
    expect(sovereign.build).toEqual({ context: '.', target: 'sovereign' });
    expect(sovereign.environment).toEqual({ TOR_SOCKS: 'tor:9050' });
    expect(sovereign.depends_on).toEqual(['tor']);
    // One command and it ends: nothing restarts it, and an init process hands it Ctrl-C.
    expect(sovereign).not.toHaveProperty('restart');
    expect(sovereign.init).toBe(true);
    const s = stage('sovereign');
    expect(s).toContain('ENTRYPOINT ["node", "--import", "tsx", "apps/sovereign-client/src/cli.ts"]\n');
    expect(s).toContain('CMD ["maturity"]\n');
    // `service` stays the last stage, the one a build without --target makes.
    expect([...dockerfile.matchAll(/^FROM \S+ AS (\S+)$/gm)].map((m) => m[1]).at(-1)).toBe('service');
  });

  it('reaches nothing but tor: its only network is internal and shared with tor alone, with no DNS, hosts or proxy of its own', () => {
    expect(sovereign.networks).toEqual(['tor-socks']);
    expect(compose.networks['tor-socks']).toEqual({ driver: 'bridge', internal: true });
    const onTorSocks = Object.entries(compose.services).filter(([, s]) => JSON.stringify(s.networks ?? []).includes('tor-socks'));
    expect(onTorSocks.map(([name]) => name).sort()).toEqual(['sovereign', 'tor']);
    for (const key of ['network_mode', 'dns', 'dns_search', 'dns_opt', 'extra_hosts', 'links', 'external_links', 'env_file']) expect(sovereign, key).not.toHaveProperty(key);
    expect(Object.keys(sovereign.environment ?? {}).filter((k) => /proxy/i.test(k))).toEqual([]);
    // What it reaches on tor: SOCKS alone, for the private ranges Docker gives its networks, one circuit per persona.
    const torrc = read('infra/tor/torrc');
    expect(torrc).toMatch(/^SocksPort 0\.0\.0\.0:9050 .*\bIsolateSOCKSAuth\b/m);
    for (const range of ['172.16.0.0/12', '10.0.0.0/8', '192.168.0.0/16']) expect(torrc).toContain(`SocksPolicy accept ${range}\n`);
    expect(torrc).toMatch(/^SocksPolicy reject \*$/m);
    expect(torrc).not.toMatch(/^(ControlPort|DNSPort|TransPort|NATDPort|HTTPTunnelPort)\b/m);
  });

  it('runs unprivileged and publishes nothing: no capabilities, no new privileges, read-only root filesystem, non-root user', () => {
    expect(sovereign.read_only).toBe(true);
    expect(sovereign.cap_drop).toEqual(['ALL']);
    expect(sovereign.security_opt).toEqual(['no-new-privileges:true']);
    expect(sovereign.tmpfs).toEqual(['/tmp']);
    for (const key of ['ports', 'expose', 'privileged', 'cap_add', 'user', 'devices', 'pid', 'ipc', 'userns_mode', 'volumes_from', 'group_add', 'sysctls']) expect(sovereign, key).not.toHaveProperty(key);
    const s = stage('sovereign');
    expect(s).toMatch(/^RUN addgroup -S app && adduser -S app -G app /m);
    expect([...s.matchAll(/^USER (\S+)$/gm)].map((m) => m[1])).toEqual(['app']);
    expect(s).not.toMatch(/^EXPOSE /m);
  });

  it('writes only to its own volume, sovereign-data, which scripts/backup.sh leaves out on purpose', () => {
    expect(sovereign.volumes).toEqual(['sovereign-data:/data']);
    expect(compose.volumes).toHaveProperty('sovereign-data');
    const others = Object.entries(compose.services).filter(([name, s]) => name !== 'sovereign' && JSON.stringify(s.volumes ?? []).includes('sovereign-data'));
    expect(others).toEqual([]);
    expect(stage('sovereign')).toMatch(/^ENV .*\bSOVEREIGN_DATA_DIR=\/data\/sovereign\b/m);
    // Its personas are not the operator's data: the stack backup does not copy them, and says why.
    const backup = read('scripts/backup.sh');
    expect(backup).not.toMatch(/\bsovereign:\/data/);
    expect(backup).toMatch(/^# Nor is sovereign-data \(FR020-06\)/m);
    expect(read('docs/runbooks/restore.md')).toMatch(/^\| Personas del CLI soberano \(FR020-06\) \|[^\n]*`sovereign-data`[^\n]*No lo copia `scripts\/backup\.sh`[^\n]*`backup export`/m);
  });

  it('takes the passphrase and the backup password as secret files, never as variables, and puts no secret in the image', () => {
    expect(sovereign.secrets).toEqual(['sovereign_passphrase', 'sovereign_backup_password']);
    expect(compose.secrets).toEqual({
      sovereign_passphrase: { file: '${SOVEREIGN_PASSPHRASE_FILE:-/dev/null}' },
      sovereign_backup_password: { file: '${SOVEREIGN_BACKUP_PASSWORD_FILE:-/dev/null}' },
    });
    for (const k of SECRET_VARS) expect(sovereign.environment, k).not.toHaveProperty(k);
    // compose interpolates the paths of the files, never a secret itself.
    expect(read('docker-compose.yml')).not.toMatch(/\$\{SOVEREIGN_(PASSPHRASE|BACKUP_PASSWORD|POLICY_BEARER|REVOCATION_TOKEN)(:?[-?][^}]*)?\}/);
    // The image: no ARG, and ENV only settings and the path of the secret.
    expect(stage('sovereign-files') + stage('sovereign')).not.toMatch(/^ARG /m);
    const env = [...stage('sovereign').matchAll(/^ENV (.+)$/gm)].flatMap((m) => m[1]!.split(/\s+/));
    expect(env.sort()).toEqual(['NODE_ENV=production', 'SOVEREIGN_DATA_DIR=/data/sovereign', 'SOVEREIGN_PASSPHRASE_FILE=/run/secrets/sovereign_passphrase']);
    // No .env and no local store from anywhere in the build context, and the passphrase never goes to .env.
    const ignored = read('.dockerignore').split('\n');
    for (const pattern of ['**/.env', '**/.data']) expect(ignored).toContain(pattern);
    for (const file of ['.env.example', 'scripts/init-env.sh']) expect(read(file), file).not.toMatch(/SOVEREIGN_(PASSPHRASE|BACKUP_PASSWORD)\b/);
    // Key material reaches the CLI as files as well: no option or variable of it carries a key or a bunker URL.
    const cliSource = read('apps/sovereign-client/src/cli.ts');
    for (const flag of ['--key-file', '--bunker-file', '--backup', '--password-file']) expect(cliSource).toContain(`opt('${flag}')`);
    expect(cliSource).not.toMatch(/opt\('--(nsec|key|bunker|secret|password|passphrase)'\)/);
    expect([...cliSource.matchAll(/process\.env\.(\w+)/g)].map((m) => m[1]!).filter((v) => /NSEC|KEY|SECRET|BUNKER/.test(v))).toEqual([]);
  });

  it('the CLI reads the passphrase from SOVEREIGN_PASSPHRASE_FILE, the only source when it is set', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sovereign-service-'));
    const passphrase = join(dir, 'passphrase');
    writeFileSync(passphrase, 'service-pass\n', { mode: 0o600 });
    const base = { SOVEREIGN_DATA_DIR: join(dir, 'data'), TOR_SOCKS: 'tor:9050' };
    const created = cli(['persona', 'create', '--label', 'Servicio', '--relay', `ws://${onion}`, '--tor'], { ...base, SOVEREIGN_PASSPHRASE_FILE: passphrase });
    expect(created.status, created.stderr).toBe(0);
    const id = (JSON.parse(created.stdout) as { id: string }).id;
    // The file opens the stores whatever SOVEREIGN_PASSPHRASE says; that variable alone does not.
    const withFile = cli(['persona', 'list'], { ...base, SOVEREIGN_PASSPHRASE_FILE: passphrase, SOVEREIGN_PASSPHRASE: 'another' });
    expect(withFile.status, withFile.stderr).toBe(0);
    expect(withFile.stdout).toContain(id);
    const withVariable = cli(['persona', 'list'], { ...base, SOVEREIGN_PASSPHRASE: 'another' });
    expect(withVariable.status).toBe(1);
    expect(withVariable.stderr).toContain('error: wrong passphrase for encrypted store');
    // The trailing newline of the file is not part of the passphrase.
    expect(cli(['persona', 'list'], { ...base, SOVEREIGN_PASSPHRASE: 'service-pass' }).stdout).toContain(id);
    // /dev/null is the compose default without SOVEREIGN_PASSPHRASE_FILE: the CLI says the file is empty.
    const empty = cli(['persona', 'list'], { ...base, SOVEREIGN_PASSPHRASE_FILE: '/dev/null', SOVEREIGN_PASSPHRASE: 'service-pass' });
    expect(empty.status).toBe(1);
    expect(empty.stderr).toContain('error: empty passphrase file: /dev/null (SOVEREIGN_PASSPHRASE_FILE)');
    // The default command of the image needs no passphrase.
    const maturity = cli(['maturity'], { ...base, SOVEREIGN_PASSPHRASE_FILE: '/dev/null' });
    expect(maturity.status, maturity.stderr).toBe(0);
    expect(maturity.stdout).toMatch(/^\S.* +sovereign-tor: /m);
  }, 60_000);

  it('with the environment of the service and no tor to reach, a Tor persona sends nothing: the message waits', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sovereign-service-'));
    writeFileSync(join(dir, 'passphrase'), 'service-pass\n', { mode: 0o600 });
    // Here `tor` resolves to nothing, as in the container when the tor service is stopped: nothing leaves.
    const env = { SOVEREIGN_DATA_DIR: join(dir, 'data'), SOVEREIGN_PASSPHRASE_FILE: join(dir, 'passphrase'), TOR_SOCKS: 'tor:9050' };
    const created = cli(['persona', 'create', '--label', 'Servicio', '--relay', `ws://${onion}`, '--tor'], env);
    expect(created.status, created.stderr).toBe(0);
    expect(created.stderr).toMatch(/^relays de DM \(kind 10050\): QUEUED — No enviado: red de privacidad no disponible$/m);
    const sent = cli(['channel', 'send', '--persona', (JSON.parse(created.stdout) as { id: string }).id, '--group', 'sala', 'sin tor'], env);
    expect(sent.status, sent.stderr).toBe(0);
    expect(sent.stdout).toMatch(/^QUEUED — No enviado: red de privacidad no disponible \(op [0-9a-f]{32}\)$/m);
  }, 60_000);

  it('its image takes the production closure of the CLI and nothing else: the selection of the Dockerfile on a fixture tree', () => {
    const files = stage('sovereign-files');
    expect(files).toMatch(/^FROM prod-deps AS sovereign-files$/m);
    expect(files).toContain('RUN npm ls --omit=dev --all --parseable --workspace=@sedecim/sovereign-client --include-workspace-root > /tmp/closure || true\n');
    const s = stage('sovereign');
    expect(s).toMatch(/^FROM \$\{NODE_IMAGE\} AS sovereign$/m);
    expect(dockerfile).toMatch(/^ARG NODE_IMAGE=node:[\w.-]+@sha256:[0-9a-f]{64}$/m);
    expect([...s.matchAll(/^COPY (.+)$/gm)].map((m) => m[1])).toEqual(['--from=sovereign-files /out /app', 'infra/web/flags.json infra/web/flags.json']);
    expect(read('apps/sovereign-client/src/cli.ts')).toContain("process.env.SOVEREIGN_FLAGS ?? 'infra/web/flags.json'");
    const script = /^RUN node - \/app \/out \/tmp\/closure <<'EOF'\n([\s\S]*?)\nEOF$/m.exec(files)?.[1];
    expect(script).toBeDefined();

    // A tree laid out as npm leaves /app in prod-deps, and what npm ls lists of it.
    const dir = mkdtempSync(join(tmpdir(), 'sovereign-files-'));
    const app = join(dir, 'app');
    const put = (path: string, content = '{}') => {
      mkdirSync(dirname(join(app, path)), { recursive: true });
      writeFileSync(join(app, path), content);
    };
    const link = (path: string, target: string) => {
      mkdirSync(dirname(join(app, path)), { recursive: true });
      symlinkSync(target, join(app, path));
    };
    put('package.json', JSON.stringify({ devDependencies: { typescript: '5.9.3' } }));
    put('package-lock.json', JSON.stringify({ packages: { 'node_modules/typescript': { devOptional: true }, 'node_modules/tsx': {}, 'node_modules/esbuild': {} } }));
    for (const p of ['node_modules/tsx/package.json', 'node_modules/esbuild/package.json', 'node_modules/esbuild/node_modules/nested/package.json', 'node_modules/typescript/package.json', 'node_modules/react/package.json']) put(p);
    for (const p of ['apps/sovereign-client/package.json', 'apps/sovereign-client/src/cli.ts', 'apps/sovereign-client/test/cli.test.ts', 'apps/web-saas/package.json']) put(p);
    for (const p of ['packages/nostr-core/package.json', 'packages/nostr-core/src/index.ts', 'packages/nostr-core/test/x.test.ts', 'packages/nostr-core/node_modules/@noble/hashes/package.json', 'services/indexer/src/main.ts']) put(p);
    link('node_modules/@sedecim/sovereign-client', '../../apps/sovereign-client');
    link('node_modules/@sedecim/nostr-core', '../../packages/nostr-core');
    link('node_modules/@sedecim/indexer', '../../services/indexer');
    const listed = ['', '/node_modules/@sedecim/sovereign-client', '/node_modules/tsx', '/node_modules/esbuild', '/node_modules/@sedecim/nostr-core', '/node_modules/typescript', '/packages/nostr-core/node_modules/@noble/hashes'];
    const select = (lines: string[]) => {
      const list = join(dir, `closure-${lines.length}`);
      const out = join(dir, `out-${lines.length}`);
      writeFileSync(list, lines.map((l) => app + l).join('\n') + '\n');
      return { out, run: spawnSync(process.execPath, ['-', app, out, list], { input: script, encoding: 'utf8' }) };
    };
    const { out, run } = select(listed);
    expect(run.status, run.stderr).toBe(0);
    const has = (p: string) => existsSync(join(out, p));
    for (const p of ['package.json', 'node_modules/tsx/package.json', 'node_modules/esbuild/node_modules/nested/package.json', 'apps/sovereign-client/src/cli.ts', 'packages/nostr-core/src/index.ts', 'packages/nostr-core/node_modules/@noble/hashes/package.json']) expect(has(p), p).toBe(true);
    // The workspace links stay relative, pointing into the copy.
    expect(readlinkSync(join(out, 'node_modules/@sedecim/sovereign-client'))).toBe('../../apps/sovereign-client');
    expect(readlinkSync(join(out, 'node_modules/@sedecim/nostr-core'))).toBe('../../packages/nostr-core');
    // Left out: tests, what npm ls did not list, and typescript, an optional peer that only development installs.
    for (const p of ['apps/sovereign-client/test', 'packages/nostr-core/test', 'node_modules/typescript', 'node_modules/react', 'node_modules/@sedecim/indexer', 'services', 'apps/web-saas']) expect(has(p), p).toBe(false);
    // A listing without tsx is an error, not an image that cannot start.
    const broken = select(listed.filter((l) => l !== '/node_modules/tsx'));
    expect(broken.run.status).not.toBe(0);
    expect(broken.run.stderr).toContain(`npm ls did not list ${app}/node_modules/tsx`);
  });

  it('its code imports only what its package.json files declare: the closure npm lists for the image has all it runs', () => {
    // The image keeps what npm ls lists from the package.json files; an import that works today only because npm
    // hoisted the package for another workspace would be missing there.
    const dirs: Record<string, string> = {};
    for (const base of ['packages', 'apps', 'services']) {
      for (const d of readdirSync(join(root, base))) if (existsSync(join(root, base, d, 'package.json'))) dirs[(JSON.parse(read(`${base}/${d}/package.json`)) as { name: string }).name] = `${base}/${d}`;
    }
    const manifest = (name: string) => JSON.parse(read(`${dirs[name]}/package.json`)) as { dependencies?: Record<string, string>; peerDependencies?: Record<string, string> };
    const closure = new Set<string>();
    for (const queue = ['@sedecim/sovereign-client']; queue.length; ) {
      const name = queue.shift()!;
      if (closure.has(name)) continue;
      closure.add(name);
      queue.push(...Object.keys(manifest(name).dependencies ?? {}).filter((d) => dirs[d]));
    }
    expect([...closure]).toEqual(expect.arrayContaining(['@sedecim/sovereign-client', '@sedecim/tor-network', '@sedecim/signer']));
    const sources = (dir: string): string[] =>
      readdirSync(join(root, dir), { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? sources(`${dir}/${e.name}`) : /\.(ts|tsx|mts|mjs|js)$/.test(e.name) ? [`${dir}/${e.name}`] : []));
    const undeclared: string[] = [];
    for (const name of closure) {
      const declared = new Set([name, ...Object.keys(manifest(name).dependencies ?? {}), ...Object.keys(manifest(name).peerDependencies ?? {})]);
      for (const file of sources(`${dirs[name]}/src`)) {
        for (const m of read(file).matchAll(/^\s*(?:import|export)\s+(?!type\s)(?:[^;]*?\sfrom\s+)?['"]([^'"]+)['"]|import\(\s*['"]([^'"]+)['"]\s*\)/gm)) {
          const spec = (m[1] ?? m[2])!;
          if (spec.startsWith('.') || spec.startsWith('node:') || builtinModules.includes(spec.split('/')[0]!)) continue;
          const pkg = spec.startsWith('@') ? spec.split('/').slice(0, 2).join('/') : spec.split('/')[0]!;
          if (!declared.has(pkg)) undeclared.push(`${file}: ${spec}`);
        }
      }
    }
    expect(undeclared).toEqual([]);
  });

  describe('the sandbox checks of the tor-profile job (scripts/sovereign-sandbox.mjs)', () => {
    const secret = 'tor-profile-check 0123456789abcdef';
    const container = () => ({
      Config: {
        User: 'app',
        Env: ['TOR_SOCKS=tor:9050', 'PATH=/usr/local/bin:/usr/bin:/bin', 'NODE_ENV=production', 'SOVEREIGN_DATA_DIR=/data/sovereign', 'SOVEREIGN_PASSPHRASE_FILE=/run/secrets/sovereign_passphrase'],
        ExposedPorts: null as Record<string, unknown> | null,
        Labels: { 'com.docker.compose.service': 'sovereign' } as Record<string, string>,
      },
      HostConfig: {
        PortBindings: {} as Record<string, unknown>,
        PublishAllPorts: false,
        ReadonlyRootfs: true,
        CapDrop: ['ALL'],
        CapAdd: null as string[] | null,
        Privileged: false,
        SecurityOpt: ['no-new-privileges:true'],
        Init: true,
        Dns: [] as string[],
        DnsSearch: [] as string[],
        DnsOptions: [] as string[],
        ExtraHosts: [] as string[],
        Tmpfs: { '/tmp': '' },
      },
      Mounts: [
        { Type: 'volume', Name: 'sedecim-nostr_sovereign-data', Destination: '/data', RW: true },
        { Type: 'bind', Source: '/tmp/x/sovereign-passphrase', Destination: '/run/secrets/sovereign_passphrase', RW: false },
        { Type: 'bind', Source: '/tmp/x/sovereign-backup-password', Destination: '/run/secrets/sovereign_backup_password', RW: false },
      ] as { Type: string; Name?: string; Source?: string; Destination: string; RW: boolean }[],
      NetworkSettings: { Networks: { 'sedecim-nostr_tor-socks': {} } as Record<string, unknown> },
    });
    const image = () => ({ Config: { User: 'app', Env: ['NODE_ENV=production', 'SOVEREIGN_DATA_DIR=/data/sovereign', 'SOVEREIGN_PASSPHRASE_FILE=/run/secrets/sovereign_passphrase'], ExposedPorts: null } });
    const network = () => ({ Name: 'sedecim-nostr_tor-socks', Internal: true });

    it('docker inspect: the configuration of the service passes, and each way out of the sandbox fails its check', () => {
      expect(failed(inspectChecks(container(), image(), network(), secret))).toEqual([]);
      type Mutation = (c: ReturnType<typeof container>, n: ReturnType<typeof network>) => void;
      const cases: [string, Mutation][] = [
        ['no port published to the host', (c) => (c.HostConfig.PortBindings = { '9050/tcp': [{ HostIp: '0.0.0.0', HostPort: '9050' }] })],
        ['no port exposed by the container or its image', (c) => (c.Config.ExposedPorts = { '8080/tcp': {} })],
        ['read-only root filesystem', (c) => (c.HostConfig.ReadonlyRootfs = false)],
        ['no capabilities: CapDrop ALL, no CapAdd, not privileged', (c) => (c.HostConfig.CapAdd = ['NET_ADMIN'])],
        ['no capabilities: CapDrop ALL, no CapAdd, not privileged', (c) => (c.HostConfig.Privileged = true)],
        ['no-new-privileges', (c) => (c.HostConfig.SecurityOpt = [])],
        ['runs as a user other than root', (c) => (c.Config.User = 'root')],
        ['an init process forwards signals to the CLI (init: true)', (c) => (c.HostConfig.Init = false)],
        ['its only network is <project>_tor-socks', (c) => (c.NetworkSettings.Networks['sedecim-nostr_nostr'] = {})],
        ['<project>_tor-socks is internal: no route out', (_c, n) => (n.Internal = false)],
        ['no DNS servers, search domains or extra hosts of its own', (c) => (c.HostConfig.Dns = ['8.8.8.8'])],
        ['no DNS servers, search domains or extra hosts of its own', (c) => (c.HostConfig.ExtraHosts = ['relay.example:203.0.113.7'])],
        ['mounts: its volume at /data, the secrets read-only, /tmp as tmpfs, nothing else', (c) => c.Mounts.push({ Type: 'bind', Source: '/var/run/docker.sock', Destination: '/var/run/docker.sock', RW: false })],
        ['mounts: its volume at /data, the secrets read-only, /tmp as tmpfs, nothing else', (c) => (c.Mounts[1]!.RW = true)],
        ['no variable of the container or its image holds a secret', (c) => c.Config.Env.push(`SOVEREIGN_PASSPHRASE=${secret}`)],
        ['no variable of the container or its image holds a secret', (c) => c.Config.Env.push(`EXTRA=${secret}`)],
        ['the passphrase is nowhere in the configuration of the container or its image', (c) => (c.Config.Labels.note = secret)],
        ['SOVEREIGN_PASSPHRASE_FILE=/run/secrets/sovereign_passphrase and TOR_SOCKS=tor:9050', (c) => (c.Config.Env = c.Config.Env.filter((e) => !e.startsWith('TOR_SOCKS=')))],
      ];
      for (const [check, mutate] of cases) {
        const c = container();
        const n = network();
        mutate(c, n);
        expect(failed(inspectChecks(c, image(), n, secret)), check).toContain(check);
      }
    });

    it('from inside: the container the service must be passes, and each way out of the sandbox fails its check', async () => {
      type Over = { fields?: Record<string, unknown>; status?: Record<string, string>; env?: Record<string, string>; present?: string[]; resolves?: string[]; connects?: string[] };
      const probe = (over: Over = {}) => {
        const files: Record<string, string> = { '/run/secrets/sovereign_passphrase': `${secret}\n`, '/app/package.json': JSON.stringify({ devDependencies: { vitest: '5', typescript: '5' } }) };
        const present = new Set(['/run/secrets/sovereign_passphrase', '/run/secrets/sovereign_backup_password', ...(over.present ?? [])]);
        const status: Record<string, string> = { CapEff: '0000000000000000', CapPrm: '0000000000000000', CapBnd: '0000000000000000', CapAmb: '0000000000000000', NoNewPrivs: '1', Seccomp: '2', ...over.status };
        const dirs: Record<string, string[]> = { '/app/apps': ['sovereign-client'], '/app/packages': ['nostr-core', 'tor-network'] };
        return {
          uid: 100,
          gid: 101,
          status: (f: string) => status[f],
          env: { TOR_SOCKS: 'tor:9050', SOVEREIGN_PASSPHRASE_FILE: '/run/secrets/sovereign_passphrase', ...over.env },
          writable: (p: string) => (p.startsWith('/run/secrets/') || ['/', '/app', '/usr/local/bin'].includes(p) ? 'EROFS' : true),
          canCreate: () => true,
          read: (p: string) => files[p],
          exists: (p: string) => present.has(p),
          list: (p: string) => dirs[p] ?? [],
          resolves: async (host: string) => host === 'tor' || (over.resolves ?? []).includes(host),
          connects: async (host: string, port: number) => `${host}:${port}` === 'tor:9050' || (over.connects ?? []).includes(`${host}:${port}`),
          ...over.fields,
        };
      };
      expect(failed(await insideChecks(probe()))).toEqual([]);
      const cases: [string, Over][] = [
        ['runs as a user and group other than root', { fields: { uid: 0 } }],
        ['no capabilities: CapEff, CapPrm, CapBnd and CapAmb are 0', { status: { CapEff: '00000000a80425fb' } }],
        ['no new privileges (NoNewPrivs 1)', { status: { NoNewPrivs: '0' } }],
        ['seccomp filter on (Seccomp 2)', { status: { Seccomp: '0' } }],
        ['read-only root filesystem: /, /app and /usr/local/bin are EROFS', { fields: { writable: (p: string) => (p === '/app' ? 'EACCES' : 'EROFS') } }],
        ['writes where it must: its volume /data/sovereign and /tmp', { fields: { canCreate: (d: string) => (d === '/tmp' ? true : 'EACCES') } }],
        ['the passphrase arrives as the read-only file /run/secrets/sovereign_passphrase, and so does the backup password', { fields: { writable: () => true } }],
        ['no environment variable holds a secret', { env: { SOVEREIGN_PASSPHRASE: 'x' } }],
        ['no environment variable holds a secret', { env: { OTHER: secret } }],
        ['TOR_SOCKS=tor:9050: tor resolves and its SOCKS port answers', { fields: { connects: async () => false } }],
        ['no other compose service on its network: relay, secure-relay, secure-relay-onion and postgres do not resolve', { resolves: ['relay'] }],
        ['no DNS outside Tor: example.com and check.torproject.org do not resolve', { resolves: ['example.com'] }],
        ['no route out: 1.1.1.1:443, 9.9.9.9:53 and [2606:4700:4700::1111]:443 do not connect', { connects: ['9.9.9.9:53'] }],
        ['the image holds the CLI: no services, apps/ is sovereign-client, no tests', { present: ['/app/services'] }],
        ['the image holds the CLI: no services, apps/ is sovereign-client, no tests', { present: ['/app/packages/tor-network/test'] }],
        ['none of the 2 devDependencies of the repository is installed', { present: ['/app/node_modules/typescript'] }],
        ['no package of other workspaces (web, admin console, managed signer, indexer)', { present: ['/app/node_modules/aws-amplify'] }],
        ['no .env or .data in the image', { present: ['/app/packages/nostr-core/.data'] }],
      ];
      for (const [check, over] of cases) expect(failed(await insideChecks(probe(over))), check).toContain(check);
    });
  });

  it('the tor-profile job runs the service as documented, checks its sandbox, and runs the CLI through tor and without it', () => {
    const check = read('scripts/tor-profile-check.sh');
    // `docker compose run --rm sovereign …` without --profile, with the two secret files.
    expect(check).toContain('sov_compose() { SOVEREIGN_PASSPHRASE_FILE="$SOV_PASS" SOVEREIGN_BACKUP_PASSWORD_FILE="$SOV_BACKUP_PASS" timeout 180 docker compose "$@"; }');
    expect(check).toContain('svc() { sov_compose run --rm -T "$@"; }');
    expect(check).toContain('chmod 644 "$SOV_PASS" "$SOV_BACKUP_PASS"');
    // The sandbox, from the host and from inside, before the CLI runs.
    const inspect = check.indexOf('node scripts/sovereign-sandbox.mjs inspect ');
    const inside = check.indexOf('--entrypoint node sovereign /sandbox-check.mjs inside');
    const create = check.indexOf('svc sovereign persona create --label tor-compose --relay "ws://$SECURE_ONION" --tor');
    expect(inspect).toBeGreaterThan(0);
    expect(inside).toBeGreaterThan(inspect);
    expect(create).toBeGreaterThan(inside);
    for (const step of [
      'svc sovereign channel send --persona "$C" --group tor-check "$CTEXT"',
      'svc sovereign channel read --persona "$C" --group tor-check',
      'svc sovereign backup export --persona "$C" --out /data/tor-check-backup.json --password-file /run/secrets/sovereign_backup_password',
      'svc --entrypoint cat sovereign /data/tor-check-backup.json > "$DATA/sovereign-backup.json"',
      'sovereign backup restore /restore/backup.json --password-file /run/secrets/sovereign_backup_password',
    ])
      expect(check).toContain(step);
    const stop = check.indexOf('"${COMPOSE[@]}" stop tor');
    expect(stop).toBeGreaterThan(check.indexOf('sovereign backup restore'));
    expect(check.slice(stop)).toMatch(/\nsvc --no-deps sovereign channel send [^\n]+\ngrep -q 'QUEUED — No enviado: red de privacidad no disponible'/);
    const ci = read('.github/workflows/ci.yml');
    expect(ci).toMatch(/\n {2}tor-profile:\n[\s\S]*?run: bash scripts\/tor-profile-check\.sh\n/);
    expect(ci).toMatch(/shellcheck -x [^\n]*scripts\/tor-profile-check\.sh/);
  });

  it('is documented step by step: the secret files, what the service is, its backups and what happens when tor is down', () => {
    const doc = read('docs/sovereign-tor.md');
    const at = doc.indexOf('## El CLI como servicio del perfil `tor` (FR020-06)');
    expect(at).toBeGreaterThan(0);
    const section = doc.slice(at, doc.indexOf('\n## ', at + 1));
    for (const text of [
      'docker compose run --rm sovereign persona create',
      'TOR_SOCKS=tor:9050',
      'SOVEREIGN_PASSPHRASE_FILE',
      'SOVEREIGN_BACKUP_PASSWORD_FILE',
      '--password-file /run/secrets/sovereign_backup_password',
      'No enviado: red de privacidad no disponible',
      'run --rm --no-deps sovereign',
      'down -v',
      'scripts/sovereign-sandbox.mjs',
    ])
      expect(section, text).toContain(text);
    expect(read('README.md')).toContain('docker compose run --rm sovereign');
  });
});
