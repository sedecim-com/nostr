#!/usr/bin/env node
// FR020-06: what the tor-profile job (scripts/tor-profile-check.sh) checks of the container of the compose service
// `sovereign`, the sovereign CLI. One line per check, `ok - …` or `not ok - …` with what was found; exit 1 if any fails.
//   node scripts/sovereign-sandbox.mjs inspect CONTAINER.json IMAGE.json NETWORK.json SECRET_FILE
//        on the host: `docker inspect` of a container of the service, `docker image inspect` of its image and
//        `docker network inspect` of its network; SECRET_FILE is the passphrase file it was given
//   node /sandbox-check.mjs inside
//        inside a container of the service (this file mounted read-only, `--entrypoint node`)
import { existsSync, lstatSync, readdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { lookup } from 'node:dns/promises';
import { connect } from 'node:net';

const PASSPHRASE = '/run/secrets/sovereign_passphrase';
const SECRETS = [PASSPHRASE, '/run/secrets/sovereign_backup_password'];
/** Variables that would hold a secret of the CLI in the clear. */
const SECRET_VARS = ['SOVEREIGN_PASSPHRASE', 'SOVEREIGN_BACKUP_PASSWORD', 'SOVEREIGN_POLICY_BEARER', 'SOVEREIGN_REVOCATION_TOKEN'];
/**
 * Never needed by the CLI: packages of other workspaces (web, admin console, managed signer, indexer), and typescript,
 * which nostr-tools only asks for as an optional peer and only development installs.
 */
const NOT_NEEDED = ['aws-amplify', '@aws-sdk/client-kms', 'react', '@mui/material', '@sedecim/indexer', '@sedecim/managed-signer', '@sedecim/web-saas', 'typescript'];

const check = (ok, what, found) => ({ ok: Boolean(ok), what: ok || found === undefined ? what : `${what} (found: ${found})` });
const envMap = (list = []) => Object.fromEntries(list.map((e) => [e.slice(0, e.indexOf('=')), e.slice(e.indexOf('=') + 1)]));
const isRoot = (user) => !user || /^(root|0)(:|$)/.test(user);

/**
 * The container's configuration as Docker applied it: `container`, `image` and `network` are the first element of
 * `docker inspect`, `docker image inspect` and `docker network inspect`; `secret` is the passphrase it was given.
 */
export function inspectChecks(container, image, network, secret) {
  const hc = container.HostConfig ?? {};
  const cfg = container.Config ?? {};
  const env = envMap(cfg.Env);
  const nets = Object.keys(container.NetworkSettings?.Networks ?? {});
  const bindings = Object.entries(hc.PortBindings ?? {}).filter(([, b]) => (b ?? []).length);
  const exposed = [...Object.keys(cfg.ExposedPorts ?? {}), ...Object.keys(image.Config?.ExposedPorts ?? {})];
  const mounts = container.Mounts ?? [];
  const tmpfs = [...new Set([...Object.keys(hc.Tmpfs ?? {}), ...mounts.filter((m) => m.Type === 'tmpfs').map((m) => m.Destination)])];
  const unexpected = mounts.filter(
    (m) =>
      !(m.Type === 'volume' && m.Destination === '/data' && m.RW && /_sovereign-data$/.test(m.Name ?? '')) &&
      !(m.Type === 'bind' && SECRETS.includes(m.Destination) && !m.RW) &&
      !(m.Type === 'tmpfs' && m.Destination === '/tmp') &&
      m.Destination !== '/sbin/docker-init',
  );
  const leaked = [...SECRET_VARS.filter((k) => k in env || k in envMap(image.Config?.Env)), ...Object.keys(env).filter((k) => secret && env[k]?.includes(secret))];
  const user = cfg.User || image.Config?.User || '';
  return [
    check(!bindings.length && !hc.PublishAllPorts, 'no port published to the host', bindings.map(([p]) => p).join(', ') || 'PublishAllPorts'),
    check(!exposed.length, 'no port exposed by the container or its image', exposed.join(', ')),
    check(hc.ReadonlyRootfs === true, 'read-only root filesystem', `ReadonlyRootfs=${hc.ReadonlyRootfs}`),
    check((hc.CapDrop ?? []).includes('ALL') && !(hc.CapAdd ?? []).length && !hc.Privileged, 'no capabilities: CapDrop ALL, no CapAdd, not privileged', `CapDrop=${hc.CapDrop} CapAdd=${hc.CapAdd} Privileged=${hc.Privileged}`),
    check((hc.SecurityOpt ?? []).some((o) => /^no-new-privileges([:=]true)?$/.test(o)), 'no-new-privileges', `SecurityOpt=${hc.SecurityOpt}`),
    check(!isRoot(user) && !isRoot(image.Config?.User ?? ''), 'runs as a user other than root', user || 'root'),
    check(hc.Init === true, 'an init process forwards signals to the CLI (init: true)', `Init=${hc.Init}`),
    check(nets.length === 1 && /_tor-socks$/.test(nets[0] ?? ''), 'its only network is <project>_tor-socks', nets.join(', ') || 'none'),
    check(network.Internal === true && /_tor-socks$/.test(network.Name ?? ''), '<project>_tor-socks is internal: no route out', `${network.Name} Internal=${network.Internal}`),
    check(!(hc.Dns ?? []).length && !(hc.DnsSearch ?? []).length && !(hc.DnsOptions ?? []).length && !(hc.ExtraHosts ?? []).length, 'no DNS servers, search domains or extra hosts of its own', JSON.stringify({ Dns: hc.Dns, DnsSearch: hc.DnsSearch, ExtraHosts: hc.ExtraHosts })),
    check(!unexpected.length && tmpfs.length === 1 && tmpfs[0] === '/tmp' && mounts.some((m) => m.Destination === '/data'), 'mounts: its volume at /data, the secrets read-only, /tmp as tmpfs, nothing else', unexpected.map((m) => `${m.Type} ${m.Destination}${m.RW ? ' rw' : ''}`).join(', ') || `tmpfs ${tmpfs.join(', ') || 'none'}`),
    check(env.SOVEREIGN_PASSPHRASE_FILE === PASSPHRASE && env.TOR_SOCKS === 'tor:9050', `SOVEREIGN_PASSPHRASE_FILE=${PASSPHRASE} and TOR_SOCKS=tor:9050`, `SOVEREIGN_PASSPHRASE_FILE=${env.SOVEREIGN_PASSPHRASE_FILE} TOR_SOCKS=${env.TOR_SOCKS}`),
    check(!leaked.length, 'no variable of the container or its image holds a secret', leaked.join(', ')),
    check(Boolean(secret) && !JSON.stringify(container).includes(secret) && !JSON.stringify(image).includes(secret), 'the passphrase is nowhere in the configuration of the container or its image', secret ? 'present' : 'empty secret: nothing to look for'),
  ];
}

/** What the checks inside the container use; the unit tests hand in fakes. */
export function realProbe() {
  const status = readFileSync('/proc/self/status', 'utf8');
  return {
    uid: process.getuid?.() ?? -1,
    gid: process.getgid?.() ?? -1,
    status: (field) => new RegExp(`^${field}:\\s*(\\S+)`, 'm').exec(status)?.[1],
    env: process.env,
    /**
     * The mounts of this process (/proc/self/mountinfo): mount point, per-mount options and filesystem type. A
     * read-only root shows here as `ro`; access(2) says EACCES first to a user that does not own the directory.
     */
    mounts: () =>
      readFileSync('/proc/self/mountinfo', 'utf8')
        .trim()
        .split('\n')
        .map((line) => {
          const [left = '', right = ''] = line.split(' - ');
          const fields = left.split(' ');
          return { point: (fields[4] ?? '').replace(/\\040/g, ' '), options: (fields[5] ?? '').split(','), fstype: right.split(' ')[0] ?? '' };
        }),
    /** Creates and removes a file in `dir`: true, or the error code. */
    canCreate: (dir) => {
      const file = `${dir}/.sandbox-check-${process.pid}`;
      try {
        writeFileSync(file, 'x', { flag: 'wx' });
        unlinkSync(file);
        return true;
      } catch (e) {
        return e.code;
      }
    },
    read: (path) => {
      try {
        return readFileSync(path, 'utf8');
      } catch {
        return undefined;
      }
    },
    exists: (path) => {
      try {
        lstatSync(path);
        return true;
      } catch {
        return false;
      }
    },
    list: (path) => (existsSync(path) ? readdirSync(path).sort() : []),
    resolves: (host) => Promise.race([lookup(host).then(() => true, () => false), new Promise((resolve) => setTimeout(() => resolve(false), 10_000))]),
    connects: (host, port) =>
      new Promise((resolve) => {
        const socket = connect({ host, port, timeout: 5000 });
        const end = (ok) => {
          socket.destroy();
          resolve(ok);
        };
        socket.once('connect', () => end(true));
        socket.once('timeout', () => end(false));
        socket.once('error', () => end(false));
      }),
  };
}

/** The same properties seen from inside: user, capabilities, filesystem, secrets, network and what the image holds. */
export async function insideChecks(p = realProbe()) {
  const zero = (field) => /^0+$/.test(p.status(field) ?? '');
  const caps = ['CapEff', 'CapPrm', 'CapBnd', 'CapAmb'];
  const mounts = p.mounts();
  /** The mount that decides for a path: the last one mounted at exactly that point. */
  const at = (point) => mounts.filter((m) => m.point === point).at(-1);
  const mode = (point) => at(point)?.options.find((o) => o === 'ro' || o === 'rw') ?? 'missing';
  const created = ['/data/sovereign', '/tmp'].map((d) => [d, p.canCreate(d)]);
  const secret = (p.read(PASSPHRASE) ?? '').replace(/\r?\n$/, '');
  const inEnv = [...SECRET_VARS.filter((k) => k in p.env), ...Object.keys(p.env).filter((k) => secret && p.env[k]?.includes(secret))];
  const others = [];
  for (const host of ['relay', 'secure-relay', 'secure-relay-onion', 'postgres']) if (await p.resolves(host)) others.push(host);
  const external = [];
  for (const host of ['example.com', 'check.torproject.org']) if (await p.resolves(host)) external.push(host);
  const routes = [];
  for (const [host, port] of [['1.1.1.1', 443], ['9.9.9.9', 53], ['2606:4700:4700::1111', 443]]) if (await p.connects(host, port)) routes.push(`${host}:${port}`);
  const packages = p.list('/app/packages');
  const tests = ['/app/apps/sovereign-client/test', ...packages.map((d) => `/app/packages/${d}/test`)].filter((t) => p.exists(t));
  const json = (file) => {
    try {
      return JSON.parse(p.read(file) ?? '{}');
    } catch {
      return {};
    }
  };
  // What only development needs: devDependencies of the repository that no package in the image declares (esbuild and
  // nostr-tools are devDependencies too, and dependencies of tsx and of the packages).
  const manifests = [...p.list('/app/apps').map((d) => `/app/apps/${d}`), ...packages.map((d) => `/app/packages/${d}`)];
  const walk = (dir, depth) => {
    for (const entry of p.list(dir)) {
      if (entry.startsWith('.')) continue;
      if (entry.startsWith('@')) walk(`${dir}/${entry}`, depth);
      else {
        manifests.push(`${dir}/${entry}`);
        if (depth < 3) walk(`${dir}/${entry}/node_modules`, depth + 1);
      }
    }
  };
  walk('/app/node_modules', 0);
  for (const d of packages) walk(`/app/packages/${d}/node_modules`, 1);
  const declared = new Set(manifests.flatMap((m) => ['dependencies', 'optionalDependencies', 'peerDependencies'].flatMap((f) => Object.keys(json(`${m}/package.json`)[f] ?? {}))));
  const devOnly = Object.keys(json('/app/package.json').devDependencies ?? {}).filter((d) => !declared.has(d));
  const devPresent = devOnly.filter((d) => p.exists(`/app/node_modules/${d}`));
  const foreign = NOT_NEEDED.filter((d) => p.exists(`/app/node_modules/${d}`));
  const dirs = ['/app', ...p.list('/app/apps').map((d) => `/app/apps/${d}`), ...packages.map((d) => `/app/packages/${d}`)];
  const local = dirs.flatMap((d) => ['.env', '.data'].map((f) => `${d}/${f}`)).filter((f) => p.exists(f));
  return [
    check(p.uid !== 0 && p.gid !== 0, 'runs as a user and group other than root', `uid ${p.uid} gid ${p.gid}`),
    check(caps.every(zero), 'no capabilities: CapEff, CapPrm, CapBnd and CapAmb are 0', caps.map((f) => `${f}=${p.status(f)}`).join(' ')),
    check(p.status('NoNewPrivs') === '1', 'no new privileges (NoNewPrivs 1)', p.status('NoNewPrivs')),
    check(p.status('Seccomp') === '2', 'seccomp filter on (Seccomp 2)', p.status('Seccomp')),
    check(mode('/') === 'ro', 'read-only root filesystem (/ mounted ro)', `/ ${mode('/')}`),
    check(mode('/data') === 'rw' && at('/tmp')?.fstype === 'tmpfs' && mode('/tmp') === 'rw' && created.every(([, c]) => c === true), 'writes where it must: its volume at /data and /tmp (tmpfs)', `/data ${mode('/data')}, /tmp ${at('/tmp')?.fstype ?? 'missing'} ${mode('/tmp')}, ${created.map(([d, c]) => `${d}=${c}`).join(' ')}`),
    check(p.env.SOVEREIGN_PASSPHRASE_FILE === PASSPHRASE && Boolean(secret) && SECRETS.every((s) => mode(s) === 'ro'), `the passphrase arrives as the read-only file ${PASSPHRASE}, and so does the backup password`, `SOVEREIGN_PASSPHRASE_FILE=${p.env.SOVEREIGN_PASSPHRASE_FILE} passphrase ${secret ? 'set' : 'empty'} ${SECRETS.map((s) => `${s} ${mode(s)}`).join(', ')}`),
    check(!inEnv.length, 'no environment variable holds a secret', inEnv.join(', ')),
    check(p.env.TOR_SOCKS === 'tor:9050' && (await p.resolves('tor')) && (await p.connects('tor', 9050)), 'TOR_SOCKS=tor:9050: tor resolves and its SOCKS port answers', `TOR_SOCKS=${p.env.TOR_SOCKS}`),
    check(!others.length, 'no other compose service on its network: relay, secure-relay, secure-relay-onion and postgres do not resolve', others.join(', ')),
    check(!external.length, 'no DNS outside Tor: example.com and check.torproject.org do not resolve', external.join(', ')),
    check(!routes.length, 'no route out: 1.1.1.1:443, 9.9.9.9:53 and [2606:4700:4700::1111]:443 do not connect', routes.join(', ')),
    check(!p.exists('/app/services') && p.list('/app/apps').join() === 'sovereign-client' && !tests.length, 'the image holds the CLI: no services, apps/ is sovereign-client, no tests', `services=${p.exists('/app/services')} apps=${p.list('/app/apps').join(',')} ${tests.join(' ')}`),
    check(devOnly.length > 0 && !devPresent.length, `none of the ${devOnly.length} packages only development needs is installed`, devPresent.join(', ') || 'no devDependencies left to look for in /app/package.json'),
    check(!foreign.length, 'no package of other workspaces (web, admin console, managed signer, indexer), nor typescript', foreign.join(', ')),
    check(!local.length, 'no .env or .data in the image', local.join(', ')),
  ];
}

function report(checks) {
  for (const c of checks) console.log(`${c.ok ? 'ok' : 'not ok'} - ${c.what}`);
  const failed = checks.filter((c) => !c.ok).length;
  if (failed) console.log(`${failed} of ${checks.length} sandbox checks failed`);
  return failed ? 1 : 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [mode, ...args] = process.argv.slice(2);
  if (mode === 'inside') process.exit(report(await insideChecks()));
  if (mode === 'inspect' && args.length === 4) {
    const [container, image, network] = args.slice(0, 3).map((f) => JSON.parse(readFileSync(f, 'utf8'))[0] ?? {});
    process.exit(report(inspectChecks(container, image, network, readFileSync(args[3], 'utf8').replace(/\r?\n$/, ''))));
  }
  console.error('usage: node scripts/sovereign-sandbox.mjs inspect CONTAINER.json IMAGE.json NETWORK.json SECRET_FILE | inside');
  process.exit(2);
}
