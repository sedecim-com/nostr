import { describe, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import fc from 'fast-check';
import {
  browserEnvironment,
  buildCrashReport,
  cleanCrashText,
  cleanStack,
  CRASH_LIMITS,
  CRASH_RETENTION,
  CrashCapture,
  crashReportJson,
  CrashReportStore,
  nodeEnvironment,
  parseCrashReport,
  redactFreeText,
  type CrashContext,
  type CrashErrorNode,
  type CrashReport,
  type CrashReportCollection,
  type StoredCrashReport,
} from '../src/index';

const BECH32 = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const BASE32 = 'abcdefghijklmnopqrstuvwxyz234567';
const bech32Like = (hrp: string, n: number) => `${hrp}1${Array.from(randomBytes(n), (b) => BECH32[b % 32]).join('')}`;
const word = (n: number) => Array.from(randomBytes(n), (b) => 'abcdefghijklmnopqrstuvwxyz'[b % 26]).join('');
const b64u = (v: string) => Buffer.from(v).toString('base64url');
/** A random token with letters and digits, as tokens are (docs/crash-reports.md: what is recognised as one). */
const token = (bytes: number) => {
  const t = randomBytes(bytes).toString('base64url');
  return /\d/.test(t) ? t : `${t}0`;
};

/** One of each kind of value that must never reach a report, made at run time (none is a real credential). */
function canaries() {
  const user = `u${word(9)}`;
  const pubkey = randomBytes(32).toString('hex');
  return {
    pubkey,
    npub: bech32Like('npub', 58),
    nsec: bech32Like('nsec', 58),
    ncryptsec: bech32Like('ncryptsec', 152),
    nprofile: bech32Like('nprofile', 70),
    nevent: bech32Like('nevent', 80),
    urlToken: token(18),
    urlUserinfo: `pw${word(12)}`,
    host: `relay-${word(7)}.example.org`,
    onion: `${Array.from(randomBytes(56), (b) => BASE32[b % 32]).join('')}.onion`,
    ipv4: '203.0.113.47',
    ipv6: '2001:db8:85a3::8a2e:370:7334',
    user,
    path: `/home/${user}/Documentos/fuentes/${word(8)}.txt`,
    // The text of a chat message; the random word tells a partial leak too.
    messageWord: word(10),
    personaId: randomBytes(8).toString('hex'),
    groupId: randomBytes(32).toString('hex'),
    bearer: token(24),
    jwt: [b64u(JSON.stringify({ alg: 'RS256', typ: 'JWT' })), b64u(JSON.stringify({ sub: pubkey.slice(0, 16) })), randomBytes(32).toString('base64url')].join('.'),
    email: `fuente.${word(6)}@example.org`,
    label: `Fuente${word(6)}`,
  };
}
type Canaries = ReturnType<typeof canaries>;
const chatText = (c: Canaries) => `Nos vemos en la plaza ${c.messageWord} a las siete`;

/** The canaries found in a text: the test of every leak below, and of its negative control. */
function leaks(text: string, c: Canaries): string[] {
  return Object.entries(c)
    .filter(([, value]) => text.includes(value))
    .map(([name]) => name);
}

/** A failure that carries every canary in its message, its stack, its nested causes and its own fields. */
function poisoned(c: Canaries): Error {
  const url = `https://admin:${c.urlUserinfo}@${c.host}/v1/feed?token=${c.urlToken}`;
  let parsed: unknown;
  try {
    JSON.parse(chatText(c));
  } catch (e) {
    parsed = e; // the engine's own message quotes the start of the text it could not read
  }
  const deepest = new AggregateError(
    [new RangeError(`${c.ncryptsec} and ${c.nprofile} of "${c.label}"`), `${c.nsec} ${chatText(c)}`, { message: `${c.nevent} via ${c.ipv6}`, stack: `fn@/home/${c.user}/x/${c.npub}.js:1:1` }, parsed],
    `${c.onion} wrote to ${c.email}: '${chatText(c)}' {"content":"${chatText(c)}","pubkey":"${c.pubkey}"}`,
  );
  const cause = new TypeError(`token=${c.bearer} Authorization: Bearer ${c.jwt}`, { cause: deepest });
  const top = new Error(`could not send "${chatText(c)}" to ${url} from ${c.path} (persona ${c.personaId}, group ${c.groupId}, ${c.npub}, ${c.ipv4}, ${c.host})`, { cause });
  top.stack = [
    `Error: ${top.message}`,
    `at ${c.messageWord}`,
    `    at sendDm (file://${c.path.replace('.txt', '.ts')}:10:5)`,
    `    at ${c.nsec} (https://${c.host}/assets/index-B5t3Xk2a.js:1:2345)`,
    `    at Object.<anonymous> (/home/${c.user}/nostr/apps/sovereign-client/src/app.ts:12:3)`,
    `    at new Persona (/home/${c.user}/${c.npub}/node_modules/@noble/hashes/esm/scrypt.js:4:5)`,
    `    at http://${c.ipv4}:8080/${c.pubkey}.js:1:1`,
    `    at ${c.onion}/x.js:1:1`,
    `fn@https://${c.host}/${c.personaId}.js:2:3`,
  ].join('\n');
  // Fields of the error that no report has: never read.
  Object.assign(top, { config: { url, headers: { authorization: `Bearer ${c.bearer}` } }, path: c.path, pubkey: c.pubkey, persona: c.personaId });
  return top;
}

const ctx = (over: Partial<CrashContext> = {}): CrashContext => ({ app: 'acceso-nostr-web', appVersion: '0.1.0', profile: 'convenience', environment: { os: 'linux', runtime: 'chrome', runtimeMajor: 128 }, source: 'error', ...over });

/** The report's grammar: its keys, and each value within its rule. */
const FILE = String.raw`(?:<anonymous>|<eval>|node:[a-z_/]+|(?:[a-z0-9@._~-]+\/){0,2}[A-Za-z0-9_.@-]+\.(?:[cm]?js|jsx|[cm]?ts|tsx|wasm|html?))(?::\d{1,7}){0,2}`;
const FN = String.raw`(?:new )?(?:<anonymous>|[A-Za-z_$][\w$]*)(?:\.(?:<anonymous>|[A-Za-z_$#][\w$]*))*`;
const FRAME = new RegExp(`^at (?:${FN}(?: \\((?:\\?|${FILE})\\))?|${FILE})$`);
function expectGrammar(r: CrashReport): void {
  expect(Object.keys(r).every((k) => ['format', 'version', 'app', 'profile', 'environment', 'source', 'error', 'componentStack'].includes(k))).toBe(true);
  expect(Object.keys(r.app).sort()).toEqual(['name', 'version']);
  expect(r.app.version).toMatch(/^\d{1,3}\.\d{1,3}\.\d{1,3}(?:-[0-9A-Za-z.]{1,20})?$/);
  expect(Object.keys(r.environment).every((k) => ['os', 'runtime', 'runtimeMajor'].includes(k))).toBe(true);
  for (const f of r.componentStack ?? []) expect(f).toMatch(FRAME);
  let nodes = 0;
  const node = (n: CrashErrorNode, depth: number) => {
    nodes++;
    expect(depth).toBeLessThanOrEqual(CRASH_LIMITS.depth);
    expect(Object.keys(n).every((k) => ['name', 'message', 'stack', 'cause', 'errors'].includes(k))).toBe(true);
    expect(n.name).toMatch(/^(?:_OTHER|_NonError|(?:[A-Z][a-z]{1,14}|[A-Z]{2,5})+)$/);
    expect(n.message.length).toBeLessThanOrEqual(CRASH_LIMITS.message);
    expect(n.message).not.toMatch(/[\n\r]/);
    expect(n.stack.length).toBeLessThanOrEqual(CRASH_LIMITS.frames);
    for (const f of n.stack) expect(f, f).toMatch(FRAME);
    if (n.cause) node(n.cause, depth + 1);
    expect((n.errors ?? []).length).toBeLessThanOrEqual(CRASH_LIMITS.errors);
    for (const e of n.errors ?? []) node(e, depth + 1);
  };
  node(r.error, 0);
  expect(nodes).toBeLessThanOrEqual(CRASH_LIMITS.nodes);
}

describe('crash reports are clean (NFR007-03)', () => {
  it('NFR007-03: no canary sown in the message, the stack, nested causes, aggregated errors, fields or a React component stack reaches the export', () => {
    const c = canaries();
    const componentStack = `\n    at PanelView (https://${c.host}/src/views/PanelView.tsx?t=${c.urlToken}:30:20)\n    at Persona (/home/${c.user}/app/${c.pubkey}.tsx:1:1)\n    at div`;
    const reports = [
      buildCrashReport(poisoned(c), ctx()),
      buildCrashReport(poisoned(c), ctx({ source: 'component', componentStack })),
      // Values thrown that are not errors: recorded by their type only.
      buildCrashReport(`${c.nsec} ${chatText(c)} ${c.path}`, ctx({ source: 'unhandledrejection' })),
      buildCrashReport({ reason: c.pubkey, url: `wss://${c.onion}` }, ctx({ source: 'unhandledrejection' })),
    ];
    const exported = reports.map(crashReportJson).join('\n');
    expect(leaks(exported, c)).toEqual([]);
    for (const r of reports) expectGrammar(r);
    // Still worth reading: classes, frames cut down to the package or bundle file, causes and aggregated errors.
    const [r] = reports;
    expect(r!.error.name).toBe('Error');
    expect(r!.error.message).toMatch(/^could not send "\[texto\]" to https:\/\/\[url\] from \[ruta\] \(persona \[hex\], group \[hex\], \[npub\], \[ip\], \[host\]\)$/);
    expect(r!.error.stack).toEqual([`at sendDm (${c.path.split('/').pop()!.replace('.txt', '.ts')}:10:5)`, 'at index-B5t3Xk2a.js:1:2345', 'at Object.<anonymous> (sovereign-client/app.ts:12:3)', 'at new Persona (@noble/hashes/scrypt.js:4:5)', 'at x.js:1:1', 'at fn (?)']);
    expect(r!.error.cause?.name).toBe('TypeError');
    expect(r!.error.cause?.message).toBe('token=[…] Authorization: […] [REDACTED]');
    expect(r!.error.cause?.cause?.name).toBe('AggregateError');
    expect(r!.error.cause?.cause?.errors?.map((e) => e.name)).toEqual(['RangeError', '_NonError', 'Object', 'SyntaxError']);
    expect(reports[1]!.componentStack).toEqual(['at PanelView (PanelView.tsx:30:20)', 'at Persona (?)', 'at div']);
    expect([reports[2]!.error, reports[3]!.error]).toEqual([
      { name: '_NonError', message: '[string]', stack: [] },
      { name: '_NonError', message: '[object]', stack: [] },
    ]);
  });

  it('NFR007-03: negative control: the same check finds every canary when the failure is serialised as it is', () => {
    const c = canaries();
    const naive = (e: unknown): unknown => (e instanceof Error ? { ...e, name: e.name, message: e.message, stack: e.stack, cause: naive(e.cause), errors: e instanceof AggregateError ? e.errors.map(naive) : undefined } : e);
    expect(leaks(JSON.stringify(naive(poisoned(c))), c).sort()).toEqual(Object.keys(c).sort());
    // And with only the message of each error, still most of them: cleaning, not the choice of fields, removes these.
    const messages = (e: unknown): string => (e instanceof Error ? `${e.message} ${messages(e.cause)} ${e instanceof AggregateError ? e.errors.map(messages).join(' ') : ''}` : '');
    expect(leaks(messages(poisoned(c)), c).sort()).toEqual(['pubkey', 'npub', 'ncryptsec', 'nprofile', 'urlToken', 'urlUserinfo', 'host', 'onion', 'ipv4', 'path', 'user', 'messageWord', 'personaId', 'groupId', 'bearer', 'jwt', 'email', 'label'].sort());
  });

  it('NFR007-03: property: a canary between separators never survives the message cleaning', () => {
    const c = canaries();
    // Recognised only where they travel (tested above): a chat text or a label between quotes, a user name in a home
    // path, a URL password in its URL. Plain words outside those cannot be told from the program's own words.
    const { messageWord: _text, label: _label, user: _user, urlUserinfo: _userinfo, ...shaped } = c;
    const sep = fc.constantFrom(' ', ': ', ' (', ') ', ', ', ' = ', '\n', '\t', ' [', '] ', '"', "'");
    fc.assert(
      fc.property(fc.string(), sep, fc.constantFrom(...Object.values(shaped)), sep, fc.string(), (a, s1, value, s2, b) => {
        expect(leaks(cleanCrashText(`${a}${s1}${value}${s2}${b}`, 4000), c)).toEqual([]);
      }),
      { numRuns: 500 },
    );
  });

  it('NFR007-03: property: whatever is thrown, a report keeps the allowlist, its bounds and its grammar, and reads back the same', () => {
    const thrown = fc.oneof(
      fc.anything(),
      fc.record({ message: fc.string(), name: fc.string(), stack: fc.string(), cause: fc.anything() }),
      fc.tuple(fc.string(), fc.string(), fc.anything()).map(([m, s, cause]) => Object.assign(new Error(m, { cause }), { stack: s, extra: cause })),
    );
    fc.assert(
      fc.property(thrown, (t) => {
        const r = buildCrashReport(t, ctx());
        expectGrammar(r);
        expect(parseCrashReport(JSON.parse(crashReportJson(r)))).toEqual(r);
      }),
      { numRuns: 400 },
    );
  });

  it('NFR007-03: property: cleaning a message twice changes nothing', () => {
    const c = canaries();
    const piece = fc.oneof(fc.string(), fc.constantFrom(...Object.values(c), '"', "'", '«', '»', 'wss://', '/home/', ' ', ':'));
    fc.assert(
      fc.property(fc.array(piece, { maxLength: 12 }), fc.integer({ min: 20, max: 300 }), (parts, max) => {
        const once = cleanCrashText(parts.join(''), max);
        expect(cleanCrashText(once, max)).toBe(once);
        expect(once.length).toBeLessThanOrEqual(max);
      }),
      { numRuns: 500 },
    );
  });

  it('NFR007-03: hostile values (throwing getters, proxies, cycles, huge or deep chains) give a bounded report and never throw', () => {
    const revoked = Proxy.revocable({}, {});
    revoked.revoke();
    const throwing = new Proxy({}, { get: () => { throw new Error('trap'); }, getPrototypeOf: () => { throw new Error('trap'); } });
    const getter = Object.defineProperty(new Error('x'), 'cause', { get: () => { throw new Error('getter'); } });
    const cyclic = new Error('a');
    cyclic.cause = new Error('b', { cause: cyclic });
    let deep: Error = new Error('end');
    for (let i = 0; i < 500; i++) deep = new Error(`level ${i}`, { cause: deep });
    const many = new AggregateError(Array.from({ length: 10_000 }, (_, i) => new Error(String(i))), 'many');
    const huge = new Error('x'.repeat(2_000_000));
    for (const t of [revoked.proxy, throwing, getter, cyclic, deep, many, huge, Symbol('s'), 10n, () => 1, null, undefined]) {
      const r = buildCrashReport(t, ctx());
      expectGrammar(r);
      expect(crashReportJson(r).length).toBeLessThan(40_000);
    }
  });

  it('NFR007-03: a stack keeps the frames, cut down to package/file or the bundle file, from V8, SpiderMonkey and JavaScriptCore', () => {
    const user = `u${word(8)}`;
    const stack = [
      'TypeError: boom',
      '    at saveConfig (https://app.example.com/assets/index-B5t3Xk2a.js:1:2345)',
      '    at async Promise.all (index 0)',
      `    at file:///home/${user}/nostr/apps/sovereign-client/src/app.ts:12:3`,
      `    at C:\\Users\\${user}\\nostr\\packages\\profiles\\src\\disclose.ts:4:5`,
      '    at node:internal/process/task_queues:95:5',
      '    at eval (eval at <anonymous> (x.js:1:1), <anonymous>:1:1)',
      'saveConfig@https://app.example.com/assets/index-B5t3Xk2a.js:1:2345',
      'async*PanelView/<@http://localhost:5173/src/views/PanelView.tsx?t=17:30:20',
      `@/home/${user}/x/node_modules/@scope/pkg/dist/a.mjs:1:1`,
    ].join('\n');
    expect(cleanStack(stack)).toEqual([
      'at saveConfig (index-B5t3Xk2a.js:1:2345)',
      'at Promise.all (<anonymous>)',
      'at sovereign-client/app.ts:12:3',
      'at profiles/disclose.ts:4:5',
      'at node:internal/process/task_queues:95:5',
      'at eval (<eval>:1:1)',
      'at saveConfig (index-B5t3Xk2a.js:1:2345)',
      'at PanelView (PanelView.tsx:30:20)',
      'at @scope/pkg/a.mjs:1:1',
    ]);
    expect(JSON.stringify(cleanStack(stack))).not.toContain(user);
  });

  it('NFR007-03: the message keeps what the engines say about code and loses what carries data', () => {
    const user = `u${word(8)}`;
    const cases: Array<[string, string]> = [
      ["Cannot read properties of undefined (reading 'foo')", "Cannot read properties of undefined (reading 'foo')"],
      ['this.store.get is not a function', 'this.store.get is not a function'],
      ['can\'t access property "foo", e is undefined', 'can\'t access property "foo", e is undefined'],
      ['Ya escribiste desde tu persona "Trabajo"', 'Ya escribiste desde tu persona "[texto]"'],
      ['getaddrinfo ENOTFOUND relay.example.com', 'getaddrinfo ENOTFOUND [host]'],
      ['connect ECONNREFUSED 127.0.0.1:9050', 'connect ECONNREFUSED [ip]'],
      [`ENOENT: no such file or directory, open '/home/${user}/fuentes.txt'`, "ENOENT: no such file or directory, open '[ruta]'"],
      ['kind 10050 rejected at 1700000000123', 'kind 10050 rejected at [n]'],
      ['listen on [2001:db8::1]:443 at 12:30:45', 'listen on [ip] at 12:30:45'],
      ['id 550e8400-e29b-41d4-a716-446655440000', 'id [uuid]'],
      [`C:\\Users\\${user}\\AppData\\x.txt`, '[ruta]'],
      ['x {"kind":1,"content":"nos vemos en la plaza"} y', 'x {"[texto]"} y'],
      ['the users\' data is broken', "the users' data is broken"],
    ];
    for (const [input, output] of cases) expect(cleanCrashText(input), input).toBe(output);
    expect(cleanCrashText('palabra '.repeat(1000)).length).toBeLessThanOrEqual(CRASH_LIMITS.message);
    expect(cleanCrashText('palabra '.repeat(1000))).toMatch(/^(?:palabra )+palabra…$/);
  });

  it('NFR007-03: system and browser in a generic form: family and major version, never the user agent', () => {
    const uas: Array<[string, unknown]> = [
      ['Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.84 Safari/537.36', { os: 'linux', runtime: 'chrome', runtimeMajor: 128 }],
      ['Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0', { os: 'windows', runtime: 'firefox', runtimeMajor: 131 }],
      ['Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15', { os: 'macos', runtime: 'safari', runtimeMajor: 17 }],
      ['Mozilla/5.0 (Linux; Android 14; SM-S918B Build/UP1A.231005.007) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.70 Mobile Safari/537.36 EdgA/129.0.2792.84', { os: 'android', runtime: 'edge', runtimeMajor: 129 }],
      ['Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1', { os: 'ios', runtime: 'safari', runtimeMajor: 17 }],
      ['curl/8.0', { os: 'other', runtime: 'other' }],
    ];
    for (const [ua, env] of uas) {
      expect(browserEnvironment(ua)).toEqual(env);
      for (const part of ['SM-S918B', 'Win64', 'x86_64', 'AppleWebKit', '6613', 'UP1A']) expect(JSON.stringify(buildCrashReport(new Error('x'), ctx({ environment: browserEnvironment(ua) })))).not.toContain(part);
    }
    expect(nodeEnvironment('linux', '22.20.4')).toEqual({ os: 'linux', runtime: 'node', runtimeMajor: 22 });
    expect(nodeEnvironment('sunos', 'x')).toEqual({ os: 'other', runtime: 'node' });
    // Anything outside the lists is recorded as its fallback, never as given.
    expect(buildCrashReport(new Error('x'), ctx({ profile: 'persona-de-alicia', environment: { os: 'Ubuntu 24.04 alicia-laptop' as never, runtime: 'chrome' } }))).toMatchObject({ profile: 'custom', environment: { os: 'other', runtime: 'chrome' } });
  });
});

describe('the terminal line of a failure (NFR007-03)', () => {
  it('NFR007-03: redactFreeText removes secrets, URL credentials and queries, long keys, tokens and the home user, and keeps hosts and .onion', () => {
    const c = canaries();
    const text = `failed ${c.nsec} ${c.ncryptsec} wss://u:${c.urlUserinfo}@${c.host}/x?token=${c.urlToken} key ${c.pubkey} Authorization: Bearer ${c.bearer} ${c.jwt} password=${c.urlUserinfo}x open ${c.path} and /root/.data/x via ${c.onion}`;
    const out = redactFreeText(text, { home: '/root' });
    expect(leaks(out, c).sort()).toEqual(['host', 'onion'].sort());
    expect(out).toContain(`wss://${c.host}/x?[…]`);
    expect(out).toContain('~/.data/x');
    expect(out).toContain('/home/<usuario>/Documentos');
    // A path that is not under a home directory stays: it says what failed.
    expect(redactFreeText('empty passphrase file: /dev/null (SOVEREIGN_PASSPHRASE_FILE)', { home: '/root' })).toBe('empty passphrase file: /dev/null (SOVEREIGN_PASSPHRASE_FILE)');
    expect(redactFreeText('a /rootfs/x', { home: '/root' })).toBe('a /rootfs/x');
  });
});

/** A collection held in a Map: what an encrypted-store Collection does, without the sealing. */
function memoryCollection(): CrashReportCollection & { data: Map<string, StoredCrashReport> } {
  const data = new Map<string, StoredCrashReport>();
  return {
    data,
    put: async (id, value) => void data.set(id, structuredClone(value)),
    delete: async (id) => void data.delete(id),
    all: async () => [...data].map(([id, value]) => ({ id, value: structuredClone(value) })),
  };
}

/** Reports that differ only by their message (no stack, so the same call gives the same report). */
const distinct = (i: number) => buildCrashReport({ name: 'Error', message: `failure number ${i}` }, ctx());

describe('what each mode captures (NFR007-03)', () => {
  it('NFR007-03: off captures nothing, not even in memory: the thrown value is not read at all', () => {
    let reads = 0;
    const spy = new Proxy(new Error('x'), { get: (t, k) => (reads++, Reflect.get(t, k)), getPrototypeOf: (t) => (reads++, Reflect.getPrototypeOf(t)) });
    const capture = new CrashCapture({ app: 'acceso-nostr-web', appVersion: '0.1.0', environment: { os: 'linux', runtime: 'chrome' } });
    expect(capture.currentMode).toBe('off');
    expect(capture.capture(spy, 'error')).toBeUndefined();
    capture.configure({ mode: 'manual-export' });
    expect(capture.capture(new Error('a'), 'error')).toBeDefined();
    capture.configure({ mode: 'off' });
    expect(capture.lastReport()).toBeUndefined(); // off also forgets
    expect(capture.capture(spy, 'unhandledrejection')).toBeUndefined();
    capture.configure({ mode: 'debug' }); // unknown: off
    expect(capture.capture(spy, 'error')).toBeUndefined();
    expect(reads).toBe(0);
  });

  it('NFR007-03: manual-export keeps the last report in memory only; opt-in also keeps it in the store', async () => {
    const col = memoryCollection();
    const store = new CrashReportStore(col);
    const capture = new CrashCapture({ app: 'acceso-nostr-web', appVersion: '0.1.0', environment: { os: 'linux', runtime: 'chrome' } });
    capture.configure({ mode: 'manual-export', profile: 'convenience', store });
    const first = capture.capture(new Error('first'), 'error');
    const second = capture.capture(new Error('second'), 'unhandledrejection');
    expect(capture.lastReport()).toBe(second);
    expect([first?.profile, second?.source]).toEqual(['convenience', 'unhandledrejection']);
    await new Promise((r) => setTimeout(r, 10));
    expect(col.data.size).toBe(0); // given a store, manual-export still keeps nothing
    capture.configure({ mode: 'opt-in', profile: 'custom', store });
    const kept = capture.capture(new Error('kept'), 'component');
    await new Promise((r) => setTimeout(r, 10));
    expect((await store.list()).map((r) => r.report)).toEqual([kept]);
  });

  it('NFR007-03: at most ten captures a minute, so a failure loop cannot fill the store; listeners never break a capture', () => {
    let now = 1_000_000;
    let told = 0;
    const capture = new CrashCapture({ app: 'sovereign-cli', appVersion: '0.1.0', environment: { os: 'linux', runtime: 'node' }, now: () => now });
    capture.subscribe(() => {
      told++;
      throw new Error('listener');
    });
    capture.configure({ mode: 'manual-export' });
    const got = Array.from({ length: 12 }, (_, i) => capture.capture(new Error(`e${i}`), 'fatal'));
    expect(got.filter(Boolean)).toHaveLength(10);
    now += 60_001;
    expect(capture.capture(new Error('later'), 'fatal')).toBeDefined();
    expect(told).toBeGreaterThan(10);
  });
});

describe('local store of the reports (NFR007-03)', () => {
  it('NFR007-03: keeps at most maxReports and maxAgeDays, deleting from the store what is past either bound', async () => {
    let now = Date.UTC(2026, 9, 1);
    const col = memoryCollection();
    const store = new CrashReportStore(col, { now: () => now });
    for (let i = 0; i < CRASH_RETENTION.maxReports + 5; i++) {
      now += 1000;
      await store.save(distinct(i));
    }
    const kept = await store.list();
    expect(kept).toHaveLength(CRASH_RETENTION.maxReports);
    expect(col.data.size).toBe(CRASH_RETENTION.maxReports); // deleted, not hidden
    expect(kept[0]!.report).toEqual(distinct(CRASH_RETENTION.maxReports + 4)); // newest first
    now += CRASH_RETENTION.maxAgeDays * 86_400_000 - 19_000; // the oldest kept (saved 6 s in) is now exactly at the bound
    expect(await store.list()).toHaveLength(CRASH_RETENTION.maxReports);
    now += 1;
    expect(await store.list()).toHaveLength(CRASH_RETENTION.maxReports - 1);
    now += CRASH_RETENTION.maxAgeDays * 86_400_000;
    expect(await store.list()).toEqual([]);
    expect(col.data.size).toBe(0);
  });

  it('NFR007-03: the same failure counts again instead of taking another place; remove and clear delete for real', async () => {
    const col = memoryCollection();
    const store = new CrashReportStore(col);
    const a = await store.save(distinct(1));
    const again = await store.save(distinct(1));
    const b = await store.save(distinct(2));
    expect(again).toMatchObject({ id: a.id, count: 2 });
    expect(col.data.size).toBe(2);
    expect(await store.remove(a.id)).toBe(true);
    expect(await store.remove(a.id)).toBe(false);
    expect([...col.data.keys()]).toEqual([b.id]);
    expect(await store.clear()).toBe(1);
    expect(col.data.size).toBe(0);
  });

  it('NFR007-03: a record read back goes through the allowlist again: unknown fields, values out of their rule and non-reports are dropped or deleted', async () => {
    const c = canaries();
    const col = memoryCollection();
    const store = new CrashReportStore(col);
    const good = distinct(3);
    const tampered = { ...good, secret: c.nsec, app: { ...good.app, build: c.host }, error: { ...good.error, message: `${good.error.message} ${c.path}`, stack: [`at x (/home/${c.user}/a.js:1:1)`], extra: c.pubkey } };
    await col.put('tampered', { id: 'tampered', savedAt: Date.now(), count: 1, report: tampered as unknown as CrashReport });
    await col.put('garbage', { id: 'garbage', savedAt: Date.now(), count: 1, report: { format: 'other' } as unknown as CrashReport });
    await col.put('future', { id: 'future', savedAt: Date.now() + 3 * 86_400_000, count: 1, report: good });
    const listed = await store.list();
    expect(listed.map((r) => r.id)).toEqual(['tampered']);
    expect(leaks(JSON.stringify(listed), c)).toEqual([]);
    expect(listed[0]!.report.error.stack).toEqual(['at x (a.js:1:1)']);
    expect([...col.data.keys()]).toEqual(['tampered']);
  });
});

describe('no request, in any mode (NFR007-03)', () => {
  it('NFR007-03: the code of the reports has no network primitive, and capturing, keeping and exporting call none', async () => {
    const root = new URL('../../..', import.meta.url).pathname;
    for (const file of ['packages/telemetry-policy/src/crash-report.ts', 'packages/telemetry-policy/src/redact.ts', 'packages/telemetry-policy/src/rules.ts', 'apps/web-saas/src/lib/crash.ts', 'apps/web-saas/src/views/CrashReports.tsx', 'apps/sovereign-client/src/crash.ts']) {
      expect(readFileSync(`${root}${file}`, 'utf8'), file).not.toMatch(/\bfetch\(|XMLHttpRequest|WebSocket|sendBeacon|EventSource|node:(?:http|https|net|tls|dgram|dns)|['"]ws['"]/);
    }
    const g = globalThis as Record<string, unknown>;
    const saved = { fetch: g.fetch, WebSocket: g.WebSocket };
    let calls = 0;
    g.fetch = () => {
      calls++;
      throw new Error('no network');
    };
    g.WebSocket = class {
      constructor() {
        calls++;
        throw new Error('no network');
      }
    };
    try {
      const store = new CrashReportStore(memoryCollection());
      const capture = new CrashCapture({ app: 'acceso-nostr-web', appVersion: '0.1.0', environment: { os: 'linux', runtime: 'chrome' } });
      for (const mode of ['off', 'manual-export', 'opt-in'] as const) {
        capture.configure({ mode, store });
        const r = capture.capture(poisoned(canaries()), 'error');
        if (r) crashReportJson(r);
      }
      await new Promise((r) => setTimeout(r, 10));
      for (const r of await store.list()) crashReportJson(r.report);
    } finally {
      Object.assign(g, saved);
    }
    expect(calls).toBe(0);
  });
});
