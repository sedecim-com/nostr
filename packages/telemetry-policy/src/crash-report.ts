import { redactString } from './redact';
import { isErrorType, VALUE_LIKE } from './rules';

/*
 * NFR007-03: crash reports that never leave the device by themselves. No mode sends anything or makes a request: what
 * goes out, the person takes out by hand (a file they save). What the profile decides (`crashReports`):
 *  - 'off': nothing is captured, not even in memory (`CrashCapture.capture` returns before reading the thrown value);
 *  - 'manual-export': the clean report of the last failure, in memory only, for the person to see and save in a file;
 *  - 'opt-in': the same, and each report is also kept in the device's local encrypted store (CrashReportStore), at most
 *    CRASH_RETENTION.maxReports for CRASH_RETENTION.maxAgeDays, until the person deletes it.
 *
 * A report is built by an allowlist, like the spans of NFR007-02 (and with their rules, `./rules`): a fixed set of
 * fields, each made from a value that passes its rule; nothing of the thrown value is copied as it is. The free text
 * (the message) goes through `cleanCrashText`; a stack keeps only the frames that parse, cut down to the file of the
 * package or bundle; a value thrown that is not an error is recorded by its type only. No person, group or pubkey id
 * has a field, hashed or not.
 */

export const CRASH_REPORT_FORMAT = 'acceso-nostr-crash-report';
export const CRASH_REPORT_VERSION = 1;

export const CRASH_REPORTS_MODES = ['off', 'manual-export', 'opt-in'] as const;
export type CrashReportsMode = (typeof CRASH_REPORTS_MODES)[number];
/** Where a failure was caught: a global error, an unhandled rejection, a UI component, or a fatal error of the CLI. */
export const CRASH_SOURCES = ['error', 'unhandledrejection', 'component', 'fatal'] as const;
export type CrashSource = (typeof CRASH_SOURCES)[number];
export const CRASH_APPS = ['acceso-nostr-web', 'sovereign-cli'] as const;
export type CrashApp = (typeof CRASH_APPS)[number];
/** The preset of the persona (packages/profiles) or `custom`: never the persona. */
export const CRASH_PROFILES = ['convenience', 'private-resilient', 'institutional', 'sovereign', 'sovereign-tor', 'custom'] as const;
export type CrashProfile = (typeof CRASH_PROFILES)[number];
export const OS_FAMILIES = ['linux', 'macos', 'windows', 'android', 'ios', 'chromeos', 'other'] as const;
export type OsFamily = (typeof OS_FAMILIES)[number];
export const RUNTIME_FAMILIES = ['chrome', 'edge', 'firefox', 'safari', 'node', 'other'] as const;
export type RuntimeFamily = (typeof RUNTIME_FAMILIES)[number];

/** System and browser (or Node) in a generic form: the family and the major version, never a user agent. */
export interface CrashEnvironment {
  os: OsFamily;
  runtime: RuntimeFamily;
  runtimeMajor?: number;
}

export interface CrashErrorNode {
  /** Class of the error (`TypeError`, `DOMException`), `_OTHER` when it is not a plain class name, `_NonError` for a value. */
  name: string;
  /** The message after `cleanCrashText`; for a value that is not an error, its type only (`[string]`). */
  message: string;
  /** Frames `at fn (file:line:col)`, the file cut down to `package/file` or the bundle's file name. */
  stack: string[];
  cause?: CrashErrorNode;
  /** The errors of an AggregateError. */
  errors?: CrashErrorNode[];
}

/** Every field a report can have (the allowlist). */
export interface CrashReport {
  format: typeof CRASH_REPORT_FORMAT;
  version: typeof CRASH_REPORT_VERSION;
  app: { name: CrashApp; version: string };
  profile: CrashProfile;
  environment: CrashEnvironment;
  source: CrashSource;
  error: CrashErrorNode;
  /** The components a UI failure went through (React), as frames. */
  componentStack?: string[];
}

/** Bounds of a report, so that a failure loop or a huge message cannot make it large. */
export const CRASH_LIMITS = { input: 4000, message: 300, frames: 30, nestedFrames: 10, nodes: 12, depth: 4, errors: 8 } as const;
/** How many reports the local store keeps, and for how long (opt-in). */
export const CRASH_RETENTION = { maxReports: 20, maxAgeDays: 30 } as const;
const DAY_MS = 86_400_000;

const oneOf = <T extends string>(v: unknown, values: readonly T[], fallback: T): T => (typeof v === 'string' && (values as readonly string[]).includes(v) ? (v as T) : fallback);
const isRecord = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);

// ---- free text

/** Top-level domains a host name outside a URL is recognised by (plus every two-letter country domain). */
const TLDS = new Set(
  'com net org edu gov mil int info biz xyz io dev app ai me co tv fm im social chat network cloud online site space club pub news page link live life world zone tech email pro fun host works land band wine mom lol ninja rocks cafe garden center community digital media studio systems onion local localhost lan internal home arpa test example invalid'.split(' '),
);
/** File extensions, not domains (`index.js`, `README.md`, `run.sh`). */
const CODE_EXTS = new Set('js mjs cjs ts mts cts tsx jsx json map css html htm wasm md txt sh py rs so pl cc cs go rb kt hs ex vb fs ps db gz xz bz yml yaml toml lock log'.split(' '));
/** First labels of code expressions (`this.id`, `e.to`): what follows is a property, not a domain. */
const CODE_RECEIVERS = new Set('this self window globalthis document navigator location event err error res req props state ctx opts options config data args target'.split(' '));
const NET_CONTEXT = /(?:ENOTFOUND|EAI_AGAIN|ECONN[A-Z]+|ETIMEDOUT|EHOST[A-Z]+|ENET[A-Z]+|EPIPE|host(?:name)?:?|Host:|DNS:|servername:?)\s*$/i;

function hostLike(name: string, port: string | undefined, before: string): boolean {
  const labels = name.toLowerCase().split('.');
  const last = labels[labels.length - 1]!;
  if (CODE_EXTS.has(last)) return false;
  if (port !== undefined || NET_CONTEXT.test(before) || labels.some((l) => l.includes('-'))) return true;
  if (labels[0]!.length === 1 || CODE_RECEIVERS.has(labels[0]!)) return false;
  return TLDS.has(last) || /^[a-z]{2}$/.test(last);
}

/** A placeholder of these rules, alone or after a URL scheme (`'[ruta]'`, `"wss://[url]"`). */
const PLACEHOLDER = /^(?:(?:[a-z][a-z0-9+.-]{1,20}:\/\/)?\[[A-Za-z:…]+\](?::\d{1,5})?)?$/;
/** A property or expression name (`foo`, `this.store`). */
const CODE_NAME = /^[A-Za-z_$][\w$]{0,39}(?:\.[A-Za-z_$][\w$]{0,39}){0,4}$/;
/** Where the JavaScript engines quote a property name: `(reading 'x')`, `(evaluating 'a.b')`, `property "x"`. */
const CODE_QUOTE_CONTEXT = /(?:\((?:reading|setting|evaluating)|propert(?:y|ies)) $/;

const isWordChar = (c: string | undefined) => !!c && /[\p{L}\p{N}]/u.test(c);

/** The quoted spans of one kind, in order, and where an unclosed quote starts. An apostrophe in a word is no quote. */
function quoteSpans(s: string, open: string, close: string): { spans: Array<[number, number]>; unclosed?: number } {
  const spans: Array<[number, number]> = [];
  let start = -1;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c !== open && c !== close) continue;
    const single = open === "'";
    if (start < 0) {
      if (c === open && !(single && isWordChar(s[i - 1]))) start = i;
      else if (c === close && open !== close) return { spans, unclosed: i };
    } else if (c === close && !(single && isWordChar(s[i + 1]))) {
      spans.push([start, i]);
      start = -1;
    }
  }
  return start >= 0 ? { spans, unclosed: start } : { spans };
}

/**
 * Quoted text, where data travels in error messages (a JSON snippet, a value, a persona's label). A span stays if it
 * holds a placeholder, or a property name where the engines quote one; otherwise everything from that span to the
 * last one becomes `[texto]` (so a quote inside the content cannot leave part of it outside), and an unclosed quote
 * takes the rest of the message with it.
 */
function cleanQuotes(s: string): string {
  let out = s;
  for (const [open, close] of [['"', '"'], ["'", "'"], ['`', '`'], ['«', '»'], ['“', '”'], ['‘', '’']] as const) {
    const { spans, unclosed } = quoteSpans(out, open, close);
    const keep = ([a, b]: [number, number]) => {
      const inner = out.slice(a + 1, b);
      return PLACEHOLDER.test(inner) || (CODE_NAME.test(inner) && !VALUE_LIKE.test(inner) && CODE_QUOTE_CONTEXT.test(out.slice(Math.max(0, a - 16), a)));
    };
    const firstBad = spans.findIndex((span) => !keep(span));
    if (firstBad < 0 && unclosed === undefined) continue;
    const from = firstBad >= 0 ? spans[firstBad]![0] : unclosed!;
    out = unclosed !== undefined ? `${out.slice(0, from)}${open}[texto]` : `${out.slice(0, from)}${open}[texto]${close}${out.slice(spans[spans.length - 1]![1] + 1)}`;
  }
  return out;
}

type Replacement = string | ((match: string, ...rest: any[]) => string);

/** The rules of `cleanCrashText`, in order: the most specific shapes first, so that a later rule never sees them. */
const TEXT_RULES: Array<[RegExp, Replacement]> = [
  // V8 and Safari quote the start of what JSON.parse could not read: it can be the text of a message.
  [/\bUnexpected token '[^']*', ".*"(?:\.\.\.)? is not valid JSON/g, `Unexpected token '?', "[texto]" is not valid JSON`],
  [/\bJSON Parse error: Unexpected identifier "[^"]*"/g, 'JSON Parse error: Unexpected identifier "[texto]"'],
  [/\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g, '[token]'],
  // URLs keep their scheme only; a data: URI is content.
  [/\b([a-z][a-z0-9+.-]{1,20}):\/\/[^\s"'<>`(),;]*/gi, (_m, scheme: string) => `${scheme.toLowerCase()}://[url]`],
  [/\bdata:[a-z]+\/[a-z0-9.+-]+[^\s"'<>`]*/gi, 'data:[url]'],
  [/(?<![a-z0-9.-])(?:[a-z0-9-]+\.)*[a-z2-7]{16,56}\.onion\b(?::\d{1,5})?/gi, '[onion]'],
  [/(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b/g, '[email]'],
  [/\b(npub|nsec|nprofile|nevent|naddr|note|nrelay|ncryptsec)1[02-9ac-hj-np-z]{6,}/gi, (_m, hrp: string) => `[${hrp.toLowerCase()}]`],
  [/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, '[uuid]'],
  // File system paths: the user name is in them (home directories), and the rest may say what the person keeps.
  [/\b[A-Za-z]:[\\/](?:[^\\/\s"'<>|*?]+[\\/])*[^\\/\s"'<>|*?]*/g, '[ruta]'],
  [/\\\\[^\\\s"'<>]+(?:\\[^\\\s"'<>]+)+/g, '[ruta]'],
  [/(?<![\w.:/\]~])~\/[^\s"'<>]*/g, '[ruta]'],
  [/(?<![\w./\]~])\/(?:[^/\s"'<>()[\]]+\/)+[^/\s"'<>()[\]]*/g, '[ruta]'],
  [/(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])(?::\d{1,5})?/g, '[ip]'],
  [/\[[0-9a-f:.]*:[0-9a-f:.]*\](?::\d{1,5})?|(?<![0-9a-f:.])[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?![0-9a-f:.])/gi, (m) => (m.startsWith('[') || m.includes('::') || m.split(':').length === 8 ? '[ip]' : m)],
  [/\b(access_token|refresh_token|id_token|token|secret|password|passphrase|passwd|pwd|api[_-]?key|auth|authorization|cookie|session|sig|signature|otp|pin)(\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s,;&)]+)/gi, '$1$2[…]'],
  [/\b(set-cookie|cookie|proxy-authorization)(\s*:\s*)[^,;]+/gi, '$1$2[…]'],
  // Keys, ids and signatures in hex; a shorter run (a pubkey prefix, an id) when it mixes digits and letters.
  [/[0-9a-f]{16,}/gi, '[hex]'],
  [/(?<![0-9a-z])[0-9a-f]{8,15}(?![0-9a-z])/gi, (m) => (/\d/.test(m) && /[a-f]/i.test(m) ? '[hex]' : m)],
  [/(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])/g, (m) => (/\d/.test(m) && /[A-Za-z]/.test(m) ? '[token]' : m)],
  [/(?<![\w.@/:-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62})(:\d{1,5})?(?![\w-])/gi, (m: string, name: string, port: string | undefined, offset: number, whole: string) => (hostLike(name, port, whole.slice(Math.max(0, offset - 16), offset)) ? '[host]' : m)],
  // Long numbers: times, phone numbers, ids.
  [/(?<![\d.])\d{6,}(?![\d.])/g, '[n]'],
];

const replaceAll = (s: string, re: RegExp, rep: Replacement) => (typeof rep === 'string' ? s.replace(re, rep) : s.replace(re, rep));

const QUOTE_CHARS = ['"', "'", '`', '«', '“', '‘'];

/** Cuts at a space when there is one in the second half, and never leaves a quote open (it would be cleaned again). */
function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  let cut = s.slice(0, max - 1);
  const space = cut.lastIndexOf(' ');
  if (space > max / 2) cut = cut.slice(0, space);
  for (let i = 0; i < 8 && cleanQuotes(cut) !== cut; i++) cut = cut.slice(0, Math.max(0, ...QUOTE_CHARS.map((c) => cut.lastIndexOf(c))));
  return `${cut.trimEnd()}…`;
}

/**
 * The message of an error, made fit for a report (NFR007-03): secrets (`redactString`), URLs (only the scheme stays),
 * .onion addresses, e-mails, NIP-19 entities (npub, nsec, nprofile, nevent…, ncryptsec), UUIDs, file system paths,
 * IPs, `token=`-like pairs and cookies, hex runs, long tokens, host names, long numbers and quoted text are replaced
 * by a placeholder (`[url]`, `[host]`, `[ruta]`, `[texto]`…). One line, at most `max` characters. Idempotent.
 *
 * What has none of these shapes (plain words outside quotes) stays: a message built with the text of a chat message
 * would keep it. That is why the person sees the whole report before saving it.
 */
export function cleanCrashText(text: unknown, max: number = CRASH_LIMITS.message): string {
  if (typeof text !== 'string') return '';
  // Until nothing changes: cutting the text may leave a value that only a later pass recognises (`…8a2e:370:[hex]`).
  let out = text.slice(0, CRASH_LIMITS.input);
  for (let i = 0; i < 5; i++) {
    const next = cleanOnce(out, max);
    if (next === out) break;
    out = next;
  }
  return out;
}

function cleanOnce(text: string, max: number): string {
  let out = redactString(text.replace(/\s+/g, ' '));
  for (const [re, rep] of TEXT_RULES) out = replaceAll(out, re, rep);
  return truncate(cleanQuotes(out).replace(/\s+/g, ' ').trim(), max);
}

// ---- stacks

const FILE_NAME = /^[A-Za-z0-9_.@-]{1,80}\.(?:[cm]?js|jsx|[cm]?ts|tsx|wasm|html?)$/;
const PACKAGE_NAME = /^(?:@[a-z0-9][a-z0-9._~-]{0,40}\/)?[a-z0-9][a-z0-9._~-]{0,60}$/;
const FN_NAME = /^(?:new )?(?:<anonymous>|[A-Za-z_$][\w$]{0,63})(?:\.(?:<anonymous>|[A-Za-z_$#][\w$]{0,63})){0,5}$/;
/** A file or package name that carries a value (an id in hex, a NIP-19 entity) is no source file name. */
const DATA_IN_NAME = /[0-9a-f]{16}|(?:npub|nsec|nprofile|nevent|naddr|note|nrelay|ncryptsec)1/i;

/** A package name, never a host (`relay.example`, an IP, a .onion) or a value. */
const packageName = (p: string | undefined) => (p && PACKAGE_NAME.test(p) && !DATA_IN_NAME.test(p) && !/^[\d.]+$/.test(p) && !(p.includes('.') && hostLike(p, undefined, '')) && !/\.onion$/i.test(p) ? p : undefined);

/**
 * The file of a frame: `package/file` when the path goes through node_modules or the monorepo's packages, apps or
 * services, the file name otherwise (the bundle's `index-B5t3Xk2a.js`). Host, directories (and the user name in
 * them), query and hash are dropped; anything that is not a source file name gives undefined.
 */
function frameFile(raw: string): string | undefined {
  const f = raw.trim();
  if (f === '<anonymous>' || f === 'native' || f === '[native code]' || /^index \d+$/.test(f)) return '<anonymous>';
  if (/^node:[a-z_/]{1,60}$/.test(f)) return f;
  if (f.includes('eval at ')) return '<eval>';
  const relative = !/^[a-z][a-z0-9+.-]*:/i.test(f) && !/^[\\/~]/.test(f);
  const path = f
    .replace(/^[a-z][a-z0-9+.-]*:\/\/[^/]*/i, '')
    .replace(/^[a-z][a-z0-9+.-]*:(?![\\/])/i, '')
    .replace(/[?#].*$/, '');
  const segs = path.split(/[\\/]+/).filter(Boolean);
  const base = segs[segs.length - 1];
  if (!base || !FILE_NAME.test(base) || DATA_IN_NAME.test(base)) return undefined;
  // Already `package/file` (a report read back from the store).
  if (relative && segs.length >= 2 && segs.length <= 3 && packageName(segs.slice(0, -1).join('/'))) return segs.join('/');
  let pkg: string | undefined;
  const nm = segs.lastIndexOf('node_modules');
  if (nm >= 0 && nm < segs.length - 2) pkg = segs[nm + 1]!.startsWith('@') && nm < segs.length - 3 ? `${segs[nm + 1]}/${segs[nm + 2]}` : segs[nm + 1];
  else {
    const root = Math.max(segs.lastIndexOf('packages'), segs.lastIndexOf('apps'), segs.lastIndexOf('services'));
    if (root >= 0 && root < segs.length - 2) pkg = segs[root + 1];
  }
  return packageName(pkg) ? `${pkg}/${base}` : base;
}

function frameFn(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  // V8 prefixes (async, new) and Gecko's markers (async*fn, outer/inner/<).
  const fn = raw
    .trim()
    .replace(/^async\s+/, '')
    .replace(/^.*\*/, '')
    .replace(/(?:\/<)+$/, '')
    .replace(/\/(?=[A-Za-z_$<])/g, '.');
  return fn && FN_NAME.test(fn) && !VALUE_LIKE.test(fn.replace(/^new /, '')) ? fn : undefined;
}

/**
 * One frame in the V8 format (`at fn (file:line:col)`), or undefined when it does not parse. A live V8 frame is
 * indented (a line of the message that starts with «at» is not a frame); a stored one, already clean, is not.
 */
function cleanFrame(line: string, stored: boolean): string | undefined {
  let fn: string | undefined;
  let loc: string | undefined;
  const v8 = (stored ? /^\s*at\s+(.+?)\s*$/ : /^\s+at\s+(.+?)\s*$/).exec(line);
  if (v8) {
    const rest = v8[1]!;
    const call = /^(.*?) \((.*)\)$/.exec(rest);
    if (call) [fn, loc] = [call[1], call[2]];
    else if (/:\d+(?::\d+)?$/.test(rest) || /[\\/]/.test(rest)) loc = rest;
    else fn = rest;
  } else {
    const gecko = /^\s*(.*?)@(\S+)\s*$/.exec(line);
    if (!gecko) return undefined;
    [fn, loc] = [gecko[1], gecko[2]];
  }
  const name = frameFn(fn);
  if (loc === undefined) return name ? `at ${name}` : undefined;
  const pos = /^(.*?)(?::(\d{1,7}))?(?::(\d{1,7}))?$/.exec(loc);
  const file = pos ? frameFile(pos[1]!) : undefined;
  if (!file) return name ? `at ${name} (?)` : undefined;
  const where = pos?.[2] ? `${file}:${pos[2]}${pos[3] ? `:${pos[3]}` : ''}` : file;
  return name ? `at ${name} (${where})` : `at ${where}`;
}

/**
 * The frames of a stack that parse (V8, SpiderMonkey or JavaScriptCore), cleaned. The header (`TypeError: message`)
 * is never a frame: the caller strips the message (`withoutMessage`) and a V8 frame must be indented.
 */
export function cleanStack(stack: unknown, max: number = CRASH_LIMITS.frames, stored = false): string[] {
  if (typeof stack !== 'string') return [];
  const out: string[] = [];
  for (const line of stack.slice(0, 20_000).split('\n').slice(0, 200)) {
    if (out.length >= max) break;
    // No frame is that long (and a long line would make the frame patterns slow).
    if (line.length > 600) continue;
    const frame = cleanFrame(line, stored);
    if (frame) out.push(frame);
  }
  return out;
}

/** A V8 stack starts with `name: message`: that header, and the lines of the message in it, are dropped. */
function withoutMessage(stack: unknown, message: string): unknown {
  if (typeof stack !== 'string' || !message) return stack;
  const at = stack.indexOf(message);
  return at >= 0 && at < 200 ? stack.slice(at + message.length) : stack;
}

// ---- errors

/** A class name: capitalised words without digits (the `error.type` rule of the traces), with acronyms (`DOMException`). */
function isClassName(v: unknown): v is string {
  if (typeof v !== 'string' || v.length > 64) return false;
  return (isErrorType(v) && !/^\d/.test(v)) || (/^(?:[A-Z][a-z]{1,14}|[A-Z]{2,5}(?=[A-Z][a-z]|$))+$/.test(v) && !VALUE_LIKE.test(v));
}

interface Budget {
  nodes: number;
  seen: WeakSet<object>;
}

/** Reads one property; a getter or a proxy that throws reads as undefined. */
function read(obj: object, key: string): unknown {
  try {
    return (obj as Record<string, unknown>)[key];
  } catch {
    return undefined;
  }
}

function constructorName(obj: object): unknown {
  try {
    return (Object.getPrototypeOf(obj) as { constructor?: { name?: unknown } } | null)?.constructor?.name;
  } catch {
    return undefined;
  }
}

function errorNode(thrown: unknown, depth: number, budget: Budget): CrashErrorNode {
  budget.nodes--;
  if (thrown === null || (typeof thrown !== 'object' && typeof thrown !== 'function')) return { name: '_NonError', message: `[${thrown === null ? 'null' : typeof thrown}]`, stack: [] };
  const message = read(thrown, 'message');
  // Only something with a message is read as an error (also one from another realm); anything else, by its type.
  if (typeof message !== 'string') return { name: '_NonError', message: `[${typeof thrown === 'function' ? 'function' : 'object'}]`, stack: [] };
  budget.seen.add(thrown);
  const name = [read(thrown, 'name'), constructorName(thrown)].find(isClassName) ?? '_OTHER';
  const node: CrashErrorNode = { name, message: cleanCrashText(message), stack: cleanStack(withoutMessage(read(thrown, 'stack'), message), depth === 0 ? CRASH_LIMITS.frames : CRASH_LIMITS.nestedFrames) };
  if (depth >= CRASH_LIMITS.depth) return node;
  const unseen = (v: unknown) => !(v !== null && typeof v === 'object' && budget.seen.has(v));
  const cause = read(thrown, 'cause');
  if (cause !== undefined && budget.nodes > 0 && unseen(cause)) node.cause = errorNode(cause, depth + 1, budget);
  const errors = read(thrown, 'errors');
  if (Array.isArray(errors)) {
    const list: CrashErrorNode[] = [];
    for (let i = 0; i < Math.min(errors.length, CRASH_LIMITS.errors) && budget.nodes > 0; i++) {
      const e = read(errors, String(i));
      if (unseen(e)) list.push(errorNode(e, depth + 1, budget));
    }
    if (list.length) node.errors = list;
  }
  return node;
}

// ---- environment

/** The family and major version of the browser and the system, from a user agent that is read here and not kept. */
export function browserEnvironment(userAgent: unknown): CrashEnvironment {
  const ua = typeof userAgent === 'string' ? userAgent.slice(0, 512) : '';
  const os: OsFamily = /Android/.test(ua) ? 'android' : /iPhone|iPad|iPod/.test(ua) ? 'ios' : /CrOS/.test(ua) ? 'chromeos' : /Windows/.test(ua) ? 'windows' : /Mac OS X|Macintosh/.test(ua) ? 'macos' : /Linux|X11/.test(ua) ? 'linux' : 'other';
  const browsers: Array<[RuntimeFamily, RegExp]> = [
    ['edge', /Edg(?:e|A|iOS)?\/(\d+)/],
    ['firefox', /(?:Firefox|FxiOS)\/(\d+)/],
    ['chrome', /(?:Chrome|CriOS)\/(\d+)/],
    ['safari', /Version\/(\d+)[^ ]* (?:Mobile\/\S+ )?Safari\//],
  ];
  for (const [runtime, re] of browsers) {
    const m = re.exec(ua);
    if (m) return cleanEnvironment({ os, runtime, runtimeMajor: Number(m[1]) });
  }
  return { os, runtime: 'other' };
}

/** The same for the CLI: `process.platform` and `process.versions.node`. */
export function nodeEnvironment(platform: unknown, nodeVersion: unknown): CrashEnvironment {
  const os: OsFamily = platform === 'linux' ? 'linux' : platform === 'darwin' ? 'macos' : platform === 'win32' ? 'windows' : platform === 'android' ? 'android' : 'other';
  return cleanEnvironment({ os, runtime: 'node', runtimeMajor: Number(String(nodeVersion).split('.')[0]) });
}

function cleanEnvironment(e: unknown): CrashEnvironment {
  const r = isRecord(e) ? e : {};
  const major = r.runtimeMajor;
  return { os: oneOf(r.os, OS_FAMILIES, 'other'), runtime: oneOf(r.runtime, RUNTIME_FAMILIES, 'other'), ...(typeof major === 'number' && Number.isInteger(major) && major > 0 && major < 1000 ? { runtimeMajor: major } : {}) };
}

const appVersion = (v: unknown) => (typeof v === 'string' && /^\d{1,3}\.\d{1,3}\.\d{1,3}(?:-[0-9A-Za-z.]{1,20})?$/.test(v) ? v : '0.0.0');

// ---- reports

export interface CrashContext {
  app: CrashApp;
  appVersion: string;
  /** The preset of the active persona or `custom`; anything else is recorded as `custom`. */
  profile: string;
  environment: CrashEnvironment;
  source: CrashSource;
  /** React's component stack of a UI failure. */
  componentStack?: string;
}

/** The report of one failure, built by the allowlist. Never throws: an unreadable value gives a report that says so. */
export function buildCrashReport(thrown: unknown, ctx: CrashContext): CrashReport {
  let error: CrashErrorNode;
  try {
    error = errorNode(thrown, 0, { nodes: CRASH_LIMITS.nodes, seen: new WeakSet() });
  } catch {
    error = { name: '_OTHER', message: '[unreadable]', stack: [] };
  }
  const componentStack = cleanStack(ctx.componentStack, CRASH_LIMITS.frames);
  return {
    format: CRASH_REPORT_FORMAT,
    version: CRASH_REPORT_VERSION,
    app: { name: oneOf(ctx.app, CRASH_APPS, CRASH_APPS[0]), version: appVersion(ctx.appVersion) },
    profile: oneOf(ctx.profile, CRASH_PROFILES, 'custom'),
    environment: cleanEnvironment(ctx.environment),
    source: oneOf(ctx.source, CRASH_SOURCES, 'error'),
    error,
    ...(componentStack.length ? { componentStack } : {}),
  };
}

function parseNode(v: unknown, depth: number, budget: { nodes: number }): CrashErrorNode | undefined {
  if (!isRecord(v) || budget.nodes-- <= 0) return undefined;
  const name = v.name === '_NonError' || v.name === '_OTHER' || isClassName(v.name) ? (v.name as string) : '_OTHER';
  const frames = Array.isArray(v.stack) ? v.stack.filter((f): f is string => typeof f === 'string').join('\n') : '';
  const node: CrashErrorNode = { name, message: cleanCrashText(v.message), stack: cleanStack(frames, depth === 0 ? CRASH_LIMITS.frames : CRASH_LIMITS.nestedFrames, true) };
  if (depth >= CRASH_LIMITS.depth) return node;
  const cause = parseNode(v.cause, depth + 1, budget);
  if (cause) node.cause = cause;
  if (Array.isArray(v.errors)) {
    const errors = v.errors.slice(0, CRASH_LIMITS.errors).flatMap((e) => parseNode(e, depth + 1, budget) ?? []);
    if (errors.length) node.errors = errors;
  }
  return node;
}

/**
 * A report read back (from the store, before showing or exporting it): rebuilt by the same allowlist and rules, so an
 * unknown field or a value out of its rule never gets through, whatever the record holds. Undefined if it is not one.
 */
export function parseCrashReport(v: unknown): CrashReport | undefined {
  if (!isRecord(v) || v.format !== CRASH_REPORT_FORMAT || v.version !== CRASH_REPORT_VERSION || !isRecord(v.app)) return undefined;
  const error = parseNode(v.error, 0, { nodes: CRASH_LIMITS.nodes });
  if (!error) return undefined;
  const componentStack = Array.isArray(v.componentStack) ? cleanStack(v.componentStack.filter((f): f is string => typeof f === 'string').join('\n'), CRASH_LIMITS.frames, true) : [];
  return {
    format: CRASH_REPORT_FORMAT,
    version: CRASH_REPORT_VERSION,
    app: { name: oneOf(v.app.name, CRASH_APPS, CRASH_APPS[0]), version: appVersion(v.app.version) },
    profile: oneOf(v.profile, CRASH_PROFILES, 'custom'),
    environment: cleanEnvironment(v.environment),
    source: oneOf(v.source, CRASH_SOURCES, 'error'),
    error,
    ...(componentStack.length ? { componentStack } : {}),
  };
}

/** Exactly what is shown before exporting and what the exported file holds. */
export function crashReportJson(report: CrashReport): string {
  return `${JSON.stringify(report, null, 2)}\n`;
}

/** One line for a list: the class and the start of the message. */
export function crashSummary(report: CrashReport): string {
  const line = `${report.error.name}: ${report.error.message}`;
  return line.length > 120 ? `${line.slice(0, 119)}…` : line;
}

// ---- local store (opt-in)

/** A report kept in the device's encrypted store. `savedAt` and `count` stay in the store: they are not exported. */
export interface StoredCrashReport {
  id: string;
  /** Last time this report was captured (ms), for the retention. */
  savedAt: number;
  /** Times the same report was captured. */
  count: number;
  report: CrashReport;
}

/** The part of an encrypted-store Collection the reports use (the web's and the CLI's stores both fit). */
export interface CrashReportCollection {
  put(id: string, value: StoredCrashReport): Promise<void>;
  delete(id: string): Promise<void>;
  all(): Promise<Array<{ id: string; value: StoredCrashReport }>>;
}

export interface CrashStoreOptions {
  maxReports?: number;
  maxAgeMs?: number;
  now?: () => number;
}

const randomId = () => Array.from(globalThis.crypto.getRandomValues(new Uint8Array(8)), (b) => b.toString(16).padStart(2, '0')).join('');

/**
 * The reports kept on the device (opt-in), in a collection of its encrypted store: at most `maxReports`, each for at
 * most `maxAgeMs` since it was last captured; past either bound, a report is deleted from the store, not hidden. A
 * record that is not a valid report is deleted too.
 */
export class CrashReportStore {
  private readonly maxReports: number;
  private readonly maxAgeMs: number;
  private readonly now: () => number;

  constructor(
    private readonly col: CrashReportCollection,
    opts: CrashStoreOptions = {},
  ) {
    this.maxReports = opts.maxReports ?? CRASH_RETENTION.maxReports;
    this.maxAgeMs = opts.maxAgeMs ?? CRASH_RETENTION.maxAgeDays * DAY_MS;
    this.now = opts.now ?? Date.now;
  }

  /** The reports kept, newest first, after applying the retention. */
  async list(): Promise<StoredCrashReport[]> {
    const now = this.now();
    const keep: StoredCrashReport[] = [];
    for (const { id, value } of await this.col.all()) {
      const report = isRecord(value) ? parseCrashReport(value.report) : undefined;
      const savedAt = isRecord(value) && typeof value.savedAt === 'number' ? value.savedAt : NaN;
      // Too old, dated in the future (a clock that went back) or not a report: deleted.
      if (!report || !(now - savedAt <= this.maxAgeMs) || savedAt > now + DAY_MS) await this.col.delete(id);
      else keep.push({ id, savedAt, count: isRecord(value) && Number.isInteger(value.count) && (value.count as number) > 0 ? (value.count as number) : 1, report });
    }
    keep.sort((a, b) => b.savedAt - a.savedAt);
    for (const extra of keep.splice(this.maxReports)) await this.col.delete(extra.id);
    return keep;
  }

  /** Keeps a report; the same report captured again counts once more instead of taking another place. */
  async save(report: CrashReport): Promise<StoredCrashReport> {
    const clean = parseCrashReport(report);
    if (!clean) throw new Error('not a crash report');
    const json = crashReportJson(clean);
    const same = (await this.list()).find((r) => crashReportJson(r.report) === json);
    const record: StoredCrashReport = same ? { ...same, savedAt: this.now(), count: same.count + 1 } : { id: randomId(), savedAt: this.now(), count: 1, report: clean };
    await this.col.put(record.id, record);
    await this.list();
    return record;
  }

  async get(id: string): Promise<StoredCrashReport | undefined> {
    return (await this.list()).find((r) => r.id === id);
  }

  async remove(id: string): Promise<boolean> {
    const found = (await this.list()).some((r) => r.id === id);
    if (found) await this.col.delete(id);
    return found;
  }

  /** Deletes every report from the store; returns how many there were. */
  async clear(): Promise<number> {
    const all = await this.col.all();
    for (const { id } of all) await this.col.delete(id);
    return all.length;
  }
}

// ---- capture

export interface CrashCaptureOptions {
  app: CrashApp;
  appVersion: string;
  environment: CrashEnvironment;
  /** At most this many failures are captured per minute (default 10): a failure loop cannot fill the store. */
  maxPerMinute?: number;
  now?: () => number;
}

/**
 * What a client does with a failure, as the active persona's profile says (`configure`). Holds the last report in
 * memory ('manual-export' and 'opt-in') and, with a store, keeps each one there ('opt-in'). Never throws and never
 * makes a request.
 */
export class CrashCapture {
  private mode: CrashReportsMode = 'off';
  private profile = 'custom';
  private store: CrashReportStore | undefined;
  private last: CrashReport | undefined;
  private readonly recent: number[] = [];
  private readonly listeners = new Set<() => void>();
  private rev = 0;
  private readonly now: () => number;

  constructor(private readonly opts: CrashCaptureOptions) {
    this.now = opts.now ?? Date.now;
  }

  /** 'off' also forgets the last report; a store is used in 'opt-in' only. An unknown mode is 'off'. */
  configure(c: { mode: unknown; profile?: string; store?: CrashReportStore }): void {
    this.mode = oneOf(c.mode, CRASH_REPORTS_MODES, 'off');
    this.profile = c.profile ?? 'custom';
    this.store = this.mode === 'opt-in' ? c.store : undefined;
    if (this.mode === 'off') this.last = undefined;
    this.changed();
  }

  get currentMode(): CrashReportsMode {
    return this.mode;
  }

  /** The store the reports go to now (opt-in with a store), if any. */
  get currentStore(): CrashReportStore | undefined {
    return this.store;
  }

  /** The clean report of a failure, or undefined when the mode is 'off' (the value is then not even read) or the rate is exceeded. */
  capture(thrown: unknown, source: CrashSource, extra: { componentStack?: string } = {}): CrashReport | undefined {
    if (this.mode === 'off') return undefined;
    const now = this.now();
    while (this.recent.length && now - this.recent[0]! > 60_000) this.recent.shift();
    if (this.recent.length >= (this.opts.maxPerMinute ?? 10)) return undefined;
    this.recent.push(now);
    const report = buildCrashReport(thrown, { app: this.opts.app, appVersion: this.opts.appVersion, environment: this.opts.environment, profile: this.profile, source, ...(extra.componentStack !== undefined ? { componentStack: extra.componentStack } : {}) });
    this.last = report;
    this.changed();
    this.store?.save(report).then(
      () => this.changed(),
      () => undefined,
    );
    return report;
  }

  /** The last report of this session (memory only). */
  lastReport(): CrashReport | undefined {
    return this.last;
  }

  forgetLast(): void {
    this.last = undefined;
    this.changed();
  }

  /** For useSyncExternalStore: told of every change (capture, forget, configure, a report kept). */
  readonly subscribe = (fn: () => void): (() => void) => {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  };

  readonly revision = (): number => this.rev;

  /** Tells the subscribers that something changed (e.g. the store after a deletion). */
  changed(): void {
    this.rev++;
    for (const fn of this.listeners) {
      try {
        fn();
      } catch {
        // A listener never breaks a capture.
      }
    }
  }
}
