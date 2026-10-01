/** Things that must never be logged (spec §18.1). */
const SECRET_PATTERNS: Array<[RegExp, string]> = [
  [/nsec1[02-9ac-hj-np-z]{20,}/gi, '[REDACTED:nsec]'],
  [/ncryptsec1[02-9ac-hj-np-z]{20,}/gi, '[REDACTED:ncryptsec]'],
  [/(bunker:\/\/[^\s"']*?[?&]secret=)[^&\s"']+/gi, '$1[REDACTED]'],
  [/(authorization["']?\s*[:=]\s*["']?)(Nostr|Bearer)\s+[A-Za-z0-9+/=._-]+/gi, '$1$2 [REDACTED]'],
];

const SENSITIVE_KEYS = /^(nsec|seed|secret|secretkey|secret_key|privkey|private_key|privatekey|sk|password|passphrase|token|recovery|recoverytoken|recovery_token|mnemonic|credential|passkey|plaintext|decrypted|authorization)$/i;
const IP_KEYS = /^(ip|ip_address|ipaddress|remote_addr|remoteaddress|x-forwarded-for|client_ip)$/i;

export interface RedactOptions {
  /** Drop IP address fields (profiles declaring IP minimisation). */
  minimizeIp?: boolean;
}

export function redactString(s: string): string {
  let out = s;
  for (const [re, rep] of SECRET_PATTERNS) out = out.replace(re, rep);
  return out;
}

/** Secrets that free text (an error message) can carry, beyond SECRET_PATTERNS. */
const FREE_TEXT_PATTERNS: Array<[RegExp, string | ((m: string) => string)]> = [
  // URL credentials and query strings: a token or a password travels there.
  [/\b([a-z][a-z0-9+.-]{1,20}:\/\/)[^\s/@"'<>]*@/gi, '$1'],
  [/\b([a-z][a-z0-9+.-]{1,20}:\/\/[^\s?#"'<>]*)[?#][^\s"'<>]*/gi, '$1?[…]'],
  [/\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g, '[token]'],
  // 64 hex characters or more: a secret key, a pubkey, an event id or a signature.
  [/[0-9a-f]{64,}/gi, '[hex]'],
  [/(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{32,}(?![A-Za-z0-9_-])/g, (m) => (/\d/.test(m) && /[A-Z]/.test(m) && /[a-z]/.test(m) ? '[token]' : m)],
  [/\b(access_token|refresh_token|id_token|token|secret|password|passphrase|passwd|pwd|api[_-]?key|auth)(\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s,;&)]+)/gi, '$1$2[…]'],
  [/\b(set-cookie|cookie)(\s*:\s*)[^\n]+/gi, '$1$2[…]'],
  // The user name of a home directory (Linux, macOS, Windows).
  [/(\/(?:var\/)?home\/|\/Users\/)[^/\s"'<>]+/g, '$1<usuario>'],
  [/\b([A-Za-z]:[\\/]Users[\\/])[^\\/\s"'<>]+/g, '$1<usuario>'],
];

/**
 * NFR007-03: secrets in free text meant for the person's own terminal (the fatal error line of the CLI): the patterns
 * of `redactString`, URL credentials and query strings, keys and ids of 64 hex characters, JWT and long tokens,
 * `token=`-like pairs, cookies and the user name of a home directory (`home`, when given, becomes `~`). Host names,
 * .onion addresses and the rest of a path stay: they say what failed. Crash reports, which the person may take out of
 * the device, go through the stricter `cleanCrashText`.
 */
export function redactFreeText(s: string, opts: { home?: string } = {}): string {
  let out = redactString(s);
  // Trailing separators off by hand: a `/[\\/]+$/` replace is polynomial on a long run of them (CodeQL js/polynomial-redos).
  let end = opts.home?.length ?? 0;
  while (end > 0 && (opts.home![end - 1] === '/' || opts.home![end - 1] === '\\')) end--;
  const home = opts.home?.slice(0, end);
  // A path of more than 1024 characters is no home directory (and would not compile as a RegExp): it is left alone.
  if (home && home.length > 1 && home.length <= 1024) out = out.replace(new RegExp(`${home.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![\\w.-])`, 'g'), '~');
  for (const [re, rep] of FREE_TEXT_PATTERNS) out = out.replace(re, rep as string);
  return out;
}

export function redact<T>(value: T, opts: RedactOptions = {}, depth = 0): T {
  if (depth > 8) return '[TRUNCATED]' as T;
  if (typeof value === 'string') return redactString(value) as T;
  if (value instanceof Uint8Array) return `[BYTES:${value.length}]` as T;
  if (Array.isArray(value)) return value.map((v) => redact(v, opts, depth + 1)) as T;
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      if (SENSITIVE_KEYS.test(k)) out[k] = '[REDACTED]';
      else if (opts.minimizeIp && IP_KEYS.test(k)) continue;
      else out[k] = redact(v, opts, depth + 1);
    }
    return out as T;
  }
  return value;
}
