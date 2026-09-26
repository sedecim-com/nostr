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
