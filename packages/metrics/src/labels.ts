import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

export interface RelayLabelOptions {
  /** Replace every relay host by a stable hash (telemetry level 'minimal': which relays a user talks to is a fingerprint). */
  pseudonymize?: boolean;
  /** Optional secret salt so hashed labels cannot be reversed by hashing a list of known relays. */
  salt?: string;
}

const hashLabel = (prefix: string, value: string, salt = '') => `${prefix}-${bytesToHex(sha256(new TextEncoder().encode(`${salt}\n${value}`))).slice(0, 12)}`;

/** A host label that could carry a user identifier (hex pubkey/event id, npub/nprofile…) is never emitted as is. */
const IDENTIFYING = /([0-9a-f]{32,})|(n(pub|profile|event|addr|sec)1[02-9ac-hj-np-z]{6,})/i;

/**
 * Metrics label for a relay (NFR004-01): the host only — never the scheme, path, query or credentials,
 * which may carry user-identifying data (e.g. wss://relay.example/npub1…?token=…). Onion relays and
 * hosts that look like identifiers get a stable hashed label instead (`onion-<12 hex>` / `relay-<12 hex>`).
 */
export function relayLabel(url: string, opts: RelayLabelOptions = {}): string {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return 'invalid';
  }
  const host = u.host.toLowerCase();
  if (!host) return 'invalid';
  if (u.hostname.toLowerCase().endsWith('.onion')) return hashLabel('onion', host, opts.salt);
  if (opts.pseudonymize || IDENTIFYING.test(host)) return hashLabel('relay', host, opts.salt);
  return host;
}

export type RegionMap = Record<string, string> | ((url: string) => string | undefined);

/**
 * Parses `RELAY_REGIONS`-style config: `host=region` or `wss://url=region` pairs separated by commas,
 * e.g. `relay.example=eu-west-1,ws://relay:3000=us-east-1`.
 */
export function parseRegionMap(raw: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const pair of (raw ?? '').split(',')) {
    const i = pair.lastIndexOf('=');
    if (i <= 0) continue;
    const key = pair.slice(0, i).trim().toLowerCase();
    const region = pair.slice(i + 1).trim();
    if (key && region) out[key] = region;
  }
  return out;
}

const REGION_RE = /^[a-z0-9][a-z0-9_.-]{0,62}$/i;

/** Region of a relay: exact URL, then host, then hostname; `defaultRegion` otherwise. Only short slug values are accepted. */
export function regionFor(url: string, map: RegionMap | undefined, defaultRegion = 'unknown'): string {
  let found: string | undefined;
  if (typeof map === 'function') found = map(url);
  else if (map) {
    const lower = url.toLowerCase().replace(/\/$/, '');
    let host = '';
    let hostname = '';
    try {
      const u = new URL(url);
      host = u.host.toLowerCase();
      hostname = u.hostname.toLowerCase();
    } catch {
      /* invalid url: default */
    }
    found = map[lower] ?? map[lower + '/'] ?? (host ? map[host] : undefined) ?? (hostname ? map[hostname] : undefined);
  }
  return found && REGION_RE.test(found) ? found : defaultRegion;
}
