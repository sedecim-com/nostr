/**
 * Leak analysis of a network capture (FR020-03) and egress allowlist check (FR022-02).
 *
 * The capture is taken on the only interface of a network namespace that runs the sovereign CLI. A
 * packet the client emits is acceptable only when it goes to an allowed endpoint (the SOCKS proxy in
 * the Tor profile, the persona's relays in a direct profile). Everything else is a finding:
 *  - dns:    UDP/TCP 53, DoT 853, mDNS 5353, LLMNR 5355 (the name left the client unresolved by Tor)
 *  - doh:    HTTPS to a well-known DNS-over-HTTPS resolver
 *  - ipv6:   any IPv6 packet other than the kernel's own neighbour discovery / MLD on the link
 *  - direct: any other TCP/UDP/ICMP packet to a destination outside the allowlist
 */
import type { Packet } from './pcap';

export type FindingKind = 'dns' | 'doh' | 'ipv6' | 'direct';

export interface Endpoint {
  ip: string;
  port: number;
  protocol?: 'tcp' | 'udp';
}

export interface LeakPolicy {
  /** Addresses of the client side (the namespace); packets from other sources are inbound. */
  clientAddrs: string[];
  /** Endpoints the client may talk to. */
  allowed: Endpoint[];
}

export interface Finding {
  kind: FindingKind;
  ts: number;
  src: string;
  dst: string;
  protocol: string;
  detail: string;
}

export interface LeakReport {
  packets: number;
  /** Outbound IP packets that were checked */
  outbound: number;
  /** Distinct outbound destinations ("tcp 10.0.0.1:9050") */
  destinations: string[];
  findings: Finding[];
  /** Findings per kind */
  counts: Record<FindingKind, number>;
}

/** Public DoH resolvers (Google, Cloudflare, Quad9, OpenDNS, AdGuard, Mullvad, NextDNS...). */
export const DOH_RESOLVERS = new Set([
  '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9', '149.112.112.112', '208.67.222.222', '208.67.220.220',
  '94.140.14.14', '94.140.15.15', '194.242.2.2', '45.90.28.0', '45.90.30.0', '2001:4860:4860::8888',
  '2001:4860:4860::8844', '2606:4700:4700::1111', '2606:4700:4700::1001', '2620:fe::fe', '2620:fe::9',
]);
const DNS_PORTS = new Map([
  [53, 'DNS'],
  [853, 'DNS-over-TLS'],
  [5353, 'mDNS'],
  [5355, 'LLMNR'],
]);
/** ICMPv6 the kernel emits by itself on a link: MLD (130-132, 143), RS/RA/NS/NA/redirect (133-137). */
const LINK_ICMPV6 = new Set([130, 131, 132, 133, 134, 135, 136, 137, 143]);
const PROTO: Record<number, string> = { 1: 'icmp', 6: 'tcp', 17: 'udp', 58: 'icmpv6' };

const endpointKey = (protocol: string, ip: string, port?: number) => (port === undefined ? `${protocol} ${ip}` : `${protocol} ${ip.includes(':') ? `[${ip}]` : ip}:${port}`);

export function parseEndpoint(s: string): Endpoint {
  const m = /^(?:(tcp|udp)\/)?(?:\[([0-9a-f:]+)\]|([^:]+)):(\d+)$/i.exec(s.trim());
  if (!m) throw new Error(`invalid endpoint (expected [tcp/]ip:port): ${s}`);
  return { ip: (m[2] ?? m[3])!, port: Number(m[4]), ...(m[1] ? { protocol: m[1].toLowerCase() as 'tcp' | 'udp' } : {}) };
}

export function analyzeCapture(packets: Packet[], policy: LeakPolicy): LeakReport {
  const findings: Finding[] = [];
  const destinations = new Set<string>();
  let outbound = 0;
  const allowed = (proto: string, ip: string, port?: number) => policy.allowed.some((e) => e.ip === ip && e.port === port && (!e.protocol || e.protocol === proto));
  for (const p of packets) {
    const ip = p.ip;
    if (!ip) continue; // ARP and other link-layer frames carry no destination beyond the link
    const proto = PROTO[ip.protocol] ?? `ip-proto-${ip.protocol}`;
    const add = (kind: FindingKind, detail: string) => findings.push({ kind, ts: p.ts, src: ip.src, dst: ip.dst, protocol: proto, detail });
    if (ip.version === 6) {
      if (ip.protocol === 58 && LINK_ICMPV6.has(ip.icmpType ?? -1) && (ip.dst.startsWith('ff02:') || ip.src.startsWith('fe80:') || ip.src === '::')) continue;
      outbound++;
      destinations.add(endpointKey(proto, ip.dst, ip.dstPort));
      const service = ip.dstPort !== undefined ? DNS_PORTS.get(ip.dstPort) : undefined;
      add('ipv6', `IPv6 ${endpointKey(proto, ip.dst, ip.dstPort)}${service ? ` (${service})` : ''}`);
      if (service) add('dns', `${service} over IPv6 to ${ip.dst}`);
      continue;
    }
    if (!policy.clientAddrs.includes(ip.src)) continue; // inbound: replies, ICMP errors from the host side
    if (ip.protocol === 2) continue; // IGMP membership reports (multicast bookkeeping of the kernel)
    outbound++;
    destinations.add(endpointKey(proto, ip.dst, ip.dstPort));
    if (allowed(proto, ip.dst, ip.dstPort)) continue;
    const service = ip.dstPort !== undefined ? DNS_PORTS.get(ip.dstPort) : undefined;
    if (service) add('dns', `${service} to ${endpointKey(proto, ip.dst, ip.dstPort)}`);
    else if (proto === 'tcp' && ip.dstPort === 443 && DOH_RESOLVERS.has(ip.dst)) add('doh', `HTTPS to public DoH resolver ${ip.dst}`);
    else add('direct', `connection outside the allowlist: ${endpointKey(proto, ip.dst, ip.dstPort)}`);
  }
  const counts: Record<FindingKind, number> = { dns: 0, doh: 0, ipv6: 0, direct: 0 };
  for (const f of findings) counts[f.kind]++;
  return { packets: packets.length, outbound, destinations: [...destinations].sort(), findings, counts };
}

/** One CONNECT request as logged by the SOCKS stub (the destination Tor would have been asked for). */
export interface SocksRequest {
  host: string;
  port: number;
  addressType: 'ipv4' | 'domain' | 'ipv6';
  /** RFC 1929 username the client authenticated with (logged since FR006-06). */
  username?: string;
}

/**
 * Egress allowlist of a persona as the real client enforces it (NetworkGuard): the hosts of its relays.
 * Built from `sovereign persona list` output so the test checks the configuration the CLI stored.
 */
export interface PersonaEgress {
  id: string;
  network: 'direct' | 'tor-only';
  relays: URL[];
}

export function parsePersonaList(stdout: string): PersonaEgress[] {
  return stdout
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
    .map((line) => {
      const cols = line.split(/\s+/);
      const network = cols.find((c) => c === 'direct' || c === 'tor-only') as PersonaEgress['network'] | undefined;
      const relays = cols[cols.length - 1]!;
      if (!network || !/^wss?:\/\//.test(relays)) throw new Error(`unexpected persona list line: ${line}`);
      return { id: cols[0]!, network, relays: relays.split(',').map((r) => new URL(r)) };
    });
}

const defaultPort = (u: URL) => Number(u.port || (u.protocol === 'wss:' || u.protocol === 'https:' ? 443 : 80));

/**
 * Network-level allowlist for a profile: Tor-only personas may only reach the SOCKS proxy; direct
 * personas only their relays (the harness uses IP-literal relays, so no resolution is involved).
 */
export function networkAllowlist(p: PersonaEgress, socks: Endpoint): Endpoint[] {
  if (p.network === 'tor-only') return [{ ...socks, protocol: 'tcp' }];
  return p.relays.map((u) => {
    const host = u.hostname.replace(/^\[|\]$/g, '');
    if (!/^[\d.]+$/.test(host) && !host.includes(':')) throw new Error(`direct relay ${u.href} must be an IP literal in the harness (a hostname needs DNS)`);
    return { ip: host, port: defaultPort(u), protocol: 'tcp' as const };
  });
}

/**
 * SOCKS-level check: in the Tor profile every CONNECT must name an allowlisted relay host by name
 * (socks5h: resolution inside Tor, never an address the client resolved locally).
 *
 * `requireIsolation` (FR006-06): every CONNECT of a Tor persona authenticated with the persona id as SOCKS username,
 * so Tor (IsolateSOCKSAuth) keeps each persona on its own circuits. Logs recorded before usernames were logged
 * cannot show it.
 *
 * FR020-05: `extraHosts` (`host:port`) are other names the personas may reach through Tor besides their relays: the
 * Blossom server of their group files, the policy-engine of the rotation worker. With several personas (two users of
 * the CLI in one capture), each CONNECT is judged against the persona its SOCKS username names.
 */
export function checkSocksRequests(requests: SocksRequest[], personas: PersonaEgress | PersonaEgress[], opts: { requireIsolation?: boolean; extraHosts?: string[] } = {}): string[] {
  const list = Array.isArray(personas) ? personas : [personas];
  const problems: string[] = [];
  const hostsOf = (ps: PersonaEgress[]) => new Set([...ps.flatMap((p) => p.relays.map((u) => `${u.hostname}:${defaultPort(u)}`)), ...(opts.extraHosts ?? [])]);
  if (list.every((p) => p.network !== 'tor-only') && requests.length) problems.push(`direct persona used the SOCKS proxy (${requests.length} requests)`);
  for (const r of requests) {
    const owner = list.length === 1 ? list[0] : list.find((p) => p.id === r.username);
    const hosts = hostsOf(owner ? [owner] : list);
    if (r.addressType !== 'domain') problems.push(`SOCKS CONNECT by ${r.addressType} address ${r.host}: the client resolved the name locally (expected socks5h)`);
    if (!hosts.has(`${r.host}:${r.port}`)) problems.push(`SOCKS CONNECT to ${r.host}:${r.port} outside the persona allowlist (${[...hosts].join(', ')})`);
    if (opts.requireIsolation && (!owner || r.username !== owner.id)) {
      const expected = list.length === 1 ? list[0]!.id : `one of ${list.map((p) => p.id).join(', ')}`;
      problems.push(`SOCKS CONNECT to ${r.host}:${r.port} without the persona isolation credentials (username ${r.username ?? 'none'}, expected ${expected})`);
    }
  }
  return problems;
}
