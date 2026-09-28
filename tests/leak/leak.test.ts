/**
 * Unit tests of the leak harness (FR020-03 / FR022-02): the pcap reader and the analysis, with real
 * tcpdump captures taken by scripts/leak-test.sh (fixtures/) and synthetic packets for the cases a
 * given kernel cannot produce (IPv6 on a host without it, DoH, mDNS...). The live run is in CI.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { analyzeCapture, checkSocksRequests, networkAllowlist, parseEndpoint, parsePersonaList, type SocksRequest } from './analyze';
import { formatIpv6, ipv4Packet, ipv6Packet, LINKTYPE, parsePcap, writePcap } from './pcap';

const fixture = (name: string) => readFileSync(new URL(`./fixtures/${name}`, import.meta.url));
const CLIENT = '10.200.0.2';
const SOCKS = { ip: '10.200.0.1', port: 9050, protocol: 'tcp' as const };
const TOR_POLICY = { clientAddrs: [CLIENT, 'fd00:acce:55::2'], allowed: [SOCKS] };
const synthetic = (...ip: Uint8Array[]) => parsePcap(writePcap(ip.map((p) => ({ ip: p })))).packets;

describe('real captures of the sovereign CLI (tcpdump fixtures)', () => {
  it('Tor profile: every packet goes to the SOCKS proxy, no DNS, no IPv6', () => {
    const { linkType, packets } = parsePcap(fixture('tor-clean.pcap'));
    expect(linkType).toBe(LINKTYPE.ETHERNET);
    const report = analyzeCapture(packets, TOR_POLICY);
    expect(report.outbound).toBeGreaterThan(10);
    expect(report.findings).toEqual([]);
    expect(report.destinations).toEqual(['tcp 10.200.0.1:9050']);
  });

  it('the same capture fails a policy that does not allow the proxy (the analysis can fail)', () => {
    const report = analyzeCapture(parsePcap(fixture('tor-clean.pcap')).packets, { clientAddrs: [CLIENT], allowed: [{ ip: '10.200.0.1', port: 7777 }] });
    expect(report.counts.direct).toBe(report.outbound);
  });

  it('negative control: a name resolved outside Tor is detected as DNS (ICMP replies are inbound, ignored)', () => {
    const report = analyzeCapture(parsePcap(fixture('dns-leak.pcap')).packets, TOR_POLICY);
    expect(report.counts.dns).toBe(3);
    expect(report.findings.every((f) => f.kind === 'dns' && f.dst === '10.200.0.1')).toBe(true);
  });

  it('SOCKS log of the Tor run: CONNECT by name to the persona relay only (socks5h)', () => {
    const [persona] = parsePersonaList(fixture('tor-personas.txt').toString());
    const requests = fixture('tor-socks.jsonl').toString().trim().split('\n').map((l) => JSON.parse(l) as SocksRequest);
    expect(persona!.network).toBe('tor-only');
    expect(networkAllowlist(persona!, SOCKS)).toEqual([SOCKS]);
    expect(checkSocksRequests(requests, persona!)).toEqual([]);
  });

  it('FR006-06: with isolation required, every CONNECT must carry the persona id as SOCKS username', () => {
    const [persona] = parsePersonaList(fixture('tor-personas.txt').toString());
    const [first] = fixture('tor-socks.jsonl').toString().trim().split('\n').map((l) => JSON.parse(l) as SocksRequest);
    expect(checkSocksRequests([{ ...first!, username: persona!.id }], persona!, { requireIsolation: true })).toEqual([]);
    expect(checkSocksRequests([{ ...first!, username: 'otra-persona' }], persona!, { requireIsolation: true })[0]).toMatch(/without the persona isolation credentials \(username otra-persona/);
    expect(checkSocksRequests([first!], persona!, { requireIsolation: true })[0]).toMatch(/username none/);
  });
});

describe('leak analysis (synthetic packets)', () => {
  it('flags IPv6 application traffic but not the kernel neighbour discovery / MLD', () => {
    const report = analyzeCapture(
      synthetic(
        ipv6Packet('fe80::1', 'ff02::1:ff00:1', 58, 0, 0, { icmpType: 135 }),
        ipv6Packet('fe80::1', 'ff02::16', 58, 0, 0, { icmpType: 143 }),
        ipv6Packet('fd00:acce:55::2', 'fd00:acce:55::1', 6, 40000, 443),
        ipv6Packet('fd00:acce:55::2', '2001:4860:4860::8888', 17, 40001, 53),
      ),
      TOR_POLICY,
    );
    expect(report.counts).toEqual({ dns: 1, doh: 0, ipv6: 2, direct: 0 });
    expect(report.findings[0]!.detail).toContain('[fd00:acce:55::1]:443');
  });

  it('classifies DNS, DoT, mDNS, DoH and direct connections; inbound packets are ignored', () => {
    const report = analyzeCapture(
      synthetic(
        ipv4Packet(CLIENT, '10.200.0.1', 6, 40000, 9050),
        ipv4Packet('10.200.0.1', CLIENT, 6, 9050, 40000, { tcpFlags: 0x12 }),
        ipv4Packet(CLIENT, '10.200.0.1', 17, 40001, 53),
        ipv4Packet(CLIENT, '9.9.9.9', 6, 40002, 853),
        ipv4Packet(CLIENT, '224.0.0.251', 17, 5353, 5353),
        ipv4Packet(CLIENT, '1.1.1.1', 6, 40003, 443),
        ipv4Packet(CLIENT, '93.184.216.34', 6, 40004, 443),
        ipv4Packet(CLIENT, '10.200.0.1', 1, 0, 0, { icmpType: 8 }),
        ipv4Packet('198.51.100.7', CLIENT, 6, 443, 40005),
      ),
      TOR_POLICY,
    );
    expect(report.counts).toEqual({ dns: 3, doh: 1, ipv6: 0, direct: 2 });
    expect(report.outbound).toBe(7);
    expect(report.destinations).toContain('tcp 10.200.0.1:9050');
  });

  it('an allowlist entry can be pinned to a transport protocol', () => {
    const packets = synthetic(ipv4Packet(CLIENT, '10.200.0.1', 17, 40000, 9050));
    expect(analyzeCapture(packets, TOR_POLICY).counts.direct).toBe(1);
    expect(analyzeCapture(packets, { clientAddrs: [CLIENT], allowed: [parseEndpoint('10.200.0.1:9050')] }).findings).toEqual([]);
  });
});

describe('pcap reader', () => {
  it('reads big-endian nanosecond captures and raw-IP / Linux cooked v2 link types', () => {
    const ip = ipv4Packet(CLIENT, '10.200.0.1', 6, 1234, 9050);
    const header = (magic: number, link: number) => {
      const h = new DataView(new ArrayBuffer(24));
      h.setUint32(0, magic, false);
      h.setUint32(20, link, false);
      return new Uint8Array(h.buffer);
    };
    const record = (frame: Uint8Array) => {
      const r = new DataView(new ArrayBuffer(16));
      r.setUint32(0, 10, false);
      r.setUint32(4, 500_000_000, false);
      r.setUint32(8, frame.length, false);
      r.setUint32(12, frame.length, false);
      return Buffer.concat([new Uint8Array(r.buffer), frame]);
    };
    const raw = parsePcap(Buffer.concat([header(0xa1b23c4d, LINKTYPE.RAW), record(ip)]));
    expect(raw.packets[0]).toMatchObject({ ts: 10.5, ip: { version: 4, src: CLIENT, dst: '10.200.0.1', protocol: 6, srcPort: 1234, dstPort: 9050, tcpFlags: 0x02 } });
    const sll2 = new Uint8Array(20 + ip.length);
    sll2.set([0x08, 0x00]);
    sll2.set(ip, 20);
    expect(parsePcap(Buffer.concat([header(0xa1b2c3d4, LINKTYPE.LINUX_SLL2), record(sll2)])).packets[0]!.ip?.dstPort).toBe(9050);
  });

  it('rejects pcapng and garbage, tolerates a truncated last record', () => {
    expect(() => parsePcap(Buffer.from([0x0a, 0x0d, 0x0d, 0x0a, ...new Array(24).fill(0)]))).toThrow(/pcapng/);
    expect(() => parsePcap(Buffer.alloc(24))).toThrow(/bad magic/);
    const full = writePcap([{ ip: ipv4Packet(CLIENT, '10.200.0.1', 6, 1, 2) }, { ip: ipv4Packet(CLIENT, '10.200.0.1', 6, 3, 4) }]);
    expect(parsePcap(full.subarray(0, full.length - 5)).packets).toHaveLength(1);
  });

  it('formats IPv6 addresses canonically (RFC 5952)', () => {
    expect(synthetic(ipv6Packet('2001:db8::1', 'fd00:0:0:1::', 17, 1, 2))[0]!.ip).toMatchObject({ src: '2001:db8::1', dst: 'fd00:0:0:1::' });
    expect(formatIpv6(new Uint8Array(16))).toBe('::');
  });
});

describe('egress allowlist per profile (FR022-02)', () => {
  const personas = parsePersonaList(
    ['aaaa1111  directa           direct   standard     ws://10.200.0.1:7777,wss://10.200.0.5', 'bbbb2222  fuente           tor-only high-risk    ws://abc.onion'].join('\n'),
  );

  it('direct personas may reach exactly their relays; Tor personas only the proxy', () => {
    expect(networkAllowlist(personas[0]!, SOCKS)).toEqual([
      { ip: '10.200.0.1', port: 7777, protocol: 'tcp' },
      { ip: '10.200.0.5', port: 443, protocol: 'tcp' },
    ]);
    expect(networkAllowlist(personas[1]!, SOCKS)).toEqual([SOCKS]);
    expect(() => networkAllowlist(parsePersonaList('cccc  x  direct  standard  wss://relay.example')[0]!, SOCKS)).toThrow(/IP literal/);
  });

  it('negative: SOCKS requests outside the allowlist, by address, or from a direct persona are reported', () => {
    const tor = personas[1]!;
    expect(checkSocksRequests([{ host: 'abc.onion', port: 80, addressType: 'domain' }], tor)).toEqual([]);
    expect(checkSocksRequests([{ host: 'tracker.example', port: 443, addressType: 'domain' }], tor)[0]).toMatch(/outside the persona allowlist/);
    expect(checkSocksRequests([{ host: '203.0.113.9', port: 80, addressType: 'ipv4' }], tor).join()).toMatch(/resolved the name locally/);
    expect(checkSocksRequests([{ host: '10.200.0.1', port: 7777, addressType: 'ipv4' }], personas[0]!)[0]).toMatch(/direct persona used the SOCKS proxy/);
  });
});
