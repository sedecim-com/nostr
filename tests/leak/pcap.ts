/**
 * Minimal pcap reader for the leak tests (FR020-03). Reads the classic libpcap format that
 * `tcpdump -w` writes (both byte orders, micro/nanosecond timestamps) and decodes just enough of each
 * frame to decide where it was going: IPv4/IPv6, TCP/UDP ports, ICMP/ICMPv6 types.
 *
 * Link types: Ethernet (1), raw IP (101 / 228 / 229), Linux cooked v1 (113) and v2 (276), BSD loopback (0).
 * Frames of other link-layer protocols (ARP, LLDP...) are returned with `ip: undefined`.
 */

export interface Packet {
  /** seconds since the epoch (fractional) */
  ts: number;
  /** capture length of the frame */
  length: number;
  /** EtherType / protocol of the link layer payload (0x0800 IPv4, 0x86dd IPv6, 0x0806 ARP...) */
  etherType?: number;
  ip?: {
    version: 4 | 6;
    src: string;
    dst: string;
    /** IP protocol / IPv6 next header after skipping extension headers (6 TCP, 17 UDP, 1 ICMP, 58 ICMPv6) */
    protocol: number;
    srcPort?: number;
    dstPort?: number;
    /** TCP flags byte (0x02 SYN, 0x10 ACK...) */
    tcpFlags?: number;
    /** ICMP / ICMPv6 type */
    icmpType?: number;
  };
}

export const LINKTYPE = { NULL: 0, ETHERNET: 1, RAW: 101, LINUX_SLL: 113, IPV4: 228, IPV6: 229, LINUX_SLL2: 276 } as const;

const MAGIC_US = 0xa1b2c3d4;
const MAGIC_NS = 0xa1b23c4d;

export function parsePcap(buf: Uint8Array): { linkType: number; packets: Packet[] } {
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  if (buf.byteLength < 24) throw new Error('pcap: file too short for a global header');
  const magicBE = view.getUint32(0, false);
  const magicLE = view.getUint32(0, true);
  let le: boolean;
  let nano: boolean;
  if (magicLE === MAGIC_US || magicLE === MAGIC_NS) [le, nano] = [true, magicLE === MAGIC_NS];
  else if (magicBE === MAGIC_US || magicBE === MAGIC_NS) [le, nano] = [false, magicBE === MAGIC_NS];
  else if (magicLE === 0x0a0d0d0a) throw new Error('pcap: pcapng is not supported (capture with tcpdump -w, not dumpcap)');
  else throw new Error(`pcap: bad magic 0x${magicBE.toString(16)}`);
  const linkType = view.getUint32(20, le) & 0x0fffffff;
  const packets: Packet[] = [];
  let off = 24;
  while (off + 16 <= buf.byteLength) {
    const sec = view.getUint32(off, le);
    const frac = view.getUint32(off + 4, le);
    const incl = view.getUint32(off + 8, le);
    off += 16;
    if (off + incl > buf.byteLength) break; // truncated last record (capture killed mid-write)
    const frame = buf.subarray(off, off + incl);
    off += incl;
    packets.push({ ts: sec + frac / (nano ? 1e9 : 1e6), length: incl, ...decodeLink(linkType, frame) });
  }
  return { linkType, packets };
}

function decodeLink(linkType: number, f: Uint8Array): Pick<Packet, 'etherType' | 'ip'> {
  const u16 = (o: number) => (f[o]! << 8) | f[o + 1]!;
  switch (linkType) {
    case LINKTYPE.ETHERNET: {
      if (f.length < 14) return {};
      let type = u16(12);
      let off = 14;
      while ((type === 0x8100 || type === 0x88a8) && f.length >= off + 4) {
        type = u16(off + 2); // 802.1Q / 802.1ad VLAN tag
        off += 4;
      }
      return withIp(type, f.subarray(off));
    }
    case LINKTYPE.LINUX_SLL:
      return f.length < 16 ? {} : withIp(u16(14), f.subarray(16));
    case LINKTYPE.LINUX_SLL2:
      return f.length < 20 ? {} : withIp(u16(0), f.subarray(20));
    case LINKTYPE.RAW:
    case LINKTYPE.IPV4:
    case LINKTYPE.IPV6: {
      const v = f.length ? f[0]! >> 4 : 0;
      return withIp(v === 6 ? 0x86dd : v === 4 ? 0x0800 : 0, f);
    }
    case LINKTYPE.NULL: {
      if (f.length < 4) return {};
      const family = f[0]! || f[3]!; // host byte order of the capturing machine
      return withIp(family === 2 ? 0x0800 : [24, 28, 30].includes(family) ? 0x86dd : 0, f.subarray(4));
    }
    default:
      throw new Error(`pcap: unsupported link type ${linkType}`);
  }
}

function withIp(etherType: number, p: Uint8Array): Pick<Packet, 'etherType' | 'ip'> {
  const ip = etherType === 0x0800 ? decodeIpv4(p) : etherType === 0x86dd ? decodeIpv6(p) : undefined;
  return ip ? { etherType, ip } : { etherType };
}

function transport(protocol: number, p: Uint8Array): Omit<NonNullable<Packet['ip']>, 'version' | 'src' | 'dst' | 'protocol'> {
  if ((protocol === 6 || protocol === 17) && p.length >= 4) {
    const out = { srcPort: (p[0]! << 8) | p[1]!, dstPort: (p[2]! << 8) | p[3]! };
    return protocol === 6 && p.length >= 14 ? { ...out, tcpFlags: p[13]! } : out;
  }
  if ((protocol === 1 || protocol === 58) && p.length >= 1) return { icmpType: p[0]! };
  return {};
}

function decodeIpv4(p: Uint8Array): Packet['ip'] {
  if (p.length < 20 || p[0]! >> 4 !== 4) return undefined;
  const ihl = (p[0]! & 0x0f) * 4;
  const protocol = p[9]!;
  const fragOffset = ((p[6]! & 0x1f) << 8) | p[7]!;
  const src = [...p.subarray(12, 16)].join('.');
  const dst = [...p.subarray(16, 20)].join('.');
  // Non-first fragments carry no transport header.
  return { version: 4, src, dst, protocol, ...(fragOffset === 0 ? transport(protocol, p.subarray(ihl)) : {}) };
}

export function formatIpv6(b: Uint8Array): string {
  const groups: number[] = [];
  for (let i = 0; i < 16; i += 2) groups.push((b[i]! << 8) | b[i + 1]!);
  // RFC 5952: compress the longest run (>= 2) of zero groups.
  let best = [-1, 0];
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > best[1]! && j - i >= 2) best = [i, j - i];
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (best[0]! < 0) return hex.join(':');
  return `${hex.slice(0, best[0]).join(':')}::${hex.slice(best[0]! + best[1]!).join(':')}`;
}

function decodeIpv6(p: Uint8Array): Packet['ip'] {
  if (p.length < 40 || p[0]! >> 4 !== 6) return undefined;
  let next = p[6]!;
  let off = 40;
  // Skip hop-by-hop (0), routing (43), fragment (44), destination options (60).
  for (let guard = 0; guard < 8 && [0, 43, 44, 60].includes(next) && p.length >= off + 8; guard++) {
    const hdrNext = p[off]!;
    const len = next === 44 ? 8 : (p[off + 1]! + 1) * 8;
    next = hdrNext;
    off += len;
  }
  return { version: 6, src: formatIpv6(p.subarray(8, 24)), dst: formatIpv6(p.subarray(24, 40)), protocol: next, ...transport(next, p.subarray(off)) };
}

/** Builds a classic little-endian pcap (Ethernet) from raw IP packets: used by the tests' fixtures. */
export function writePcap(frames: Array<{ ts?: number; ip: Uint8Array }>): Uint8Array {
  const header = new Uint8Array(24);
  const hv = new DataView(header.buffer);
  hv.setUint32(0, MAGIC_US, true);
  hv.setUint16(4, 2, true);
  hv.setUint16(6, 4, true);
  hv.setUint32(16, 65535, true);
  hv.setUint32(20, LINKTYPE.ETHERNET, true);
  const records = frames.map(({ ts = 0, ip }) => {
    const eth = new Uint8Array(14 + ip.length);
    const v6 = ip[0]! >> 4 === 6;
    eth.set([0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2, v6 ? 0x86 : 0x08, v6 ? 0xdd : 0x00]);
    eth.set(ip, 14);
    const rec = new Uint8Array(16 + eth.length);
    const rv = new DataView(rec.buffer);
    rv.setUint32(0, Math.floor(ts), true);
    rv.setUint32(4, Math.round((ts % 1) * 1e6), true);
    rv.setUint32(8, eth.length, true);
    rv.setUint32(12, eth.length, true);
    rec.set(eth, 16);
    return rec;
  });
  const out = new Uint8Array(24 + records.reduce((n, r) => n + r.length, 0));
  out.set(header);
  let off = 24;
  for (const r of records) {
    out.set(r, off);
    off += r.length;
  }
  return out;
}

/** IPv4 packet with a TCP/UDP header (no payload, checksums zero): fixture builder. */
export function ipv4Packet(src: string, dst: string, protocol: 6 | 17 | 1, srcPort = 0, dstPort = 0, opts: { tcpFlags?: number; icmpType?: number } = {}): Uint8Array {
  const l4 = protocol === 6 ? new Uint8Array(20) : protocol === 17 ? new Uint8Array(8) : new Uint8Array(8);
  if (protocol === 1) l4[0] = opts.icmpType ?? 8;
  else {
    l4.set([srcPort >> 8, srcPort & 0xff, dstPort >> 8, dstPort & 0xff]);
    if (protocol === 6) {
      l4[12] = 0x50;
      l4[13] = opts.tcpFlags ?? 0x02;
    } else l4.set([0, 8], 4);
  }
  const p = new Uint8Array(20 + l4.length);
  p.set([0x45, 0, (p.length >> 8) & 0xff, p.length & 0xff, 0, 0, 0x40, 0, 64, protocol]);
  p.set(src.split('.').map(Number), 12);
  p.set(dst.split('.').map(Number), 16);
  p.set(l4, 20);
  return p;
}

function parseIpv6(addr: string): Uint8Array {
  const [head, tail] = addr.includes('::') ? addr.split('::') : [addr, undefined];
  const h = head ? head.split(':') : [];
  const t = tail !== undefined && tail !== '' ? tail.split(':') : [];
  const groups = tail === undefined ? h : [...h, ...Array(8 - h.length - t.length).fill('0'), ...t];
  const out = new Uint8Array(16);
  groups.forEach((g, i) => {
    const v = parseInt(g, 16);
    out[i * 2] = v >> 8;
    out[i * 2 + 1] = v & 0xff;
  });
  return out;
}

/** IPv6 packet with a TCP/UDP/ICMPv6 header: fixture builder. */
export function ipv6Packet(src: string, dst: string, next: 6 | 17 | 58, srcPort = 0, dstPort = 0, opts: { icmpType?: number } = {}): Uint8Array {
  const l4 = next === 6 ? new Uint8Array(20) : new Uint8Array(8);
  if (next === 58) l4[0] = opts.icmpType ?? 128;
  else {
    l4.set([srcPort >> 8, srcPort & 0xff, dstPort >> 8, dstPort & 0xff]);
    if (next === 6) {
      l4[12] = 0x50;
      l4[13] = 0x02;
    }
  }
  const p = new Uint8Array(40 + l4.length);
  p.set([0x60, 0, 0, 0, (l4.length >> 8) & 0xff, l4.length & 0xff, next, 64]);
  p.set(parseIpv6(src), 8);
  p.set(parseIpv6(dst), 24);
  p.set(l4, 40);
  return p;
}
