import { createServer, connect, type Server, type Socket } from 'node:net';
import type { AddressInfo } from 'node:net';

export interface SocksRequestLog {
  host: string;
  port: number;
  /** 'domain' means the client delegated DNS resolution to the proxy (socks5h behaviour). */
  addressType: 'ipv4' | 'domain' | 'ipv6';
  /** RFC 1929 username of the connection, when it authenticated: what Tor's IsolateSOCKSAuth isolates on. */
  username?: string;
}

export interface TestSocksOptions {
  /**
   * Require username/password (RFC 1929) and refuse clients that do not offer it. Either way, a client that
   * offers it gets it, as Tor does (Tor 0.3.5.7+ prefers it): its credentials are recorded per request.
   */
  requireAuth?: boolean;
}

/**
 * Minimal SOCKS5 server (CONNECT only) that emulates a Tor SOCKS port for tests.
 * `routes` maps requested hostnames (e.g. an .onion address) to a local host:port.
 */
export class TestSocksServer {
  readonly requests: SocksRequestLog[] = [];
  /** Called for every CONNECT request (the leak harness streams them to a log file). */
  onRequest?: (r: SocksRequestLog) => void;
  private server?: Server;
  private readonly sockets = new Set<Socket>();

  constructor(
    private readonly routes: Record<string, { host: string; port: number }> = {},
    private readonly opts: TestSocksOptions = {},
  ) {}

  get port(): number {
    return (this.server?.address() as AddressInfo).port;
  }

  /** Listens on 127.0.0.1 and a random port by default (the leak harness binds a veth address). */
  async start(port = 0, host = '127.0.0.1'): Promise<number> {
    this.server = createServer((sock) => this.onClient(sock));
    await new Promise<void>((r) => this.server!.listen(port, host, () => r()));
    return this.port;
  }

  async stop(): Promise<void> {
    for (const s of this.sockets) s.destroy();
    await new Promise<void>((r) => (this.server ? this.server.close(() => r()) : r()));
  }

  private onClient(sock: Socket) {
    this.sockets.add(sock);
    sock.on('close', () => this.sockets.delete(sock));
    sock.on('error', () => undefined);
    let stage = 0;
    let buf = Buffer.alloc(0);
    let username: string | undefined;
    const onData = (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      if (stage === 0) {
        if (buf.length < 2 || buf.length < 2 + buf[1]!) return;
        const methods = [...buf.subarray(2, 2 + buf[1]!)];
        buf = buf.subarray(2 + buf[1]!);
        if (methods.includes(0x02)) {
          sock.write(Buffer.from([0x05, 0x02]));
          stage = 3;
        } else if (this.opts.requireAuth) {
          sock.end(Buffer.from([0x05, 0xff]));
          return;
        } else {
          sock.write(Buffer.from([0x05, 0x00]));
          stage = 1;
        }
      }
      if (stage === 3) {
        // RFC 1929: VER=1, ULEN, UNAME, PLEN, PASSWD. Any credentials are accepted (Tor only isolates on them).
        if (buf.length < 2 || buf.length < 2 + buf[1]! + 1) return;
        const ulen = buf[1]!;
        const plen = buf[2 + ulen]!;
        if (buf.length < 3 + ulen + plen) return;
        username = buf.subarray(2, 2 + ulen).toString('utf8');
        buf = buf.subarray(3 + ulen + plen);
        sock.write(Buffer.from([0x01, 0x00]));
        stage = 1;
      }
      if (stage === 1) {
        if (buf.length < 5) return;
        const atyp = buf[3]!;
        let host: string;
        let offset: number;
        let addressType: SocksRequestLog['addressType'];
        if (atyp === 0x01) {
          if (buf.length < 10) return;
          host = [...buf.subarray(4, 8)].join('.');
          offset = 8;
          addressType = 'ipv4';
        } else if (atyp === 0x03) {
          const len = buf[4]!;
          if (buf.length < 5 + len + 2) return;
          host = buf.subarray(5, 5 + len).toString('utf8');
          offset = 5 + len;
          addressType = 'domain';
        } else {
          if (buf.length < 22) return;
          host = buf.subarray(4, 20).toString('hex');
          offset = 20;
          addressType = 'ipv6';
        }
        const port = buf.readUInt16BE(offset);
        const rest = buf.subarray(offset + 2);
        const req: SocksRequestLog = { host, port, addressType, ...(username !== undefined ? { username } : {}) };
        this.requests.push(req);
        this.onRequest?.(req);
        sock.off('data', onData);
        const target = this.routes[host] ?? (addressType !== 'domain' ? { host, port } : undefined);
        if (!target) {
          sock.end(Buffer.from([0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
          return;
        }
        const upstream = connect(target.port, target.host, () => {
          sock.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
          if (rest.length) upstream.write(rest);
          sock.pipe(upstream);
          upstream.pipe(sock);
        });
        this.sockets.add(upstream);
        upstream.on('close', () => this.sockets.delete(upstream));
        upstream.on('error', () => sock.destroy());
        stage = 2;
      }
    };
    sock.on('data', onData);
  }
}
