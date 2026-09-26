/**
 * Deliberately leaky commands for the harness's negative controls (scripts/leak-test.sh). Each one
 * emits the kind of traffic the leak tests must catch; if the capture does not show it, the harness
 * is blind and the suite fails. Every attempt is bounded and errors are expected (nothing answers).
 *
 *   tsx tests/leak/leaky.ts dns-libc | dns-cares | doh | direct HOST:PORT | ipv6 [ADDR]:PORT
 */
import { connect } from 'node:net';
import { Resolver } from 'node:dns/promises';

const [mode, target] = process.argv.slice(2);

function tcp(host: string, port: number): Promise<void> {
  return new Promise((resolve) => {
    const s = connect({ host, port, timeout: 1500 });
    const done = () => (s.destroy(), resolve());
    s.once('connect', done).once('timeout', done).once('error', done);
  });
}

function hostPort(t: string | undefined): [string, number] {
  const m = /^\[?([^\]]+?)\]?:(\d+)$/.exec(t ?? '');
  if (!m) throw new Error(`target HOST:PORT required, got ${t}`);
  return [m[1]!, Number(m[2])];
}

switch (mode) {
  case 'dns-libc':
    // getaddrinfo through nsswitch (what fetch, net.connect and most libraries use).
    await fetch('http://leak-canary.example/', { signal: AbortSignal.timeout(3000) }).catch(() => undefined);
    break;
  case 'dns-cares':
    // c-ares reading resolv.conf directly (dns.resolve*).
    await new Resolver({ timeout: 1000, tries: 1 }).resolve4('leak-canary.example').catch(() => undefined);
    break;
  case 'doh':
    await tcp('1.1.1.1', 443);
    break;
  case 'direct':
  case 'ipv6':
    await tcp(...hostPort(target));
    break;
  default:
    throw new Error('usage: leaky.ts dns-libc | dns-cares | doh | direct HOST:PORT | ipv6 [ADDR]:PORT');
}
console.log(`leaky ${mode} done`);
