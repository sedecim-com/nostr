/**
 * Host side of the leak harness (scripts/leak-test.sh): an in-memory relay plus a SOCKS5 stub that
 * stands in for the Tor SOCKS port. The stub maps a fixed .onion name to the relay, so the sovereign
 * CLI does real Tor-profile work (socks5h CONNECT by name, NIP-01 publish/read) without bootstrapping
 * Tor. The property under test does not depend on what is behind the proxy: the client must emit
 * nothing except to the proxy address:port. Every CONNECT is appended to --socks-log as JSON lines.
 *
 *   tsx tests/leak/stub.ts --host 10.200.0.1 --relay-port 7777 --socks-port 9050 --socks-log socks.jsonl
 */
import { appendFileSync } from 'node:fs';
import { TestRelay, TestSocksServer } from '@sedecim/test-relay';

export const LEAK_ONION = 'accesoleaktestrelayaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion';

const argv = process.argv.slice(2);
const opt = (n: string, d: string) => (argv.includes(n) ? argv[argv.indexOf(n) + 1]! : d);
const host = opt('--host', '127.0.0.1');
const relayPort = Number(opt('--relay-port', '7777'));
const socksPort = Number(opt('--socks-port', '9050'));
const socksLog = opt('--socks-log', '');

const relay = new TestRelay({ host, port: relayPort });
await relay.start();
const socks = new TestSocksServer({ [LEAK_ONION]: { host, port: relayPort } });
socks.onRequest = (r) => {
  if (socksLog) appendFileSync(socksLog, JSON.stringify(r) + '\n');
};
await socks.start(socksPort, host);
console.log(`leak stub ready: relay ws://${host}:${relayPort}  socks ${host}:${socksPort}  onion ws://${LEAK_ONION}`);

const stop = async () => {
  await socks.stop();
  await relay.stop();
  process.exit(0);
};
process.on('SIGTERM', () => void stop());
process.on('SIGINT', () => void stop());
