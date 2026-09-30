/**
 * Host side of the leak harness (scripts/leak-test.sh): an in-memory relay plus a SOCKS5 stub that
 * stands in for the Tor SOCKS port. The stub maps a fixed .onion name to the relay, so the sovereign
 * CLI does real Tor-profile work (socks5h CONNECT by name, NIP-01 publish/read) without bootstrapping
 * Tor. The property under test does not depend on what is behind the proxy: the client must emit
 * nothing except to the proxy address:port. Every CONNECT is appended to --socks-log as JSON lines.
 *
 * FR020-05: two more onions, for what a persona reaches besides its relays: a Blossom server (group files) and an
 * organisation's policy-engine (the rotation worker). A control endpoint on the host, never on the captured link,
 * sets the policy up: `POST /admin {pubkey}` makes a persona a policy admin, `POST /revoke {groupId, member}` revokes a
 * device of `member` in that group, which leaves a rotation pending.
 *
 *   tsx tests/leak/stub.ts --host 10.200.0.1 --relay-port 7777 --socks-port 9050 --socks-log socks.jsonl
 *        [--control-port 7780]
 */
import { appendFileSync } from 'node:fs';
import { createServer, type IncomingMessage } from 'node:http';
import { createPolicyApi, PolicyEngine } from '@sedecim/policy-engine';
import { TestBlossomServer, TestRelay, TestSocksServer } from '@sedecim/test-relay';

export const LEAK_ONION = 'accesoleaktestrelayaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion';
export const LEAK_BLOB_ONION = 'accesoleaktestblobbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion';
export const LEAK_POLICY_ONION = 'accesoleaktestpolicycccccccccccccccccccccccccccccccccccc.onion';

const argv = process.argv.slice(2);
const opt = (n: string, d: string) => (argv.includes(n) ? argv[argv.indexOf(n) + 1]! : d);
const host = opt('--host', '127.0.0.1');
const relayPort = Number(opt('--relay-port', '7777'));
const socksPort = Number(opt('--socks-port', '9050'));
const controlPort = Number(opt('--control-port', '7780'));
const socksLog = opt('--socks-log', '');

const relay = new TestRelay({ host, port: relayPort });
await relay.start();
// The Blossom server names its blobs by its onion, like a hidden service would.
const blossom = new TestBlossomServer();
await blossom.start();
blossom.publicUrl = `http://${LEAK_BLOB_ONION}`;
const engine = new PolicyEngine();
const admins: string[] = [];
const policy = createPolicyApi(engine, { name: 'leak-policy', adminPubkeys: admins, publicBaseUrl: `http://${LEAK_POLICY_ONION}` });
const policyPort = new URL(await policy.listen(0, '127.0.0.1')).port;

const socks = new TestSocksServer({
  [LEAK_ONION]: { host, port: relayPort },
  [LEAK_BLOB_ONION]: { host: '127.0.0.1', port: Number(new URL(blossom.url).port) },
  [LEAK_POLICY_ONION]: { host: '127.0.0.1', port: Number(policyPort) },
});
socks.onRequest = (r) => {
  if (socksLog) appendFileSync(socksLog, JSON.stringify(r) + '\n');
};
await socks.start(socksPort, host);

const body = async (req: IncomingMessage) => {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}') as Record<string, string>;
};
const control = createServer((req, res) => {
  void (async () => {
    const b = await body(req);
    if (req.url === '/admin') admins.push(b.pubkey!);
    else if (req.url === '/revoke') {
      const admin = admins[0];
      if (!admin) throw new Error('POST /admin first');
      await engine.upsertSubject(admin, { pubkey: b.member!, roles: ['member'], attributes: {} });
      const device = await engine.registerDevice(admin, b.member!, 'registered');
      await engine.upsertResource(admin, { id: b.groupId!, kind: 'group', sensitivity: 'confidential', rules: [], members: [b.member!] });
      await engine.revokeDevice(admin, device.id, 'leak test');
    } else throw new Error(`unknown control ${req.url}`);
    res.writeHead(200, { 'content-type': 'application/json' }).end('{"ok":true}');
  })().catch((e: Error) => res.writeHead(500).end(e.message));
});
await new Promise<void>((r) => control.listen(controlPort, '127.0.0.1', () => r()));
console.log(`leak stub ready: relay ws://${host}:${relayPort}  socks ${host}:${socksPort}  onions ws://${LEAK_ONION} http://${LEAK_BLOB_ONION} http://${LEAK_POLICY_ONION}  control 127.0.0.1:${controlPort}`);

const stop = async () => {
  control.close();
  await policy.close();
  await blossom.stop();
  await socks.stop();
  await relay.stop();
  process.exit(0);
};
process.on('SIGTERM', () => void stop());
process.on('SIGINT', () => void stop());
