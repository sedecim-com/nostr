// Provisions a Buzz community for an extra host, e.g. the relay's .onion address (FR021-02).
//   BUZZ_OPERATOR_SECRET=<hex|nsec> npx tsx scripts/buzz-provision-community.ts <host> [--relay http://localhost:3000]
//
// Buzz binds every connection to the community of its Host header and rejects unmapped hosts (fail
// closed), so a relay reached through its onion service needs a community for that host. Communities
// are created with `POST /operator/communities`, authenticated with NIP-98 by a key listed in the relay's
// RELAY_OPERATOR_PUBKEYS. The onion host is a separate tenant: its data is not shared with the clearnet
// community.
import { finalizeEvent, getPublicKey, hexToBytes, nip19, nip98, toUnsigned } from '@sedecim/nostr-core';

const args = process.argv.slice(2);
const host = args.find((a) => !a.startsWith('--'));
const relayIdx = args.indexOf('--relay');
const relay = (relayIdx >= 0 ? args[relayIdx + 1] : undefined) ?? process.env.BUZZ_HTTP_URL ?? 'http://localhost:3000';
const secret = process.env.BUZZ_OPERATOR_SECRET ?? '';

if (!host || !/^[a-z0-9.-]+(:\d+)?$/.test(host)) {
  console.error('usage: BUZZ_OPERATOR_SECRET=<hex|nsec> npx tsx scripts/buzz-provision-community.ts <host> [--relay http://localhost:3000]');
  process.exit(2);
}
if (!secret) {
  console.error('BUZZ_OPERATOR_SECRET is required (a key listed in the relay RELAY_OPERATOR_PUBKEYS)');
  process.exit(2);
}

const decoded = secret.startsWith('nsec1') ? nip19.decode(secret) : undefined;
const sk = decoded ? (decoded.data as Uint8Array) : hexToBytes(secret);
const url = `${relay.replace(/\/$/, '')}/operator/communities`;
const body = JSON.stringify({ host });
const auth = finalizeEvent(toUnsigned(nip98.buildHttpAuthTemplate(url, 'POST', body), getPublicKey(sk)), sk);

const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', authorization: nip98.encodeAuthHeader(auth) }, body });
const text = await res.text();
if (!res.ok) {
  console.error(`POST ${url} -> ${res.status} ${text}`);
  process.exit(1);
}
console.log(`community provisioned for ${host}: ${text}`);
