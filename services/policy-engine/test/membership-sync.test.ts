import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { finalizeEvent, generateSecretKey, getPublicKey, toUnsigned, type EventTemplate, type Filter, type NostrEvent } from '@sedecim/nostr-core';
import type { RelayGrant } from '@sedecim/policy-client';
import { BuzzMembershipSync, nip11Self, parseRelayEntry, type Nip29Relay } from '../src/membership-sync';

type Role = 'owner' | 'admin' | 'member';
interface Channel {
  visibility: 'private' | 'open';
  members: Map<string, Role>;
}

/**
 * Buzz as the sync identity sees it (crates/buzz-relay/src/handlers/channel_authz.rs at the pinned commit): group state
 * signed by the relay key and readable only by members of a private channel; kind 9000 needs an active member in a
 * private channel, kind 9001 on somebody else an owner or admin, and the last owner cannot be removed.
 */
class FakeBuzz implements Nip29Relay {
  readonly relaySk = generateSecretKey();
  readonly relayKey = getPublicKey(this.relaySk);
  readonly channels = new Map<string, Channel>();
  readonly published: EventTemplate[] = [];
  /** Extra events served as they are (forged state signed by another key). */
  readonly extra: NostrEvent[] = [];
  down = false;
  private clock = 1_700_000_000;

  constructor(readonly actor: string) {}

  channel(id: string, visibility: Channel['visibility'], members: Array<[string, Role]>) {
    this.channels.set(id, { visibility, members: new Map(members) });
  }

  private sign(kind: number, tags: string[][]): NostrEvent {
    return finalizeEvent(toUnsigned({ kind, content: '', tags, created_at: this.clock++ }, this.relayKey), this.relaySk);
  }

  async query(filters: Filter[]): Promise<NostrEvent[]> {
    const f = filters[0]!;
    const out: NostrEvent[] = [];
    for (const id of f['#d'] ?? []) {
      const ch = this.channels.get(id);
      if (!ch || (ch.visibility === 'private' && !ch.members.has(this.actor))) continue;
      out.push(this.sign(39000, [['d', id], ['name', id], [ch.visibility === 'private' ? 'private' : 'public'], ['closed']]));
      out.push(this.sign(39001, [['d', id], ...[...ch.members].filter(([, r]) => r !== 'member').map(([pk, r]) => ['p', pk, r])]));
      out.push(this.sign(39002, [['d', id], ...[...ch.members].map(([pk, r]) => ['p', pk, '', r])]));
    }
    return [...out, ...this.extra].filter((e) => !f.authors || f.authors.includes(e.pubkey));
  }

  async publish(t: EventTemplate): Promise<{ ok: boolean; message: string }> {
    if (this.down) return { ok: false, message: 'error: relay unavailable' };
    this.published.push(t);
    const id = t.tags?.find((x) => x[0] === 'h')?.[1];
    const target = t.tags?.find((x) => x[0] === 'p')?.[1];
    const ch = id ? this.channels.get(id) : undefined;
    if (!ch || !target) return { ok: false, message: 'invalid: channel not found' };
    const role = ch.members.get(this.actor);
    const elevated = role === 'owner' || role === 'admin';
    if (t.kind === 9000) {
      if (ch.visibility === 'private' && !role) return { ok: false, message: 'actor not authorized' };
      if (!ch.members.has(target)) ch.members.set(target, 'member');
      return { ok: true, message: '' };
    }
    if (t.kind === 9001) {
      if (!elevated) return { ok: false, message: 'actor not authorized' };
      const owners = [...ch.members].filter(([, r]) => r === 'owner');
      if (owners.length === 1 && owners[0]![0] === target) return { ok: false, message: 'cannot remove the last owner' };
      ch.members.delete(target);
      return { ok: true, message: '' };
    }
    return { ok: false, message: 'restricted: unknown event kind' };
  }
}

const pk = () => getPublicKey(generateSecretKey());
const grant = (resourceId: string, pubkeys: string[], kind: RelayGrant['kind'] = 'channel'): RelayGrant => ({ resourceId, kind, pubkeys });

describe('NIP-29 membership sync with the policy-engine (FR023-10)', () => {
  const syncId = pk();
  const [owner, admin, ana, beto, carla] = [pk(), pk(), pk(), pk(), pk()];
  const make = (buzz: FakeBuzz, relayKey: string | null = buzz.relayKey) => new BuzzMembershipSync({ relay: buzz, self: syncId, relayKey: async () => relayKey ?? undefined });

  it('makes the members of a registered private channel the people the policy lets publish there', async () => {
    const buzz = new FakeBuzz(syncId);
    buzz.channel('legal', 'private', [[owner, 'owner'], [admin, 'admin'], [syncId, 'admin'], [beto, 'member'], [carla, 'member']]);
    const sync = make(buzz);
    const r = await sync.apply([grant('legal', [ana, carla])]);
    expect(r).toEqual({ channels: 1, added: 1, removed: 1, notEnforced: [], withoutAuthority: [], unreachable: [], errors: [] });
    // Owners, admins and the sync identity itself stay.
    expect([...buzz.channels.get('legal')!.members.keys()].sort()).toEqual([owner, admin, syncId, ana, carla].sort());
    expect(buzz.published.map((t) => [t.kind, t.tags])).toEqual([
      [9000, [['h', 'legal'], ['p', ana]]],
      [9001, [['h', 'legal'], ['p', beto]]],
    ]);
    // Nothing more to do on the next pass.
    expect(await sync.apply([grant('legal', [ana, carla])])).toMatchObject({ added: 0, removed: 0, errors: [] });
    expect(buzz.published).toHaveLength(2);
    expect(sync.last).toMatchObject({ channels: 1, added: 0, removed: 0 });
  });

  it('reports the channels it cannot manage and leaves them alone', async () => {
    const buzz = new FakeBuzz(syncId);
    buzz.channel('solo-miembro', 'private', [[owner, 'owner'], [syncId, 'member'], [beto, 'member']]);
    buzz.channel('ajeno', 'private', [[owner, 'owner'], [beto, 'member']]);
    const r = await make(buzz).apply([grant('solo-miembro', [ana]), grant('ajeno', [ana]), grant('inexistente', [ana])]);
    expect(r).toMatchObject({ channels: 3, added: 0, removed: 0, withoutAuthority: ['solo-miembro'], unreachable: ['ajeno', 'inexistente'], errors: [] });
    expect(buzz.published).toEqual([]);
  });

  it('syncs an open channel but reports it: Buzz lets anybody post there', async () => {
    const buzz = new FakeBuzz(syncId);
    buzz.channel('abierto', 'open', [[syncId, 'owner'], [beto, 'member']]);
    const r = await make(buzz).apply([grant('abierto', [ana])]);
    expect(r).toMatchObject({ added: 1, removed: 1, notEnforced: ['abierto'], errors: [] });
  });

  it('trusts only lists signed by the relay key: a forged admin list does not shield a member', async () => {
    const buzz = new FakeBuzz(syncId);
    buzz.channel('legal', 'private', [[owner, 'owner'], [syncId, 'admin'], [beto, 'member']]);
    const forgerSk = generateSecretKey();
    buzz.extra.push(finalizeEvent(toUnsigned({ kind: 39001, content: '', tags: [['d', 'legal'], ['p', beto, 'admin']], created_at: 1_900_000_000 }, getPublicKey(forgerSk)), forgerSk));
    buzz.extra.push(finalizeEvent(toUnsigned({ kind: 39002, content: '', tags: [['d', 'legal'], ['p', ana, '', 'member']], created_at: 1_900_000_000 }, getPublicKey(forgerSk)), forgerSk));
    const r = await make(buzz).apply([grant('legal', [ana])]);
    expect(r).toMatchObject({ added: 1, removed: 1, errors: [] });
    expect(buzz.channels.get('legal')!.members.has(beto)).toBe(false);
  });

  it('does nothing without the relay key and reports what the relay refused', async () => {
    const buzz = new FakeBuzz(syncId);
    buzz.channel('legal', 'private', [[owner, 'owner'], [syncId, 'admin']]);
    expect((await make(buzz, null).apply([grant('legal', [ana])])).errors).toEqual(['relay signing key unknown: set BUZZ_MEMBERSHIP_RELAY_KEY or publish NIP-11 self']);
    expect(buzz.published).toEqual([]);
    buzz.down = true;
    const r = await make(buzz).apply([grant('legal', [ana])]);
    expect(r.added).toBe(0);
    expect(r.errors).toEqual([`legal: put-user ${ana.slice(0, 8)}: error: relay unavailable`]);
  });

  it('leaves Marmot groups alone: they are not NIP-29 channels', async () => {
    const buzz = new FakeBuzz(syncId);
    expect(await make(buzz).apply([grant('ab'.repeat(32), [ana], 'group')])).toMatchObject({ channels: 0, added: 0, removed: 0 });
    expect(buzz.published).toEqual([]);
  });
});

describe('relay entries and NIP-11 self (FR023-10)', () => {
  const relayKey = pk();
  let server: Server;
  let port: number;
  const hosts: string[] = [];

  beforeAll(async () => {
    // Buzz serves each community by its Host header: only the public host gets the document.
    server = createServer((req, res) => {
      hosts.push(String(req.headers.host));
      if (req.headers.host !== 'relay.example:3000' || req.headers.accept !== 'application/nostr+json') return void res.writeHead(404).end();
      res.writeHead(200, { 'content-type': 'application/nostr+json' }).end(JSON.stringify({ name: 'buzz', self: relayKey }));
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
    port = (server.address() as AddressInfo).port;
  });
  afterAll(() => new Promise<void>((r) => server.close(() => r())));

  it('parses public=dial entries', () => {
    expect(parseRelayEntry('ws://localhost:3000=ws://relay:3000')).toEqual({ public: 'ws://localhost:3000', dial: 'ws://relay:3000' });
    expect(parseRelayEntry('wss://relay.example')).toEqual({ public: 'wss://relay.example', dial: 'wss://relay.example' });
    expect(() => parseRelayEntry('relay:3000')).toThrow(/invalid relay entry/);
    expect(() => parseRelayEntry('ws://a=http://b')).toThrow(/invalid relay entry/);
  });

  it('asks the dial address with the public host', async () => {
    expect(await nip11Self({ public: 'ws://relay.example:3000', dial: `ws://127.0.0.1:${port}` })).toBe(relayKey);
    expect(await nip11Self({ public: `ws://127.0.0.1:${port}`, dial: `ws://127.0.0.1:${port}` })).toBeUndefined();
    expect(hosts).toEqual(['relay.example:3000', `127.0.0.1:${port}`]);
    expect(await nip11Self({ public: 'ws://relay.example:3000', dial: 'ws://127.0.0.1:1' })).toBeUndefined();
  });
});
