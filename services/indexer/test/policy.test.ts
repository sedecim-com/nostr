import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import * as nt from 'nostr-tools';
import { finalizeEvent, generateSecretKey, getPublicKey, nip98, toUnsigned, type NostrEvent } from '@sedecim/nostr-core';
import { nip98Fetch } from '@sedecim/service-kit';
import { createIndexerApi, GroupAuthorities, MemoryEventRepository, POLICY_DEVICE_HEADER, type IndexerPolicy } from '../src/index';

/**
 * FR023-05: in institutional mode every mirror read goes through the policy-engine (default deny), on top of the
 * NIP-29 membership every channel read needs (FR014-05).
 */
describe('indexer institutional mode (policy-engine enforcement)', () => {
  const reader = generateSecretKey();
  const readerPk = getPublicKey(reader);
  const author = generateSecretKey();
  const calls: Array<{ resourceId: string; deviceId?: string }> = [];
  // Reader may read 'general' and the workspace; 'secret' needs device 'dev-1'; engine down for 'flaky'.
  const policy: IndexerPolicy = {
    workspaceId: 'acme',
    async evaluate(i) {
      calls.push({ resourceId: i.resourceId, ...(i.deviceId ? { deviceId: i.deviceId } : {}) });
      if (i.resourceId === 'flaky') throw new Error('engine down');
      const allow = i.pubkey === readerPk && (['general', 'acme', 'lobby'].includes(i.resourceId) || (i.resourceId === 'secret' && i.deviceId === 'dev-1'));
      return { allow, reasons: [] };
    },
  };
  // The reader is a member of every channel but 'lobby' (relay-signed kind 39002 lists).
  const relaySk = generateSecretKey();
  const groups = new GroupAuthorities([getPublicKey(relaySk)]);
  const memberList = (h: string) => finalizeEvent(toUnsigned({ kind: 39002, content: '', tags: [['d', h], ['p', readerPk, '', 'member']], created_at: Math.floor(Date.now() / 1000) }, getPublicKey(relaySk)), relaySk);
  const repo = new MemoryEventRepository();
  const api = createIndexerApi(repo, { name: 'indexer-policy-test', policy, groups });
  let base: string;
  const now = Math.floor(Date.now() / 1000);
  const msg = (h: string | undefined, content: string, kind = 9) => nt.finalizeEvent({ kind, content, tags: h ? [['h', h]] : [], created_at: now }, author) as NostrEvent;
  const ev = { general: msg('general', 'hola general'), secret: msg('secret', 'hola secreto'), other: msg('other', 'hola otro'), flaky: msg('flaky', 'hola flaky'), lobby: msg('lobby', 'hola lobby'), note: msg(undefined, 'hola nota', 1) };

  /** NIP-98 GET with an extra header. */
  async function getWithDevice(url: string, device: string) {
    const evt = finalizeEvent(toUnsigned(nip98.buildHttpAuthTemplate(url, 'GET'), readerPk), reader);
    const res = await fetch(url, { headers: { authorization: nip98.encodeAuthHeader(evt), [POLICY_DEVICE_HEADER]: device } });
    return (await res.json()) as { events: NostrEvent[] };
  }
  const ids = (r: { events: NostrEvent[] }) => r.events.map((e) => e.id).sort();

  beforeAll(async () => {
    for (const e of [...Object.values(ev), ...['general', 'secret', 'other', 'flaky'].map(memberList)]) await repo.upsert(e, 'ws://relay');
    base = await api.listen();
  });
  afterAll(() => api.close());

  it('requires authentication for every read', async () => {
    expect((await fetch(`${base}/v1/events?kinds=9`)).status).toBe(401);
    expect((await fetch(`${base}/v1/search?q=hola`)).status).toBe(401);
  });

  it('filters listed events by channel and workspace; unknown readers see nothing', async () => {
    const r = await nip98Fetch(reader, `${base}/v1/events?kinds=1,9`);
    expect(ids(r.json)).toEqual([ev.general.id, ev.note.id].sort());
    expect(r.json.meta).toHaveLength(2);
    expect((await nip98Fetch(generateSecretKey(), `${base}/v1/events?kinds=1,9`)).json.events).toEqual([]);
    // One evaluation per resource and request.
    calls.length = 0;
    await nip98Fetch(reader, `${base}/v1/events?kinds=1,9`);
    expect(calls.map((c) => c.resourceId).sort()).toEqual(['acme', 'flaky', 'general', 'other', 'secret']);
  });

  it('passes the device header so sensitive channels can require a registered device', async () => {
    expect(ids(await getWithDevice(`${base}/v1/events?kinds=9`, 'dev-1'))).toEqual([ev.general.id, ev.secret.id].sort());
    expect(calls.at(-1)).toMatchObject({ deviceId: 'dev-1' });
  });

  it('denies single events, summaries, cursors and unread counts of forbidden channels', async () => {
    expect((await nip98Fetch(reader, `${base}/v1/events/${ev.general.id}`)).status).toBe(200);
    expect((await nip98Fetch(reader, `${base}/v1/events/${ev.other.id}`)).status).toBe(404);
    expect((await nip98Fetch(reader, `${base}/v1/channels/general/summary`)).json.messages).toBe(1);
    expect((await nip98Fetch(reader, `${base}/v1/channels/other/summary`)).status).toBe(403);
    // An engine error is a deny.
    expect((await nip98Fetch(reader, `${base}/v1/channels/flaky/summary`)).status).toBe(403);
    expect((await nip98Fetch(reader, `${base}/v1/read-cursor`, 'PUT', { h: 'other', until: now })).status).toBe(403);
    expect((await nip98Fetch(reader, `${base}/v1/read-cursor`, 'PUT', { h: 'general', until: now - 10 })).status).toBe(200);
    expect((await nip98Fetch(reader, `${base}/v1/unread?h=general,other`)).json.unread).toEqual({ general: 1 });
    // FR014-04: the message times the web counts with omit the same channels ('secret' needs the device header).
    expect((await nip98Fetch(reader, `${base}/v1/unread/recent?h=general,other,secret,flaky,lobby`)).json.recent).toEqual({ general: [now] });
  });

  it('the policy is not enough: a channel the reader is not a member of stays closed (FR014-05)', async () => {
    expect((await nip98Fetch(reader, `${base}/v1/events/${ev.lobby.id}`)).status).toBe(404);
    expect((await nip98Fetch(reader, `${base}/v1/channels/lobby/summary`)).status).toBe(403);
    expect((await nip98Fetch(reader, `${base}/v1/search?q=hola&h=lobby`)).json.events).toEqual([]);
  });

  it('search only returns readable channels', async () => {
    expect(ids((await nip98Fetch(reader, `${base}/v1/search?q=hola`)).json)).toEqual([ev.general.id]);
    expect((await nip98Fetch(reader, `${base}/v1/search?q=hola&h=other,secret`)).json.events).toEqual([]);
    expect(ids((await nip98Fetch(reader, `${base}/v1/search?q=hola&h=other,general`)).json)).toEqual([ev.general.id]);
  });
});
