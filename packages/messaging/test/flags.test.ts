import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { generateSecretKey, getPublicKey } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { BUZZ_ADAPTER_JITTER_SECONDS, BUZZ_PINNED_ADAPTER, createDirectMessage, DEFAULT_TIMESTAMP_JITTER_SECONDS, flagsFromInteropReport, nip17FlagsChange, nip17GateDecision, wrapOptionsFromFlags, type Nip17StrategyResult } from '../src/index';

const ok: Nip17StrategyResult = { accepted: 3, attempts: 3, messages: [] };
const rejected: Nip17StrategyResult = { accepted: 0, attempts: 3, messages: Array(3).fill('invalid: event timestamp too far from server time') };
const report = (strategies: Record<string, Nip17StrategyResult>, received = 6) => ({ relay: 'ws://buzz', finishedAt: '2026-09-26T00:00:00Z', nip17: { strategies, receivedByRecipient: received, ...nip17GateDecision(strategies, received) } });
const flagsOf = (strategies: Record<string, Nip17StrategyResult>, received?: number) => flagsFromInteropReport(report(strategies, received), 'buzz@test', 'test');

describe('NIP-17 gate → deployment flags (FR017-05, upstream #4192)', () => {
  it('stays on the 300 s adapter while Buzz rejects the NIP-59 default', () => {
    const f = flagsOf({ 'nip59-default-2d': rejected, 'bounded-5m': ok, none: ok });
    expect(f.nip17).toEqual({ enabled: true, timestampJitterSeconds: BUZZ_ADAPTER_JITTER_SECONDS });
    expect(BUZZ_ADAPTER_JITTER_SECONDS).toBe(300);
    expect(wrapOptionsFromFlags(f, BUZZ_PINNED_ADAPTER.wrap).timestampJitterSeconds).toBe(300);
  });

  it('reverts to the standard 2-day jitter as soon as the gate accepts the NIP-59 default', () => {
    const f = flagsOf({ 'nip59-default-2d': ok, 'bounded-5m': ok, none: ok });
    expect(f.nip17).toEqual({ enabled: true, timestampJitterSeconds: 172800 });
    expect(DEFAULT_TIMESTAMP_JITTER_SECONDS).toBe(172800);
    // The flags override the pinned adapter's fallback: clients stop using the 300 s window.
    expect(wrapOptionsFromFlags(f, BUZZ_PINNED_ADAPTER.wrap).timestampJitterSeconds).toBe(172800);
  });

  it('a partially accepted default does not count as fixed', () => {
    const f = flagsOf({ 'nip59-default-2d': { accepted: 2, attempts: 3 }, 'bounded-5m': ok });
    expect(f.nip17.timestampJitterSeconds).toBe(300);
  });

  it('keeps NIP-17 off when no strategy passes or nothing was received', () => {
    expect(flagsOf({ 'nip59-default-2d': rejected, 'bounded-5m': rejected }).nip17).toEqual({ enabled: false, timestampJitterSeconds: null });
    expect(flagsOf({ 'nip59-default-2d': ok, 'bounded-5m': ok }, 0).nip17).toEqual({ enabled: false, timestampJitterSeconds: null });
    expect(nip17GateDecision({}, 3)).toEqual({ recommendedJitterSeconds: null, enableFlag: false });
    expect(nip17GateDecision({ 'nip59-default-2d': { accepted: 0, attempts: 0 } }, 3).recommendedJitterSeconds).toBeNull();
  });

  it('matches the committed gate evidence and flags (Buzz still rejects: 300 s)', () => {
    const evidence = JSON.parse(readFileSync(new URL('../../../docs/interop/buzz-upstream-8096413eb360-report.json', import.meta.url), 'utf8'));
    expect(nip17GateDecision(evidence.nip17.strategies, evidence.nip17.receivedByRecipient)).toEqual({ recommendedJitterSeconds: evidence.nip17.recommendedJitterSeconds, enableFlag: evidence.nip17.enableFlag });
    const committed = JSON.parse(readFileSync(new URL('../../../infra/web/flags.json', import.meta.url), 'utf8'));
    expect(committed.nip17.timestampJitterSeconds).toBe(evidence.nip17.recommendedJitterSeconds);
  });

  it('wraps built with the reverted flags use the full two-day window again', async () => {
    const sk = generateSecretKey();
    const now = 1_800_000_000;
    const opts = { ...wrapOptionsFromFlags(flagsOf({ 'nip59-default-2d': ok, 'bounded-5m': ok }), BUZZ_PINNED_ADAPTER.wrap), now };
    const ages: number[] = [];
    for (let i = 0; i < 12; i++) {
      const dm = await createDirectMessage(new LocalSigner(sk), { recipients: [getPublicKey(generateSecretKey())], content: `m${i}` }, opts);
      for (const w of dm.wraps) ages.push(now - w.event.created_at);
    }
    expect(Math.min(...ages)).toBeGreaterThanOrEqual(0);
    expect(Math.max(...ages)).toBeLessThanOrEqual(172800);
    expect(Math.max(...ages)).toBeGreaterThan(300);
  });

  it('summarises the jitter change for the pin PR body', () => {
    const adapter = flagsOf({ 'nip59-default-2d': rejected, 'bounded-5m': ok });
    const standard = flagsOf({ 'nip59-default-2d': ok, 'bounded-5m': ok });
    const off = flagsOf({ 'nip59-default-2d': rejected, 'bounded-5m': rejected });
    expect(nip17FlagsChange(adapter, adapter)).toBeUndefined();
    expect(nip17FlagsChange(adapter, standard)).toMatch(/^#4192 resuelto upstream: se vuelve al jitter estándar de NIP-59 \(172800 s, antes: jitter 300 s\)/);
    expect(nip17FlagsChange(standard, adapter)).toMatch(/^Regresión de #4192/);
    expect(nip17FlagsChange(adapter, off)).toBe('Cambian los flags NIP-17: jitter 300 s → NIP-17 deshabilitado.');
    expect(nip17FlagsChange(undefined, standard)).toMatch(/^#4192 resuelto/);
  });
});
