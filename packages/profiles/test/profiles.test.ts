import { describe, expect, it } from 'vitest';
import { PRESETS, preset, disclose, summarize, validateConfig, isValid, assertNoAbsoluteClaims, receiptPolicy, type PresetName } from '../src/index';

describe('sovereignty profiles', () => {
  it('reference presets are valid on their intended platforms', () => {
    for (const name of Object.keys(PRESETS) as PresetName[]) {
      const platform = name === 'sovereign-tor' ? 'cli' : 'web';
      expect(isValid(preset(name), platform), name).toBe(true);
    }
  });

  it('rejects unsafe Tor-only combinations and Tor-only in the browser', () => {
    const c = { ...preset('sovereign-tor'), telemetry: 'standard' as const, notifications: 'push' as const, custody: 'managed' as const };
    const codes = validateConfig(c, 'web').filter((i) => i.severity === 'error').map((i) => i.code);
    expect(codes).toEqual(expect.arrayContaining(['TOR_WEB_UNSUPPORTED', 'TOR_TELEMETRY', 'TOR_PUSH', 'TOR_MANAGED_KEY']));
  });

  it('every control shows consequences and trust assumptions (FR-028)', () => {
    for (const name of Object.keys(PRESETS) as PresetName[]) {
      const items = disclose(preset(name));
      const controls = new Set(items.map((i) => i.control));
      for (const k of ['custody', 'network', 'identity', 'persistence', 'messaging', 'files', 'telemetry', 'notifications']) expect(controls.has(k as never)).toBe(true);
      for (const i of items) {
        expect(i.statement.length).toBeGreaterThan(10);
        expect(() => assertNoAbsoluteClaims(i.statement)).not.toThrow();
      }
    }
    const managed = disclose({ ...preset('convenience'), custody: 'managed' }).find((i) => i.control === 'custody')!;
    expect(managed.statement).toMatch(/capacidad técnica de firmar/);
    expect(managed.statement).toMatch(/CUSTODIAL/);
  });

  it('summarizes the four dimensions separately with backing statements', () => {
    const s = summarize(preset('institutional'));
    expect(Object.keys(s).sort()).toEqual(['control-institucional', 'privacidad-operador', 'recuperabilidad', 'soberania']);
    expect(s.soberania.reducedBy.some((t) => t.includes('CUSTODIAL'))).toBe(true);
  });

  it('refuses absolute anonymity claims', () => {
    expect(() => assertNoAbsoluteClaims('Modo 100% anónimo')).toThrow();
  });

  it('applies the ADR 0005 receipt policy per preset', () => {
    expect(receiptPolicy(preset('convenience'))).toEqual({ delivered: true, read: false });
    expect(receiptPolicy(preset('institutional'))).toEqual({ delivered: true, read: false });
    expect(receiptPolicy(preset('sovereign'))).toEqual({ delivered: false, read: false });
    expect(receiptPolicy(preset('sovereign-tor'))).toEqual({ delivered: false, read: false });
    const codes = validateConfig({ ...preset('sovereign-tor'), deliveryReceipts: true }, 'cli').map((i) => i.code);
    expect(codes).toContain('TOR_DELIVERY_RECEIPTS');
  });
});
