import { describe, expect, it } from 'vitest';
import { PRESETS, preset, disclose, disclosureCatalog, summarize, validateConfig, isValid, assertNoAbsoluteClaims, receiptPolicy, DISCLOSURE_VERSION, MANAGED_CONSENT_TEXTS, managedConsentVersion, type PresetName, type SovereigntyConfig } from '../src/index';

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

  it("refuses a quorum above the persona's relays instead of capping it in silence (FR010-04)", () => {
    const resilient = preset('private-resilient');
    expect(resilient.quorum).toBe(2);
    const refused = validateConfig(resilient, 'web', { relays: 1 }).find((i) => i.code === 'QUORUM_RELAYS');
    expect(refused).toMatchObject({ severity: 'error', controls: ['quorum'] });
    expect(refused!.message).toMatch(/quorum \(2\) supera los relays de esta persona \(1\)/);
    expect(isValid(resilient, 'web', { relays: 1 })).toBe(false);
    expect(validateConfig(resilient, 'web', { relays: 2 }).filter((i) => i.code.startsWith('QUORUM'))).toEqual([]);
    // Without the relays (e.g. a preset on its own) only the hint for direct connections remains.
    const direct = { ...preset('convenience'), quorum: 2 };
    expect(validateConfig(direct, 'web').map((i) => i.code)).toContain('QUORUM_SINGLE');
    expect(validateConfig(direct, 'web', { relays: 3 }).filter((i) => i.code.startsWith('QUORUM'))).toEqual([]);
  });

  it('tells only what this version does (PANEL-05): no audit claimed, no crash reports or tracing promised', () => {
    const all = disclosureCatalog();
    expect(all.flatMap((d) => [d.statement, ...d.trustAssumptions]).join(' ')).not.toMatch(/auditada/);
    for (const d of all.filter((x) => x.control === 'crashReports' || x.control === 'telemetry')) expect(d.statement).toMatch(/no (los genera|genera|envía|se emite)/);
    for (const name of Object.keys(PRESETS) as PresetName[]) expect(preset(name).crashReports).toBe('off');
    const metadata = (on: boolean) => disclose({ ...preset('convenience'), stripFileMetadata: on }).find((d) => d.control === 'stripFileMetadata')!;
    expect(metadata(true)).toMatchObject({ improves: ['privacidad-operador'], statement: expect.stringMatching(/HEIC, TIFF\/RAW\) se rechazan/) });
    expect(metadata(false)).toMatchObject({ sacrifices: ['privacidad-operador'], statement: expect.stringMatching(/dónde y con qué dispositivo/) });
  });

  it('shows the residual risks of the high-risk profile, and the IP of a pseudonymous persona without Tor (PANEL-05)', () => {
    const warnings = (c: SovereigntyConfig) => validateConfig(c, 'cli').filter((i) => i.severity === 'warning').map((i) => i.code);
    expect(warnings(preset('sovereign-tor'))).toEqual(expect.arrayContaining(['TOR_EXPERIMENTAL', 'TOR_CORRELATION', 'TOR_HABITS']));
    expect(isValid(preset('sovereign-tor'), 'cli')).toBe(true); // shown, never blocking
    expect(warnings(preset('sovereign'))).toContain('NO_TOR_IP');
    expect(warnings(preset('convenience'))).not.toContain('NO_TOR_IP'); // a linked identity has no pseudonym to protect
    expect(warnings({ ...preset('sovereign'), custody: 'local' })).toContain('LOSS_RISK'); // a key on this device, no backup
  });

  it('the managed custody consent is reviewed copy with a version (FR005-08)', () => {
    const custody = disclose({ ...preset('convenience'), custody: 'managed' }).find((d) => d.control === 'custody')!;
    expect(custody.statement).toMatch(/descifra en su servidor tus mensajes directos \(NIP-44\)/);
    const reviewed = disclosureCatalog().map((d) => d.statement);
    for (const text of Object.values(MANAGED_CONSENT_TEXTS)) expect(reviewed).toContain(text);
    expect(managedConsentVersion('2026-10')).toBe(`textos ${DISCLOSURE_VERSION}; términos 2026-10`);
    expect(managedConsentVersion()).toBe(`textos ${DISCLOSURE_VERSION}; términos no publicados`);
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

describe('localProtection (ADR 0007)', () => {
  it('allows the device key only for the convenience profile', () => {
    const ok = validateConfig({ ...preset('convenience'), localProtection: 'device' }, 'web');
    expect(ok.some((i) => i.severity === 'error')).toBe(false);
    expect(ok.map((i) => i.code)).toContain('DEVICE_KEY');
    for (const name of ['private-resilient', 'institutional', 'sovereign', 'sovereign-tor'] as const) {
      expect(validateConfig({ ...preset(name), localProtection: 'device' }, 'cli').map((i) => i.code)).toContain('DEVICE_KEY_PROFILE');
    }
  });

  it('every preset defaults to a passphrase and discloses it', () => {
    for (const name of Object.keys(PRESETS) as Array<keyof typeof PRESETS>) expect(preset(name).localProtection).toBe('passphrase');
    expect(disclose({ ...preset('convenience'), localProtection: 'device' }).find((d) => d.control === 'localProtection')?.statement).toMatch(/cualquiera con acceso/);
  });
});

describe('disclosure copy versioning (FR028-02)', () => {
  it('changing any statement requires bumping DISCLOSURE_VERSION (and a new legal/UX review)', async () => {
    const { createHash } = await import('node:crypto');
    const { DISCLOSURE_VERSION, disclosureCatalog } = await import('../src/index');
    const reviewed: Record<string, string> = { '1.0.0': 'e4ecf0a4490a8626', '1.1.0': '8e60df4e7bddcb9d', '1.2.0': '17d3382b506f8e66', '1.3.0': 'c334d30e84ceb453', '1.4.0': '26815b67816b9ac2' };
    const digest = createHash('sha256').update(JSON.stringify(disclosureCatalog())).digest('hex').slice(0, 16);
    expect(reviewed[DISCLOSURE_VERSION], `record the digest of version ${DISCLOSURE_VERSION}`).toBe(digest);
    for (const d of disclosureCatalog()) expect(() => assertNoAbsoluteClaims(d.statement)).not.toThrow();
  });
});

describe('notification model per profile (ADR 0010, DEC-08)', async () => {
  const { NOTIFICATION_MODES, OPAQUE_PUSH_PAYLOAD, notificationMatrix, notificationPolicy, nextPushDelayMs } = await import('../src/index');

  it('encodes the decided matrix: opaque push, privacy-push, none', () => {
    const matrix = Object.fromEntries(notificationMatrix().map((r) => [r.profile, r.policy.mode]));
    expect(matrix).toEqual({ convenience: 'push', 'private-resilient': 'privacy-push', institutional: 'push', sovereign: 'none', 'sovereign-tor': 'none' });
  });

  it('never carries content, sender or count; privacy-push is a wake signal with longer delays', () => {
    expect(JSON.parse(OPAQUE_PUSH_PAYLOAD)).toEqual({ v: 1 });
    const push = NOTIFICATION_MODES.push;
    const wake = NOTIFICATION_MODES['privacy-push'];
    expect(push.payload).toBe('fixed-opaque');
    expect(wake.payload).toBe('empty');
    expect(NOTIFICATION_MODES.none.payload).toBe('none');
    expect(wake.minDelayMs).toBeGreaterThan(push.maxDelayMs);
    expect(wake.minIntervalMs).toBeGreaterThan(push.minIntervalMs);
    for (const m of [push, wake]) {
      expect(m.minDelayMs).toBeGreaterThan(0);
      expect(m.exposes.pushProvider.length && m.exposes.gatewayOperator.length && m.exposes.relay.length).toBeGreaterThan(0);
      for (const t of [...m.exposes.pushProvider, ...m.exposes.gatewayOperator, ...m.exposes.relay]) expect(() => assertNoAbsoluteClaims(t)).not.toThrow();
    }
    expect(NOTIFICATION_MODES.none.exposes).toEqual({ pushProvider: [], gatewayOperator: [], relay: [] });
  });

  it('Tor-only never pushes, and any push is blocking in Tor-only', () => {
    expect(notificationPolicy({ ...preset('convenience'), network: 'tor-only' }).mode).toBe('none');
    for (const n of ['push', 'privacy-push'] as const) {
      const codes = validateConfig({ ...preset('sovereign-tor'), notifications: n }, 'cli').filter((i) => i.severity === 'error').map((i) => i.code);
      expect(codes).toContain('TOR_PUSH');
    }
  });

  it('delays are random within bounds and respect the minimum interval (batching)', () => {
    const p = NOTIFICATION_MODES.push;
    // aligned to the batch tick: the delay is the random jitter rounded up to the next tick boundary
    expect(nextPushDelayMs(p, 0, undefined, () => 0)).toBe(Math.ceil(p.minDelayMs / p.batchTickMs) * p.batchTickMs);
    expect(nextPushDelayMs(p, 0, undefined, () => 0.999999)).toBe(Math.ceil(p.maxDelayMs / p.batchTickMs) * p.batchTickMs);
    for (let i = 0; i < 50; i++) {
      const now = 1_000_003 + i * 7919;
      const d = nextPushDelayMs(p, now, undefined);
      expect(d).toBeGreaterThanOrEqual(p.minDelayMs);
      expect(d).toBeLessThan(p.maxDelayMs + p.batchTickMs);
      expect((now + d) % p.batchTickMs).toBe(0);
    }
    // just sent: the next push waits at least minIntervalMs
    expect(nextPushDelayMs(p, 0, 0, () => 0)).toBeGreaterThanOrEqual(p.minIntervalMs);
  });
});
