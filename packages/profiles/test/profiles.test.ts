import { describe, expect, it } from 'vitest';
import { PRESETS, preset, disclose, disclosureCatalog, summarize, validateConfig, isValid, assertNoAbsoluteClaims, receiptPolicy, continuityPolicy, DISCLOSURE_VERSION, MANAGED_CONSENT_TEXTS, managedConsentVersion, PUBLIC_PROFILE_TEXTS, type PresetName, type SovereigntyConfig } from '../src/index';

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

  it('tells only what this version does (PANEL-05): no audit claimed, no tracing promised', () => {
    const all = disclosureCatalog();
    expect(all.flatMap((d) => [d.statement, ...d.trustAssumptions]).join(' ')).not.toMatch(/auditada/);
    for (const d of all.filter((x) => x.control === 'telemetry')) expect(d.statement).toMatch(/no (los genera|genera|envía|se emite)/);
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

  it('Tor-only accepts a NIP-46 signer and says when the key is on the device instead; custody texts fit imported keys and signers (FR004-08)', () => {
    const tor = (custody: SovereigntyConfig['custody']) => validateConfig({ ...preset('sovereign-tor'), custody }, 'cli');
    // Spec §14: an offline key or a signer. A signer is valid and warns nothing about the key; a key on the device is said so.
    expect(tor('external').filter((i) => i.severity === 'error')).toEqual([]);
    expect(tor('external').map((i) => i.code)).not.toContain('TOR_DEVICE_KEY');
    const onDevice = tor('local').find((i) => i.code === 'TOR_DEVICE_KEY');
    expect(onDevice).toMatchObject({ severity: 'warning', controls: ['custody', 'network'] });
    expect(onDevice!.message).toMatch(/está en este dispositivo.*Con un signer externo \(NIP-46\), la llave no está en este dispositivo/);
    expect(validateConfig({ ...preset('sovereign'), custody: 'local' }, 'cli').map((i) => i.code)).not.toContain('TOR_DEVICE_KEY');
    const custody = (c: SovereigntyConfig['custody']) => disclose({ ...preset('sovereign-tor'), custody: c }).find((d) => d.control === 'custody')!.statement;
    // A local key may have been imported: the text no longer says it was generated here.
    expect(custody('local')).toMatch(/^La llave se guarda cifrada en este dispositivo, creada aquí o importada/);
    expect(custody('external')).toMatch(/este cliente nunca ve la nsec\. El signer ve lo que firma y los mensajes directos que descifra por ti\./);
  });

  it('the managed custody consent is reviewed copy with a version (FR005-08)', () => {
    const custody = disclose({ ...preset('convenience'), custody: 'managed' }).find((d) => d.control === 'custody')!;
    expect(custody.statement).toMatch(/descifra en su servidor tus mensajes directos \(NIP-44\)/);
    const reviewed = disclosureCatalog().map((d) => d.statement);
    for (const text of Object.values(MANAGED_CONSENT_TEXTS)) expect(reviewed).toContain(text);
    expect(managedConsentVersion('2026-10')).toBe(`textos ${DISCLOSURE_VERSION}; términos 2026-10`);
    expect(managedConsentVersion()).toBe(`textos ${DISCLOSURE_VERSION}; términos no publicados`);
  });

  it('what publishing a public profile reveals is reviewed copy, pseudonymous personas included (FR006-04)', () => {
    const reviewed = disclosureCatalog().filter((d) => d.control === 'identity' && d.option.startsWith('public-profile'));
    expect(reviewed.map((d) => d.statement)).toEqual(Object.values(PUBLIC_PROFILE_TEXTS));
    expect(PUBLIC_PROFILE_TEXTS.pseudonymous).toMatch(/no se publica ningún perfil salvo que lo elijas/);
    expect(PUBLIC_PROFILE_TEXTS.pseudonymous).toMatch(/relacionarla con otras identidades tuyas/);
    expect(PUBLIC_PROFILE_TEXTS.withdraw).toMatch(/las copias que otros ya guardaron no desaparecen/);
  });

  it('what the web secure groups say about devices, rotation, proposals and files is reviewed copy (FR025-14)', async () => {
    const { SECURE_GROUP_TEXTS } = await import('../src/index');
    const reviewed = disclosureCatalog().filter((d) => d.control === 'messaging' && d.option.startsWith('marmot en la web'));
    expect(reviewed.map((d) => d.statement)).toEqual(Object.values(SECURE_GROUP_TEXTS));
    // Who sees what: the relay only ever gets ciphertext, a Blossom server gets the npub that signs the upload.
    expect(SECURE_GROUP_TEXTS.devices).toMatch(/key package firmado con tu npub por cada dispositivo/);
    expect(SECURE_GROUP_TEXTS.media).toMatch(/cada servidor ve tu npub, que firma la subida, tu dirección IP/);
    expect(SECURE_GROUP_TEXTS.proposals).toMatch(/no pueden enviar mensajes ni archivos/);
    expect(SECURE_GROUP_TEXTS.rotate).toMatch(/Las propuestas pendientes se descartan/);
    expect(SECURE_GROUP_TEXTS.addDevices).toMatch(/dispositivo perdido o revocado/);
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

describe('Continuity Vault policy (VAULT-04)', () => {
  it('private-resilient requires the copy, convenience and institutional copy best-effort, the sovereign profiles none', () => {
    expect(Object.fromEntries(Object.entries(PRESETS).map(([n, c]) => [n, c.continuity]))).toEqual({ convenience: 'best-effort', 'private-resilient': 'required-for-resilient', institutional: 'best-effort', sovereign: 'off', 'sovereign-tor': 'off' });
    // A configuration stored before VAULT-04 has no policy: it means off, never a copy the user did not choose.
    const { continuity: _dropped, ...older } = preset('convenience');
    expect(continuityPolicy(older)).toBe('off');
  });

  it('a copy needs the cloud backup on, and requiring it needs a vault', () => {
    const codes = (c: SovereigntyConfig, ctx?: { continuityVault?: boolean; relays?: number }) => validateConfig(c, 'web', ctx).map((i) => `${i.severity}:${i.code}`);
    expect(codes({ ...preset('sovereign'), continuity: 'best-effort' })).toContain('error:CONTINUITY_CLOUD_OFF');
    expect(codes(preset('private-resilient'), { continuityVault: false, relays: 2 })).toContain('error:CONTINUITY_NO_VAULT');
    expect(codes(preset('convenience'), { continuityVault: false })).toContain('warning:CONTINUITY_NO_VAULT');
    expect(codes(preset('private-resilient'), { continuityVault: true, relays: 2 }).filter((c) => c.includes('CONTINUITY'))).toEqual([]);
    // Unknown deployment (no context): nothing to say about the vault.
    expect(codes(preset('private-resilient')).filter((c) => c.includes('CONTINUITY'))).toEqual([]);
  });

  it('each policy says what the vault operator sees and what may hold a send', () => {
    const say = (continuity: SovereigntyConfig['continuity']) => disclose({ ...preset('convenience'), continuity }).find((d) => d.control === 'continuity')!;
    expect(say('best-effort').statement).toMatch(/el envío sale igual.*El operador del vault ve cuándo envías/s);
    expect(say('required-for-resilient').statement).toMatch(/queda retenido/);
    expect(say('required-for-resilient').sacrifices).toContain('soberania');
    expect(say('off').sacrifices).toContain('recuperabilidad');
  });
});

describe('crash reports per profile (NFR007-03)', async () => {
  const { CRASH_RETENTION } = await import('@sedecim/telemetry-policy/crash-report');
  type Mode = SovereigntyConfig['crashReports'];

  it('NFR007-03: manual-export where Appendix B has manual-export or opt-in, off in private-resilient and sovereign-tor, and no preset keeps reports on the device', () => {
    expect(Object.fromEntries(Object.entries(PRESETS).map(([n, c]) => [n, c.crashReports]))).toEqual({ convenience: 'manual-export', 'private-resilient': 'off', institutional: 'manual-export', sovereign: 'manual-export', 'sovereign-tor': 'off' });
  });

  it('NFR007-03: Tor-only allows manual-export and refuses opt-in, a record of failures kept on the device; elsewhere opt-in is the person’s choice', () => {
    const crashIssues = (c: SovereigntyConfig, platform: 'cli' | 'web') => validateConfig(c, platform).filter((i) => i.controls.includes('crashReports'));
    const tor = (crashReports: Mode) => crashIssues({ ...preset('sovereign-tor'), crashReports }, 'cli');
    expect(tor('off')).toEqual([]);
    expect(tor('manual-export')).toEqual([]);
    expect(tor('opt-in')).toEqual([expect.objectContaining({ severity: 'error', code: 'TOR_CRASH_REPORTS' })]);
    expect(tor('opt-in')[0]!.message).toMatch(/elige off o manual-export, que solo escribe un informe limpio en un archivo si lo pides con --crash-report/);
    expect(isValid({ ...preset('sovereign-tor'), crashReports: 'manual-export' }, 'cli')).toBe(true);
    for (const name of ['convenience', 'private-resilient', 'institutional', 'sovereign'] as const) expect(crashIssues({ ...preset(name), crashReports: 'opt-in' }, name === 'sovereign' ? 'cli' : 'web')).toEqual([]);
  });

  it('NFR007-03: each option says what the code does: nothing is sent, the last failure is not stored, the store keeps reports within its retention', () => {
    const say = (crashReports: Mode) => disclose({ ...preset('convenience'), crashReports }).find((d) => d.control === 'crashReports')!;
    expect(say('off').statement).toMatch(/no guarda ni recuerda nada del fallo/);
    expect(say('manual-export').statement).toMatch(/sin guardarlo en el dispositivo ni enviarlo\. Puedes verlo entero y guardarlo en un archivo/);
    expect(say('manual-export').statement).toMatch(/en el CLI, repitiendo el comando con --crash-report/);
    expect(say('opt-in').statement).toMatch(new RegExp(`cifrado en el almacén local de este dispositivo, como máximo ${CRASH_RETENTION.maxReports} informes y ${CRASH_RETENTION.maxAgeDays} días cada uno`));
    expect(say('opt-in').statement).toMatch(/Nada se envía: lo que sale del dispositivo lo sacas tú\. Ningún perfil lo enciende por defecto\./);
    // No option sends anything to an operator, so none moves a dimension of the panel.
    for (const mode of ['off', 'manual-export', 'opt-in'] as const) expect([say(mode).improves, say(mode).sacrifices]).toEqual([[], []]);
    expect(disclosureCatalog().filter((d) => d.control === 'crashReports').map((d) => d.statement).join(' ')).not.toMatch(/todavía no existen|no genera ninguno/);
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
    const reviewed: Record<string, string> = { '1.0.0': 'e4ecf0a4490a8626', '1.1.0': '8e60df4e7bddcb9d', '1.2.0': '17d3382b506f8e66', '1.3.0': 'c334d30e84ceb453', '1.4.0': '26815b67816b9ac2', '1.5.0': '7c37100740b85027', '1.6.0': 'fc1a8bc65067a39b', '1.7.0': '5744da9a3d86d6a3', '1.8.0': 'ea21f9293106b69d', '1.9.0': 'a144762b252f4f4c', '1.10.0': 'c77e72631f7b5747', '1.11.0': '7d98f0e859013455', '1.12.0': '834fcc54845c134d', '1.13.0': 'e423fd07d4a31dd0', '1.14.0': 'c8cb0d54911f1cec', '1.15.0': '957da59e00fd9df7' };
    const digest = createHash('sha256').update(JSON.stringify(disclosureCatalog())).digest('hex').slice(0, 16);
    expect(reviewed[DISCLOSURE_VERSION], `record the digest of version ${DISCLOSURE_VERSION}`).toBe(digest);
    for (const d of disclosureCatalog()) expect(() => assertNoAbsoluteClaims(d.statement)).not.toThrow();
  });
});

describe('deleting in channels (FR015-04)', async () => {
  const { CHANNEL_DELETION_TEXTS } = await import('../src/index');

  it('FR015-04: says which deletion each action publishes and that copies already out are not withdrawn, as reviewed copy', () => {
    expect(CHANNEL_DELETION_TEXTS.message).toMatch(/kind 9005.*autor del mensaje o un admin del canal/s);
    expect(CHANNEL_DELETION_TEXTS.reaction).toMatch(/NIP-09 \(kind 5\)/);
    expect(CHANNEL_DELETION_TEXTS.copies).toMatch(/no retira las copias que ya circularon/);
    const reviewed = disclosureCatalog();
    for (const text of Object.values(CHANNEL_DELETION_TEXTS)) expect(reviewed.find((d) => d.statement === text)?.control).toBe('persistence');
  });
});

describe('channel mirror per profile (FR014-04)', async () => {
  const { CHANNEL_MIRROR_TEXTS, mirrorMatrix, mirrorPolicy } = await import('../src/index');

  it('FR014-04: convenience and institutional use the mirror; private-resilient, sovereign and Tor never do', () => {
    expect(Object.fromEntries(mirrorMatrix().map((r) => [r.profile, r.policy.use]))).toEqual({ convenience: true, 'private-resilient': false, institutional: true, sovereign: false, 'sovereign-tor': false });
    // Derived from the controls, so a customized persona gets what its controls say.
    expect(mirrorPolicy({ ...preset('convenience'), identity: 'pseudonymous' })).toMatchObject({ use: false, reason: 'pseudonymous' });
    expect(mirrorPolicy({ ...preset('convenience'), network: 'tor-only' })).toMatchObject({ use: false, reason: 'tor-only' });
    expect(mirrorPolicy({ ...preset('private-resilient'), identity: 'linked' })).toMatchObject({ use: true });
    // Tor-only wins over any identity.
    expect(mirrorPolicy({ ...preset('sovereign-tor'), identity: 'verified' })).toMatchObject({ use: false, reason: 'tor-only' });
  });

  it('FR014-04: each answer says what the operator sees or why there are no counters, as reviewed copy', () => {
    expect(mirrorPolicy(preset('convenience')).statement).toMatch(/firmada con tu npub \(NIP-98\).*el texto que buscas/s);
    expect(mirrorPolicy(preset('sovereign')).statement).toMatch(/no hay contadores de no leídos ni búsqueda/);
    expect(mirrorPolicy(preset('sovereign-tor')).statement).toMatch(/Tor-only/);
    expect(CHANNEL_MIRROR_TEXTS.readState).toMatch(/no se envía al mirror/);
    const reviewed = disclosureCatalog();
    for (const text of Object.values(CHANNEL_MIRROR_TEXTS)) expect(reviewed.map((d) => d.statement)).toContain(text);
    expect(reviewed.find((d) => d.statement === CHANNEL_MIRROR_TEXTS.torOnly)?.control).toBe('network');
  });
});

describe('presence per profile (FR015-05)', async () => {
  const { PRESENCE_TEXTS, presenceMatrix, presenceOption, presencePolicy } = await import('../src/index');
  const codes = (c: SovereigntyConfig, platform: 'web' | 'cli' = 'web') => validateConfig(c, platform).map((i) => `${i.severity}:${i.code}`);

  it('FR015-05: no preset turns presence on, and a configuration stored before it has none, which is off', () => {
    for (const name of Object.keys(PRESETS) as PresetName[]) expect(preset(name).presence, name).toBe('off');
    const { presence: _dropped, ...older } = preset('convenience');
    expect(presenceOption(older)).toBe('off');
    expect(presencePolicy(older)).toMatchObject({ use: false, reason: 'off' });
    for (const name of Object.keys(PRESETS) as PresetName[]) expect(presencePolicy(preset(name)).use, name).toBe(false);
  });

  it('FR015-05: once turned on, convenience, private-resilient and sovereign allow it; institutional and sovereign-tor never', () => {
    expect(Object.fromEntries(presenceMatrix().map((r) => [r.profile, r.policy.use ? 'allowed' : r.policy.reason]))).toEqual({
      convenience: 'allowed',
      'private-resilient': 'allowed',
      institutional: 'organization',
      sovereign: 'allowed',
      'sovereign-tor': 'tor-only',
    });
    // Derived from the controls, so a customized persona gets what its controls say: Tor-only wins over any identity.
    expect(presencePolicy({ ...preset('sovereign-tor'), identity: 'linked', presence: 'status' })).toMatchObject({ use: false, reason: 'tor-only' });
    expect(presencePolicy({ ...preset('convenience'), identity: 'verified', presence: 'status' })).toMatchObject({ use: false, reason: 'organization' });
  });

  it('FR015-05: turning it on is blocking in Tor-only and with a verified identity, a warning for a pseudonymous persona, and nothing more for a linked one', () => {
    const on = (name: PresetName) => ({ ...preset(name), presence: 'status' as const });
    expect(codes(on('sovereign-tor'), 'cli')).toContain('error:TOR_PRESENCE');
    expect(isValid(on('sovereign-tor'), 'cli')).toBe(false);
    expect(isValid(preset('sovereign-tor'), 'cli')).toBe(true);
    expect(codes(on('institutional'))).toContain('error:PRESENCE_ORGANIZATION');
    expect(isValid(on('institutional'), 'web')).toBe(false);
    for (const name of ['private-resilient', 'sovereign'] as const) {
      expect(codes(on(name)), name).toContain('warning:PRESENCE_PSEUDONYMOUS');
      expect(isValid(on(name), 'web'), name).toBe(true);
    }
    expect(codes(on('convenience')).filter((c) => c.includes('PRESENCE'))).toEqual([]);
    expect(isValid(on('convenience'), 'web')).toBe(true);
    // Off, nothing is said about presence in any profile.
    for (const name of Object.keys(PRESETS) as PresetName[]) expect(codes(preset(name), 'cli').filter((c) => c.includes('PRESENCE')), name).toEqual([]);
    const tor = validateConfig(on('sovereign-tor'), 'cli').find((i) => i.code === 'TOR_PRESENCE')!;
    expect(tor).toMatchObject({ controls: ['presence', 'network'], message: PRESENCE_TEXTS.torOnly });
  });

  it('FR015-05: the panel says what each option publishes and asks, and every presence text is reviewed copy', () => {
    const say = (presence: SovereigntyConfig['presence']) => disclose({ ...preset('convenience'), presence }).find((d) => d.control === 'presence')!;
    expect(say('off')).toMatchObject({ improves: ['privacidad-operador'], statement: expect.stringMatching(/no publica ni pide estados \(NIP-38, kind 30315\)/) });
    expect(say('status')).toMatchObject({ sacrifices: ['privacidad-operador'], statement: expect.stringMatching(/caduca como mucho a las 24 horas.*en la misma consulta que sus perfiles/s) });
    const reviewed = disclosureCatalog().filter((d) => d.control === 'presence' && d.option.startsWith('estado ('));
    expect(reviewed.map((d) => d.statement)).toEqual(Object.values(PRESENCE_TEXTS));
    expect(PRESENCE_TEXTS.what).toMatch(/ni «en línea», ni «escribiendo», ni la última vez que te conectaste/);
    expect(PRESENCE_TEXTS.clear).toMatch(/caduca en una hora.*las copias que otros ya guardaron no desaparecen/s);
    expect(PRESENCE_TEXTS.others).toMatch(/ninguna consulta aparte pide el estado de otra persona/);
    for (const text of Object.values(PRESENCE_TEXTS)) expect(() => assertNoAbsoluteClaims(text)).not.toThrow();
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
