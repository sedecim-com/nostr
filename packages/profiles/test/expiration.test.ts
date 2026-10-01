/**
 * PANEL-06 (§12.2): the expiration of direct messages per profile, persona and conversation, what its copy says, and
 * the notice when the Continuity Vault may keep copies longer than the messages ask to live.
 */
import { describe, expect, it } from 'vitest';
import {
  assertNoAbsoluteClaims,
  CHANNEL_DELETION_TEXTS,
  disclose,
  disclosureCatalog,
  DM_DELETION_TEXTS,
  expirationDays,
  MESSAGE_EXPIRATION_OPTIONS,
  MESSAGE_EXPIRATION_TEXTS,
  PRESETS,
  preset,
  resolveMessageExpiration,
  validateConfig,
  vaultExpirationNotice,
  type PresetName,
} from '../src/index';

describe('message expiration settings (PANEL-06)', () => {
  it('PANEL-06: the conversation wins over the persona, and the persona over the profile; `off` is a choice too', () => {
    expect(resolveMessageExpiration({ profile: '90d', persona: '30d', conversation: '7d' })).toEqual({ option: '7d', source: 'conversation' });
    expect(resolveMessageExpiration({ profile: '90d', persona: '30d' })).toEqual({ option: '30d', source: 'persona' });
    expect(resolveMessageExpiration({ profile: '90d' })).toEqual({ option: '90d', source: 'profile' });
    expect(resolveMessageExpiration({})).toEqual({ option: 'off', source: 'profile' });
    // A conversation set to `off` has no expiration whatever the persona says, and a persona may turn off its profile's.
    expect(resolveMessageExpiration({ persona: '1d', conversation: 'off' })).toEqual({ option: 'off', source: 'conversation' });
    expect(resolveMessageExpiration({ profile: '7d', persona: 'off' })).toEqual({ option: 'off', source: 'persona' });
    // Something stored that is not an option counts as «as the level below».
    expect(resolveMessageExpiration({ persona: '2h' as never, conversation: 'nunca' as never, profile: '30d' })).toEqual({ option: '30d', source: 'profile' });
  });

  it('PANEL-06: the choices are whole days, every preset says none, and a configuration stored before PANEL-06 discloses nothing it did not choose', () => {
    expect(MESSAGE_EXPIRATION_OPTIONS.map(expirationDays)).toEqual([undefined, 1, 7, 30, 90]);
    for (const name of Object.keys(PRESETS) as PresetName[]) expect(preset(name).messageExpiration).toBe('off');
    const { messageExpiration: _dropped, ...older } = preset('sovereign');
    expect(disclose(older as never).some((d) => d.control === 'messageExpiration')).toBe(false);
    expect(disclose({ ...preset('sovereign'), messageExpiration: '7d' }).find((d) => d.control === 'messageExpiration')).toMatchObject({ statement: expect.stringMatching(/piden caducar a los 7 días \(NIP-40\).*no respetan NIP-40/), sacrifices: ['recuperabilidad'] });
  });

  it('PANEL-06: the vault notice: unknown, longer or «until deleted» retention warns; a shorter one, no vault in use or no expiration does not', () => {
    const used = { cloudBackup: 'ciphertext-user-key' as const, continuityVault: true };
    expect(vaultExpirationNotice('7d', { ...used, retentionDays: 90 })).toMatch(/caducar a los 7 días, pero tu vault guarda cada archivo 90 días desde que se guardó/);
    expect(vaultExpirationNotice('7d', { ...used, retentionDays: null })).toMatch(/guarda cada archivo hasta que lo borres/);
    expect(vaultExpirationNotice('30d', used)).toMatch(/con su propio plazo, que desde aquí no se conoce/);
    expect(vaultExpirationNotice('30d', { ...used, retentionDays: 30 })).toBeUndefined();
    expect(vaultExpirationNotice('90d', { ...used, retentionDays: 7 })).toBeUndefined();
    expect(vaultExpirationNotice('off', { ...used, retentionDays: null })).toBeUndefined();
    expect(vaultExpirationNotice('1d', { cloudBackup: 'off', retentionDays: null })).toBeUndefined();
    expect(vaultExpirationNotice('1d', { ...used, continuityVault: false })).toBeUndefined();
    // The panel shows it as a warning, never blocking.
    const issue = validateConfig({ ...preset('convenience'), messageExpiration: '7d' }, 'web', { continuityVault: true, vaultRetentionDays: 365 }).find((i) => i.code === 'EXPIRATION_VAULT');
    expect(issue).toMatchObject({ severity: 'warning', controls: ['messageExpiration', 'cloudBackup'] });
    expect(validateConfig({ ...preset('convenience'), messageExpiration: '7d' }, 'web', { continuityVault: true, vaultRetentionDays: 7 }).map((i) => i.code)).not.toContain('EXPIRATION_VAULT');
    expect(validateConfig(preset('convenience'), 'web', { continuityVault: true, vaultRetentionDays: null }).map((i) => i.code)).not.toContain('EXPIRATION_VAULT');
  });

  it('PANEL-06: the copy says it is a request, what the relay sees and which copies may survive, as reviewed copy', () => {
    expect(MESSAGE_EXPIRATION_TEXTS.request).toMatch(/es una petición \(NIP-40\).*los que no la respetan lo siguen sirviendo/s);
    expect(MESSAGE_EXPIRATION_TEXTS.relay).toMatch(/redondeada hacia arriba a la medianoche \(UTC\): el relay la ve, no el contenido/);
    expect(MESSAGE_EXPIRATION_TEXTS.past).toMatch(/solo afecta a los mensajes nuevos/);
    expect(MESSAGE_EXPIRATION_TEXTS.vault).toMatch(/no caducan con el mensaje.*vencen con el plazo del vault/s);
    expect(DM_DELETION_TEXTS.copies).toMatch(/las copias replicadas pueden seguir existiendo/);
    expect(DM_DELETION_TEXTS.request).toMatch(/Solo puedes borrar los mensajes que escribiste tú/);
    const reviewed = disclosureCatalog();
    for (const text of Object.values(MESSAGE_EXPIRATION_TEXTS)) expect(reviewed.find((d) => d.statement === text)?.control).toBe('messageExpiration');
    for (const text of Object.values(DM_DELETION_TEXTS)) expect(reviewed.find((d) => d.statement === text)?.control).toBe('persistence');
  });

  it('PANEL-06: deleting a DM opens with the same notice as deleting in a channel', () => {
    const notice = 'Borrar no retira las copias que ya circularon';
    expect(DM_DELETION_TEXTS.copies.startsWith(notice)).toBe(true);
    expect(CHANNEL_DELETION_TEXTS.copies.startsWith(notice)).toBe(true);
  });

  it('PANEL-06: no copy promises a guaranteed deletion, and the lint refuses one', () => {
    for (const claim of ['Borrado garantizado de tus mensajes', 'El mensaje se borra de todas partes', 'desaparece de todas partes al caducar', 'Guaranteed deletion']) expect(() => assertNoAbsoluteClaims(claim)).toThrow();
    for (const d of disclosureCatalog()) expect(() => assertNoAbsoluteClaims(d.statement)).not.toThrow();
  });

  it('PANEL-06: the claim lint runs in linear time on a long run of the words it looks for (CodeQL js/polynomial-redos)', () => {
    const started = Date.now();
    for (const word of ['borra', 'elimina', 'desaparece']) expect(() => assertNoAbsoluteClaims(word.repeat(30_000))).not.toThrow();
    expect(Date.now() - started).toBeLessThan(1500);
    // The bound leaves the real phrasings caught: a verb with an ending, then "de todas partes".
    expect(() => assertNoAbsoluteClaims('Se borrará de todas partes')).toThrow();
  });
});
