import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { configMaturity, MATURITY, maturity, maturityTable, PRESETS, preset, type PresetName } from '../src/index';

// PANEL-07: one catalog for the web, the CLI, the README and the release notes.
describe('maturity catalog', () => {
  it('declares what the PRD says: Beta for Marmot, Experimental for Tor and push, Preview for the enclave', () => {
    expect(maturity('marmot-groups').level).toBe('beta');
    expect(maturity('sovereign-tor').level).toBe('experimental');
    expect(maturity('push').level).toBe('experimental');
    expect(maturity('enclave-custody').level).toBe('preview');
  });

  it('declares nothing GA before v1.0, and covers every preset', () => {
    expect(MATURITY.map((m) => m.level as string)).not.toContain('ga');
    for (const name of Object.keys(PRESETS)) expect(() => maturity(name as PresetName)).not.toThrow();
    expect(new Set(MATURITY.map((m) => m.id)).size).toBe(MATURITY.length);
  });

  it('agrees with the production feature gates (OPS-20) on the features both label', () => {
    const gates = JSON.parse(readFileSync(new URL('../../../deploy/production-gates.json', import.meta.url), 'utf8')).features;
    expect(gates.enclave.maturity).toBe('Preview');
    expect(gates.push.maturity).toBe('Experimental');
    expect(maturityTable()).toContain('| Custodia en Nitro Enclave | Función | Preview |');
    expect(maturityTable()).toContain('| Notificaciones push | Función | Experimental |');
  });
});

describe('maturity of a configuration', () => {
  it('private-resilient is never above Beta without a Continuity Vault in the deployment', () => {
    expect(configMaturity(preset('private-resilient'), { continuityVault: false })).toMatchObject({ level: 'beta', label: 'Beta' });
    expect(configMaturity(preset('private-resilient'), { continuityVault: true }).level).toBe('early-release');
  });

  it('is the least mature of what the configuration uses', () => {
    expect(configMaturity(preset('sovereign-tor')).level).toBe('experimental');
    expect(configMaturity(preset('institutional'), { continuityVault: true }).parts.map((p) => p.id)).toContain('marmot-groups');
    expect(configMaturity({ ...preset('convenience'), custody: 'managed-enclave' }, { continuityVault: true }).level).toBe('preview');
    expect(configMaturity({ ...preset('convenience'), messaging: 'marmot' }, { continuityVault: true }).level).toBe('beta');
    // Continuity best-effort without a vault only means no copy: convenience keeps its level.
    expect(configMaturity(preset('convenience'), { continuityVault: false }).level).toBe('early-release');
  });
});
