import { describe, expect, it } from 'vitest';
import { createLogger, redact, TelemetryPolicy, TelemetryBlockedError, type LogRecord } from '../src/index';

const NSEC = 'nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5';

describe('redaction (NFR-006, §18.1)', () => {
  it('never writes secrets, tokens or plaintext fields', () => {
    const out: LogRecord[] = [];
    const log = createLogger({ write: (r) => out.push(r), minimizeIp: true });
    log.info(`imported key ${NSEC}`, { secretKey: 'abc', nested: { password: 'p', ok: 1 }, ip: '10.0.0.1', url: 'bunker://ab?relay=wss://r&secret=topsecret', authorization: 'Nostr eyJhbGc' });
    const s = JSON.stringify(out);
    expect(s).not.toContain(NSEC);
    expect(s).not.toContain('topsecret');
    expect(s).not.toContain('10.0.0.1');
    expect(s).not.toContain('eyJhbGc');
    expect(out[0]!.nested).toEqual({ password: '[REDACTED]', ok: 1 });
  });

  it('redacts byte arrays', () => {
    expect(redact({ data: new Uint8Array(32) })).toEqual({ data: '[BYTES:32]' });
  });
});

describe('telemetry policy (FR-022, NFR-007)', () => {
  it('emits nothing and blocks endpoints at level none', async () => {
    const sent: string[] = [];
    const t = new TelemetryPolicy({ level: 'none', endpoints: ['https://telemetry.example'] }, (e) => void sent.push(e));
    expect(await t.emit({ name: 'app.open' })).toBe(false);
    expect(await t.emit({ name: 'health.ok' })).toBe(false);
    expect(sent).toHaveLength(0);
    expect(() => t.assertEndpointAllowed('https://telemetry.example/v1')).toThrow(TelemetryBlockedError);
  });

  it('minimal only allows health events without attributes', async () => {
    const t = new TelemetryPolicy({ level: 'minimal', endpoints: ['https://telemetry.example'] });
    expect(await t.emit({ name: 'app.open', attributes: { user: 'x' } })).toBe(false);
    expect(await t.emit({ name: 'health.relay', attributes: { user: 'x' } })).toBe(true);
    expect(t.emitted[0]!.event.attributes).toEqual({});
  });
});
