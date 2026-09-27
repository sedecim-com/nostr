import { describe, expect, it } from 'vitest';
import { runLoad, stats, toMarkdown, verdict } from '../../scripts/load/lib';
import { startLocalStack } from '../../scripts/load/local-stack';

describe('load tool (NFR005-02)', () => {
  it('computes percentiles', () => {
    expect(stats([])).toMatchObject({ count: 0, p95: 0 });
    const s = stats(Array.from({ length: 100 }, (_, i) => i + 1));
    expect(s).toEqual({ count: 100, mean: 50.5, p50: 50, p95: 95, p99: 99, max: 100 });
  });

  it('drives authenticated publishers/subscribers against the test relay and measures indexer lag with 2 replicas', async () => {
    const stack = await startLocalStack({ indexers: 2 });
    try {
      const r = await runLoad({ relay: stack.relay, indexers: stack.indexers, clients: 3, rate: 3, durationS: 3, drainS: 10, channels: 2, lagSample: 1, mix: { 9: 70, 1059: 20, 1: 10 }, label: 'test' });
      expect(r.setup.connectedClients).toBe(3);
      expect(r.publish.ok).toBeGreaterThan(10);
      expect(r.publish.failed).toBe(0);
      expect(r.delivery.ratio).toBe(1);
      expect(r.indexer.sampled).toBeGreaterThan(0);
      expect(r.indexer.found).toBe(r.indexer.sampled);
      expect(r.publish.ackMs.p95).toBeGreaterThan(0);
      expect(verdict({ ...r, publish: { ...r.publish, throughputOkPerS: r.publish.offeredPerS } })).toEqual([]);
      const md = toMarkdown([r]);
      expect(md).toContain('| test | 3 |');
      expect(md).toContain('kind 9:');
    } finally {
      await stack.stop();
    }
  }, 90_000);
});
