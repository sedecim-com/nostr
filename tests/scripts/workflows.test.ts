/**
 * A workflow file that does not parse fails at once with no jobs at all, and the pull request still reads
 * "clean": none of its checks exist to fail (a step name with an unquoted ": " in ci.yml did it once). This parses
 * every workflow, so that one typo cannot turn the whole pipeline off without a red test.
 */
import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseDocument } from 'yaml';

const dir = join(new URL('../..', import.meta.url).pathname, '.github/workflows');
const files = readdirSync(dir).filter((f) => /\.ya?ml$/.test(f));

type Step = { name?: unknown; uses?: unknown; run?: unknown };
type Job = { needs?: string | string[]; steps?: Step[] };
function parse(text: string) {
  const doc = parseDocument(text);
  return { errors: doc.errors.map((e) => e.message.split('\n')[0]), jobs: ((doc.toJS() as { jobs?: Record<string, Job> } | null)?.jobs ?? {}) as Record<string, Job> };
}

describe('workflows parse', () => {
  it('finds the workflows', () => {
    expect(files).toContain('ci.yml');
  });

  for (const file of files) {
    it(`${file} is valid YAML; its jobs need jobs that exist and its steps run or use something`, () => {
      const { errors, jobs } = parse(readFileSync(join(dir, file), 'utf8'));
      expect(errors).toEqual([]);
      const ids = Object.keys(jobs);
      expect(ids.length).toBeGreaterThan(0);
      for (const [id, job] of Object.entries(jobs)) {
        for (const need of [job.needs ?? []].flat()) expect(ids, `${file}: job ${id} needs ${need}`).toContain(need);
        for (const [i, step] of (job.steps ?? []).entries()) {
          expect(Boolean(step.run ?? step.uses), `${file}: job ${id}, step ${i + 1}`).toBe(true);
          if (step.name !== undefined) expect(typeof step.name, `${file}: job ${id}, step ${i + 1} name`).toBe('string');
        }
      }
    });
  }

  it('flags a step name with an unquoted ": ", the typo that switched ci.yml off', () => {
    expect(parse('jobs:\n  a:\n    steps:\n      - name: Edge proxy: only / reaches Buzz\n        run: "true"\n').errors).not.toEqual([]);
    expect(parse('jobs:\n  a:\n    steps:\n      - name: Edge proxy forwards only / to Buzz\n        run: "true"\n').errors).toEqual([]);
  });
});
