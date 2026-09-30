/**
 * OPS-12: the bots (backlog-sync, buzz-upstream) push their branch and open their PR with a GitHub App token when
 * the App is configured, so those PRs run CI like any other; a PR opened with the workflow's GITHUB_TOKEN runs none
 * and could never pass the required checks of main. Without the App they fall back to the GITHUB_TOKEN.
 */
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const root = new URL('../..', import.meta.url).pathname;
const read = (wf: string) => readFileSync(join(root, '.github/workflows', wf), 'utf8');
const TOKEN = '${{ steps.bot.outputs.token || github.token }}';

describe('bots with the GitHub App token (OPS-12)', () => {
  for (const wf of ['backlog-sync.yml', 'buzz-upstream.yml']) {
    it(`${wf}: an App token with only Contents and Pull requests, when BOT_APP_CLIENT_ID is set`, () => {
      const text = read(wf);
      const step = text.slice(text.indexOf('- name: Bot token (GitHub App, OPS-12)'), text.indexOf('- uses: actions/checkout@', text.indexOf('- name: Bot token')));
      expect(step).toMatch(/id: bot\n/);
      expect(step).toMatch(/if: vars\.BOT_APP_CLIENT_ID != ''\n/);
      expect(step).toMatch(/uses: actions\/create-github-app-token@[0-9a-f]{40} # v\d+\.\d+\.\d+\n/);
      expect(step).toContain('client-id: ${{ vars.BOT_APP_CLIENT_ID }}');
      expect(step).toContain('private-key: ${{ secrets.BOT_APP_PRIVATE_KEY }}');
      expect([...step.matchAll(/permission-([a-z-]+): (\w+)/g)].map((m) => `${m[1]}=${m[2]}`)).toEqual(['contents=write', 'pull-requests=write']);
    });

    it(`${wf}: the branch is pushed and the PR opened with it, or with the GITHUB_TOKEN without the App`, () => {
      const text = read(wf);
      const checkout = text.slice(text.indexOf('- uses: actions/checkout@', text.indexOf('- name: Bot token')));
      expect(checkout.slice(0, checkout.indexOf('\n      - ', 1))).toContain(`token: ${TOKEN}`);
      expect(text).toContain(`GH_TOKEN: ${TOKEN}`);
    });
  }

  it('buzz-upstream.yml dispatches ci only without the App, and opens the fallback issue with the GITHUB_TOKEN', () => {
    const text = read('buzz-upstream.yml');
    expect(text).toContain("BOT: ${{ steps.bot.outputs.token != '' }}");
    expect(text).toContain('WORKFLOW_TOKEN: ${{ github.token }}');
    expect(text).toMatch(/if \[ "\$BOT" != true \]; then\n(?:\s+#[^\n]*\n)*\s+GH_TOKEN="\$WORKFLOW_TOKEN" gh workflow run ci\.yml/);
    expect(text).toContain('GH_TOKEN="$WORKFLOW_TOKEN" gh issue create');
  });

  it('buzz-upstream.yml runs npm only where no write credential is: install scripts never see the App token (IR-2026-10-06)', async () => {
    const { parse } = await import('yaml');
    const jobs = parse(read('buzz-upstream.yml')).jobs as Record<string, { permissions?: Record<string, string>; steps?: Array<{ run?: string; uses?: string; with?: Record<string, unknown> }> }>;
    for (const [name, job] of Object.entries(jobs)) {
      const runs = (job.steps ?? []).map((st) => st.run ?? '').join('\n');
      const writes = Object.values(job.permissions ?? {}).includes('write');
      const bot = (job.steps ?? []).some((st) => st.uses?.startsWith('actions/create-github-app-token@'));
      if (/\bnpm\b|\bnpx\b/.test(runs)) {
        expect(writes || bot, `${name} runs npm with a write credential`).toBe(false);
        expect(runs, name).toMatch(/npm ci [^\n]*--ignore-scripts/);
        const checkout = (job.steps ?? []).find((st) => st.uses?.startsWith('actions/checkout@'));
        expect(checkout?.with?.['persist-credentials'], name).toBe(false);
      }
    }
    // The job that pushes with the App token applies the patch the read-only job computed.
    expect((jobs['pin-pr']!.steps ?? []).map((st) => st.run ?? '').join('\n')).toContain('git apply --index "$RUNNER_TEMP/pin/pin.patch"');
  });

  it('backlog-sync.yml keeps reading and writing issues with the GITHUB_TOKEN', () => {
    const text = read('backlog-sync.yml');
    expect(text).toMatch(/\n    env:\n      GITHUB_TOKEN: \$\{\{ github\.token \}\}\n      GH_TOKEN: \$\{\{ github\.token \}\}\n/);
  });
});
