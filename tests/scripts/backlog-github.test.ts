import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { readFileSync } from 'node:fs';
// @ts-expect-error plain ESM script without types
import { createClient, parseBody, parseTitle, pull, seed, taskBody } from '../../scripts/backlog-github.mjs';

type Issue = { id: number; number: number; title: string; body: string; labels: Array<{ name: string }>; milestone: { number: number; title: string } | null; state: 'open' | 'closed'; state_reason: string | null; issue_field_values?: unknown[]; parent?: number; blocked_by: number[] };

/** Minimal in-memory GitHub REST/GraphQL for the endpoints the sync uses. */
class FakeGitHub {
  labels: Array<{ name: string }> = [];
  milestones: Array<{ number: number; title: string; state: string; due_on?: string }> = [];
  issues: Issue[] = [];
  writes = 0;
  server?: Server;
  url = '';
  fields = true;
  async start() {
    this.server = createServer((req, res) => {
      let raw = '';
      req.on('data', (c) => (raw += c));
      req.on('end', () => {
        const out = this.handle(req.method!, req.url!, raw ? JSON.parse(raw) : undefined);
        res.writeHead(out.status, { 'content-type': 'application/json' }).end(JSON.stringify(out.body));
      });
    });
    await new Promise<void>((r) => this.server!.listen(0, '127.0.0.1', () => r()));
    this.url = `http://127.0.0.1:${(this.server!.address() as AddressInfo).port}`;
  }
  stop() {
    this.server?.close();
  }
  private page<T>(items: T[], q: URLSearchParams) {
    const per = Number(q.get('per_page') ?? 30);
    const p = Number(q.get('page') ?? 1);
    return items.slice((p - 1) * per, p * per);
  }
  handle(method: string, url: string, body: any): { status: number; body: unknown } {
    const u = new URL(url, 'http://x');
    const path = u.pathname.replace('/repos/o/r', '');
    if (method !== 'GET' && path !== '/graphql') this.writes++;
    if (path === '/graphql')
      return this.fields
        ? { status: 200, body: { data: { repository: { issueFields: { nodes: [{ __typename: 'IssueFieldSingleSelect', fullDatabaseId: '1', name: 'Priority' }, { __typename: 'IssueFieldSingleSelect', fullDatabaseId: '2', name: 'Effort' }, { __typename: 'IssueFieldDate', fullDatabaseId: '3', name: 'Start date' }, { __typename: 'IssueFieldDate', fullDatabaseId: '4', name: 'Target date' }] } } } } }
        : { status: 200, body: { errors: [{ message: 'no fields' }] } };
    if (path === '/labels' && method === 'GET') return { status: 200, body: this.page(this.labels, u.searchParams) };
    if (path === '/labels' && method === 'POST') return this.labels.push({ name: body.name }), { status: 201, body: {} };
    if (path === '/milestones' && method === 'GET') return { status: 200, body: this.page(this.milestones, u.searchParams) };
    if (path === '/milestones' && method === 'POST') {
      const m = { number: this.milestones.length + 1, title: body.title, state: body.state ?? 'open', due_on: body.due_on };
      this.milestones.push(m);
      return { status: 201, body: m };
    }
    if (path === '/issues' && method === 'GET') {
      const label = u.searchParams.get('labels');
      const list = this.issues.filter((i) => !label || i.labels.some((l) => l.name === label));
      return { status: 200, body: this.page(list, u.searchParams) };
    }
    if (path === '/issues' && method === 'POST') {
      const n = this.issues.length + 1;
      const ms = body.milestone ? this.milestones.find((m) => m.number === body.milestone)! : null;
      const i: Issue = { id: 1000 + n, number: n, title: body.title, body: body.body, labels: (body.labels ?? []).map((name: string) => ({ name })), milestone: ms && { number: ms.number, title: ms.title }, state: 'open', state_reason: null, issue_field_values: body.issue_field_values, blocked_by: [] };
      this.issues.push(i);
      return { status: 201, body: i };
    }
    let m = /^\/issues\/(\d+)$/.exec(path);
    if (m && method === 'PATCH') {
      const i = this.issues[Number(m[1]) - 1]!;
      Object.assign(i, body.state ? { state: body.state, state_reason: body.state_reason ?? null } : {});
      return { status: 200, body: i };
    }
    m = /^\/issues\/(\d+)\/sub_issues$/.exec(path);
    if (m && method === 'GET') return { status: 200, body: this.page(this.issues.filter((i) => i.parent === Number(m![1])), u.searchParams) };
    if (m && method === 'POST') return (this.issues.find((i) => i.id === body.sub_issue_id)!.parent = Number(m[1])), { status: 201, body: {} };
    m = /^\/issues\/(\d+)\/dependencies\/blocked_by$/.exec(path);
    if (m && method === 'GET') return { status: 200, body: this.page(this.issues[Number(m[1]) - 1]!.blocked_by.map((id) => ({ id })), u.searchParams) };
    if (m && method === 'POST') return this.issues[Number(m[1]) - 1]!.blocked_by.push(body.issue_id), { status: 201, body: {} };
    return { status: 404, body: { message: `fake: ${method} ${path}` } };
  }
}

const backlog = JSON.parse(readFileSync(new URL('../../docs/backlog/backlog.json', import.meta.url), 'utf8'));
const strip = (t: Record<string, unknown>) => {
  const { issue: _i, ...rest } = t;
  return rest;
};

describe('backlog ⇄ GitHub Issues (GitHub is the source)', () => {
  const gh = new FakeGitHub();
  let api: ReturnType<typeof createClient>;
  beforeAll(async () => {
    await gh.start();
    api = createClient({ token: 't', repo: 'o/r', baseUrl: gh.url, writeDelayMs: 0, log: () => undefined });
  });
  afterAll(() => gh.stop());

  it('body and title formats round-trip (and match issue-form sections)', () => {
    const t = backlog.tasks.find((x: { deps: string[] }) => x.deps.length > 1);
    const parsed = parseBody(taskBody(t));
    expect(parsed).toMatchObject({ Requisito: t.req, Tipo: t.type, 'Story points': String(t.sp), 'Criterio de hecho': t.done });
    expect(parseTitle(`[${t.id}] ${t.title}`)).toEqual({ id: t.id, title: t.title });
    expect(parseBody('### Evidencia\n\n_No response_')).toEqual({ Evidencia: '' });
  });

  it('seed creates every task once, with epics, milestones, states, fields and relations', async () => {
    const r = await seed(api, backlog);
    const tasks = gh.issues.filter((i) => i.labels.some((l) => l.name === 'backlog'));
    expect(r.created.length).toBe(backlog.tasks.length);
    expect(tasks.length).toBe(backlog.tasks.length);
    expect(gh.issues.filter((i) => i.labels.some((l) => l.name === 'epic')).length).toBe(new Set(backlog.tasks.map((t: { epic: string }) => t.epic)).size);
    expect(gh.milestones.map((m) => m.title.split(' · ')[0])).toEqual(backlog.meta.sprints.map((s: { id: string }) => s.id));
    const done = backlog.tasks.find((t: { status: string }) => t.status === 'Hecho');
    const discarded = backlog.tasks.find((t: { status: string }) => t.status === 'Descartado');
    const issueOf = (id: string) => tasks.find((i) => i.title.startsWith(`[${id}]`))!;
    expect(issueOf(done.id)).toMatchObject({ state: 'closed', state_reason: 'completed' });
    expect(issueOf(discarded.id)).toMatchObject({ state: 'closed', state_reason: 'not_planned' });
    const p0 = backlog.tasks.find((t: { priority: string; sp: number }) => t.priority === 'P0' && t.sp === 3);
    expect(issueOf(p0.id).issue_field_values).toEqual(expect.arrayContaining([{ field_id: 1, value: 'Urgent' }, { field_id: 2, value: 'Medium' }]));
    expect(tasks.every((i) => i.parent)).toBe(true);
    const withDeps = backlog.tasks.find((t: { deps: string[] }) => t.deps.length > 0);
    expect(issueOf(withDeps.id).blocked_by.length).toBe(withDeps.deps.length);
  });

  it('an interrupted seed is completed by the next run (relations included)', async () => {
    const gh3 = new FakeGitHub();
    await gh3.start();
    const api3 = createClient({ token: 't', repo: 'o/r', baseUrl: gh3.url, writeDelayMs: 0, log: () => undefined });
    const small = { meta: backlog.meta, tasks: backlog.tasks.filter((t: { deps: string[] }, _: number, all: Array<{ id: string; deps: string[] }>) => t.deps.length === 0 || t.deps.every((d) => all.slice(0, 40).some((x) => x.id === d))).slice(0, 40) };
    const handle = gh3.handle.bind(gh3);
    let calls = 0;
    gh3.handle = (method, url, body) => (method === 'POST' && url.includes('/sub_issues') && ++calls > 5 ? { status: 500, body: { message: 'boom' } } : handle(method, url, body));
    await seed(api3, small);
    gh3.handle = handle;
    const r = await seed(api3, small);
    expect(r.created).toEqual([]);
    expect(r.linked).toBeGreaterThan(0);
    expect(gh3.issues.filter((i) => i.labels.some((l) => l.name === 'backlog')).every((i) => i.parent)).toBe(true);
    gh3.stop();
  });

  it('seed is idempotent: a second run creates nothing', async () => {
    const before = gh.writes;
    const r = await seed(api, backlog);
    expect(r.created).toEqual([]);
    expect(gh.writes).toBe(before);
  });

  it('pull rebuilds exactly the same tasks from GitHub', async () => {
    const { backlog: next, warnings } = await pull(api, backlog);
    expect(warnings).toEqual([]);
    expect(next.tasks.map(strip)).toEqual(backlog.tasks);
    expect(next.tasks.every((t: { issue: number }) => Number.isInteger(t.issue))).toBe(true);
    expect(next.meta.github).toBe('o/r');
  });

  it('edits made on GitHub flow into the backlog; malformed issues are reported, not guessed', async () => {
    const open = gh.issues.find((i) => i.state === 'open' && i.labels.some((l) => l.name === 'backlog') && !i.labels.some((l) => l.name === 'status:parcial'))!;
    const id = parseTitle(open.title).id;
    open.labels = open.labels.filter((l) => !/^P\d$/.test(l.name)).concat({ name: 'P3' }, { name: 'status:parcial' });
    open.milestone = { number: 9, title: 'S8 · Hardening, escalabilidad y release' };
    open.body = open.body.replace(/### Evidencia\n\n.*$/s, '### Evidencia\n\nhecho en #99');
    gh.issues.push({ id: 9999, number: 999, title: 'sin id', body: '', labels: [{ name: 'backlog' }], milestone: null, state: 'open', state_reason: null, blocked_by: [] });
    const { backlog: next, warnings } = await pull(api, backlog);
    expect(next.tasks.find((t: { id: string }) => t.id === id)).toMatchObject({ priority: 'P3', status: 'Parcial', sprint: 'S8', evidence: 'hecho en #99' });
    expect(warnings).toEqual([expect.stringContaining('#999')]);
  });

  it('works without org issue fields (labels remain the source of priority)', async () => {
    const gh2 = new FakeGitHub();
    gh2.fields = false;
    await gh2.start();
    const api2 = createClient({ token: 't', repo: 'o/r', baseUrl: gh2.url, writeDelayMs: 0, log: () => undefined });
    const small = { meta: backlog.meta, tasks: backlog.tasks.slice(0, 5) };
    await seed(api2, small);
    expect(gh2.issues.filter((i) => i.issue_field_values).length).toBe(0);
    expect((await pull(api2, small)).backlog.tasks.map(strip)).toEqual(small.tasks);
    gh2.stop();
  });
});
