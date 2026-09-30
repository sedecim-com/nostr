// Orden de desbloqueo: the open tasks laid out in waves by their open dependencies, rendered into
// docs/backlog/README.md by scripts/backlog.mjs (so the synchronization keeps it current).
//
// Wave 0 waits for no open task; wave N waits only for tasks of earlier waves. Inside a wave the tasks that unlock the
// most open work come first, then by priority. `blockers` (meta.externalBlockers, hand-maintained and kept by the
// synchronization) names what no code change can move: a person, AWS or a third party. A task is ready to work on when
// it has no blocker of its own, no open pull request (evidencia:in-pr) and every open task it waits for is only waiting
// on such a blocker (its code is merged).

export const isOpen = (t) => t.status !== 'Hecho' && t.status !== 'Descartado';

/**
 * @param {Array<{id: string, deps: string[], status: string, priority: string}>} tasks
 * @param {Record<string, string>} [blockers] task id -> blocker kind
 * @returns {Array<{task: object, wave: number, unlocks: number, waitsOn: string[], blocker?: string, inPr: boolean, ready: boolean}>}
 */
export function unblockOrder(tasks, blockers = {}) {
  const open = tasks.filter(isOpen);
  const byId = new Map(open.map((t) => [t.id, t]));
  const waitsOn = new Map(open.map((t) => [t.id, t.deps.filter((d) => byId.has(d))]));
  const dependents = new Map(open.map((t) => [t.id, []]));
  for (const t of open) for (const d of waitsOn.get(t.id)) dependents.get(d).push(t.id);

  // Longest chain of open dependencies below the task. The graph is acyclic (scripts/backlog.mjs rejects cycles);
  // the in-progress set only keeps a stray cycle from recursing forever.
  const wave = new Map();
  const inProgress = new Set();
  const waveOf = (id) => {
    if (wave.has(id)) return wave.get(id);
    if (inProgress.has(id)) return 0;
    inProgress.add(id);
    const w = waitsOn.get(id).reduce((m, d) => Math.max(m, waveOf(d) + 1), 0);
    inProgress.delete(id);
    wave.set(id, w);
    return w;
  };
  // Open tasks that wait for it, directly or through others.
  const unlocks = (id) => {
    const seen = new Set();
    const stack = [...dependents.get(id)];
    while (stack.length) {
      const x = stack.pop();
      if (!seen.has(x)) {
        seen.add(x);
        stack.push(...dependents.get(x));
      }
    }
    return seen.size;
  };
  // Only waiting on work that is not code: a partial task whose rest is a person, AWS or a third party.
  const codeMerged = (id) => byId.get(id).status === 'Parcial' && Boolean(blockers[id]);

  return open
    .map((task) => ({
      task,
      wave: waveOf(task.id),
      unlocks: unlocks(task.id),
      waitsOn: waitsOn.get(task.id),
      blocker: blockers[task.id],
      inPr: task.evidenceState === 'in-pr',
      ready: !blockers[task.id] && task.evidenceState !== 'in-pr' && waitsOn.get(task.id).every(codeMerged),
    }))
    .sort((a, b) => a.wave - b.wave || b.unlocks - a.unlocks || a.task.priority.localeCompare(b.task.priority) || a.task.id.localeCompare(b.task.id));
}
