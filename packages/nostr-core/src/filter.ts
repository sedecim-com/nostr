import type { NostrEvent } from './event';

export interface Filter {
  ids?: string[];
  authors?: string[];
  kinds?: number[];
  since?: number;
  until?: number;
  limit?: number;
  search?: string;
  [tag: `#${string}`]: string[] | undefined;
}

export function matchFilter(filter: Filter, evt: NostrEvent): boolean {
  if (filter.ids && !filter.ids.includes(evt.id)) return false;
  if (filter.authors && !filter.authors.includes(evt.pubkey)) return false;
  if (filter.kinds && !filter.kinds.includes(evt.kind)) return false;
  if (filter.since !== undefined && evt.created_at < filter.since) return false;
  if (filter.until !== undefined && evt.created_at > filter.until) return false;
  for (const key of Object.keys(filter)) {
    if (!key.startsWith('#') || key.length !== 2) continue;
    const values = filter[key as `#${string}`];
    if (!values) continue;
    const name = key.slice(1);
    if (!evt.tags.some((t) => t[0] === name && t[1] !== undefined && values.includes(t[1]))) return false;
  }
  return true;
}

export function matchFilters(filters: Filter[], evt: NostrEvent): boolean {
  return filters.some((f) => matchFilter(f, evt));
}
