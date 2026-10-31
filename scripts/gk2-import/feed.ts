// What the coordinator holds for the keys a send writes, read the way the app reads: Delta pages
// from a cursor, folded by the client's merge rule (an event applies when its version is higher
// than the one held; sync.proto rule 2, compared bytewise). Only the frozen keys are kept, so a
// collector's whole feed is read through without being held in memory.
//
// The coordinator has no read of Push receipts, so the pre-check reads keys, not receipts: a
// batch that landed left its keys at its versions; one that never landed left none.
import { SyncOp, compareVersion, parseUserFacetKey } from '@figurecollecting/fc-api-contract';
import type { FrozenBatch, FrozenEvent } from './freeze.js';

export interface Held {
  version: string;
  op: SyncOp;
  payload: string;
}

export interface FeedPage {
  events: { facetKey: string; version: string; op: SyncOp; payload: string }[];
  nextCursor: string;
  hasMore: boolean;
}

export type Pull = (cursor: string) => Promise<FeedPage>;

export interface ReadState {
  state: Map<string, Held>;
  /** Where the next read starts: the last page's next_cursor. */
  cursor: string;
  pages: number;
}

/** Read every page from `from`, folding the asked keys into `state`. */
export async function readState(pull: Pull, keys: ReadonlySet<string>, from: string, state = new Map<string, Held>()): Promise<ReadState> {
  let cursor = from;
  let pages = 0;
  for (;;) {
    const page = await pull(cursor);
    pages += 1;
    for (const e of page.events) {
      if (!keys.has(e.facetKey)) continue;
      const held = state.get(e.facetKey);
      if (held === undefined || compareVersion(e.version, held.version) > 0) state.set(e.facetKey, { version: e.version, op: e.op, payload: e.payload });
    }
    if (!page.hasMore) return { state, cursor: page.nextCursor === '' ? cursor : page.nextCursor, pages };
    if (page.nextCursor === cursor) throw new Error(`the feed did not advance past cursor ${cursor}`);
    cursor = page.nextCursor;
  }
}

const familyOf = (facetKey: string): string => parseUserFacetKey(facetKey)!.family;
const opOf = (e: FrozenEvent): SyncOp => (e.op === 'SYNC_OP_DELETE' ? SyncOp.DELETE : SyncOp.UPSERT);
const holds = (held: Held, e: FrozenEvent): boolean => held.version === e.version && held.op === opOf(e) && held.payload === e.payload;
const bump = (counts: Record<string, number>, key: string): void => {
  counts[key] = (counts[key] ?? 0) + 1;
};

/** The frozen keys the coordinator holds already (a tombstone too), by family. */
export function existingKeys(batches: readonly FrozenBatch[], state: ReadonlyMap<string, Held>): { total: number; byFamily: Record<string, number> } {
  const byFamily: Record<string, number> = {};
  let total = 0;
  for (const e of batches.flatMap((b) => b.events)) {
    if (!state.has(e.facetKey)) continue;
    total += 1;
    bump(byFamily, familyOf(e.facetKey));
  }
  return { total, byFamily };
}

export type BatchState = 'landed' | 'unsent' | 'mixed';

/**
 * For a retry of a frozen file: each batch landed (every key holds its frozen event), unsent (none
 * is held) or mixed; and how many keys hold something else, which this file did not write.
 */
export function resumeState(batches: readonly FrozenBatch[], state: ReadonlyMap<string, Held>): { batches: BatchState[]; foreign: number } {
  let foreign = 0;
  const states = batches.map((b): BatchState => {
    let landed = 0;
    let absent = 0;
    for (const e of b.events) {
      const held = state.get(e.facetKey);
      if (held === undefined) absent += 1;
      else if (holds(held, e)) landed += 1;
      else foreign += 1;
    }
    return landed === b.events.length ? 'landed' : absent === b.events.length ? 'unsent' : 'mixed';
  });
  return { batches: states, foreign };
}

/**
 * MATCH the frozen event stands; EDITED or DELETED a newer upsert or delete (the collector changed
 * it since); MISSING nothing held; DIFFERENT anything else.
 */
export type Verdict = 'MATCH' | 'EDITED' | 'DELETED' | 'MISSING' | 'DIFFERENT';

export interface ReadBack {
  ok: boolean;
  byFamily: Record<string, Partial<Record<Verdict, number>>>;
  keys: { facetKey: string; verdict: Verdict; held?: string }[];
}

export function readBack(batches: readonly FrozenBatch[], state: ReadonlyMap<string, Held>): ReadBack {
  const byFamily: ReadBack['byFamily'] = {};
  const keys: ReadBack['keys'] = [];
  for (const e of batches.flatMap((b) => b.events)) {
    const held = state.get(e.facetKey);
    let verdict: Verdict;
    if (held === undefined) verdict = 'MISSING';
    else if (holds(held, e)) verdict = 'MATCH';
    else if (compareVersion(held.version, e.version) > 0) verdict = held.op === SyncOp.DELETE ? 'DELETED' : 'EDITED';
    else verdict = 'DIFFERENT';
    keys.push(held === undefined ? { facetKey: e.facetKey, verdict } : { facetKey: e.facetKey, verdict, held: held.version });
    bump((byFamily[familyOf(e.facetKey)] ??= {}) as Record<string, number>, verdict);
  }
  return { ok: keys.every((k) => k.verdict === 'MATCH'), byFamily, keys };
}
