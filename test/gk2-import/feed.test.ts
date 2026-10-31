import { SyncOp } from '@figurecollecting/fc-api-contract';
import { describe, expect, it } from 'vitest';
import { existingKeys, readBack, readState, resumeState, type FeedPage, type Held } from '../../scripts/gk2-import/feed.js';
import type { FrozenBatch } from '../../scripts/gk2-import/freeze.js';

const DEVICE = '0f3a5c7e9b1d2f4a6c8e0b2d4f6a8c0e';
const v = (n: number, device = DEVICE) => `2026-10-31T12:00:00.000000Z#${String(n).padStart(10, '0')}#${device}`;
const OCC = '11111111-1111-5111-8111-111111111111';
const HEAD = '3907070b-50f1-4f99-b912-6d63db4bf805';
const TAG = '22222222-2222-5222-8222-222222222222';
const K = {
  head: `occ/${OCC}/head`,
  status: `occ/${OCC}/status`,
  note: `uf/${HEAD}/note`,
  tag: `tag/${TAG}/name`,
};
const ev = (facetKey: string, n: number, payload = `{"n":${n}}`, op: 'SYNC_OP_UPSERT' | 'SYNC_OP_DELETE' = 'SYNC_OP_UPSERT') => ({ facetKey, version: v(n), op, payload, basis: '' });
const BATCHES: FrozenBatch[] = [
  { clientId: 'p-0001', events: [ev(K.tag, 1), ev(K.head, 2)] },
  { clientId: 'p-0002', events: [ev(K.status, 3), ev(K.note, 4)] },
];
const held = (n: number, payload = `{"n":${n}}`, op = SyncOp.UPSERT): Held => ({ version: v(n), op, payload });
const stateOf = (entries: [string, Held][]) => new Map(entries);

describe('readState', () => {
  const pagesOf = (pages: FeedPage[]) => {
    const asked: string[] = [];
    return {
      asked,
      pull: async (cursor: string) => {
        asked.push(cursor);
        return pages[asked.length - 1]!;
      },
    };
  };
  const wire = (facetKey: string, n: number, op = SyncOp.UPSERT, payload = `{"n":${n}}`) => ({ facetKey, version: v(n), op, payload });

  it('follows the pages from the cursor it is given and keeps only the asked keys, the highest version winning', async () => {
    const p = pagesOf([
      { events: [wire(K.head, 5), wire('occ/other/head', 9), wire(K.note, 2)], nextCursor: 'c1', hasMore: true },
      { events: [wire(K.head, 4), wire(K.note, 3, SyncOp.DELETE, '')], nextCursor: 'c2', hasMore: false },
    ]);
    const read = await readState(p.pull, new Set([K.head, K.note]), 'c0');
    expect(p.asked).toEqual(['c0', 'c1']);
    expect(read.cursor).toBe('c2');
    expect(read.pages).toBe(2);
    expect([...read.state.entries()]).toEqual([
      [K.head, held(5)],
      [K.note, held(3, '', SyncOp.DELETE)],
    ]);
  });

  it('continues a state it is handed, and an empty last page keeps the cursor', async () => {
    const start = stateOf([[K.head, held(1)]]);
    const p = pagesOf([{ events: [wire(K.head, 2)], nextCursor: 'c9', hasMore: true }, { events: [], nextCursor: 'c9', hasMore: false }]);
    const read = await readState(p.pull, new Set([K.head]), 'c8', start);
    expect(read.state).toBe(start);
    expect(read.state.get(K.head)).toEqual(held(2));
    expect(read.cursor).toBe('c9');
  });

  it('refuses a page that says there is more but does not move the cursor', async () => {
    const p = pagesOf([{ events: [], nextCursor: 'c0', hasMore: true }]);
    await expect(readState(p.pull, new Set([K.head]), 'c0')).rejects.toThrow(/the feed did not advance past cursor/);
  });
});

describe('existingKeys', () => {
  it('counts, by family, the frozen keys the coordinator already holds, a tombstone included', () => {
    expect(existingKeys(BATCHES, new Map())).toEqual({ total: 0, byFamily: {} });
    expect(existingKeys(BATCHES, stateOf([[K.head, held(1)], [K.status, held(1, '', SyncOp.DELETE)], [K.note, held(9)]]))).toEqual({ total: 3, byFamily: { 'occ/head': 1, 'occ/status': 1, 'uf/note': 1 } });
  });
});

describe('resumeState', () => {
  it('is landed for a batch whose every key holds its frozen event, unsent when none is held', () => {
    const r = resumeState(BATCHES, stateOf([[K.tag, held(1)], [K.head, held(2)]]));
    expect(r).toEqual({ batches: ['landed', 'unsent'], foreign: 0 });
  });

  it('is mixed when a batch is part held and part absent', () => {
    expect(resumeState(BATCHES, stateOf([[K.tag, held(1)]]))).toEqual({ batches: ['mixed', 'unsent'], foreign: 0 });
  });

  it('counts a key held at another version, op or payload as foreign: that is not this file', () => {
    const r = resumeState(BATCHES, stateOf([[K.tag, held(7)], [K.head, held(2, '{"other":1}')], [K.status, held(3, '{"n":3}', SyncOp.DELETE)], [K.note, held(4)]]));
    expect(r).toEqual({ batches: ['mixed', 'mixed'], foreign: 3 });
  });
});

describe('readBack', () => {
  it('is MATCH for every key that holds its frozen event, and ok', () => {
    const r = readBack(BATCHES, stateOf([[K.tag, held(1)], [K.head, held(2)], [K.status, held(3)], [K.note, held(4)]]));
    expect(r.ok).toBe(true);
    expect(r.byFamily).toEqual({ 'tag/name': { MATCH: 1 }, 'occ/head': { MATCH: 1 }, 'occ/status': { MATCH: 1 }, 'uf/note': { MATCH: 1 } });
    expect(r.keys.map((k) => k.verdict)).toEqual(['MATCH', 'MATCH', 'MATCH', 'MATCH']);
  });

  it('says EDITED for a newer upsert, DELETED for a newer delete, MISSING and DIFFERENT, and is not ok', () => {
    const r = readBack(BATCHES, stateOf([[K.tag, held(8)], [K.head, held(9, '', SyncOp.DELETE)], [K.note, held(4, '{"x":1}')]]));
    expect(r.ok).toBe(false);
    expect(r.keys).toEqual([
      { facetKey: K.tag, verdict: 'EDITED', held: v(8) },
      { facetKey: K.head, verdict: 'DELETED', held: v(9) },
      { facetKey: K.status, verdict: 'MISSING' },
      { facetKey: K.note, verdict: 'DIFFERENT', held: v(4) },
    ]);
    expect(r.byFamily).toEqual({ 'tag/name': { EDITED: 1 }, 'occ/head': { DELETED: 1 }, 'occ/status': { MISSING: 1 }, 'uf/note': { DIFFERENT: 1 } });
  });

  it('says DIFFERENT for an older version, which a written key can only hold if something rewrote it', () => {
    expect(readBack([{ clientId: 'p-0001', events: [ev(K.head, 5)] }], stateOf([[K.head, held(4)]])).keys[0]!.verdict).toBe('DIFFERENT');
  });
});
