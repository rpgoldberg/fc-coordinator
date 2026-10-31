// A plan as the exact facet writes a device would push: one Push per batch, a copy's head and status always in the
// same batch (a status with no head is a hidden copy), every id derived from the plan's namespace and the line, every
// payload the contract's own shape. Nothing here sends anything; main.ts runs each event through the coordinator's
// Push validation, and send.ts freezes them for a signed-in, enrolled device and pushes them.
import { SyncOp, canonicalVersion, collNameKey, collectionRef, occFacetKey, occTagKey, parseUserFacetKey, tagNameKey, ufFacetKey } from '@figurecollecting/fc-api-contract';
import { uuidV5 } from './ids.js';
import type { Entry, Plan } from './plan.js';

/** The coordinator's batch cap (src/sync/service.ts MAX_BATCH). */
export const MAX_EVENTS_PER_BATCH = 200;

export interface BuildOptions {
  /** The importing device, 32 lowercase hex: every version names it. */
  deviceHex: string;
  /** The edit time stamped on every write, and the instant of every version. */
  at: Date;
  /** The IANA zone stamped on every write. */
  tz: string;
  /** A batch's client_id is `${clientPrefix}-${index}`, four digits from 0001. */
  clientPrefix: string;
}

export interface Write {
  /** The line the write belongs to, or '' for a collection or tag name. Never sent. */
  line: string;
  facetKey: string;
  op: SyncOp;
  payload: string;
  version: string;
  basis: string;
}

export interface Batch {
  clientId: string;
  events: Write[];
}

export interface Built {
  batches: Batch[];
  /** The lines of parked entries: written by nothing here. */
  parked: string[];
  /** Events written, by facet family. */
  counts: Record<string, number>;
}

export function buildBatches(plan: Plan, opts: BuildOptions): Built {
  const ns = plan.namespace;
  const stamp = { edited_at: opts.at.toISOString(), tz: opts.tz };
  let counter = 0;
  const write = (line: string, facetKey: string, body: object): Write => ({
    line,
    facetKey,
    op: SyncOp.UPSERT,
    payload: JSON.stringify({ ...body, ...stamp }),
    version: canonicalVersion({ instant: opts.at, counter: ++counter, deviceId: opts.deviceHex }),
    basis: '',
  });

  const collId = (e: Entry) => uuidV5(ns, `gk2:coll:${e.status}:${e.collection}`);
  const tagId = (name: string) => uuidV5(ns, `gk2:tag:${name}`);

  // Names first: a collection or a tag a copy is filed in exists before the copy arrives.
  const setup: Write[] = [];
  const collections = new Set<string>();
  const tags = new Set<string>();
  for (const e of plan.entries) {
    if (e.kind === 'parked') continue;
    if (e.collection !== undefined && !collections.has(`${e.status}/${e.collection}`)) {
      collections.add(`${e.status}/${e.collection}`);
      setup.push(write('', collNameKey(e.status as 'owned', collId(e)), { name: e.collection }));
    }
    for (const t of e.tags) {
      if (tags.has(t)) continue;
      tags.add(t);
      setup.push(write('', tagNameKey(tagId(t)), { name: t }));
    }
  }

  const groups: Write[][] = [];
  const parked: string[] = [];
  for (const e of plan.entries) {
    if (e.kind === 'parked') {
      parked.push(e.line);
      continue;
    }
    const head = e.kind === 'text' ? uuidV5(ns, `gk2:head:${e.line}`) : e.headId!;
    const out: Write[] = [];
    for (let k = 1; k <= e.copies; k++) {
      const occ = uuidV5(ns, `gk2:occ:${e.line}:${k}`);
      out.push(write(e.line, occFacetKey(occ, 'head'), { head_id: head }));
      out.push(write(e.line, occFacetKey(occ, 'status'), { status: e.status }));
      if (e.collection !== undefined) out.push(write(e.line, occFacetKey(occ, 'collection'), { collection: collectionRef(e.status as 'owned', collId(e)) }));
      if (e.disposal !== undefined) out.push(write(e.line, occFacetKey(occ, 'disposal'), { ...e.disposal }));
      for (const t of e.tags) out.push(write(e.line, occTagKey(occ, tagId(t)), {}));
    }
    if (e.label !== undefined) out.push(write(e.line, ufFacetKey(head, 'label'), { ...e.label }));
    if (e.note !== undefined) out.push(write(e.line, ufFacetKey(head, 'note'), { note: e.note }));
    if (e.links.length > 0) out.push(write(e.line, ufFacetKey(head, 'refs'), { links: e.links.map((url) => ({ url })) }));
    if (out.length > MAX_EVENTS_PER_BATCH) throw new Error(`entry ${e.line} is ${out.length} events: more than the ${MAX_EVENTS_PER_BATCH} one batch may carry`);
    groups.push(out);
  }

  // Pack whole entries into batches; the names ride in the first.
  const batches: Batch[] = [];
  let current: Write[] = [...setup];
  if (current.length > MAX_EVENTS_PER_BATCH) throw new Error(`the collection and tag names are ${current.length} events: more than the ${MAX_EVENTS_PER_BATCH} one batch may carry`);
  const flush = () => {
    if (current.length === 0) return;
    batches.push({ clientId: `${opts.clientPrefix}-${String(batches.length + 1).padStart(4, '0')}`, events: current });
    current = [];
  };
  for (const g of groups) {
    if (current.length + g.length > MAX_EVENTS_PER_BATCH) flush();
    current.push(...g);
  }
  flush();

  const counts: Record<string, number> = {};
  for (const b of batches) {
    for (const w of b.events) {
      const family = parseUserFacetKey(w.facetKey)!.family;
      counts[family] = (counts[family] ?? 0) + 1;
    }
  }
  return { batches, parked, counts };
}
