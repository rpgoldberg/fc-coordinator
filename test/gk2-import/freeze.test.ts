import { createHash } from 'node:crypto';
import { SyncOp } from '@figurecollecting/fc-api-contract';
import { describe, expect, it } from 'vitest';
import { buildBatches, type BuildOptions } from '../../scripts/gk2-import/build.js';
import { FrozenError, freeze, frozenFileName, parseFrozen, refusals, shaSidecar, summaryLines, wireEvents, type FrozenBatch } from '../../scripts/gk2-import/freeze.js';
import { parsePlan } from '../../scripts/gk2-import/plan.js';

const NS = '7d0c1d9e-5a43-4c52-9d4f-6f2a4b8f1c07';
const HEAD = '3907070b-50f1-4f99-b912-6d63db4bf805';
const DEVICE = '0f3a5c7e9b1d2f4a6c8e0b2d4f6a8c0e';
const OTHER_DEVICE = '9c1e3a5b7d9f1b3d5f7a9c1e3b5d7f9a';
const AT = new Date('2026-10-31T12:00:00.000Z');
const OPTS: BuildOptions = { deviceHex: DEVICE, at: AT, tz: 'America/Chicago', clientPrefix: 'gk2-send-t' };
const PLAN = parsePlan({
  namespace: NS,
  entries: [
    { line: 'owned-3', kind: 'matched', status: 'owned', headId: HEAD, copies: 1, links: ['https://a.example/1'], tags: ['Licensed PVCs'], note: 'a note' },
    { line: 'owned-8', kind: 'text', status: 'owned', copies: 2, label: { name: 'A label' }, links: [], tags: [] },
    { line: 'sold-1', kind: 'matched', status: 'former', headId: HEAD, copies: 1, links: [], tags: [], disposal: { reason: 'sold' } },
    { line: 'owned-19', kind: 'parked', status: 'owned', headId: HEAD, copies: 1, links: [], tags: [] },
  ],
});
const frozenOf = (over: Partial<BuildOptions> = {}) => {
  const opts = { ...OPTS, ...over };
  return freeze(buildBatches(PLAN, opts), opts);
};

describe('freeze', () => {
  it('is the batches exactly as `gk2-import --out` writes them, with their sha256, prefix and device', () => {
    const built = buildBatches(PLAN, OPTS);
    const f = freeze(built, OPTS);
    const expected = built.batches.map((b) => ({
      clientId: b.clientId,
      events: b.events.map((w) => ({ facetKey: w.facetKey, version: w.version, op: 'SYNC_OP_UPSERT', payload: w.payload, basis: w.basis })),
    }));
    expect(f.text).toBe(`${JSON.stringify(expected, null, 1)}\n`);
    expect(f.sha256).toBe(createHash('sha256').update(f.text, 'utf8').digest('hex'));
    expect(f.batches).toEqual(expected);
    expect(f.prefix).toBe('gk2-send-t');
    expect(f.deviceHex).toBe(DEVICE);
    expect(f.events).toBe(built.batches.reduce((n, b) => n + b.events.length, 0));
  });

  it('is byte-identical for the same plan, device, time and prefix, and differs when any of them changes', () => {
    expect(frozenOf().sha256).toBe(frozenOf().sha256);
    expect(frozenOf({ deviceHex: OTHER_DEVICE }).sha256).not.toBe(frozenOf().sha256);
    expect(frozenOf({ at: new Date('2026-10-31T12:00:00.001Z') }).sha256).not.toBe(frozenOf().sha256);
    expect(frozenOf({ clientPrefix: 'gk2-send-u' }).sha256).not.toBe(frozenOf().sha256);
  });

  it('names its file after the prefix, and its sidecar is a `sha256sum -c` line', () => {
    expect(frozenFileName('gk2-import-1')).toBe('gk2-import-1.frozen.json');
    expect(shaSidecar('ab'.repeat(32), 'gk2-import-1.frozen.json')).toBe(`${'ab'.repeat(32)}  gk2-import-1.frozen.json\n`);
  });
});

describe('parseFrozen', () => {
  const text = frozenOf().text;
  const batches = () => JSON.parse(text) as FrozenBatch[];
  const refused = (value: unknown): string => {
    try {
      parseFrozen(typeof value === 'string' ? value : JSON.stringify(value));
    } catch (err) {
      expect(err).toBeInstanceOf(FrozenError);
      return (err as Error).message;
    }
    throw new Error('parseFrozen accepted it');
  };

  it('reads back what freeze wrote: the batches, the prefix, the device and the sha256', () => {
    const f = parseFrozen(text);
    expect(f.batches).toEqual(batches());
    expect(f.prefix).toBe('gk2-send-t');
    expect(f.deviceHex).toBe(DEVICE);
    expect(f.sha256).toBe(frozenOf().sha256);
    expect(f.text).toBe(text);
    expect(f.events).toBe(frozenOf().events);
  });

  it('reads a DELETE event too', () => {
    const b = batches();
    b[0]!.events[0] = { ...b[0]!.events[0]!, op: 'SYNC_OP_DELETE', payload: '' };
    expect(parseFrozen(JSON.stringify(b)).batches[0]!.events[0]!.op).toBe('SYNC_OP_DELETE');
  });

  it('refuses anything that is not exactly a frozen file', () => {
    expect(refused('{')).toMatch(/not JSON/);
    expect(refused({})).toMatch(/not a list of batches/);
    expect(refused([])).toMatch(/no batches/);
    expect(refused([1])).toMatch(/batch 1 is not an object/);
    expect(refused([{ ...batches()[0], extra: 1 }])).toMatch(/batch 1 has an unknown key: extra/);
    expect(refused([{ ...batches()[0], clientId: 7 }])).toMatch(/batch 1: clientId is not/);
    expect(refused([{ ...batches()[0], clientId: 'gk2-send-t-0002' }])).toMatch(/batch 1: clientId is not <prefix>-0001/);
    expect(refused([{ ...batches()[0], clientId: 'gk2 send-0001' }])).toMatch(/batch 1: clientId is not <prefix>-0001/);
    expect(refused([batches()[0], { ...batches()[0], clientId: 'other-0002' }])).toMatch(/batch 2: clientId is not gk2-send-t-0002/);
    expect(refused([{ ...batches()[0], events: [] }])).toMatch(/batch 1: events is not a list of 1 to 200 events/);
    expect(refused([{ ...batches()[0], events: 'x' }])).toMatch(/batch 1: events is not a list/);
    const ev = batches()[0]!.events[0]!;
    const one = (e: unknown) => [{ clientId: 'gk2-send-t-0001', events: [e] }];
    expect(refused([{ clientId: 'gk2-send-t-0001', events: Array(201).fill(ev) }])).toMatch(/1 to 200/);
    expect(refused(one('x'))).toMatch(/batch 1 event 1 is not an object/);
    expect(refused(one({ ...ev, more: 1 }))).toMatch(/unknown key: more/);
    expect(refused(one({ ...ev, payload: 3 }))).toMatch(/event 1: payload is not text/);
    expect(refused(one({ ...ev, op: 'SYNC_OP_MERGE' }))).toMatch(/event 1: op is not SYNC_OP_UPSERT or SYNC_OP_DELETE/);
    expect(refused(one({ ...ev, basis: 'AAAA' }))).toMatch(/event 1: basis is not the empty basis/);
    expect(refused(one({ ...ev, facetKey: 'holding/x/status' }))).toMatch(/event 1: facetKey is not a user-owned key/);
    expect(refused(one({ ...ev, version: '2026-10-31T12:00:00.000000Z' }))).toMatch(/event 1: version is not <instant>#<counter>#<device>/);
    expect(refused(one({ ...ev, version: 'yesterday' }))).toMatch(/event 1: version is not <instant>#<counter>#<device>/);
    expect(refused([{ clientId: 'gk2-send-t-0001', events: [ev, ev] }])).toMatch(/event 2: facetKey appears twice/);
    const otherDevice = { ...batches()[0]!.events[1]!, version: batches()[0]!.events[1]!.version.replace(DEVICE, OTHER_DEVICE) };
    expect(refused([{ clientId: 'gk2-send-t-0001', events: [ev, otherDevice] }])).toMatch(/event 2: version names another device than the first event/);
  });
});

describe('wireEvents', () => {
  it('is each event as a SyncEvent, with the op as the enum and the empty basis set, not absent', () => {
    const f = frozenOf();
    const events = wireEvents(f.batches[0]!);
    expect(events).toHaveLength(f.batches[0]!.events.length);
    expect(events[0]).toMatchObject({ facetKey: f.batches[0]!.events[0]!.facetKey, version: f.batches[0]!.events[0]!.version, op: SyncOp.UPSERT, payload: f.batches[0]!.events[0]!.payload, basis: '' });
    const del = wireEvents({ clientId: 'x-0001', events: [{ ...f.batches[0]!.events[0]!, op: 'SYNC_OP_DELETE', payload: '' }] });
    expect(del[0]!.op).toBe(SyncOp.DELETE);
  });
});

describe('refusals and summaryLines', () => {
  it('finds no refusal in a plan the coordinator would accept', () => {
    expect(refusals(buildBatches(PLAN, OPTS), { deviceHex: DEVICE, nowMicros: BigInt(AT.getTime()) * 1000n })).toEqual([]);
  });

  it('names the line, the key and the reason code of each refusal, and (names) for a name', () => {
    const lines = refusals(buildBatches(PLAN, OPTS), { deviceHex: OTHER_DEVICE, nowMicros: BigInt(AT.getTime()) * 1000n });
    expect(lines.length).toBeGreaterThan(0);
    expect(lines.every((l) => l.endsWith(': device_mismatch'))).toBe(true);
    expect(lines).toContain(`(names): ${buildBatches(PLAN, OPTS).batches[0]!.events[0]!.facetKey}: device_mismatch`);
    expect(lines.some((l) => l.startsWith('owned-3: occ/'))).toBe(true);
  });

  it('says what gk2-import says: entries, copies, events, families and the parked lines', () => {
    const built = buildBatches(PLAN, OPTS);
    expect(summaryLines(PLAN, built)).toEqual([
      '4 entries: 2 matched, 1 text, 1 parked',
      `4 copies, ${built.batches[0]!.events.length} events in 1 batches`,
      `by family: ${Object.entries(built.counts).map(([f, n]) => `${f} ${n}`).join(', ')}`,
      'parked, not written: owned-19',
    ]);
    const unparked = parsePlan({ namespace: NS, entries: [PLAN.entries[0]] });
    expect(summaryLines(unparked, buildBatches(unparked, OPTS))).toHaveLength(3);
  });
});
