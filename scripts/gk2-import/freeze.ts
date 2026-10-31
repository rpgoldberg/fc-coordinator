// The frozen batches: what one send pushes, byte for byte, written once before the first Push and
// read back by a retry. A Push's client_id is recorded with the sha256 of its request, so a retry
// must carry these very bytes: the file IS the idempotency record on this side. Its shape is
// exactly what `gk2-import --out` writes (an array of {clientId, events}), so the read-only
// post-send check and the prepared rollback read it unchanged.
import { createHash } from 'node:crypto';
import { create } from '@bufbuild/protobuf';
import { SyncEventSchema, SyncOp, parseUserFacetKey, parseVersion, type SyncEvent } from '@figurecollecting/fc-api-contract';
import { validateEvent } from '../../src/sync/validate.js';
import { MAX_EVENTS_PER_BATCH, type BuildOptions, type Built } from './build.js';
import type { Plan } from './plan.js';

export type FrozenOp = 'SYNC_OP_UPSERT' | 'SYNC_OP_DELETE';

export interface FrozenEvent {
  facetKey: string;
  version: string;
  op: FrozenOp;
  payload: string;
  basis: string;
}

export interface FrozenBatch {
  clientId: string;
  events: FrozenEvent[];
}

export interface Frozen {
  batches: FrozenBatch[];
  /** Every batch's client_id is `${prefix}-NNNN`. */
  prefix: string;
  /** The device every version names, 32 lowercase hex. */
  deviceHex: string;
  events: number;
  /** The file's bytes, and their sha256 in hex. */
  text: string;
  sha256: string;
}

export class FrozenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FrozenError';
  }
}

export const sha256Hex = (text: string): string => createHash('sha256').update(text, 'utf8').digest('hex');
export const frozenFileName = (prefix: string): string => `${prefix}.frozen.json`;
/** A `sha256sum` line: `sha256sum -c` checks the file with it. */
export const shaSidecar = (sha256: string, fileName: string): string => `${sha256}  ${fileName}\n`;

const textOf = (batches: FrozenBatch[]): string => `${JSON.stringify(batches, null, 1)}\n`;

export function freeze(built: Built, opts: Pick<BuildOptions, 'clientPrefix' | 'deviceHex'>): Frozen {
  const batches: FrozenBatch[] = built.batches.map((b) => ({
    clientId: b.clientId,
    events: b.events.map((w) => ({ facetKey: w.facetKey, version: w.version, op: `SYNC_OP_${SyncOp[w.op]}` as FrozenOp, payload: w.payload, basis: w.basis })),
  }));
  const text = textOf(batches);
  return { batches, prefix: opts.clientPrefix, deviceHex: opts.deviceHex, events: batches.reduce((n, b) => n + b.events.length, 0), text, sha256: sha256Hex(text) };
}

type Json = Record<string, unknown>;
const isObject = (v: unknown): v is Json => typeof v === 'object' && v !== null && !Array.isArray(v);
const PREFIX = /^([A-Za-z0-9._-]{1,100})-0001$/;
const EVENT_KEYS = ['facetKey', 'version', 'op', 'payload', 'basis'];

function closed(where: string, value: unknown, allowed: readonly string[]): Json {
  if (!isObject(value)) throw new FrozenError(`${where} is not an object`);
  for (const key of Object.keys(value)) if (!allowed.includes(key)) throw new FrozenError(`${where} has an unknown key: ${key}`);
  return value;
}

/** A frozen file, exactly: refused whole unless every batch and event is what freeze writes. */
export function parseFrozen(text: string): Frozen {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new FrozenError('not JSON');
  }
  if (!Array.isArray(raw)) throw new FrozenError('not a list of batches');
  if (raw.length === 0) throw new FrozenError('no batches');
  let prefix = '';
  let deviceHex = '';
  const seen = new Set<string>();
  const batches = raw.map((value, b): FrozenBatch => {
    const at = `batch ${b + 1}`;
    const batch = closed(at, value, ['clientId', 'events']);
    const clientId = batch['clientId'];
    if (b === 0) {
      const match = typeof clientId === 'string' ? PREFIX.exec(clientId) : null;
      if (match === null) throw new FrozenError(`${at}: clientId is not <prefix>-0001`);
      prefix = match[1]!;
    } else if (clientId !== `${prefix}-${String(b + 1).padStart(4, '0')}`) {
      throw new FrozenError(`${at}: clientId is not ${prefix}-${String(b + 1).padStart(4, '0')}`);
    }
    const events = batch['events'];
    if (!Array.isArray(events) || events.length === 0 || events.length > MAX_EVENTS_PER_BATCH) {
      throw new FrozenError(`${at}: events is not a list of 1 to ${MAX_EVENTS_PER_BATCH} events`);
    }
    return {
      clientId: clientId as string,
      events: events.map((ev, e): FrozenEvent => {
        const where = `${at} event ${e + 1}`;
        const event = closed(where, ev, EVENT_KEYS);
        for (const key of EVENT_KEYS) if (typeof event[key] !== 'string') throw new FrozenError(`${where}: ${key} is not text`);
        const { facetKey, version, op, payload, basis } = event as Record<string, string>;
        if (op !== 'SYNC_OP_UPSERT' && op !== 'SYNC_OP_DELETE') throw new FrozenError(`${where}: op is not SYNC_OP_UPSERT or SYNC_OP_DELETE`);
        if (basis !== '') throw new FrozenError(`${where}: basis is not the empty basis`);
        if (parseUserFacetKey(facetKey!) === undefined) throw new FrozenError(`${where}: facetKey is not a user-owned key`);
        const parsed = parseVersion(version!);
        if (parsed === undefined || parsed.deviceId === null) throw new FrozenError(`${where}: version is not <instant>#<counter>#<device>`);
        if (deviceHex === '') deviceHex = parsed.deviceId;
        else if (parsed.deviceId !== deviceHex) throw new FrozenError(`${where}: version names another device than the first event`);
        if (seen.has(facetKey!)) throw new FrozenError(`${where}: facetKey appears twice`);
        seen.add(facetKey!);
        return { facetKey: facetKey!, version: version!, op, payload: payload!, basis };
      }),
    };
  });
  return { batches, prefix, deviceHex, events: seen.size, text, sha256: sha256Hex(text) };
}

/** A batch as the Push carries it. The empty basis is SET, not left absent: absent is basis_missing. */
export function wireEvents(batch: FrozenBatch): SyncEvent[] {
  return batch.events.map((e) =>
    create(SyncEventSchema, { facetKey: e.facetKey, version: e.version, op: e.op === 'SYNC_OP_DELETE' ? SyncOp.DELETE : SyncOp.UPSERT, payload: e.payload, basis: e.basis }),
  );
}

/** Every event the coordinator's own Push validation would refuse, as `line: key: reason code`. */
export function refusals(built: Built, ctx: { deviceHex: string; nowMicros: bigint }): string[] {
  const refused: string[] = [];
  for (const batch of built.batches) {
    for (const w of batch.events) {
      const verdict = validateEvent(w, ctx);
      if (!verdict.ok) refused.push(`${w.line === '' ? '(names)' : w.line}: ${w.facetKey}: ${verdict.reason.split(':')[0]}`);
    }
  }
  return refused;
}

/** What `gk2-import` prints of a plan it built: counts, families and the parked lines. Never a payload. */
export function summaryLines(plan: Plan, built: Built): string[] {
  const byKind = (k: string) => plan.entries.filter((e) => e.kind === k).length;
  const copies = plan.entries.filter((e) => e.kind !== 'parked').reduce((n, e) => n + e.copies, 0);
  const events = built.batches.reduce((n, b) => n + b.events.length, 0);
  const lines = [
    `${plan.entries.length} entries: ${byKind('matched')} matched, ${byKind('text')} text, ${byKind('parked')} parked`,
    `${copies} copies, ${events} events in ${built.batches.length} batches`,
    `by family: ${Object.entries(built.counts).map(([f, n]) => `${f} ${n}`).join(', ')}`,
  ];
  if (built.parked.length > 0) lines.push(`parked, not written: ${built.parked.join(', ')}`);
  return lines;
}
