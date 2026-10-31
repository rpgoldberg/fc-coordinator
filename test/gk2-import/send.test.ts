// The GK2 sender against the REAL coordinator: buildApp with the real DPoP edge, the Postgres
// device table and SyncService (Testcontainers), over app.inject. Sign-in is stubbed with the test
// issuer here; the browser sign-in itself runs in send-live-local.test.ts. Faults are forced on one
// labelled exchange at a time, by rewriting its answer or by failing it before it is sent.
import { randomUUID } from 'node:crypto';
import { mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import { DeltaResponseSchema, PushOutcome, PushResponseSchema, PushResultSchema } from '@figurecollecting/fc-api-contract';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createDeviceStore } from '../../src/auth/plugin.js';
import { generateClientKey } from '../../scripts/phase2-client/dpop.js';
import { LoginError } from '../../scripts/phase2-client/login.js';
import { createSafeOutput } from '../../scripts/phase2-client/output.js';
import { Session } from '../../scripts/phase2-client/session.js';
import type { HttpRequest, HttpResponse, Transport } from '../../scripts/phase2-client/transport.js';
import { USAGE, liveDeps, main, type SendDeps } from '../../scripts/gk2-import/send.js';
import { makeIssuer, type TestIssuer } from '../helpers/auth.js';
import { CLIENT_ID, buildCoordinator, injectTransport, recording, withStatus, type Exchanged } from '../helpers/phase2Harness.js';
import { leaks } from '../helpers/phase2Run.js';
import { startSyncDatabase, type SyncDatabase } from '../helpers/syncDatabase.js';

const ORIGIN = 'https://api.test.invalid';
const HOST = 'api.test.invalid';
const LIVE = ['--target', ORIGIN, '--confirm', HOST];
const NS = '7d0c1d9e-5a43-4c52-9d4f-6f2a4b8f1c07';
const NS2 = '5b0c7c7e-2f1d-4c1e-9a1b-3c4d5e6f7a8b';
const HEAD = '3907070b-50f1-4f99-b912-6d63db4bf805';
const HEAD2 = '6c7ce962-0000-4000-8000-000000000002';
const NOTE = 'PRIVATE-NOTE-TEXT';
const LABEL = 'PRIVATE-LABEL-NAME';
/** Two batches: the two names and owned-1 (183 events), then owned-2 and sold-1 (65). */
const PLAN = {
  namespace: NS,
  entries: [
    { line: 'owned-1', kind: 'matched', status: 'owned', headId: HEAD, copies: 60, links: [], tags: ['T1'], note: NOTE },
    { line: 'owned-2', kind: 'text', status: 'owned', copies: 30, label: { name: LABEL }, links: [], tags: [] },
    { line: 'sold-1', kind: 'matched', status: 'former', headId: HEAD, copies: 1, links: [], tags: ['scammed'], disposal: { reason: 'other', note: 'never received' } },
    { line: 'owned-3', kind: 'parked', status: 'owned', headId: HEAD, copies: 1, links: [], tags: [] },
  ],
};
const EVENTS = 248;

let db: SyncDatabase;
let issuer: TestIssuer;

beforeAll(async () => {
  db = await startSyncDatabase();
  issuer = await makeIssuer({ audience: CLIENT_ID });
}, 240_000);

afterAll(async () => {
  await db?.close();
});

const tempDir = (): string => mkdtempSync(path.join(tmpdir(), 'gk2-send-'));
const planFile = (plan: object = PLAN): string => {
  const file = path.join(tempDir(), 'plan.json');
  writeFileSync(file, JSON.stringify(plan));
  return file;
};

/** A transport that fails the matching requests before they are sent, as a dropped connection does. */
function failing(inner: Transport, fails: (req: HttpRequest) => boolean): Transport {
  let count = 0;
  return {
    get count() {
      return count;
    },
    async request(req) {
      count += 1;
      if (fails(req)) throw new Error('connect ECONNRESET');
      return inner.request(req);
    },
  };
}

interface Ran {
  exit: number;
  out: string;
  err: string;
  log: Exchanged[];
  userId: string;
  requests: number;
  secrets: string[];
}

interface RunOptions {
  userId?: string;
  rewrite?: (req: HttpRequest, res: HttpResponse) => HttpResponse;
  fails?: (req: HttpRequest) => boolean;
  ttlMs?: number;
  signal?: AbortSignal;
  signIn?: SendDeps['signIn'];
  deps?: Partial<SendDeps>;
}

async function run(argv: string[], o: RunOptions = {}): Promise<Ran> {
  const userId = o.userId ?? randomUUID();
  const logLines: string[] = [];
  const app = buildCoordinator({ issuer, origin: ORIGIN, devices: createDeviceStore(db.app), sync: db.app, logLines });
  await app.ready();
  const recorded = recording(injectTransport(() => app), logLines, o.rewrite);
  const transport = o.fails === undefined ? recorded : failing(recorded, o.fails);
  const out: string[] = [];
  const err: string[] = [];
  const tokens: string[] = [];
  const deps: SendDeps = {
    ...liveDeps(),
    stdout: { write: (s: string) => out.push(s) },
    stderr: { write: (s: string) => err.push(s) },
    transport,
    signIn:
      o.signIn ??
      (async () => {
        const accessToken = await issuer.mint({ sub: userId }, { expiresIn: '10m' });
        tokens.push(accessToken);
        return { accessToken, expiresAt: Date.now() + (o.ttlMs ?? 600_000), secrets: [] };
      }),
    sleep: async () => {},
    ...(o.signal !== undefined ? { signal: o.signal } : {}),
    ...o.deps,
  };
  try {
    const exit = await main(argv, deps);
    const proofs = recorded.log.map((e) => e.request.headers['dpop']).filter((p): p is string => p !== undefined);
    return { exit, out: out.join(''), err: err.join(''), log: recorded.log, userId, requests: transport.count, secrets: [...tokens, ...proofs] };
  } finally {
    await app.close();
  }
}

const sendArgs = (plan: string, dir: string, prefix = 'gk2-t-1'): string[] => ['--plan', plan, '--client-prefix', prefix, '--send', '--frozen-dir', dir, ...LIVE];
const labelled = (log: Exchanged[], label: string): Exchanged[] => log.filter((e) => e.request.label === label);
const pushes = (log: Exchanged[]): Exchanged[] => log.filter((e) => e.request.label.startsWith('push:'));
const devices = async (userId: string) =>
  (await db.admin.query<{ id: string; label: string | null; revoked_at: Date | null }>('SELECT id, label, revoked_at FROM device WHERE user_id = $1 ORDER BY enrolled_at', [userId])).rows;
const feedCount = async (userId: string): Promise<number> =>
  Number((await db.admin.query<{ n: string }>('SELECT count(*) AS n FROM feed_event WHERE user_id = $1', [userId])).rows[0]!.n);
const facets = async (userId: string) =>
  (await db.admin.query<{ facet_key: string; version: string; op: string; payload: string }>('SELECT facet_key, version, op, payload FROM facet_state WHERE user_id = $1', [userId])).rows;
const deviceId = (out: string): string => /device enrolled: ([0-9a-f-]{36}) \(label gk2-import\)/.exec(out)![1]!;
const frozenOf = (file: string) => JSON.parse(readFileSync(file, 'utf8')) as { clientId: string; events: { facetKey: string; version: string; op: string; payload: string }[] }[];
const on = (label: string, change: (res: HttpResponse) => HttpResponse) => (req: HttpRequest, res: HttpResponse) => (req.label === label ? change(res) : res);
const pushAnswer = (results: { facetKey?: string; outcome: number; reason?: string }[]) => (res: HttpResponse): HttpResponse => ({
  ...res,
  status: 200,
  body: toBinary(PushResponseSchema, create(PushResponseSchema, { results: results.map((r) => create(PushResultSchema, { facetKey: r.facetKey ?? 'k', outcome: r.outcome as PushOutcome, reason: r.reason ?? '' })) })),
});

describe('arguments', () => {
  const refuses = async (argv: string[], message: RegExp) => {
    const r = await run(argv);
    expect(r.exit).toBe(2);
    expect(r.err).toMatch(message);
    expect(r.err).toContain(USAGE);
    expect(r.requests).toBe(0);
  };
  const plan = '/nowhere/plan.json';

  it('prints the usage for --help', async () => {
    const r = await run(['--help']);
    expect(r.exit).toBe(0);
    expect(r.out).toContain(USAGE);
  });

  it('refuses what is not a usable command, before any request', async () => {
    await refuses(['--bogus'], /Unknown option/);
    await refuses(['--plan', plan, '--client-prefix', 'p', '--dry-run', '--send'], /--dry-run and --send contradict each other/);
    await refuses(['--plan', plan, '--client-prefix', 'p', '--send', '--frozen-dir', '/d'], /--send needs --target <origin> and --confirm <host>/);
    await refuses(['--plan', plan, '--client-prefix', 'p', '--send', '--frozen-dir', '/d', '--target', ORIGIN], /--send needs --target <origin> and --confirm <host>/);
    await refuses(['--plan', plan, '--client-prefix', 'p', '--confirm', HOST], /--confirm needs --target/);
    await refuses(['--plan', plan, '--client-prefix', 'p', '--target', ORIGIN, '--confirm', 'other.test.invalid'], /--confirm 'other.test.invalid' does not match the target host 'api.test.invalid'/);
    await refuses(['--plan', plan, '--client-prefix', 'p', '--target', `${ORIGIN}/api`], /--target must be the bare origin/);
    await refuses(['--plan', plan, '--client-prefix', 'p', '--target', 'http://api.test.invalid'], /--target must be https/);
    await refuses(['--plan', plan, '--client-prefix', 'p', '--target', 'not a url'], /--target must be an absolute URL/);
    await refuses(['--client-prefix', 'p'], /one of --plan <plan.json> or --resume <frozen file>/);
    await refuses(['--plan', plan, '--resume', '/f.json'], /one of --plan <plan.json> or --resume <frozen file>/);
    await refuses(['--plan', plan], /--plan needs --client-prefix/);
    await refuses(['--plan', plan, '--client-prefix', 'has space'], /--client-prefix must be 1 to 100 letters, digits and . _ -/);
    await refuses(['--plan', plan, '--client-prefix', '.hidden'], /--client-prefix must be 1 to 100 letters, digits and . _ -/);
    await refuses(['--plan', plan, '--client-prefix', 'p', '--send', ...LIVE], /--send --plan needs --frozen-dir <dir>/);
    await refuses(['--resume', '/d/p.frozen.json', '--frozen-dir', '/d'], /--resume writes next to its frozen file: no --frozen-dir/);
    await refuses(['--plan', plan, '--client-prefix', 'p', '--tz', 'not a zone'], /--tz must be an IANA zone/);
    await refuses(['--plan', plan, '--client-prefix', 'p', '--redirect-uri', 'https://example.test/cb'], /--redirect-uri must be http on loopback/);
    await refuses(['--plan', plan, '--client-prefix', 'p', '--redirect-uri', 'http://localhost/cb'], /--redirect-uri must name its port/);
    await refuses(['--plan', plan, '--client-prefix', 'p', '--issuer', 'http://auth.test.invalid/'], /--issuer must be https/);
    await refuses(['--plan', plan, '--client-prefix', 'p', '--prefix', 'api'], /--prefix/);
    await refuses(['--revoke', 'not-a-uuid', ...LIVE], /--revoke needs a device id \(a uuid\)/);
    await refuses(['--revoke', randomUUID()], /--revoke needs --target <origin> and --confirm <host>/);
    await refuses(['--revoke', randomUUID(), '--plan', plan, ...LIVE], /--revoke takes no --plan, --resume, --send or --dry-run/);
  });
});

describe('the dry run, offline: the default', () => {
  it('says what gk2-import says, lists the batches, sends nothing and writes nothing', async () => {
    const dir = tempDir();
    const r = await run(['--plan', planFile(), '--client-prefix', 'gk2-t-1', '--frozen-dir', dir]);
    expect(r.exit).toBe(0);
    expect(r.requests).toBe(0);
    const lines = r.out.split('\n');
    expect(lines[0]).toBe('DRY RUN: nothing is signed in and nothing is sent.');
    expect(lines).toContain('4 entries: 2 matched, 1 text, 1 parked');
    expect(lines).toContain(`91 copies, ${EVENTS} events in 2 batches`);
    expect(lines).toContain('parked, not written: owned-3');
    expect(lines).toContain("every event is accepted by the coordinator's Push validation");
    expect(lines).toContain('batches: gk2-t-1-0001 (183 events), gk2-t-1-0002 (65 events)');
    expect(r.out).toMatch(/^requests sent: 0$/m);
    expect(r.out + r.err).not.toContain(NOTE);
    expect(r.out + r.err).not.toContain(LABEL);
    expect(() => statSync(path.join(dir, 'gk2-t-1.frozen.json'))).toThrow();
  });

  it('exits 2 for a plan it cannot read, parse or build, and 1 for one the coordinator would refuse', async () => {
    const r1 = await run(['--plan', '/nowhere/plan.json', '--client-prefix', 'p']);
    expect([r1.exit, r1.err]).toEqual([2, 'cannot read the plan: /nowhere/plan.json\n']);
    const notJson = path.join(tempDir(), 'plan.json');
    writeFileSync(notJson, '{');
    expect((await run(['--plan', notJson, '--client-prefix', 'p'])).err).toBe('the plan is not JSON\n');
    const r3 = await run(['--plan', planFile({ namespace: 'nope', entries: [] }), '--client-prefix', 'p']);
    expect([r3.exit, r3.err]).toEqual([2, 'plan: plan.namespace is not a lowercase dashed uuid\n']);
    const big = await run(['--plan', planFile({ namespace: NS, entries: [{ line: 'big', kind: 'matched', status: 'owned', headId: HEAD, copies: 99, links: [], tags: ['a', 'b'] }] }), '--client-prefix', 'p']);
    expect(big.exit).toBe(2);
    expect(big.err).toMatch(/entry big is 396 events/);
    const long = await run(['--plan', planFile({ namespace: NS, entries: [{ line: 'long', kind: 'matched', status: 'owned', headId: HEAD, copies: 1, links: [], tags: [], note: 'x'.repeat(10_001) }] }), '--client-prefix', 'p']);
    expect(long.exit).toBe(1);
    expect(long.err).toMatch(/1 events would be refused by the coordinator:\n {2}long: uf\/[0-9a-f-]{36}\/note: payload_invalid\n/);
  });
});

describe('a send', () => {
  let first: Ran;
  let dir: string;
  let plan: string;
  const frozenFile = () => path.join(dir, 'gk2-t-1.frozen.json');

  beforeAll(async () => {
    dir = tempDir();
    plan = planFile();
    first = await run(sendArgs(plan, dir));
  }, 120_000);

  it('signs in, enrols device gk2-import, freezes, pre-checks, pushes both batches, reads them back, revokes, and exits 0', () => {
    expect(first.err).toBe('');
    expect(first.exit).toBe(0);
    const id = deviceId(first.out);
    const sha = readFileSync(`${frozenFile()}.sha256`, 'utf8').split(' ')[0];
    expect(first.out.split('\n')).toEqual([
      'signed in; the access token expires in 600 s',
      `device enrolled: ${id} (label gk2-import)`,
      expect.stringMatching(/^clock: \d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z \(the coordinator's\)$/),
      `freeze: 2 batches (${EVENTS} events), sha256 ${sha}`,
      `pre-check: read 1 pages of the feed; none of the ${EVENTS} keys exists`,
      `frozen: ${frozenFile()} and its .sha256`,
      'push gk2-t-1-0001: 183 events: APPLIED 183',
      'push gk2-t-1-0002: 65 events: APPLIED 65',
      expect.stringMatching(/^read-back: tag\/name MATCH 2, occ\/head MATCH 91, occ\/status MATCH 91, /),
      `read-back: all ${EVENTS} keys hold the frozen value; report ${path.join(dir, 'gk2-t-1.readback.json')}`,
      `device ${id} revoked`,
      `requests sent: ${first.requests}`,
      '',
    ]);
  });

  it('froze a file the coordinator now holds byte for byte, owner-only, with a matching sha256sum line', async () => {
    const batches = frozenOf(frozenFile());
    expect(batches.map((b) => b.clientId)).toEqual(['gk2-t-1-0001', 'gk2-t-1-0002']);
    const held = new Map((await facets(first.userId)).map((f) => [f.facet_key, f]));
    const events = batches.flatMap((b) => b.events);
    expect(events).toHaveLength(EVENTS);
    for (const e of events) expect(held.get(e.facetKey)).toMatchObject({ version: e.version, op: 'upsert', payload: e.payload });
    expect(held.size).toBe(EVENTS);
    expect(statSync(frozenFile()).mode & 0o777).toBe(0o600);
    expect(statSync(`${frozenFile()}.sha256`).mode & 0o777).toBe(0o600);
    const { createHash } = await import('node:crypto');
    expect(readFileSync(`${frozenFile()}.sha256`, 'utf8')).toBe(`${createHash('sha256').update(readFileSync(frozenFile())).digest('hex')}  gk2-t-1.frozen.json\n`);
    // Every version names the enrolled device, at the coordinator's clock.
    const hex = deviceId(first.out).replaceAll('-', '');
    expect(events.every((e) => e.version.endsWith(`#${hex}`))).toBe(true);
  });

  it('wrote a read-back report of keys and verdicts only, owner-only', () => {
    const file = path.join(dir, 'gk2-t-1.readback.json');
    const report = JSON.parse(readFileSync(file, 'utf8')) as { ok: boolean; clientPrefix: string; deviceId: string; frozenSha256: string; keys: { verdict: string }[] };
    expect(report).toMatchObject({ ok: true, clientPrefix: 'gk2-t-1', deviceId: deviceId(first.out) });
    expect(report.keys).toHaveLength(EVENTS);
    expect(report.keys.every((k) => k.verdict === 'MATCH')).toBe(true);
    expect(readFileSync(file, 'utf8')).not.toContain(NOTE);
    expect(statSync(file).mode & 0o777).toBe(0o600);
  });

  it('labelled the device gk2-import and revoked it', async () => {
    expect(await devices(first.userId)).toEqual([{ id: deviceId(first.out), label: 'gk2-import', revoked_at: expect.any(Date) }]);
  });

  it('never prints the token, a proof, a note or a label', () => {
    expect(leaks(first.out + first.err, first.secrets)).toEqual([]);
    expect(first.out + first.err).not.toContain(NOTE);
    expect(first.out + first.err).not.toContain(LABEL);
  });

  it('refuses a second fresh send under the same prefix into the same directory before anyone signs in', async () => {
    const r = await run(sendArgs(plan, dir), { userId: first.userId });
    expect(r.exit).toBe(2);
    expect(r.requests).toBe(0);
    expect(r.err).toBe(`the frozen file ${frozenFile()} exists: a send under gk2-t-1 was frozen already. Retry it with --resume ${frozenFile()}, or choose another --client-prefix\n`);
  });

  it('replays the very same frozen file with --resume: every event DUPLICATE, nothing written twice, its device revoked too', async () => {
    const before = await feedCount(first.userId);
    const r = await run(['--resume', frozenFile(), '--send', ...LIVE], { userId: first.userId });
    expect(r.err).toBe('');
    expect(r.exit).toBe(0);
    expect(r.out).toContain(`resume: ${frozenFile()} (2 batches, ${EVENTS} events), its sha256 matches its .sha256`);
    expect(r.out).toContain('pre-check: read 1 pages of the feed; 2 batches landed already and replay as DUPLICATE, 0 unsent');
    expect(r.out).toContain('push gk2-t-1-0001: 183 events: DUPLICATE 183');
    expect(r.out).toContain('push gk2-t-1-0002: 65 events: DUPLICATE 65');
    expect(r.out).toContain(`read-back: all ${EVENTS} keys hold the frozen value`);
    expect(await feedCount(first.userId)).toBe(before);
    const rows = await devices(first.userId);
    expect(rows).toHaveLength(2);
    expect(rows.every((d) => d.revoked_at !== null && d.label === 'gk2-import')).toBe(true);
  });

  it('refuses a fresh freeze under the same prefix elsewhere: its keys exist, so nothing is pushed', async () => {
    const r = await run(sendArgs(plan, tempDir()), { userId: first.userId });
    expect(r.exit).toBe(1);
    expect(pushes(r.log)).toEqual([]);
    expect(r.err).toMatch(new RegExp(`^pre-check: ${EVENTS} of the ${EVENTS} keys these batches write exist already \\(.*occ/head 91.*\\): refusing to send\\. A retry of a send is --resume <the frozen file it wrote>\\.\\n$`));
    expect(r.out).toMatch(/device [0-9a-f-]{36} revoked/);
    expect((await devices(first.userId)).every((d) => d.revoked_at !== null)).toBe(true);
  });

  it('refuses, with --resume, a different frozen file under the same prefix: the coordinator holds other versions', async () => {
    // Same plan, same prefix, another clock: the versions differ.
    const other = tempDir();
    const g = path.join(other, 'gk2-t-1.frozen.json');
    const batches = frozenOf(frozenFile()).map((b) => ({ ...b, events: b.events.map((e) => ({ ...e, version: e.version.replace(/^2\d{3}/, '2025') })) }));
    const text = `${JSON.stringify(batches, null, 1)}\n`;
    writeFileSync(g, text);
    const { createHash } = await import('node:crypto');
    writeFileSync(`${g}.sha256`, `${createHash('sha256').update(text).digest('hex')}  gk2-t-1.frozen.json\n`);
    const before = await feedCount(first.userId);
    const r = await run(['--resume', g, '--send', ...LIVE], { userId: first.userId });
    expect(r.exit).toBe(1);
    expect(pushes(r.log)).toEqual([]);
    expect(r.err).toBe(`pre-check: ${EVENTS} keys hold another value than ${g} froze: it is not the file that was sent. Refusing.\n`);
    expect(await feedCount(first.userId)).toBe(before);
  });

  it('is stopped by the coordinator itself when another plan reuses the prefix: Push refuses the client_id, writing nothing', async () => {
    const before = await feedCount(first.userId);
    // Another namespace and another head: none of its keys exists, but its client_ids do.
    const other = { namespace: NS2, entries: PLAN.entries.map((e) => ('headId' in e ? { ...e, headId: HEAD2 } : e)) };
    const r = await run(sendArgs(planFile(other), tempDir()), { userId: first.userId });
    expect(r.exit).toBe(1);
    expect(pushes(r.log)).toHaveLength(1);
    expect(r.err).toBe('push gk2-t-1-0001 answered 400 invalid_argument: stopped, nothing more is sent. (Push answers this way for a client_id it recorded for a different batch, and writes nothing.)\n');
    expect(await feedCount(first.userId)).toBe(before);
    expect(r.out).toMatch(/device [0-9a-f-]{36} revoked/);
  });
});

describe('a signed dry run', () => {
  it('signs in, enrols, pre-checks and revokes, but freezes nothing to disk and pushes nothing', async () => {
    const dir = tempDir();
    const r = await run(['--plan', planFile(), '--client-prefix', 'gk2-t-1', '--frozen-dir', dir, ...LIVE]);
    expect(r.exit).toBe(0);
    expect(r.out).toMatch(/^freeze: 2 batches \(248 events\), sha256 [0-9a-f]{64}$/m);
    expect(r.out).toContain(`pre-check: read 1 pages of the feed; none of the ${EVENTS} keys exists`);
    expect(r.out).toContain('dry run: nothing written, nothing pushed');
    expect(r.out).toMatch(/device [0-9a-f-]{36} revoked/);
    expect(pushes(r.log)).toEqual([]);
    expect(() => statSync(path.join(dir, 'gk2-t-1.frozen.json'))).toThrow();
    expect((await devices(r.userId)).every((d) => d.revoked_at !== null)).toBe(true);
  });
});

describe('stops', () => {
  const fresh = () => sendArgs(planFile(), tempDir());

  it('stops at the first batch with an answer that is not APPLIED or DUPLICATE, prints its counts and keys, and revokes', async () => {
    const r = await run(fresh(), {
      rewrite: on('push:gk2-t-1-0001', pushAnswer([
        { facetKey: 'occ/a/head', outcome: PushOutcome.APPLIED },
        { facetKey: 'occ/a/status', outcome: PushOutcome.REJECTED, reason: 'payload_invalid: secret detail' },
        { facetKey: 'occ/b/head', outcome: PushOutcome.STALE },
        { facetKey: 'occ/b/status', outcome: PushOutcome.HELD },
        { facetKey: 'occ/c/head', outcome: 9 },
      ])),
    });
    expect(r.exit).toBe(1);
    expect(pushes(r.log)).toHaveLength(1);
    expect(r.err).toBe(
      [
        'push gk2-t-1-0001: 183 events, 5 results: stopped: APPLIED 1, REJECTED 1, STALE 1, HELD 1, outcome 9 1',
        '  occ/a/status: REJECTED payload_invalid',
        '  occ/b/head: STALE',
        '  occ/b/status: HELD',
        '  occ/c/head: outcome 9',
        'nothing more is sent',
        '',
      ].join('\n'),
    );
    expect(r.err).not.toContain('secret detail');
    expect(r.out).toMatch(/device [0-9a-f-]{36} revoked/);
  });

  it('shows at most 20 of the keys a batch did not land', async () => {
    const results = Array.from({ length: 25 }, (_, i) => ({ facetKey: `k${i}`, outcome: PushOutcome.REJECTED, reason: 'device_mismatch: x' }));
    const r = await run(fresh(), { rewrite: on('push:gk2-t-1-0001', pushAnswer(results)) });
    expect(r.err.split('\n').filter((l) => l.startsWith('  '))).toHaveLength(21);
    expect(r.err).toContain('  ... and 5 more');
  });

  it('retries a Push whose answer was lost with the same client_id, and the replay answers DUPLICATE', async () => {
    let dropped = false;
    const r = await run(fresh(), {
      rewrite: (req, res) => {
        if (req.label !== 'push:gk2-t-1-0001' || dropped) return res;
        dropped = true;
        return withStatus(res, 503, '{"code":"unavailable"}');
      },
    });
    expect(r.exit).toBe(0);
    expect(labelled(r.log, 'push:gk2-t-1-0001')).toHaveLength(2);
    expect(r.out).toContain('push gk2-t-1-0001: 183 events: DUPLICATE 183');
    expect(r.err).toBe('push gk2-t-1-0001: answered 503 unavailable; retrying with the same client_id (attempt 2 of 3)\n');
  });

  it('retries a Push that never left, and gives up after three attempts', async () => {
    const r = await run(fresh(), { fails: (req) => req.label === 'push:gk2-t-1-0002' });
    expect(r.exit).toBe(1);
    expect(r.out).toContain('push gk2-t-1-0001: 183 events: APPLIED 183');
    expect(r.err).toBe(
      [
        'push gk2-t-1-0002: no answer (connect ECONNRESET); retrying with the same client_id (attempt 2 of 3)',
        'push gk2-t-1-0002: no answer (connect ECONNRESET); retrying with the same client_id (attempt 3 of 3)',
        'push gk2-t-1-0002: no answer after 3 attempts: stopped, nothing more is sent. Retry with --resume <the frozen file>.',
        '',
      ].join('\n'),
    );
    expect(r.out).toMatch(/device [0-9a-f-]{36} revoked/);
  });

  it('stops when the Push answers fewer results than it sent events', async () => {
    const r = await run(fresh(), { rewrite: on('push:gk2-t-1-0001', pushAnswer([])) });
    expect(r.exit).toBe(1);
    expect(r.err).toMatch(/^push gk2-t-1-0001: 183 events, 0 results: stopped: \n/);
  });

  it('stops when a result echoes another key than the event it answers', async () => {
    const r = await run(fresh(), { rewrite: on('push:gk2-t-1-0001', pushAnswer(Array.from({ length: 183 }, () => ({ facetKey: 'occ/x/head', outcome: PushOutcome.APPLIED })))) });
    expect(r.exit).toBe(1);
    expect(r.err).toMatch(/^push gk2-t-1-0001: 183 events, 183 results: stopped: the results do not echo the events' keys in order\n/);
  });

  it('pushes nothing when the sign-in has under two minutes left, and revokes', async () => {
    const r = await run(fresh(), { ttlMs: 90_000 });
    expect(r.exit).toBe(1);
    expect(pushes(r.log)).toEqual([]);
    expect(r.err).toBe('the sign-in has 90 s left, under the 120 s a send needs: nothing pushed. Run it again.\n');
    expect(r.out).toMatch(/device [0-9a-f-]{36} revoked/);
  });

  it('stops before the next step when interrupted, and revokes', async () => {
    const abort = new AbortController();
    abort.abort();
    const r = await run(fresh(), { signal: abort.signal });
    expect(r.exit).toBe(1);
    expect(labelled(r.log, 'status')).toEqual([]);
    expect(r.err).toBe('interrupted: nothing more is sent\n');
    expect(r.out).toMatch(/device [0-9a-f-]{36} revoked/);
  });

  it('stops when Status, or Delta, does not answer, and revokes', async () => {
    const status = await run(fresh(), { rewrite: on('status', (res) => withStatus(res, 400, '{"code":"invalid_argument"}')) });
    expect([status.exit, status.err]).toEqual([1, 'Status answered 400 invalid_argument: stopped, nothing more is sent\n']);
    expect(status.out).toMatch(/device [0-9a-f-]{36} revoked/);
    const delta = await run(fresh(), { rewrite: on('delta', (res) => withStatus(res, 400, '{}')) });
    expect([delta.exit, delta.err]).toEqual([1, 'Delta answered 400: stopped, nothing more is sent\n']);
    expect(pushes(delta.log)).toEqual([]);
  });

  it('retries a Delta page that did not answer', async () => {
    let failed = false;
    const r = await run(fresh(), { fails: (req) => req.label === 'delta' && !failed && (failed = true) });
    expect(r.exit).toBe(0);
    expect(r.err).toBe('Delta: no answer (connect ECONNRESET); retrying (attempt 2 of 3)\n');
  });

  it('exits 1 when the read-back does not find what was pushed, and names the counts', async () => {
    let deltas = 0;
    const r = await run(fresh(), { rewrite: (req, res) => (req.label === 'delta' && ++deltas === 2 ? { ...res, body: new Uint8Array() } : res) });
    expect(r.exit).toBe(1);
    expect(r.out).toMatch(/^read-back: tag\/name MISSING 2, occ\/head MISSING 91, /m);
    expect(r.err).toMatch(new RegExp(`^read-back: ${EVENTS} of the ${EVENTS} keys do not hold the frozen value; report .*gk2-t-1\\.readback\\.json\\n$`));
  });

  it('refuses before freezing when the coordinator would refuse an event, and revokes', async () => {
    const dir = tempDir();
    const r = await run(sendArgs(planFile({ namespace: NS, entries: [{ line: 'long', kind: 'matched', status: 'owned', headId: HEAD, copies: 1, links: [], tags: [], note: 'x'.repeat(10_001) }] }), dir));
    expect(r.exit).toBe(1);
    expect(r.err).toMatch(/^1 events would be refused by the coordinator:\n {2}long: uf\/[0-9a-f-]{36}\/note: payload_invalid\n$/);
    expect(() => statSync(path.join(dir, 'gk2-t-1.frozen.json'))).toThrow();
    expect(r.out).toMatch(/device [0-9a-f-]{36} revoked/);
  });

  it('exits 2 on an unexpected failure mid-run, and still revokes', async () => {
    const r = await run(fresh(), { deps: { writeNew: async () => { throw new Error('ENOSPC: no space left on device'); } } });
    expect(r.exit).toBe(2);
    expect(r.err).toBe('aborted: ENOSPC: no space left on device\n');
    expect(pushes(r.log)).toEqual([]);
    expect(r.out).toMatch(/device [0-9a-f-]{36} revoked/);
  });

  it('retries an answer it cannot read, then stops', async () => {
    const r = await run(fresh(), { rewrite: on('status', (res) => ({ ...res, body: new Uint8Array([0xff, 0xff]) })) });
    expect(r.exit).toBe(1);
    expect(labelled(r.log, 'status')).toHaveLength(3);
    expect(r.err).toMatch(/^Status: no answer after 3 attempts: stopped, nothing more is sent\n$/m);
  });

  it('exits 2 when the frozen directory does not exist, before anyone signs in', async () => {
    const r = await run(sendArgs(planFile(), '/nowhere/at/all'));
    expect([r.exit, r.requests]).toEqual([2, 0]);
    expect(r.err).toBe('--frozen-dir /nowhere/at/all is not a directory\n');
  });
});

describe('sign-in and enrolment failures', () => {
  it('exits 2 and enrols nothing when the sign-in fails', async () => {
    const r = await run(sendArgs(planFile(), tempDir()), {
      signIn: async () => {
        throw new LoginError('the token endpoint answered 400 (invalid_grant)');
      },
    });
    expect([r.exit, r.err]).toEqual([2, 'sign-in failed: the token endpoint answered 400 (invalid_grant)\n']);
    expect(r.requests).toBe(0);
  });

  it('exits 2 when enrolment is refused or answers no device id: there is no device to revoke', async () => {
    const refused = await run(sendArgs(planFile(), tempDir()), { rewrite: on('enrol', (res) => withStatus(res, 403, '{"error":"account_closed"}')) });
    expect([refused.exit, refused.err]).toEqual([2, 'enrolment failed: POST /auth/devices answered 403\n']);
    expect(labelled(refused.log, 'revoke')).toEqual([]);
    const blank = await run(sendArgs(planFile(), tempDir()), { rewrite: on('enrol', (res) => withStatus(res, 201, '{"deviceId":"nope"}')) });
    expect([blank.exit, blank.err]).toEqual([2, 'enrolment failed: POST /auth/devices answered without a device id\n']);
    const garbled = await run(sendArgs(planFile(), tempDir()), { rewrite: on('enrol', (res) => withStatus(res, 201, '<html>')) });
    expect(garbled.err).toBe('enrolment failed: POST /auth/devices answered without a device id\n');
  });
});

describe('a revoke that fails', () => {
  const byHand = (id: string) =>
    [
      `  npm run gk2-import:send -- --revoke ${id} --target '${ORIGIN}' --confirm '${HOST}' --issuer 'https://auth.mindsignals1.com/application/o/fc-coordinator/' --client-id 'fc-coordinator' --redirect-uri 'http://localhost:5173/callback' --prefix '/api'`,
      `  (one more sign-in as the same person: a throwaway key is enrolled, revokes ${id}, then revokes itself)`,
      "or, with write access to the coordinator's database:",
      `  UPDATE device SET revoked_at = now() WHERE id = '${id}' AND revoked_at IS NULL;`,
    ].join('\n');

  it('prints exactly how to revoke the device by hand, and exits 1 even after a good send', async () => {
    const r = await run(sendArgs(planFile(), tempDir()), { fails: (req) => req.label === 'revoke' });
    const id = deviceId(r.out);
    expect(r.exit).toBe(1);
    expect(r.out).toContain(`read-back: all ${EVENTS} keys hold the frozen value`);
    expect(labelled(r.log, 'revoke')).toEqual([]);
    expect(r.err).toBe(`REVOKE FAILED: revoking device ${id} got no answer (connect ECONNRESET). It is still enrolled. Its key lived only in this process and is gone, so nothing can sign as it; revoke it all the same:\n${byHand(id)}\n`);
    expect((await devices(r.userId))[0]!.revoked_at).toBeNull();
  });

  it('tries three times, and says what the coordinator answered', async () => {
    const r = await run(sendArgs(planFile(), tempDir()), { rewrite: on('revoke', (res) => withStatus(res, 503, '{}')) });
    expect(r.exit).toBe(1);
    expect(labelled(r.log, 'revoke')).toHaveLength(3);
    expect(r.err).toContain(`REVOKE FAILED: revoking device ${deviceId(r.out)} answered 503.`);
  });
});

describe('--revoke: the by-hand revoke', () => {
  const enrolDirectly = async (userId: string): Promise<string> => {
    const app = buildCoordinator({ issuer, origin: ORIGIN, devices: createDeviceStore(db.app), sync: db.app, logLines: [] });
    await app.ready();
    try {
      const session = new Session(injectTransport(() => app), { origin: ORIGIN, prefix: '/api' }, await issuer.mint({ sub: userId }), createSafeOutput({ write: () => true }, { write: () => true }));
      return await session.enrol(await generateClientKey(), 'enrol');
    } finally {
      await app.close();
    }
  };

  it('revokes the named device with a throwaway key, then revokes the throwaway', async () => {
    const userId = randomUUID();
    const left = await enrolDirectly(userId);
    const r = await run(['--revoke', left, ...LIVE], { userId });
    expect(r.err).toBe('');
    expect(r.exit).toBe(0);
    const own = /device enrolled: ([0-9a-f-]{36}) \(label gk2-import-revoke\)/.exec(r.out)![1]!;
    expect(r.out).toContain(`device ${left} revoked\n`);
    expect(r.out).toContain(`device ${own} revoked\n`);
    const rows = await devices(userId);
    expect(rows.map((d) => [d.id, d.revoked_at !== null])).toEqual([
      [left, true],
      [own, true],
    ]);
  });

  it('exits 1 for a device that is not this account\'s, and still revokes its own key', async () => {
    const r = await run(['--revoke', randomUUID(), ...LIVE]);
    expect(r.exit).toBe(1);
    expect(r.err).toMatch(/^revoking device [0-9a-f-]{36} answered 404: not this account's device, or no such device\n$/);
    expect((await devices(r.userId)).every((d) => d.revoked_at !== null)).toBe(true);
  });

  it('exits 2 when the sign-in fails, and 2 when the revoke gets no answer', async () => {
    const signIn = await run(['--revoke', randomUUID(), ...LIVE], { signIn: async () => { throw new Error('boom'); } });
    expect([signIn.exit, signIn.err]).toEqual([2, 'sign-in failed: boom\n']);
    const silent = await run(['--revoke', randomUUID(), ...LIVE], { fails: (req) => req.label === 'revoke-target' });
    expect(silent.exit).toBe(2);
    expect(silent.err).toBe('aborted: connect ECONNRESET\n');
  });
});

describe('resume', () => {
  it('refuses a frozen file whose sha256 does not match, has no sidecar, or is not named for its prefix', async () => {
    const dir = tempDir();
    const sent = await run(sendArgs(planFile(), dir));
    expect(sent.exit).toBe(0);
    const file = path.join(dir, 'gk2-t-1.frozen.json');
    writeFileSync(`${file}.sha256`, `${'0'.repeat(64)}  gk2-t-1.frozen.json\n`);
    const bad = await run(['--resume', file, '--send', ...LIVE]);
    expect([bad.exit, bad.err, bad.requests]).toEqual([2, `the frozen file ${file} does not match its ${file}.sha256: refusing to use it\n`, 0]);
    const lone = path.join(tempDir(), 'gk2-t-1.frozen.json');
    writeFileSync(lone, readFileSync(file));
    expect((await run(['--resume', lone, '--send', ...LIVE])).err).toBe(`cannot read ${lone}.sha256: a frozen file is used only with its sha256 line\n`);
    const renamed = path.join(tempDir(), 'other.frozen.json');
    writeFileSync(renamed, readFileSync(file));
    expect((await run(['--resume', renamed, '--send', ...LIVE])).err).toBe(`the frozen file ${renamed} is the batches of gk2-t-1: it must be named gk2-t-1.frozen.json\n`);
    expect((await run(['--resume', '/nowhere.frozen.json'])).err).toBe('cannot read the frozen file: /nowhere.frozen.json\n');
    const garbage = path.join(tempDir(), 'g.frozen.json');
    writeFileSync(garbage, '[]');
    expect((await run(['--resume', garbage])).err).toBe(`frozen file: no batches\n`);
    expect((await run(['--resume', file, '--client-prefix', 'other'])).err).toMatch(/^--client-prefix other is not the frozen file's prefix gk2-t-1\n/);
  });

  it('describes a frozen file offline, sending nothing', async () => {
    const dir = tempDir();
    await run(sendArgs(planFile(), dir));
    const file = path.join(dir, 'gk2-t-1.frozen.json');
    const r = await run(['--resume', file, '--client-prefix', 'gk2-t-1']);
    expect(r.exit).toBe(0);
    expect(r.requests).toBe(0);
    const sha = readFileSync(`${file}.sha256`, 'utf8').split(' ')[0];
    expect(r.out).toContain(`resume: ${file} (2 batches, ${EVENTS} events), its sha256 matches its .sha256: ${sha}`);
    expect(r.out).toMatch(/^device [0-9a-f]{32}$/m);
    expect(r.out).toContain('batches: gk2-t-1-0001 (183 events), gk2-t-1-0002 (65 events)');
    expect(r.out).toMatch(/^requests sent: 0$/m);
  });

  it('refuses to send a batch that never landed from another device, and says how to recover', async () => {
    const dir = tempDir();
    // The first batch lands; the second never leaves.
    const partial = await run(sendArgs(planFile(), dir), { fails: (req) => req.label === 'push:gk2-t-1-0002' });
    expect(partial.exit).toBe(1);
    const file = path.join(dir, 'gk2-t-1.frozen.json');
    const r = await run(['--resume', file, '--send', ...LIVE], { userId: partial.userId });
    expect(r.exit).toBe(1);
    expect(pushes(r.log)).toEqual([]);
    expect(r.err).toMatch(/^pre-check: gk2-t-1-0002 never landed, and its versions name device [0-9a-f]{32}, not this run's: it cannot be sent from here\. Part of .* landed: the rest needs its unsent batches re-minted for a new device, which this tool does not do\. Stop and ask\.\n$/);

    // Nothing landed at all: a fresh send under a new prefix is the way.
    const none = tempDir();
    const unsent = await run(sendArgs(planFile(), none), { fails: (req) => req.label.startsWith('push:') });
    const r2 = await run(['--resume', path.join(none, 'gk2-t-1.frozen.json'), '--send', ...LIVE], { userId: unsent.userId });
    expect(r2.err).toMatch(/^pre-check: gk2-t-1-0001, gk2-t-1-0002 never landed, .* Nothing from .* landed: send it fresh under a new --client-prefix\.\n$/);
  });

  it('refuses a batch that landed in part', async () => {
    const dir = tempDir();
    const sent = await run(sendArgs(planFile(), dir));
    const file = path.join(dir, 'gk2-t-1.frozen.json');
    const one = frozenOf(file)[0]!.events[5]!.facetKey;
    // The pre-check's feed, minus one key of the first batch.
    const r = await run(['--resume', file, '--send', ...LIVE], {
      userId: sent.userId,
      rewrite: on('delta', (res) => {
        const page = fromBinary(DeltaResponseSchema, res.body);
        page.events = page.events.filter((e) => e.facetKey !== one);
        return { ...res, body: toBinary(DeltaResponseSchema, page) };
      }),
    });
    expect(r.exit).toBe(1);
    expect(r.err).toBe('pre-check: gk2-t-1-0001 landed in part: refusing.\n');
  });
});

describe('liveDeps', () => {
  it('writes a new file owner-only and refuses to overwrite it; reads it back; says whether a directory exists', async () => {
    const deps = liveDeps();
    const dir = tempDir();
    const file = path.join(dir, 'x.json');
    await deps.writeNew(file, 'one');
    await expect(deps.writeNew(file, 'two')).rejects.toThrow(/EEXIST/);
    expect(await deps.readFile(file)).toBe('one');
    expect(statSync(file).mode & 0o777).toBe(0o600);
    await deps.writeFile(path.join(dir, 'y.json'), 'z');
    expect(statSync(path.join(dir, 'y.json')).mode & 0o777).toBe(0o600);
    expect(await deps.isDirectory(dir)).toBe(true);
    expect(await deps.isDirectory(file)).toBe(false);
    expect(await deps.isDirectory(path.join(dir, 'none'))).toBe(false);
    expect(deps.transport.count).toBe(0);
    await deps.sleep(1);
    expect(deps.now()).toBeGreaterThan(0);
  });
});
