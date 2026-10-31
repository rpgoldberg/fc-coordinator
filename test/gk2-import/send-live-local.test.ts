// The GK2 sender end to end against a LOCAL coordinator: the real buildApp on a loopback socket,
// Postgres (Testcontainers) behind the device table and SyncService, the client's real fetch
// transport, and the real browser sign-in (authorization code + PKCE through the loopback
// listener) against a fake Authentik on 127.0.0.1. Nothing here reaches beyond 127.0.0.1.
//
// It sends a small plan, sends it again from the frozen file (every event DUPLICATE, nothing
// written twice), refuses a different freeze under the same prefix, and checks every device it
// enrolled is revoked and that no secret was ever printed.
import { createHash, randomUUID } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { FastifyInstance } from 'fastify';
import { calculateJwkThumbprint, exportJWK, generateKeyPair, type JWK } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createDeviceStore } from '../../src/auth/plugin.js';
import type { ClientKey } from '../../scripts/phase2-client/dpop.js';
import { createFetchTransport } from '../../scripts/phase2-client/transport.js';
import { main as buildOffline } from '../../scripts/gk2-import/main.js';
import { liveDeps, main, signInAsPerson } from '../../scripts/gk2-import/send.js';
import { makeIssuer, type TestIssuer } from '../helpers/auth.js';
import { startFakeOidcProvider, signInLikeABrowser, type FakeOidcProvider } from '../helpers/fakeOidcProvider.js';
import { CLIENT_ID, buildCoordinator, freePort, recording, type Exchanged } from '../helpers/phase2Harness.js';
import { leaks } from '../helpers/phase2Run.js';
import { startSyncDatabase, type SyncDatabase } from '../helpers/syncDatabase.js';

const NS = '7d0c1d9e-5a43-4c52-9d4f-6f2a4b8f1c07';
const HEAD = '3907070b-50f1-4f99-b912-6d63db4bf805';
const NOTE = 'PRIVATE-NOTE-TEXT';
const LABEL = 'PRIVATE-LABEL-NAME';
const PLAN = {
  namespace: NS,
  entries: [
    { line: 'owned-1', kind: 'matched', status: 'owned', headId: HEAD, copies: 60, links: ['https://store.example/p/1'], tags: ['Licensed PVCs'], note: NOTE },
    { line: 'owned-2', kind: 'text', status: 'owned', copies: 30, label: { name: LABEL, maker: 'Studio' }, links: [], tags: ['Unlicensed Resins'] },
    { line: 'sold-1', kind: 'matched', status: 'former', headId: HEAD, copies: 1, links: [], tags: ['scammed'], disposal: { reason: 'other', note: 'paid, never received', counterparty: 'Seller' } },
  ],
};

let db: SyncDatabase;
let provider: FakeOidcProvider;
let issuer: TestIssuer | undefined;
let app: FastifyInstance;
let origin: string;
let host: string;
const userId = randomUUID();
const logLines: string[] = [];

beforeAll(async () => {
  db = await startSyncDatabase();
  provider = await startFakeOidcProvider({
    clientId: CLIENT_ID,
    mintAccessToken: () => issuer!.mint({ sub: userId }, { expiresIn: '10m' }),
    mintIdToken: () => issuer!.mint({ sub: userId, preferred_username: 'gk2-send-test' }),
  });
  issuer = await makeIssuer({ issuer: provider.issuer, audience: CLIENT_ID });
  const port = await freePort();
  origin = `http://localhost:${port}`;
  host = `localhost:${port}`;
  app = buildCoordinator({ issuer, origin, prefix: '/api', devices: createDeviceStore(db.app), sync: db.app, logLines });
  await app.listen({ port, host: 'localhost' });
}, 240_000);

afterAll(async () => {
  await app?.close();
  await provider?.close();
  await db?.close();
});

interface Ran {
  exit: number;
  out: string;
  err: string;
  log: Exchanged[];
  secrets: string[];
}

/** One real `gk2-import:send` run, in process, as the CLI wires it but for the browser and the key. */
async function send(argv: string[]): Promise<Ran> {
  const transport = recording(createFetchTransport(), logLines);
  const out: string[] = [];
  const err: string[] = [];
  const keys: JWK[] = [];
  const exit = await main([...argv, '--target', origin, '--confirm', host, '--issuer', provider.issuer, '--redirect-uri', 'http://127.0.0.1:0/callback'], {
    ...liveDeps(),
    stdout: { write: (s: string) => out.push(s) },
    stderr: { write: (s: string) => err.push(s) },
    transport,
    signIn: (o, io) => signInAsPerson(transport, o, io, signInLikeABrowser, Date.now),
    // Extractable HERE only, so the test can grep for the private scalar too.
    generateKey: async (): Promise<ClientKey> => {
      const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
      const publicJwk = await exportJWK(publicKey);
      keys.push(await exportJWK(privateKey));
      return { privateKey, publicJwk, jkt: await calculateJwkThumbprint(publicJwk, 'sha256'), alg: 'ES256' };
    },
  });
  const sent = transport.log.flatMap((e) => [e.request.headers['authorization']?.replace(/^DPoP /, ''), e.request.headers['dpop'], e.response?.headers.get('dpop-nonce') ?? undefined]);
  const secrets = [...provider.secrets(), ...sent, ...keys.flatMap((k) => [k.x, k.y, k.d])].filter((v): v is string => typeof v === 'string' && v.length >= 8);
  return { exit, out: out.join(''), err: err.join(''), log: transport.log, secrets: [...new Set(secrets)] };
}

const feedCount = async (): Promise<number> => Number((await db.admin.query<{ n: string }>('SELECT count(*) AS n FROM feed_event WHERE user_id = $1', [userId])).rows[0]!.n);
const devices = async () => (await db.admin.query<{ id: string; label: string; revoked_at: Date | null }>('SELECT id, label, revoked_at FROM device WHERE user_id = $1 ORDER BY enrolled_at', [userId])).rows;
const pushes = (log: Exchanged[]) => log.filter((e) => e.request.label.startsWith('push:'));
const deviceOf = (out: string) => /device enrolled: ([0-9a-f-]{36}) \(label gk2-import\)/.exec(out)![1]!;

describe('gk2-import:send end to end against a local coordinator', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'gk2-send-e2e-'));
  const frozen = path.join(dir, 'gk2-e2e-1.frozen.json');
  let planPath: string;
  let first: Ran;
  let firstFeed: number;

  beforeAll(async () => {
    planPath = path.join(dir, 'plan.json');
    writeFileSync(planPath, JSON.stringify(PLAN));
    first = await send(['--plan', planPath, '--client-prefix', 'gk2-e2e-1', '--send', '--frozen-dir', dir]);
    firstFeed = await feedCount();
  }, 120_000);

  it('signs in through the browser, sends both batches APPLIED, reads them back and exits 0', () => {
    expect(first.err).toMatch(/^sign in: open this URL in a browser on this machine and sign in once\nhttp:\/\/127\.0\.0\.1:\d+\/application\/o\/authorize\/\?/);
    expect(first.exit).toBe(0);
    expect(first.out).toMatch(/^signed in; the access token expires in \d+ s$/m);
    expect(first.out).toContain('push gk2-e2e-1-0001: 185 events: APPLIED 185');
    expect(first.out).toContain('push gk2-e2e-1-0002: 95 events: APPLIED 95');
    expect(first.out).toContain('read-back: all 280 keys hold the frozen value');
    expect(pushes(first.log)).toHaveLength(2);
  });

  it('wrote 280 events to the feed, once each', async () => {
    expect(firstFeed).toBe(280);
    const batches = JSON.parse(readFileSync(frozen, 'utf8')) as { events: unknown[] }[];
    expect(batches.flatMap((b) => b.events)).toHaveLength(280);
  });

  it('re-sends the same frozen file: every event DUPLICATE, nothing written twice', async () => {
    const again = await send(['--resume', frozen, '--send']);
    expect(again.exit).toBe(0);
    expect(again.out).toContain('push gk2-e2e-1-0001: 185 events: DUPLICATE 185');
    expect(again.out).toContain('push gk2-e2e-1-0002: 95 events: DUPLICATE 95');
    expect(again.out).toContain('read-back: all 280 keys hold the frozen value');
    expect(await feedCount()).toBe(firstFeed);
  });

  it('refuses a different frozen file under the same prefix: nothing pushed, nothing written', async () => {
    const elsewhere = mkdtempSync(path.join(tmpdir(), 'gk2-send-e2e-'));
    const other = await send(['--plan', planPath, '--client-prefix', 'gk2-e2e-1', '--send', '--frozen-dir', elsewhere]);
    expect(other.exit).toBe(1);
    expect(other.err).toMatch(/pre-check: 280 of the 280 keys these batches write exist already .*: refusing to send/);
    expect(pushes(other.log)).toEqual([]);
    // The refused freeze wrote no file: only a freeze whose pre-check passes is written.
    expect(() => readFileSync(path.join(elsewhere, 'gk2-e2e-1.frozen.json'))).toThrow(/ENOENT/);
    // Another freeze of the same plan under the same prefix, by gk2-import itself, is not the file that was sent.
    const refrozen = path.join(elsewhere, 'gk2-e2e-1.frozen.json');
    const written: string[] = [];
    expect(
      await buildOffline(['--plan', planPath, '--out', refrozen, '--client-prefix', 'gk2-e2e-1', '--device', '0f3a5c7e9b1d2f4a6c8e0b2d4f6a8c0e', '--at', new Date().toISOString()], {
        stdout: { write: () => true },
        stderr: { write: () => true },
        readFile: (p) => readFile(p, 'utf8'),
        writeFile: async (p, data) => void (writeFileSync(p, data), written.push(data)),
        now: () => new Date(),
      }),
    ).toBe(0);
    writeFileSync(`${refrozen}.sha256`, `${createHash('sha256').update(written[0]!).digest('hex')}  gk2-e2e-1.frozen.json\n`);
    const r = await send(['--resume', refrozen, '--send']);
    expect(r.exit).toBe(1);
    expect(r.err).toContain(`\npre-check: 280 keys hold another value than ${refrozen} froze: it is not the file that was sent. Refusing.\n`);
    expect(pushes(r.log)).toEqual([]);
    expect(await feedCount()).toBe(firstFeed);
  });

  it('revoked every device it enrolled, each labelled gk2-import', async () => {
    const rows = await devices();
    expect(rows).toHaveLength(4);
    expect(rows.map((d) => d.id)).toContain(deviceOf(first.out));
    expect(rows.every((d) => d.label === 'gk2-import' && d.revoked_at !== null)).toBe(true);
  });

  it('never printed a token, a code, a verifier, a proof, a nonce, key material, a note or a label', () => {
    expect(first.secrets.length).toBeGreaterThan(5);
    expect(leaks(first.out + first.err, first.secrets)).toEqual([]);
    expect(first.out + first.err).not.toContain(NOTE);
    expect(first.out + first.err).not.toContain(LABEL);
  });
});
