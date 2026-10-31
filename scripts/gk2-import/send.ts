// `npm run gk2-import:send`: the GK2 import's sender. One person signs in once, in a browser, as
// themselves; a fresh DPoP key is enrolled as device `gk2-import`; the plan is frozen into batches
// whose every version names that device, at the coordinator's own clock; a read-only pre-check of
// the feed refuses to send over anything that exists; the batches are pushed in order; the feed is
// read back; and the device is revoked, always, failure or not.
//
//   npm run gk2-import:send -- --plan plan.json --client-prefix gk2-import-1                # dry run, offline
//   npm run gk2-import:send -- --plan plan.json --client-prefix gk2-import-1 \
//        --target <origin> --confirm <host>                                                # dry run, signed: pre-check only
//   npm run gk2-import:send -- --plan plan.json --client-prefix gk2-import-1 --frozen-dir <dir> \
//        --send --target <origin> --confirm <host>                                         # the send
//   npm run gk2-import:send -- --resume <dir>/gk2-import-1.frozen.json --send --target ... --confirm ...
//   npm run gk2-import:send -- --revoke <device id> --target <origin> --confirm <host>      # by hand
//
// IDEMPOTENCY. A Push's client_id is recorded with the sha256 of its request: the same batch again
// is a replay (APPLIED answers DUPLICATE, nothing is written twice); another batch under a recorded
// client_id is refused INVALID_ARGUMENT, writing nothing. The coordinator has no read of those
// receipts, so this side keeps two guards of its own: the frozen file, written once (exclusively)
// per prefix and directory just before the first Push, and the pre-check, which refuses a fresh
// freeze when any key it writes exists, and a --resume unless every key it finds holds the very
// event that file froze.
//
// SECRETS. The access, id and refresh tokens, the code, the verifier, the DPoP key and every proof
// live in memory only; none is printed or written, and every output line is scrubbed of them as a
// second line of defence. Errors name status and code, never a body. The plan's notes, labels and
// links are a person's private list: only counts, keys and line names are printed.
//
// Exit codes: 0 done (dry run clean; sent, read back whole and revoked); 1 refused or stopped (a
// refused event, the pre-check, a Push answer, the read-back, a revoke that failed); 2 the run
// could not start or was cut off (arguments, files, sign-in, enrolment, an unexpected failure).
import { readFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { create, type DescMessage, type MessageShape } from '@bufbuild/protobuf';
import {
  DeltaRequestSchema,
  DeltaResponseSchema,
  PushOutcome,
  PushRequestSchema,
  PushResponseSchema,
  StatusRequestSchema,
  StatusResponseSchema,
  normaliseDeviceId,
  parseVersion,
} from '@figurecollecting/fc-api-contract';
import { validateRoutePrefix } from '../../src/auth/config.js';
import { generateClientKey, type ClientKey } from '../phase2-client/dpop.js';
import { authorizationUrl, createPkce, discover, exchangeCode, listenForCallback, type TokenSet } from '../phase2-client/login.js';
import { DEFAULT_CLIENT_ID, DEFAULT_ISSUER, DEFAULT_REDIRECT_URI } from '../phase2-client/options.js';
import { createSafeOutput, type SafeOutput, type Sink } from '../phase2-client/output.js';
import { Session, type Target } from '../phase2-client/session.js';
import { createFetchTransport, type Transport } from '../phase2-client/transport.js';
import { buildBatches } from './build.js';
import { existingKeys, readBack, readState, resumeState, type FeedPage, type Held } from './feed.js';
import { FrozenError, freeze, frozenFileName, parseFrozen, refusals, shaSidecar, summaryLines, wireEvents, type Frozen } from './freeze.js';
import { PlanError, parsePlan, type Plan } from './plan.js';

export const DEVICE_LABEL = 'gk2-import';
export const REVOKER_LABEL = 'gk2-import-revoke';
/** The offline dry run's device, as `gk2-import` uses: the validation needs one, nothing sends it. */
const PLACEHOLDER_DEVICE = '00000000000000000000000000000001';
const DEFAULT_PREFIX = '/api';
const DEFAULT_TZ = 'America/Chicago';
const SYNC = '/coordinator.v1.SyncService';
const LOGIN_TIMEOUT_MS = 5 * 60_000;
/** A send needs this much of its 10-minute, refresh-less token left before its first Push. */
const MIN_TOKEN_MS = 120_000;
const ATTEMPTS = 3;
const RETRY_MS = 1_000;
/** Answers a retry may outlast: a proxy's or the coordinator's "try again". */
const RETRYABLE = new Set([502, 503, 504]);
const DELTA_PAGE = 1_000;
const MAX_KEYS_SHOWN = 20;

export const USAGE = `usage: npm run gk2-import:send -- (--plan <plan.json> --client-prefix <name> | --resume <frozen file>) [--dry-run | --send] [options]
       npm run gk2-import:send -- --revoke <device id> --target <origin> --confirm <host> [options]

  --plan <plan.json>        the import plan to freeze and send
  --client-prefix <name>    batch client_ids are <name>-0001, -0002, ...; names the frozen file <name>.frozen.json
  --resume <frozen file>    retry a send from the very file it froze (its .sha256 beside it): landed batches replay as DUPLICATE
  --dry-run                 the default: nothing is sent; with --target and --confirm it signs in and runs the pre-check only
  --send                    send: needs --target, --confirm and, with --plan, --frozen-dir
  --frozen-dir <dir>        where the frozen file, its .sha256 and the read-back report are written (owner-only)
  --tz <IANA zone>          stamped on every write for display (default ${DEFAULT_TZ})
  --target <origin>         the coordinator's public origin
  --confirm <host>          must equal the target's host (and port), typed out again
  --issuer <url>            OIDC issuer (default ${DEFAULT_ISSUER})
  --client-id <id>          OIDC client (default ${DEFAULT_CLIENT_ID})
  --redirect-uri <url>      loopback redirect the sign-in listener serves (default ${DEFAULT_REDIRECT_URI})
  --prefix <path>           the coordinator's route prefix (default ${DEFAULT_PREFIX})
  --revoke <device id>      revoke a device left enrolled: signs in, enrols a throwaway key, revokes the device, then the throwaway
  --help                    this text`;

export interface SignInOptions {
  issuer: string;
  clientId: string;
  redirectUri: URL;
}

export interface SendDeps {
  stdout: Sink;
  stderr: Sink;
  transport: Transport;
  /** One browser sign-in by a person: live, signInAsPerson with the sign-in URL printed. */
  signIn: (o: SignInOptions, io: SafeOutput) => Promise<TokenSet>;
  generateKey: () => Promise<ClientKey>;
  readFile: (path: string) => Promise<string>;
  isDirectory: (path: string) => Promise<boolean>;
  /** Create a file that must not exist yet, owner-only. */
  writeNew: (path: string, data: string) => Promise<void>;
  /** Create or replace a file, owner-only. */
  writeFile: (path: string, data: string) => Promise<void>;
  now: () => number;
  sleep: (ms: number) => Promise<void>;
  /** Aborted by the operator (Ctrl-C): the run stops before its next step, and revokes. */
  signal?: AbortSignal;
}

export function liveDeps(signal?: AbortSignal): SendDeps {
  const transport = createFetchTransport();
  return {
    stdout: process.stdout,
    stderr: process.stderr,
    transport,
    // The URL is printed; the person opens it in a browser on this machine.
    signIn: (o, io) => signInAsPerson(transport, o, io, async () => {}, Date.now),
    generateKey: generateClientKey,
    readFile: (p) => readFile(p, 'utf8'),
    isDirectory: async (p) => {
      try {
        return (await stat(p)).isDirectory();
      } catch {
        return false;
      }
    },
    writeNew: (p, data) => writeFile(p, data, { flag: 'wx', mode: 0o600 }),
    writeFile: (p, data) => writeFile(p, data, { mode: 0o600 }),
    now: Date.now,
    sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
    ...(signal !== undefined ? { signal } : {}),
  };
}

/** The authorization code + PKCE sign-in of scripts/phase2-client/login.ts, with every secret registered. */
export async function signInAsPerson(t: Transport, o: SignInOptions, io: SafeOutput, openBrowser: (url: string) => Promise<void>, now: () => number): Promise<TokenSet> {
  const discovery = await discover(t, o.issuer);
  const pkce = createPkce();
  io.secret(pkce.verifier);
  const listener = await listenForCallback({ redirectUri: o.redirectUri, state: pkce.state, timeoutMs: LOGIN_TIMEOUT_MS });
  let code: string;
  try {
    const url = authorizationUrl(discovery, { clientId: o.clientId, redirectUri: listener.redirectUri, pkce });
    io.err('sign in: open this URL in a browser on this machine and sign in once');
    io.err(url);
    await openBrowser(url);
    code = await listener.code;
  } finally {
    await listener.close();
  }
  io.secret(code);
  const tokens = await exchangeCode(t, discovery, { code, verifier: pkce.verifier, redirectUri: listener.redirectUri, clientId: o.clientId, now });
  io.secret(tokens.accessToken);
  for (const secret of tokens.secrets) io.secret(secret);
  return tokens;
}

class UsageError extends Error {}
/** A refusal or a stop the run explains itself: exit 1. */
class Stop extends Error {}
/** The run could not start: exit 2, nothing was asked of anyone. */
class CannotStart extends Error {}

interface Options {
  mode: 'dry-run' | 'send' | 'revoke';
  help: boolean;
  plan: string | undefined;
  resume: string | undefined;
  clientPrefix: string | undefined;
  frozenDir: string | undefined;
  tz: string;
  /** Set only with a matching --confirm. */
  target: string | undefined;
  confirm: string | undefined;
  issuer: string;
  clientId: string;
  redirectUri: URL;
  prefix: string;
  revoke: string | undefined;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const CLIENT_PREFIX = /^[A-Za-z0-9_-][A-Za-z0-9._-]{0,99}$/;
const TZ = /^[A-Za-z][A-Za-z0-9_+-]*(\/[A-Za-z0-9_+-]+)*$/;
const LOOPBACK = new Set(['127.0.0.1', 'localhost', '[::1]']);

function url(raw: string, flag: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new UsageError(`${flag} must be an absolute URL, got '${raw}'`);
  }
  if (!(parsed.protocol === 'https:' || (parsed.protocol === 'http:' && LOOPBACK.has(parsed.hostname)))) {
    throw new UsageError(`${flag} must be https (http only to loopback), got '${parsed.href}'`);
  }
  return parsed;
}

function parseOptions(argv: string[]): Options {
  let values;
  try {
    ({ values } = parseArgs({
      args: argv,
      strict: true,
      allowPositionals: false,
      options: {
        plan: { type: 'string' },
        resume: { type: 'string' },
        'client-prefix': { type: 'string' },
        'frozen-dir': { type: 'string' },
        tz: { type: 'string' },
        'dry-run': { type: 'boolean' },
        send: { type: 'boolean' },
        target: { type: 'string' },
        confirm: { type: 'string' },
        issuer: { type: 'string' },
        'client-id': { type: 'string' },
        'redirect-uri': { type: 'string' },
        prefix: { type: 'string' },
        revoke: { type: 'string' },
        help: { type: 'boolean' },
      },
    }));
  } catch (error) {
    throw new UsageError((error as Error).message);
  }

  let target: string | undefined;
  if (values.target !== undefined) {
    const parsed = url(values.target, '--target');
    if (parsed.origin !== values.target) throw new UsageError(`--target must be the bare origin '${parsed.origin}' (no path, no trailing slash), got '${values.target}'`);
    target = parsed.origin;
  }
  if (values.confirm !== undefined) {
    if (target === undefined) throw new UsageError('--confirm needs --target: it confirms that target');
    if (values.confirm !== new URL(target).host) throw new UsageError(`--confirm '${values.confirm}' does not match the target host '${new URL(target).host}'`);
  }
  const live = target !== undefined && values.confirm !== undefined;

  const issuer = values.issuer ?? DEFAULT_ISSUER;
  url(issuer, '--issuer');
  const rawRedirect = values['redirect-uri'] ?? DEFAULT_REDIRECT_URI;
  const redirectUri = url(rawRedirect, '--redirect-uri');
  if (redirectUri.protocol !== 'http:' || !(redirectUri.hostname === '127.0.0.1' || redirectUri.hostname === 'localhost')) {
    throw new UsageError(`--redirect-uri must be http on loopback (the listener is on this machine), got '${redirectUri.href}'`);
  }
  if (redirectUri.port === '') throw new UsageError(`--redirect-uri must name its port, got '${rawRedirect}'`);
  let prefix: string;
  try {
    prefix = validateRoutePrefix(values.prefix ?? DEFAULT_PREFIX, '--prefix');
  } catch (error) {
    throw new UsageError((error as Error).message);
  }
  const tz = values.tz ?? DEFAULT_TZ;
  if (!TZ.test(tz)) throw new UsageError(`--tz must be an IANA zone, got '${tz}'`);

  const common = { help: values.help === true, tz, target: live ? target : undefined, confirm: values.confirm, issuer, clientId: values['client-id'] ?? DEFAULT_CLIENT_ID, redirectUri, prefix };

  if (values.revoke !== undefined) {
    if (values.plan !== undefined || values.resume !== undefined || values.send === true || values['dry-run'] === true) throw new UsageError('--revoke takes no --plan, --resume, --send or --dry-run');
    if (!UUID.test(values.revoke)) throw new UsageError('--revoke needs a device id (a uuid)');
    if (!live) throw new UsageError('--revoke needs --target <origin> and --confirm <host>');
    return { ...common, mode: 'revoke', plan: undefined, resume: undefined, clientPrefix: undefined, frozenDir: undefined, revoke: values.revoke };
  }
  if (values['dry-run'] === true && values.send === true) throw new UsageError('--dry-run and --send contradict each other');
  if ((values.plan === undefined) === (values.resume === undefined)) {
    if (values.help === true) return { ...common, mode: 'dry-run', plan: undefined, resume: undefined, clientPrefix: undefined, frozenDir: undefined, revoke: undefined };
    throw new UsageError('give one of --plan <plan.json> or --resume <frozen file>');
  }
  const clientPrefix = values['client-prefix'];
  if (clientPrefix !== undefined && !CLIENT_PREFIX.test(clientPrefix)) throw new UsageError('--client-prefix must be 1 to 100 letters, digits and . _ -, not starting with a dot');
  if (values.plan !== undefined && clientPrefix === undefined) throw new UsageError('--plan needs --client-prefix <name>');
  if (values.resume !== undefined && values['frozen-dir'] !== undefined) throw new UsageError('--resume writes next to its frozen file: no --frozen-dir');
  const mode = values.send === true ? 'send' : 'dry-run';
  if (mode === 'send' && !live) throw new UsageError('--send needs --target <origin> and --confirm <host>');
  if (mode === 'send' && values.plan !== undefined && values['frozen-dir'] === undefined) throw new UsageError('--send --plan needs --frozen-dir <dir>');
  return { ...common, mode, plan: values.plan, resume: values.resume, clientPrefix, frozenDir: values['frozen-dir'], revoke: undefined };
}

/** What a run sends: a plan to freeze after enrolment, or a frozen file to retry. */
type Source = { kind: 'plan'; plan: Plan; dir: string | undefined } | { kind: 'frozen'; frozen: Frozen; file: string };

async function load(o: Options, deps: SendDeps): Promise<Source> {
  if (o.plan !== undefined) {
    let raw: string;
    try {
      raw = await deps.readFile(o.plan);
    } catch {
      throw new CannotStart(`cannot read the plan: ${o.plan}`);
    }
    let plan: Plan;
    try {
      plan = parsePlan(JSON.parse(raw));
    } catch (err) {
      throw new CannotStart(err instanceof PlanError ? `plan: ${err.message}` : 'the plan is not JSON');
    }
    if (o.mode === 'send') {
      const dir = o.frozenDir!;
      if (!(await deps.isDirectory(dir))) throw new CannotStart(`--frozen-dir ${dir} is not a directory`);
      const file = path.join(dir, frozenFileName(o.clientPrefix!));
      if (await deps.readFile(file).then(() => true, () => false)) {
        throw new CannotStart(`the frozen file ${file} exists: a send under ${o.clientPrefix} was frozen already. Retry it with --resume ${file}, or choose another --client-prefix`);
      }
    }
    return { kind: 'plan', plan, dir: o.frozenDir };
  }

  const file = o.resume!;
  let text: string;
  try {
    text = await deps.readFile(file);
  } catch {
    throw new CannotStart(`cannot read the frozen file: ${file}`);
  }
  let frozen: Frozen;
  try {
    frozen = parseFrozen(text);
  } catch (err) {
    throw new CannotStart(`frozen file: ${(err as FrozenError).message}`);
  }
  if (o.clientPrefix !== undefined && o.clientPrefix !== frozen.prefix) throw new CannotStart(`--client-prefix ${o.clientPrefix} is not the frozen file's prefix ${frozen.prefix}`);
  const name = frozenFileName(frozen.prefix);
  if (path.basename(file) !== name) throw new CannotStart(`the frozen file ${file} is the batches of ${frozen.prefix}: it must be named ${name}`);
  let sidecar: string;
  try {
    sidecar = await deps.readFile(`${file}.sha256`);
  } catch {
    throw new CannotStart(`cannot read ${file}.sha256: a frozen file is used only with its sha256 line`);
  }
  if (sidecar !== shaSidecar(frozen.sha256, name)) throw new CannotStart(`the frozen file ${file} does not match its ${file}.sha256: refusing to use it`);
  return { kind: 'frozen', frozen, file };
}

const batchList = (f: Frozen | { batches: { clientId: string; events: unknown[] }[] }): string =>
  `batches: ${f.batches.map((b) => `${b.clientId} (${b.events.length} events)`).join(', ')}`;
const familyCounts = (counts: Record<string, number>): string =>
  Object.entries(counts)
    .map(([f, n]) => `${f} ${n}`)
    .join(', ');

export async function main(argv: string[], deps: SendDeps): Promise<number> {
  const io = createSafeOutput(deps.stdout, deps.stderr);
  let o: Options;
  try {
    o = parseOptions(argv);
  } catch (error) {
    io.err((error as Error).message);
    io.err(USAGE);
    return 2;
  }
  if (o.help) {
    io.out(USAGE);
    return 0;
  }
  if (o.mode === 'revoke') return revokeByHand(o, deps, io);

  let source: Source;
  try {
    source = await load(o, deps);
  } catch (error) {
    io.err((error as Error).message);
    return 2;
  }
  if (o.target === undefined) return offline(o, source, io, deps);
  return online(o, source, deps, io);
}

/** The offline dry run: no sign-in, no request, nothing written. */
function offline(o: Options, source: Source, io: SafeOutput, deps: SendDeps): number {
  io.out('DRY RUN: nothing is signed in and nothing is sent.');
  if (source.kind === 'frozen') {
    const f = source.frozen;
    io.out(`resume: ${source.file} (${f.batches.length} batches, ${f.events} events), its sha256 matches its .sha256: ${f.sha256}`);
    io.out(`device ${f.deviceHex}`);
    io.out(batchList(f));
    io.out(`requests sent: ${deps.transport.count}`);
    return 0;
  }
  const at = new Date(deps.now());
  const opts = { deviceHex: PLACEHOLDER_DEVICE, at, tz: o.tz, clientPrefix: o.clientPrefix! };
  let built;
  try {
    built = buildBatches(source.plan, opts);
  } catch (err) {
    io.err((err as Error).message);
    return 2;
  }
  const refused = refusals(built, { deviceHex: PLACEHOLDER_DEVICE, nowMicros: BigInt(at.getTime()) * 1000n });
  for (const line of summaryLines(source.plan, built)) io.out(line);
  if (refused.length > 0) {
    reportRefused(refused, io);
    return 1;
  }
  io.out("every event is accepted by the coordinator's Push validation");
  io.out(batchList(built));
  io.out(
    'a send (--send --target <origin> --confirm <host> --frozen-dir <dir>) signs in once as the collector, enrols a DPoP key as device gk2-import, freezes these batches with its id at the coordinator\'s clock, pre-checks the feed, pushes them in order, reads them back and revokes the device',
  );
  io.out(`requests sent: ${deps.transport.count}`);
  return 0;
}

function reportRefused(refused: string[], io: SafeOutput): void {
  io.err(`${refused.length} events would be refused by the coordinator:`);
  for (const line of refused.slice(0, MAX_KEYS_SHOWN)) io.err(`  ${line}`);
}

interface Signed {
  session: Session;
  key: ClientKey;
  deviceId: string;
  tokens: TokenSet;
}

/** Sign in, then enrol a fresh key under `label`. Undefined, said why, when either fails: nothing to revoke. */
async function signInAndEnrol(o: Options, deps: SendDeps, io: SafeOutput, label: string): Promise<Signed | undefined> {
  let tokens: TokenSet;
  try {
    tokens = await deps.signIn({ issuer: o.issuer, clientId: o.clientId, redirectUri: o.redirectUri }, io);
  } catch (error) {
    io.err(`sign-in failed: ${(error as Error).message}`);
    return undefined;
  }
  io.secret(tokens.accessToken);
  const target: Target = { origin: o.target!, prefix: o.prefix };
  const session = new Session(deps.transport, target, tokens.accessToken, io);
  io.out(`signed in; the access token expires in ${Math.round((tokens.expiresAt - deps.now()) / 1000)} s`);
  const key = await deps.generateKey();
  io.secret(key.publicJwk.x);
  io.secret(key.publicJwk.y);
  io.secret(key.jkt);
  let deviceId: string;
  try {
    const res = await session.callRetrying({ label: 'enrol', method: 'POST', path: '/auth/devices', key, body: JSON.stringify({ label }), contentType: 'application/json' });
    if (res.status !== 201 && res.status !== 200) throw new Error(`POST /auth/devices answered ${res.status}`);
    let id: unknown;
    try {
      id = (JSON.parse(new TextDecoder().decode(res.body)) as { deviceId?: unknown }).deviceId;
    } catch {
      id = undefined;
    }
    if (typeof id !== 'string' || !UUID.test(id)) throw new Error('POST /auth/devices answered without a device id');
    deviceId = id;
  } catch (error) {
    io.err(`enrolment failed: ${(error as Error).message}`);
    return undefined;
  }
  io.out(`device enrolled: ${deviceId} (label ${label})`);
  return { session, key, deviceId, tokens };
}

const quote = (v: string): string => `'${v.replaceAll("'", `'\\''`)}'`;

/** Revoke the run's own device; on failure print exactly how to do it by hand. True when revoked. */
async function revokeOwn(o: Options, s: Signed, deps: SendDeps, io: SafeOutput): Promise<boolean> {
  let why = '';
  for (let attempt = 1; attempt <= ATTEMPTS; attempt += 1) {
    try {
      const res = await s.session.revoke(s.key, s.deviceId, 'revoke');
      if (res.status === 200) {
        io.out(`device ${s.deviceId} revoked`);
        return true;
      }
      why = `answered ${res.status}`;
    } catch (error) {
      why = `got no answer (${(error as Error).message})`;
    }
    if (attempt < ATTEMPTS) await deps.sleep(RETRY_MS * attempt);
  }
  io.err(`REVOKE FAILED: revoking device ${s.deviceId} ${why}. It is still enrolled. Its key lived only in this process and is gone, so nothing can sign as it; revoke it all the same:`);
  const flags = [
    ['--target', o.target!],
    ['--confirm', o.confirm!],
    ['--issuer', o.issuer],
    ['--client-id', o.clientId],
    ['--redirect-uri', o.redirectUri.href],
    ['--prefix', o.prefix],
  ];
  io.err(`  npm run gk2-import:send -- --revoke ${s.deviceId} ${flags.map(([f, v]) => `${f} ${quote(v!)}`).join(' ')}`);
  io.err(`  (one more sign-in as the same person: a throwaway key is enrolled, revokes ${s.deviceId}, then revokes itself)`);
  io.err("or, with write access to the coordinator's database:");
  io.err(`  UPDATE device SET revoked_at = now() WHERE id = '${s.deviceId}' AND revoked_at IS NULL;`);
  return false;
}

async function revokeByHand(o: Options, deps: SendDeps, io: SafeOutput): Promise<number> {
  const signed = await signInAndEnrol(o, deps, io, REVOKER_LABEL);
  if (signed === undefined) {
    io.out(`requests sent: ${deps.transport.count}`);
    return 2;
  }
  let code = 2;
  try {
    const res = await signed.session.revoke(signed.key, o.revoke!, 'revoke-target');
    if (res.status === 200) {
      io.out(`device ${o.revoke} revoked`);
      code = 0;
    } else {
      io.err(`revoking device ${o.revoke} answered ${res.status}${res.status === 404 ? ": not this account's device, or no such device" : ''}`);
      code = 1;
    }
  } catch (error) {
    io.err(`aborted: ${(error as Error).message}`);
    code = 2;
  } finally {
    if (!(await revokeOwn(o, signed, deps, io))) code = Math.max(code, 1);
  }
  io.out(`requests sent: ${deps.transport.count}`);
  return code;
}

async function online(o: Options, source: Source, deps: SendDeps, io: SafeOutput): Promise<number> {
  const signed = await signInAndEnrol(o, deps, io, DEVICE_LABEL);
  if (signed === undefined) {
    io.out(`requests sent: ${deps.transport.count}`);
    return 2;
  }
  let code = 2;
  try {
    code = await sendFrozen(o, source, signed, deps, io);
  } catch (error) {
    if (error instanceof Stop) {
      io.err(error.message);
      code = 1;
    } else {
      io.err(`aborted: ${(error as Error).message}`);
      code = 2;
    }
  } finally {
    // Always: a failure above must not leave the device enrolled.
    if (!(await revokeOwn(o, signed, deps, io))) code = Math.max(code, 1);
  }
  io.out(`requests sent: ${deps.transport.count}`);
  return code;
}

/** One RPC, retried on no answer or a retryable status, stopped on anything else. */
async function rpc<I extends DescMessage, O extends DescMessage>(
  s: Signed,
  deps: SendDeps,
  io: SafeOutput,
  call: { what: string; label: string; method: string; input: I; output: O; message: MessageShape<I>; push?: boolean },
): Promise<MessageShape<O>> {
  const again = call.push === true ? 'retrying with the same client_id' : 'retrying';
  for (let attempt = 1; ; attempt += 1) {
    if (deps.signal?.aborted === true) throw new Stop('interrupted: nothing more is sent');
    let problem: string;
    try {
      const res = await s.session.unary(s.key, `${SYNC}/${call.method}`, call.input, call.output, call.message, call.label);
      if (res.ok) return res.message;
      const named = `${res.status}${res.code === '' ? '' : ` ${res.code}`}`;
      if (!RETRYABLE.has(res.status)) {
        const hint = call.push === true && res.code === 'invalid_argument' ? '. (Push answers this way for a client_id it recorded for a different batch, and writes nothing.)' : '';
        throw new Stop(`${call.what} answered ${named}: stopped, nothing more is sent${hint}`);
      }
      problem = `answered ${named}`;
    } catch (error) {
      if (error instanceof Stop) throw error;
      problem = `no answer (${(error as Error).message})`;
    }
    if (attempt === ATTEMPTS) {
      const label = problem.startsWith('no answer') ? 'no answer' : problem;
      throw new Stop(`${call.what}: ${label} after ${ATTEMPTS} attempts: stopped, nothing more is sent${call.push === true ? '. Retry with --resume <the frozen file>.' : ''}`);
    }
    io.err(`${call.what}: ${problem}; ${again} (attempt ${attempt + 1} of ${ATTEMPTS})`);
    await deps.sleep(RETRY_MS * attempt);
  }
}

const outcomeName = (outcome: PushOutcome): string => PushOutcome[outcome] ?? `outcome ${outcome}`;

async function sendFrozen(o: Options, source: Source, s: Signed, deps: SendDeps, io: SafeOutput): Promise<number> {
  const status = await rpc(s, deps, io, { what: 'Status', label: 'status', method: 'Status', input: StatusRequestSchema, output: StatusResponseSchema, message: create(StatusRequestSchema, {}) });
  // The coordinator's clock, not this machine's: a version past its now + 5 minutes is refused.
  const serverNow = status.serverNowIso;
  io.out(`clock: ${serverNow} (the coordinator's)`);
  const deviceHex = normaliseDeviceId(s.deviceId);

  let frozen: Frozen;
  let file: string | undefined;
  if (source.kind === 'plan') {
    const at = new Date(serverNow);
    const opts = { deviceHex, at, tz: o.tz, clientPrefix: o.clientPrefix! };
    const built = buildBatches(source.plan, opts);
    const refused = refusals(built, { deviceHex, nowMicros: parseVersion(serverNow)!.micros });
    if (refused.length > 0) {
      reportRefused(refused, io);
      return 1;
    }
    frozen = freeze(built, opts);
    io.out(`freeze: ${frozen.batches.length} batches (${frozen.events} events), sha256 ${frozen.sha256}`);
    if (o.mode === 'send') file = path.join(source.dir!, frozenFileName(frozen.prefix));
  } else {
    frozen = source.frozen;
    file = source.file;
    io.out(`resume: ${file} (${frozen.batches.length} batches, ${frozen.events} events), its sha256 matches its .sha256: ${frozen.sha256}`);
  }

  // PRE-CHECK, read-only: the feed as the app reads it, folded for these keys.
  const keys = new Set(frozen.batches.flatMap((b) => b.events.map((e) => e.facetKey)));
  const pull = async (cursor: string): Promise<FeedPage> =>
    rpc(s, deps, io, { what: 'Delta', label: 'delta', method: 'Delta', input: DeltaRequestSchema, output: DeltaResponseSchema, message: create(DeltaRequestSchema, { cursor, limit: DELTA_PAGE }) });
  const pre = await readState(pull, keys, '');
  const read = `pre-check: read ${pre.pages} pages of the feed`;
  if (source.kind === 'plan') {
    const existing = existingKeys(frozen.batches, pre.state);
    if (existing.total > 0) {
      throw new Stop(`pre-check: ${existing.total} of the ${keys.size} keys these batches write exist already (${familyCounts(existing.byFamily)}): refusing to send. A retry of a send is --resume <the frozen file it wrote>.`);
    }
    io.out(`${read}; none of the ${keys.size} keys exists`);
  } else {
    checkResume(frozen, source.file, pre.state, deviceHex);
    const landed = resumeState(frozen.batches, pre.state).batches.filter((b) => b === 'landed').length;
    io.out(`${read}; ${landed} batches landed already and replay as DUPLICATE, ${frozen.batches.length - landed} unsent`);
  }
  if (o.mode === 'dry-run') {
    io.out('dry run: nothing written, nothing pushed');
    return 0;
  }

  // The token lives 10 minutes with no refresh: refuse before the file that commits this prefix.
  const left = s.tokens.expiresAt - deps.now();
  if (left < MIN_TOKEN_MS) throw new Stop(`the sign-in has ${Math.round(left / 1000)} s left, under the ${MIN_TOKEN_MS / 1000} s a send needs: nothing pushed. Run it again.`);
  if (source.kind === 'plan') {
    // Written once, exclusively, now that a push follows: from here on a retry is --resume.
    await deps.writeNew(file!, frozen.text);
    await deps.writeNew(`${file!}.sha256`, shaSidecar(frozen.sha256, path.basename(file!)));
    io.out(`frozen: ${file} and its .sha256`);
  }

  for (const batch of frozen.batches) {
    const what = `push ${batch.clientId}`;
    const answer = await rpc(s, deps, io, {
      what,
      label: `push:${batch.clientId}`,
      method: 'Push',
      input: PushRequestSchema,
      output: PushResponseSchema,
      message: create(PushRequestSchema, { clientId: batch.clientId, events: wireEvents(batch) }),
      push: true,
    });
    const counts = new Map<string, number>();
    for (const r of answer.results) counts.set(outcomeName(r.outcome), (counts.get(outcomeName(r.outcome)) ?? 0) + 1);
    const tally = [...counts].map(([name, n]) => `${name} ${n}`).join(', ');
    const landed = (r: { outcome: PushOutcome }) => r.outcome === PushOutcome.APPLIED || r.outcome === PushOutcome.DUPLICATE;
    const echoed = answer.results.length === batch.events.length && answer.results.every((r, i) => r.facetKey === batch.events[i]!.facetKey);
    if (answer.results.length === batch.events.length && answer.results.every(landed) && echoed) {
      io.out(`${what}: ${batch.events.length} events: ${tally}`);
      continue;
    }
    const head = `${what}: ${batch.events.length} events, ${answer.results.length} results: stopped: `;
    const bad = answer.results.filter((r) => !landed(r));
    if (bad.length === 0 && answer.results.length === batch.events.length) {
      throw new Stop(`${head}the results do not echo the events' keys in order`);
    }
    io.err(`${head}${tally}`);
    for (const r of bad.slice(0, MAX_KEYS_SHOWN)) io.err(`  ${r.facetKey}: ${`${outcomeName(r.outcome)} ${r.reason.split(':')[0]}`.trimEnd()}`);
    if (bad.length > MAX_KEYS_SHOWN) io.err(`  ... and ${bad.length - MAX_KEYS_SHOWN} more`);
    throw new Stop('nothing more is sent');
  }

  // READ-BACK, before the revoke: a revoked device can no longer read.
  const after = await readState(pull, keys, pre.cursor, pre.state);
  const result = readBack(frozen.batches, after.state);
  const report = path.join(path.dirname(file!), `${frozen.prefix}.readback.json`);
  await deps.writeFile(
    report,
    `${JSON.stringify({ clientPrefix: frozen.prefix, deviceId: s.deviceId, frozen: file, frozenSha256: frozen.sha256, ok: result.ok, byFamily: result.byFamily, keys: result.keys }, null, 1)}\n`,
  );
  const families = Object.entries(result.byFamily).map(([family, verdicts]) => `${family} ${Object.entries(verdicts).map(([v, n]) => `${v} ${n}`).join(' ')}`);
  io.out(`read-back: ${families.join(', ')}`);
  const off = result.keys.filter((k) => k.verdict !== 'MATCH').length;
  if (off === 0) {
    io.out(`read-back: all ${result.keys.length} keys hold the frozen value; report ${report}`);
    return 0;
  }
  io.err(`read-back: ${off} of the ${result.keys.length} keys do not hold the frozen value; report ${report}`);
  return 1;
}

/** A retry may only replay what landed: refuse a file the coordinator's keys do not bear out. */
function checkResume(frozen: Frozen, file: string, state: ReadonlyMap<string, Held>, deviceHex: string): void {
  const r = resumeState(frozen.batches, state);
  if (r.foreign > 0) throw new Stop(`pre-check: ${r.foreign} keys hold another value than ${file} froze: it is not the file that was sent. Refusing.`);
  const mixed = frozen.batches.filter((_, i) => r.batches[i] === 'mixed').map((b) => b.clientId);
  if (mixed.length > 0) throw new Stop(`pre-check: ${mixed.join(', ')} landed in part: refusing.`);
  const unsent = frozen.batches.filter((_, i) => r.batches[i] === 'unsent').map((b) => b.clientId);
  if (unsent.length > 0 && frozen.deviceHex !== deviceHex) {
    const which = unsent.length === 1 ? 'its versions name' : 'their versions name';
    const next =
      unsent.length === frozen.batches.length
        ? `Nothing from ${file} landed: send it fresh under a new --client-prefix.`
        : `Part of ${file} landed: the rest needs its unsent batches re-minted for a new device, which this tool does not do. Stop and ask.`;
    throw new Stop(`pre-check: ${unsent.join(', ')} never landed, and ${which} device ${frozen.deviceHex}, not this run's: it cannot be sent from here. ${next}`);
  }
}
