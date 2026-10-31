// `npm run gk2-import:send -- ...`: argv in, exit code out. Every decision is in send.ts, which is covered.
import { liveDeps, main } from './send.js';

// The frozen file, its sha256 and the read-back report are a person's private list: owner-only.
process.umask(0o077);
// The first Ctrl-C stops the run before its next step and still revokes the device; a second one
// is Node's default and exits at once.
const interrupt = new AbortController();
process.once('SIGINT', () => {
  process.stderr.write('interrupted: stopping before the next step; the device is revoked before exit (Ctrl-C again to quit at once)\n');
  interrupt.abort();
});
process.exitCode = await main(process.argv.slice(2), liveDeps(interrupt.signal));
