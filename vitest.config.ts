import { defineConfig } from 'vitest/config';

// Coverage gate is enforced HERE, not only in CI: `npm run test:coverage`
// fails locally on the same thresholds the workflow uses, so a red bar is
// found before the push rather than after it (estate standard: 85% line AND
// branch on affected code).
export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts', 'test/**/*.test.ts'],
    exclude: ['node_modules', 'dist'],
    // Testcontainers pulls and boots a real postgres:17 image on first run.
    testTimeout: 120_000,
    hookTimeout: 240_000,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      // scripts/ holds the Phase-2 client (WK-11): an operator tool, never in the image, held to
      // the same per-file gate as the service.
      include: ['src/**/*.ts', 'scripts/**/*.ts'],
      exclude: [
        'src/**/*.test.ts',
        // server.ts is the process entrypoint: listen/SIGTERM wiring with no
        // logic of its own. It is exercised by the image healthcheck, not by
        // a unit test that would have to bind a port to prove `listen` works.
        //
        // THE EXCLUSION IS ONLY HONEST WHILE THAT SENTENCE IS TRUE, and it
        // stopped being true once the entrypoint assembled the mesh JWKS
        // client by hand: deleting the headers there left the whole suite
        // green. The decision moved into `createJwksFor` (src/auth/oidc.ts),
        // which is covered and which both this file and the end-to-end test
        // call. Anything that is a DECISION rather than wiring belongs on the
        // other side of this line.
        'src/server.ts',
        // The Phase-2 client's entrypoint, on the same terms as server.ts: argv in, exit code
        // out, nothing else. Every decision is in main.ts, which is covered; this file is run
        // for real by test/phase2-client/main.test.ts as a child process.
        'scripts/phase2-client/cli.ts',
        // The GK2 import's entrypoint, on the same terms: argv in, exit code out; the decisions are in main.ts.
        'scripts/gk2-import/cli.ts',
        // The GK2 sender's entrypoint, on the same terms: argv in, exit code out; the decisions are in send.ts.
        'scripts/gk2-import/send-cli.ts',
      ],
      thresholds: {
        // PER FILE, not a repo-wide average. The estate standard is 85% on
        // AFFECTED code; a global threshold lets an entirely untested file ship
        // behind well-covered neighbours, and hands out more slack the bigger
        // the repo gets. test/coverage-gate.test.ts proves this bites.
        perFile: true,
        lines: 85,
        branches: 85,
        functions: 85,
        statements: 85,
      },
    },
  },
});
