import { defineConfig, configDefaults } from 'vitest/config';

// base must match the GitHub Pages project subpath:
// https://systemslibrarian.github.io/crypto-lab-attestation-gate/
export default defineConfig({
  base: '/crypto-lab-attestation-gate/',
  test: {
    // Colocated unit tests only; keep the Playwright specs in e2e/ out of the
    // Vitest run so they are never collected as unit tests.
    include: ['src/**/*.test.ts'],
    exclude: [...configDefaults.exclude, 'e2e/**'],
    // Vitest's default per-test budget is 5 seconds, and several of the
    // BLS12-381 pairing tests in `src/daa` legitimately run for 1-5 seconds of
    // real arithmetic. On a loaded machine — a CI runner, or the mutation
    // harness building between runs — they cross that line and the suite goes
    // red on a WALL CLOCK rather than on anything it asserts. Observed here:
    // the whole suite is 7.4s and clean when nothing else is running, and the
    // same unmutated suite failed three of five mutation-harness invocations
    // with `Test timed out in 5000ms` on `src/daa/attestation.test.ts`.
    //
    // A timeout is a limit, not a measurement, and raising one weakens no
    // assertion: every test still checks exactly what it checked. What it
    // removes is a red run that names the wrong subject — the shape this
    // fleet's own notes warn about, where an unrelated budget is reported as a
    // defect in the thing under test. 30 seconds is still far short of a hang.
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
});
