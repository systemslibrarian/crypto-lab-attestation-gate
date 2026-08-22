import { defineConfig, devices } from '@playwright/test';

/**
 * E2E runs against the production build served by `vite preview`, so what
 * passes here is what ships. Two kinds of tests:
 *   - a11y.spec.ts   — the axe WCAG gate, Chromium only (deterministic gate).
 *   - claims.spec.ts — the claims suite: does the page tell the truth?
 *     Run across Chromium, Firefox, WebKit and a mobile viewport.
 *
 * Port 4687 is unique to this lab across the fleet (never the Vite default
 * 4173 — with 170+ labs side by side, a shared port means reuseExistingServer
 * silently scans a different lab's preview).
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  timeout: 120_000, // the axe driver walks every panel and disclosure before scanning
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: 'http://localhost:4687/crypto-lab-attestation-gate/',
  },
  projects: [
    {
      name: 'a11y',
      testMatch: /a11y\.spec\.ts/,
      // Dark is the only theme this lab ships.
      use: { ...devices['Desktop Chrome'], colorScheme: 'dark' },
    },
    { name: 'claims', testMatch: /claims\.spec\.ts/, use: { ...devices['Desktop Chrome'] } },
    { name: 'claims-firefox', testMatch: /claims\.spec\.ts/, use: { ...devices['Desktop Firefox'] } },
    { name: 'claims-webkit', testMatch: /claims\.spec\.ts/, use: { ...devices['Desktop Safari'] } },
    { name: 'claims-mobile', testMatch: /claims\.spec\.ts/, use: { ...devices['Pixel 5'] } },
  ],
  webServer: {
    // Build before serving: `vite preview` only serves whatever is already in
    // dist/, so without this a failing build leaves the previous good bundle
    // in place and the suite passes green against code that no longer
    // compiles.
    command: 'npm run build && npm run preview -- --port 4687 --strictPort',
    url: 'http://localhost:4687/crypto-lab-attestation-gate/',
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
