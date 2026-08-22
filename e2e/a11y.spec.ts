import { expect, test } from '@playwright/test';
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  reportCollected,
  watchPageErrors,
} from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven along everything it teaches: the arrival state, where
 * Measured Boot sits at step 0 with four registers at their reset values and
 * the other five tabpanels are hidden and UNRENDERED; the shared skip link
 * focused; the boot stepper at its first extension, at its end, stepped back
 * and reset; one measured byte edited so the diverged-register alarm renders,
 * and reverted; all three boot disclosures open including two scrollable
 * tables; the honest quote appraising clean, its TPMS_ATTEST byte map, its EAT
 * and its RATS role table; a fresh challenge; a restricted attestation key
 * refusing to sign a hand-built structure and then, with one attribute bit
 * cleared, signing it; the same key signing a blob with no magic; every
 * rejection scenario with its failure code, its diverged register and its
 * named stage; the time-of-use climax in its ATTESTED — AND COMPROMISED state;
 * both Act 7b branches including the only NOT RUN check row in the lab and the
 * credential-activation trace; the THREAT-1 hostile-anchor fixture; three
 * hover states; two focus rings; and a focused scroll region. Every one of
 * those states is scanned, at desktop and phone width.
 *
 * See `gate.ts` for why nothing is injected into the page, why no panel is
 * revealed from script, why the lab's defaults are asserted rather than
 * assumed, and why `violations` is not the whole oracle.
 */

const THEME = 'dark' as const;

test(`no WCAG A/AA violations in ${THEME} theme`, async ({ page }) => {
  test.setTimeout(1_800_000);
  const errors = watchPageErrors(page);
  await boot(page, THEME);
  await driveAllStates(page, THEME);
  expect(errors, errors.join('\n')).toEqual([]);
  expectBaselineNotStale();
  reportCollected();
});

test(`no WCAG A/AA violations in ${THEME} theme at 380px`, async ({ page }) => {
  test.setTimeout(1_800_000);
  const errors = watchPageErrors(page);
  await page.setViewportSize(NARROW);
  await boot(page, THEME);
  await driveAllStates(page, `${THEME} @380px`);
  expect(errors, errors.join('\n')).toEqual([]);
  expectBaselineNotStale();
  reportCollected();
});
