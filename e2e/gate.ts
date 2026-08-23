import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };
/**
 * A HEADROOM probe, deliberately narrower than the 320 CSS px WCAG 1.4.10 asks
 * for. Scanning AT 320 does not work: this lab shipped a defect whose min-content
 * floor was 318px, so it fit at 320 and failed at 380 only once Linux font metrics
 * in CI inflated it — a single-width check cannot see a floor sitting just under
 * that width. 280 asserts the floor is low enough that no font-metric delta can
 * push it back over 320.
 */
export const REFLOW = { width: 280, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Five rules govern everything here, and each one corrects something the gate
 * this replaces did:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The old spec pushed
 *     `animation:none!important; transition:none!important` through
 *     `addStyleTag`. That BYPASSES this lab's own
 *     `@media (prefers-reduced-motion: reduce)` block instead of exercising it,
 *     so the one rendering a reduced-motion reader actually gets — `.panel` and
 *     `.reveal` with their animations cancelled by the stylesheet's own rule —
 *     was never once the rendering that got scanned. This gate sets the
 *     preference through `emulateMedia`, asserts from inside the page that it
 *     took effect (`test.use({ reducedMotion })` silently does nothing on
 *     Playwright 1.61.1), and injects nothing.
 *
 *  2. IT FORCED EVERY PANEL VISIBLE FROM SCRIPT. The old drive stripped every
 *     `[hidden]` attribute and set every `<details>.open` by JS before its only
 *     scan. Stripping `hidden` puts all six tabpanels on screen AT ONCE — a
 *     rendering no reader can reach and axe then scans instead of the real one
 *     — and script-opening the disclosures means the SHUT state, which is what
 *     every reader arrives at, was never scanned at all. This gate switches
 *     tabs by clicking them and opens each disclosure through its `<summary>`,
 *     which is the route a reader has, and scans before and after.
 *
 *  3. IT DROVE BLIND AND THEN THREW THE STATES AWAY. The old drive clicked
 *     every button whose label matched a regex, swallowed every failure with
 *     `.catch(() => {})`, waited a fixed 120ms per tab, and scanned ONCE at the
 *     end — so the invalid-key rendering, the malformed-hex branch, the
 *     rejected-preset pipeline and the stepper's intermediate reveals were all
 *     overwritten before anything measured them, and a click that silently did
 *     nothing looked identical to one that worked. This drive names every
 *     control it touches, asserts a real completion signal after each, and
 *     scans after every step, in {dark, light} x {1280, 380}.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE. See `scan`. The surfaces that carry
 *     this lab's meaning — every `.verdict-*` tone, both `.pill` states, the
 *     `.callout-danger` / `.callout-caveat` warnings, the `.learner-check`
 *     tint and the shared top bar's `color-mix()` ink — are all `color-mix()`
 *     fills axe files under `incomplete` rather than judging. So is an
 *     `aria-label` on a role-less element.
 *
 *  5. IT HAD NO REFLOW, NON-TEXT-CONTRAST OR GENERATED-CONTENT ORACLE. The old
 *     spec hand-rolled one luminance check over two input selectors, reading
 *     the DECLARED `border-top-color` and `background-color` — blind to
 *     `color-mix()`, to composited backdrops, to every `.btn`, `.seg-btn`,
 *     `.tab-btn` and preset control, and to all states past first paint.
 *     `nontext.ts` replaces it with a measured oracle over every control at
 *     every driven state, and `expectNoHorizontalOverflow` adds the 1.4.10
 *     check axe has no rule for.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Two rAFs are not enough. A transition sampled mid-flight has a colour that
 * exists in no state of the page, and axe will happily report it: elsewhere in
 * this fleet that produced a phantom 2.00:1 failure on a button whose settled
 * ratio is 9:1. Transitions also drain in waves rather than in one batch, so a
 * poll for "nothing running right now" can exit through a gap between waves —
 * hence six consecutive quiet frames rather than one.
 *
 * Bounded three ways, because a gate that can hang is a gate nobody runs:
 * animations that never finish (`iterations: Infinity`) are excluded from the
 * quiescence test rather than waited on, a wall-clock budget inside the page
 * gives up and proceeds, and Playwright's own timeout is the backstop.
 *
 * Under the reduced motion this gate asserts, `style.css`'s reduced-motion
 * block cancels `.panel` / `.reveal` animations and every transition, so
 * `getAnimations()` is normally empty and this returns on the sixth frame. It
 * stays because the shared top bar's `.cl-btn` transitions are declared
 * OUTSIDE the lab's `@media` block — `* { transition: none !important }` wins
 * today, but that is a property of the current stylesheet, not of the page.
 */
export async function settle(page: Page, budgetMs = 4000): Promise<void> {
  await page.waitForFunction(
    (budget: number) => {
      const w = window as unknown as { __quietFrames?: number; __settleStart?: number };
      if (w.__settleStart === undefined) w.__settleStart = performance.now();
      const done = (): boolean => {
        w.__quietFrames = 0;
        w.__settleStart = undefined;
        return true;
      };
      const running = document.getAnimations().filter((a) => {
        if (a.playState !== 'running') return false;
        const timing = a.effect?.getComputedTiming?.();
        // An infinite decorative animation never drains; waiting on it hangs.
        return timing?.iterations !== Infinity;
      });
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      if (w.__quietFrames >= 6) return done();
      if (performance.now() - (w.__settleStart ?? 0) > budget) return done();
      return false;
    },
    budgetMs,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set. This lab
 * has EXACTLY that shape in miniature: `@keyframes fade` and `@keyframes
 * reveal` both start `from { opacity: 0 }`, and every tab panel and every
 * stepper line rides one of them. The reduced-motion block cancels both with
 * `animation: none`, which restores the static `opacity: 1` — correct today,
 * and this assertion is what makes that a measurement rather than a reading.
 *
 * `aria-hidden` subtrees are excluded; what this lab hides is decorative
 * verdict/pill glyphs beside their own words — see `contrast.ts`.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page
 * is created. Every panel here renders synchronously at first activation, so a
 * renderer that throws leaves that tabpanel EMPTY — and an empty region is
 * exactly what a scan reports as perfectly accessible. Attach before `boot`,
 * assert after the drive.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * Exactly one banner landmark.
 *
 * The shared `.cl-topbar` carries an explicit `role="banner"`. This lab's own
 * hero is a `<div class="cl-hero">`, not a `<header>`, so nothing here implies
 * a second banner today — but the shared bar's `dedupeBanner()` exists because
 * other labs in this fleet DID ship one, and the hero markup is the part of
 * this page most likely to be re-templated from a lab that uses `<header>`.
 * Asserting the OUTCOME rather than the markup is what catches that edit.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION']);
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true;
      if (el.tagName !== 'HEADER') return false;
      if (el.getAttribute('role')) return false; // explicit non-banner role wins
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false;
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length;
  });
  expect(banners, 'exactly one banner landmark').toBe(1);
}

/**
 * List semantics survive their styling.
 *
 * This lab's one list is the Verify Workbench pipeline: `ol.stage-list` styled
 * `list-style: none`, which is exactly the declaration that makes Safari and
 * VoiceOver DROP the list's implicit role. `verifyWorkbench.ts` compensates
 * the documented way — an explicit `role="list"` on the `<ol>` and
 * `role="listitem"` on every `.stage` — so here, unlike most of this fleet, an
 * explicit role on a list is the fix rather than the defect. What is asserted
 * is therefore the SHAPE of that fix: any explicit role on a `ul`/`ol` must be
 * `list` (any other value orphans every `<li>` under it), and a `role="list"`
 * must never sit on an empty element, because axe applies
 * `aria-required-children` to the explicit role and fails it the day the
 * pipeline renders with no stages. Roles can be assigned as JS properties in
 * an element-creation helper, so ask the DOM rather than grepping the source.
 */
export async function assertListSemantics(page: Page): Promise<void> {
  const broken = await page.$$eval('ul[role], ol[role]', (els) =>
    els
      .filter((e) => e.getAttribute('role') !== 'list' || e.children.length === 0)
      .map(
        (e) =>
          `${e.tagName.toLowerCase()}[role=${e.getAttribute('role')}] with ${e.children.length} children`
      )
  );
  expect(
    broken,
    'an explicit non-list role on a list deletes its semantics; an empty role="list" fails aria-required-children'
  ).toEqual([]);
}
/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page — including
 * the lab's DEFAULTS, which are never assumed.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.x, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page. Nothing in this lab's JS branches on
 * `matchMedia`, but the CSS reduced-motion block is the only thing standing
 * between a scan and the mid-flight `.panel` fade opacity, so the assertion is
 * still the difference between scanning the reduced-motion rendering and
 * merely believing we did.
 *
 * The theme is seeded through `localStorage` rather than by clicking a toggle,
 * which pins down a real coupling as a side effect: `index.html`'s anti-flash
 * script writes `localStorage.setItem('theme', 'dark')` and reads nothing
 * else. Dark is the only theme here and there is no toggle at all; if the
 * anti-flash script ever drifted, this boot fails on `data-theme` rather than
 * quietly scanning something else.
 *
 * The defaults are asserted at length because `app.ts` renders each tabpanel
 * lazily on first activation. A navigation that resolves proves nothing: a
 * renderer that threw would leave `#panel-quote` empty, and an empty region is
 * exactly what a scan reports as perfectly accessible.
 */
export async function boot(page: Page, theme: 'dark'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the
  // whole test timeout and reports nothing useful. 20s turns that silent hang
  // into a named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
  await assertSingleBanner(page);
  await assertListSemantics(page);

  // ── The page really rendered ────────────────────────────────────────────
  await expect(page.locator('main')).toHaveCount(1);
  await expect(page.locator('.tab-btn')).toHaveCount(6);
  await expect(page.locator('h1')).toHaveCount(1);
  await expect(page.locator('h1')).toHaveText('Attestation Gate');

  // The shared skip link points at an id that exists. axe's skip-link rule is
  // best-practice, not WCAG-tagged, so `withTags` never runs it — a skip link
  // aimed at a missing element is exactly the kind of thing a green axe run
  // says nothing about.
  await expect(page.locator('a.cl-skip-link')).toHaveAttribute('href', '#app');
  await expect(page.locator('#app')).toHaveCount(1);

  // Dark is the only theme, so the page must carry no theme control at all —
  // not the shared bar's, which was removed, and not a lab-local one. The
  // shared CSS hides any lab toggle with `display:none !important`, which would
  // leave a dead-but-known element; asserting the count at zero catches the day
  // one is added without going through that list.
  await expect(
    page.locator('#theme-toggle, #themeToggle, .theme-toggle, .theme-toggle-btn, [data-theme-toggle]')
  ).toHaveCount(0);
  await expect(page.locator('#cl-theme-toggle')).toHaveCount(0);

  // ── The arrival state: Measured Boot active and stepped to zero ─────────
  // `renderBootPanel` runs at mount, so first paint includes the four
  // registers at their reset values and the six editable stage rows. The other
  // five panels are lazily rendered: hidden AND EMPTY until their tab is first
  // activated — asserted, because "empty" is this lab's tell that a renderer
  // threw (see `watchPageErrors`).
  await expect(page.locator('#panel-boot .step-progress')).toHaveText('Step 0 / 6');
  await expect(page.locator('#panel-boot .pcr-row')).toHaveCount(4);
  await expect(page.locator('#panel-boot .stages .stage')).toHaveCount(6);
  for (const id of ['quote', 'magic', 'break', 'time', 'signature']) {
    await expect(page.locator(`#panel-${id}`)).toBeHidden();
    await expect(page.locator(`#panel-${id}`)).toBeEmpty();
  }

  // ── Every shipped control default ───────────────────────────────────────
  await expect(page.getByRole('button', { name: '‹ Back' })).toBeDisabled();
  await expect(page.locator('#stage-firmware')).toHaveValue(
    'OpenFW 3.4.2 / POST / build 20260114'
  );
  await expect(page.locator('#stage-bootloader')).toHaveValue(
    'grubx64.efi 2.12-9 / a4f1c2 / signed'
  );
  // The separator stage is deliberately NOT editable — its bytes are fixed by
  // the specification. A text input appearing here is a content regression.
  await expect(page.locator('#stage-separator')).toHaveCount(0);

  // ── Disclosures ship shut ───────────────────────────────────────────────
  // Every `details.disclosure` arrives closed; the gate this replaces opened
  // every one from script before its only scan.
  await expect(page.locator('details.disclosure[open]')).toHaveCount(0);
  await expect(page.locator('details.disclosure')).not.toHaveCount(0);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all. This lab's long
 * values are 64-byte hex runs — every `.field-value` and `.eq-derivation`
 * relies on `overflow-wrap: anywhere` instead of a scroll region, and the
 * `.sig-pair` grid collapses to one column at 640px — so the shapes at risk
 * are a new unwrapped `<code>` run or a grid item whose automatic minimum size
 * is the min-content of a 128-char line. At 380px that is precisely what this
 * check exists to catch.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow: auto` wrapper has a huge bounding rect but
    // is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 *
 * This lab currently avoids scrollers on purpose — long hex wraps via
 * `overflow-wrap: anywhere` — so the assertion is usually vacuous here. It
 * runs at every state anyway, because the requirement MATERIALISES the moment
 * someone reaches for `overflow-x: auto` on a wide value or table (the
 * stylesheet already carries an unused `.table-wrap` rule inviting exactly
 * that), and a scroller born without a keyboard route is invisible to axe.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,summary,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY);
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * Nothing may be focusable while it paints nothing (WCAG 2.4.3 / 2.4.7).
 *
 * `opacity: 0` with `pointer-events: none` is NOT hiding: the element keeps
 * `tabIndex: 0`, so a keyboard reader tabs to a control that is not on screen
 * and the focus ring lands nowhere. `display: none` and `visibility: hidden`
 * DO remove an element from the tab order, so those are skipped rather than
 * flagged — the failure is specifically the invisible-but-tabbable pair. The
 * `hidden` tabpanels here take the `display: none` route, which is why five
 * panels' worth of buttons are legitimately absent from the tab order.
 *
 * Off-screen-but-focusable is the WCAG-sanctioned skip-link idiom and is
 * deliberately not flagged: the shared skip link parks at `top:-3rem` with
 * full opacity and slides in on focus. The drive scans it focused.
 */
export async function expectNoInvisibleFocusTargets(page: Page, label: string): Promise<void> {
  const bad = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,summary,[tabindex]:not([tabindex="-1"])';
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll<HTMLElement>(FOCUSABLE))) {
      if (el.tabIndex < 0) continue;
      // display:none / visibility:hidden already remove it from the tab order.
      if (!el.checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      for (let n: Element | null = el; n; n = n.parentElement) {
        effective *= parseFloat(getComputedStyle(n).opacity);
      }
      const r = el.getBoundingClientRect();
      if (effective !== 0 && r.width > 0 && r.height > 0) continue;
      // Confirm it really is reachable rather than inferring it.
      const before = document.activeElement;
      el.focus();
      const took = document.activeElement === el;
      (before as HTMLElement | null)?.focus?.();
      if (took) {
        out.push(
          `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}.${(el.getAttribute('class') ?? '').trim()}` +
            ` (opacity ${effective}, ${Math.round(r.width)}x${Math.round(r.height)})`
        );
      }
    }
    return Array.from(new Set(out));
  });
  expect(bad, `focusable elements that paint nothing in state: ${label}`).toEqual([]);
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run.
 * It is a debugging aid only: `A11Y_COLLECT` is never set in CI, and a run
 * with it set prints every finding as it happens and then fails at the end, so
 * a green collection run cannot be mistaken for a green gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

async function soft(fn: () => Promise<void>): Promise<void> {
  if (!COLLECTING) return fn();
  try {
    await fn();
  } catch (e) {
    // Generous, not 900: a truncated oracle dump is how a second and third
    // finding in the same state get missed on a collection pass.
    record(String(e).slice(0, 6000));
  }
}

/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no
 * text node.
 *
 * IT IS CALLED FROM `scan()`, deliberately and not by accident. Fleet-wide
 * this oracle had been called from inside a soft wrapper AFTER its
 * `if (!COLLECTING) return` guard — so in a strict run, which is every run in
 * CI and every run anyone reads as a pass, the guard returned first and
 * `nontext.ts` never executed at all. Thirteen repos certified themselves
 * clean on an oracle that had never looked. Calling it here means it runs at
 * every driven state, including `:hover`, and this repo's baseline was
 * captured by that live path.
 *
 * A check that merely logs is not a gate, so it ratchets: anything NOT in the
 * baseline fails, anything in the baseline that got WORSE fails, and anything
 * in the baseline that has been FIXED fails until its entry is deleted. That
 * last rule is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(`WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`);
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the
 * point — or the drive stopped reaching the state that shows it, which is a
 * coverage regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Nine assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state — see `expectNotBlank`.
 *  - `violations` — the usual WCAG A/AA rule failures, plus four landmark
 *    best-practice rules `withTags` does not run on its own.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically — which matters here because the surfaces carrying
 *    this lab's meaning are `color-mix()` fills axe cannot resolve: every
 *    verdict tone, both pill states, the danger/caveat callouts, the
 *    learner-check tint, the hero aside and the shared bar's ink. Everything
 *    else in that bucket is a real result axe simply could not finish —
 *    including `aria-prohibited-attr`, which is where an `aria-label` on a
 *    role-less element hides. This page leans on getting that right: the
 *    `.seg`, `.radio-row`, `.preset-row` and learner-check option groups all
 *    pair their labels with `role="group"`. Drop any of those roles and the
 *    label is silently discarded.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - the same walk over `aria-hidden` content with the exemption lifted —
 *    SC 1.4.3 is about what a reader SEES; see `contrast.ts` for what this
 *    lab hides and why it is measured anyway.
 *  - non-text contrast and generated content — SC 1.4.11, ratcheted; see
 *    `expectNoNewNonTextFailures`. This is the only oracle that judges a
 *    control's boundary against the surface OUTSIDE it.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - no focusable element that paints nothing — WCAG 2.4.3/2.4.7.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  // TWO axe runs, deliberately, and this is not a style choice.
  //
  // `AxeBuilder.withTags()` and `AxeBuilder.withRules()` both write the same
  // `options.runOnly` field, so the second call SILENTLY REPLACES the first —
  // the axe-core/playwright source says so in as many words on `withRules`
  // ("Cannot be used with AxeBuilder#withTags"). Chained as
  // `.withTags(TAGS).withRules([...4 landmark rules])`, axe runs those FOUR
  // best-practice rules and NOT ONE WCAG RULE, while a green result reads
  // exactly like a full A/AA pass. For scale, `withTags(TAGS)` selects 69 of
  // axe-core 4.12's 105 rule definitions; the chained form executes 4.
  //
  // The landmark four are still wanted because they are best-practice rather
  // than WCAG-tagged, so `withTags` alone does not reach them — and this page
  // has the shape they catch: a sticky `<header role="banner">` above a
  // `<div id="app">` holding an `<aside class="cl-hero-why">`, two `<nav>`s
  // (the shared actions and the tablist wrapper), one `<main>` and a footer.
  const wcag = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const landmarks = await new AxeBuilder({ page })
    .withRules([
      'landmark-no-duplicate-banner',
      'landmark-unique',
      'landmark-one-main',
      'landmark-complementary-is-top-level',
    ])
    .analyze();
  const results = {
    violations: [...wcag.violations, ...landmarks.violations],
    incomplete: [...wcag.incomplete, ...landmarks.incomplete],
  };

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  // The `incomplete` bucket is asserted, not skimmed. `aria-prohibited-attr`
  // and `aria-required-children` appear ONLY here — never in `violations` — so
  // a gate that ignores this bucket cannot see either. Only `color-contrast`
  // is allowed to remain, and only because the arithmetic walk below judges
  // those ratios for real; no other rule is filtered out.
  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  // The aria-hidden walk, exemption lifted — axe skips this text entirely and
  // the default walk honours the same boundary, so this second call is the
  // ONLY thing that ever measures it. See `contrast.ts` for the inventory.
  const hiddenContrast = Array.from(
    new Set(
      formatContrastFailures(
        await auditContrast(page, '[aria-hidden="true"], [aria-hidden="true"] *', true)
      )
    )
  );
  softExpect(hiddenContrast, `measured aria-hidden contrast failures in state: ${label}`, []);

  await soft(() => expectNoNewNonTextFailures(page, label));
  await soft(() => expectScrollersReachable(page, label));
  await soft(() => expectNoInvisibleFocusTargets(page, label));
  await soft(() => expectNoHorizontalOverflow(page, label));
}

// ── The drive ───────────────────────────────────────────────────────────────

/** Switch to a tab by clicking it, and prove the switch happened. */
async function openTab(page: Page, name: RegExp, panelId: string): Promise<void> {
  await page.getByRole('tab', { name }).click();
  await expect(page.getByRole('tab', { name })).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator(panelId)).toBeVisible();
  await expect(page.locator(panelId)).not.toBeEmpty();
}

/** Open one `<details>` through its summary, the way a reader does. */
async function openDisclosure(page: Page, panel: string, index: number): Promise<void> {
  const d = page.locator(`${panel} details.disclosure`).nth(index);
  await d.locator('> summary').click();
  await expect(d).toHaveAttribute('open', '');
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Five things shape this drive:
 *
 *  - THE ARRIVAL STATE IS SCANNED FIRST, exactly as a reader gets it:
 *    Measured Boot active at step 0, five panels hidden and unrendered, every
 *    disclosure shut. The gate this replaces force-revealed all of it before
 *    its only scan.
 *
 *  - EVERY PANEL IS RENDERED LAZILY, so a tab that is never clicked is a panel
 *    that is never even IN the DOM. Each of the six is activated through its
 *    real tab button and scanned in its own driven states.
 *
 *  - EVERY VERDICT TONE, IN EVERY PANEL THAT PRODUCES ONE. The three tones —
 *    pass, reject, and ATTESTED-AND-COMPROMISED — are `color-mix()` fills axe
 *    files under `incomplete` rather than judging, and the alarm tone is the
 *    one this whole exhibit exists to show. So is every `not-run` check row,
 *    which only appears when a relying party is configured to skip a check.
 *
 *  - HOVER IS A STATE, AND IT PERSISTS AFTER A CLICK. `:hover` stays on the
 *    element under the pointer after `page.click()` resolves, so it is the
 *    state a reader occupies the instant after pressing a scenario button —
 *    and `.tab-btn:hover`, `.btn:hover` and `.cl-btn:hover` all repaint their
 *    fill. Each is scanned explicitly.
 *
 *  - NO FIXED TIMEOUTS. Every wait is on a real DOM completion signal: a
 *    verdict appearing, a step counter, `aria-selected`, `aria-pressed`, the
 *    `open` attribute on a disclosure.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  await scanAt('arrival: Measured Boot at step 0, five panels unrendered, disclosures shut');

  // ── The shared skip link, focused ───────────────────────────────────────
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  await scanAt('the shared skip link focused, slid in from top:-3rem');

  // ── 1. Measured Boot ────────────────────────────────────────────────────
  const next = page.getByRole('button', { name: 'Next ›' });
  await next.click();
  await expect(page.locator('#panel-boot .step-progress')).toHaveText('Step 1 / 6');
  await expect(page.locator('#panel-boot .hex-old').first()).toBeVisible();
  await scanAt('Boot: first extension — the 64-byte preimage with both halves tinted');

  for (let i = 2; i <= 6; i++) {
    await next.click();
    await expect(page.locator('#panel-boot .step-progress')).toHaveText(`Step ${i} / 6`);
  }
  await expect(next).toBeDisabled();
  await expect(page.locator('#panel-boot .callout')).not.toHaveCount(0);
  await scanAt('Boot: stepped to the end — Next disabled, the chain-is-closed callout');

  await page.getByRole('button', { name: '‹ Back' }).click();
  await expect(page.locator('#panel-boot .step-progress')).toHaveText('Step 5 / 6');
  await scanAt('Boot: stepped back one');

  await page.getByRole('button', { name: 'Back to step 0' }).click();
  await expect(page.locator('#panel-boot .step-progress')).toHaveText('Step 0 / 6');

  // The break-it-yourself interaction: one edited byte moves exactly one
  // register, and the panel says which.
  await page.fill('#stage-bootloader', 'grubx64.efi 2.12-9 / a4f1c3 / signed');
  await expect(page.locator('#panel-boot .callout[data-tone="alarm"]')).toContainText(
    'no longer match the reference values'
  );
  await scanAt('Boot: one measured byte edited — the diverged-register alarm callout');

  await page.fill('#stage-bootloader', 'grubx64.efi 2.12-9 / a4f1c2 / signed');
  await expect(page.locator('#panel-boot .callout[data-tone="alarm"]')).toHaveCount(0);

  for (let i = 0; i < 3; i++) await openDisclosure(page, '#panel-boot', i);
  await expect(page.locator('#panel-boot .table-wrap')).toHaveCount(2);
  await scanAt('Boot: all three disclosures open, including the two scrollable tables');

  // ── 2. Quote & Verify ───────────────────────────────────────────────────
  await openTab(page, /Quote & Verify/, '#panel-quote');
  await expect(page.locator('#panel-quote .verdict[data-tone="ok"]')).toContainText('ATTESTED');
  await expect(page.locator('#panel-quote .check[data-state="pass"]')).not.toHaveCount(0);
  await expect(page.locator('#panel-quote .check[data-state="fail"]')).toHaveCount(0);
  await scanAt('Quote: the honest baseline — every check passing');

  for (let i = 0; i < 3; i++) await openDisclosure(page, '#panel-quote', i);
  await expect(page.locator('#panel-quote .bytemap .byte-field')).not.toHaveCount(0);
  await expect(page.locator('#panel-quote .byte-field[data-highlight="true"]')).not.toHaveCount(0);
  await scanAt('Quote: the TPMS_ATTEST byte map, the EAT, and the RATS role table all open');

  await page.locator('#panel-quote .btn-primary').click();
  await expect(page.locator('#panel-quote .verdict[data-tone="ok"]')).toContainText('ATTESTED');
  await scanAt('Quote: a fresh challenge, still hovered on the primary button');

  // ── 3. The Magic Value ──────────────────────────────────────────────────
  await openTab(page, /The Magic Value/, '#panel-magic');
  await expect(page.locator('#panel-magic .verdict[data-tone="ok"]')).toContainText(
    'REFUSED — TPM_RC_TICKET'
  );
  await scanAt('Magic: a restricted key refusing to sign a hand-built TPMS_ATTEST');

  const restrictedToggle = page.locator('#panel-magic .btn-row button').first();
  const magicToggle = page.locator('#panel-magic .btn-row button').nth(1);
  await restrictedToggle.click();
  await expect(restrictedToggle).toHaveAttribute('aria-pressed', 'false');
  await expect(page.locator('#panel-magic .verdict[data-tone="alarm"]')).toContainText('SIGNED');
  await scanAt('Magic: restricted cleared — the forgery is signed and verifies (alarm tone)');

  await magicToggle.click();
  await expect(magicToggle).toHaveAttribute('aria-pressed', 'false');
  await scanAt('Magic: an unrestricted key signing a blob with no magic at all');

  await restrictedToggle.click();
  await expect(restrictedToggle).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('#panel-magic .verdict[data-tone="ok"]')).toContainText('SIGNED');
  await scanAt('Magic: a restricted key signing external data BECAUSE it is not an attestation');

  await magicToggle.click();
  await expect(page.locator('#panel-magic .verdict')).toContainText('REFUSED');
  for (let i = 0; i < 5; i++) await openDisclosure(page, '#panel-magic', i);
  await scanAt('Magic: every disclosure open, including both quick checks');

  // ── 4. Break It ─────────────────────────────────────────────────────────
  await openTab(page, /Break It/, '#panel-break');
  await expect(page.locator('#panel-break .verdict[data-tone="bad"]')).toContainText('REJECTED');
  await expect(page.locator('#panel-break .check-code')).toContainText('PCR_MISMATCH');
  await expect(page.locator('#panel-break .pcr-row[data-match="false"]')).toHaveCount(1);
  await scanAt('Break: Act 3 — one byte changed, PCR_MISMATCH, the divergent stage named');

  await page.fill('#bootloader-input', 'grubx64.efi 2.12-9 / a4f1c2 / signed');
  await expect(page.locator('#panel-break .verdict[data-tone="ok"]')).toContainText('ATTESTED');
  await scanAt('Break: the edit reverted to the reference image — the same run appraises clean');

  await page.fill('#bootloader-input', 'grubx64.efi 2.12-9 / a4f1c3 / signed');
  await expect(page.locator('#panel-break .verdict[data-tone="bad"]')).toBeVisible();

  await page.locator('#panel-break button[data-which="replay"]').click();
  await expect(page.locator('#panel-break .check-code')).toContainText('NONCE_STALE');
  await expect(page.locator('#bootloader-input')).toHaveCount(0);
  await scanAt('Break: Act 4 — a genuine quote replayed, NONCE_STALE with a valid signature');

  await page.locator('#panel-break button[data-which="wrong-machine"]').click();
  await expect(page.locator('#panel-break .check-code')).toContainText('TRUST_ANCHOR_UNKNOWN');
  await expect(page.locator('#panel-break .pcr-row[data-match="false"]')).toHaveCount(0);
  await scanAt('Break: Act 5 — the wrong machine, perfect PCRs, rejected on identity');

  await openDisclosure(page, '#panel-break', 0);
  await scanAt('Break: the failure-code naming disclosure open');

  // ── 5. Time of Use ──────────────────────────────────────────────────────
  await openTab(page, /Time of Use/, '#panel-time');
  await expect(page.locator('#panel-time .verdict[data-tone="ok"]')).toContainText('ATTESTED');
  await scanAt('Time of Use: the clean boot, before anything unmeasured runs');

  await page.locator('#panel-time .btn-row button').first().click();
  await expect(page.locator('#panel-time .verdict[data-tone="alarm"]')).toContainText(
    'ATTESTED — AND COMPROMISED'
  );
  await scanAt('Time of Use: the climax — every check passing over a compromised machine');

  for (let i = 0; i < 3; i++) await openDisclosure(page, '#panel-time', i);
  await scanAt('Time of Use: the scope disclosures open');

  await page.locator('#panel-time .btn-row button').first().click();
  await expect(page.locator('#panel-time .verdict[data-tone="ok"]')).toContainText('ATTESTED');

  // ── 6. Whose Signature ──────────────────────────────────────────────────
  await openTab(page, /Whose Signature/, '#panel-signature');
  await expect(page.locator('#panel-signature .verdict[data-tone="alarm"]')).toContainText(
    'ATTESTED — AND COMPROMISED'
  );
  await scanAt('Signature: 7a — a stolen key signing a structure it built itself');

  const sigButtons = page.locator('#panel-signature .btn-row button');
  await sigButtons.nth(1).click();
  await expect(page.locator('#panel-signature .check-code')).toContainText('AK_NOT_CERTIFIED');
  await scanAt('Signature: 7b-i checked — AK_NOT_CERTIFIED');

  await sigButtons.nth(2).click();
  // The only state in the whole lab that renders a NOT RUN check row.
  await expect(page.locator('#panel-signature .check[data-state="not-run"]')).not.toHaveCount(0);
  await expect(page.locator('#panel-signature .verdict[data-tone="alarm"]')).toBeVisible();
  await scanAt('Signature: 7b-i unchecked — the dashed NOT RUN row, and a clean pass');

  await sigButtons.nth(3).click();
  await expect(page.locator('#panel-signature .verdict[data-tone="alarm"]')).toBeVisible();
  await openDisclosure(page, '#panel-signature', 0);
  await openDisclosure(page, '#panel-signature', 1);
  await scanAt('Signature: 7b-ii — the credential-activation trace open');

  await sigButtons.nth(4).click();
  await expect(page.locator('#panel-signature .callout[data-tone="alarm"]').last()).toContainText(
    'trust anchors are an assumption'
  );
  await openDisclosure(page, '#panel-signature', 0);
  await scanAt('Signature: THREAT-1 — a hostile anchor, and a completely clean appraisal');

  // ── Hover, which persists after a click ─────────────────────────────────
  await sigButtons.first().hover();
  await scanAt('a scenario button hovered');

  await page.getByRole('tab', { name: /Measured Boot/ }).hover();
  await scanAt('an inactive tab hovered — its surface-3 fill repainted');

  await page.locator('.cl-topbar .cl-btn').first().hover();
  await scanAt('a shared top bar control hovered');

  // ── Focus rings on the controls that take them ──────────────────────────
  await openTab(page, /Measured Boot/, '#panel-boot');
  await page.locator('#stage-kernel').focus();
  await expect(page.locator('#stage-kernel')).toBeFocused();
  await scanAt('a text input focused, showing its focus-visible outline');

  await page.getByRole('tab', { name: /Measured Boot/ }).focus();
  await scanAt('the active tab focused');

  await page.locator('#panel-boot .table-wrap').first().focus();
  await scanAt('a scrollable table region focused');
}
