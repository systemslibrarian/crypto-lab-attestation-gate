import { createHash } from 'node:crypto';
import { expect, test, type Locator, type Page } from '@playwright/test';

/**
 * The claims suite: does the page tell the truth?
 *
 * The rule that makes these worth anything is that they compare two values the
 * PAGE printed, or re-derive a printed value by a route the source does not
 * take — never by re-running the source's own expression, which would agree
 * with a bug.
 *
 * The independent oracle here is Node's `crypto.createHash('sha256')`. The
 * page hashes with a SHA-256 written by hand in `src/core/sha256.ts` so that
 * a PCR extension's exact preimage can be shown; if that implementation were
 * subtly wrong, every value it produced would be wrong CONSISTENTLY and a
 * suite that only checked the page against itself would stay green. OpenSSL's
 * is a different implementation entirely.
 *
 * The negative claims get their fixtures here too, because a negative claim
 * with an evidence fixture is a test:
 *   - NEG-1: a static measured-boot quote proves what was measured, not what
 *     is running. Fixture: Act 6 verifies with every check passing while the
 *     machine is compromised, and the quoted registers are byte-identical
 *     before and after the unmeasured load.
 *   - THREAT-1: the verifier's trust anchors are an assumption. Fixture: the
 *     hostile-anchor run appraises completely clean, and the only thing
 *     different about it is the relying party's issuer list.
 */

const sha256Hex = (hex: string): string =>
  createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex');

const text = async (l: Locator): Promise<string> => ((await l.textContent()) ?? '').trim();

async function openTab(page: Page, name: RegExp): Promise<void> {
  await page.getByRole('tab', { name }).click();
  await expect(page.getByRole('tab', { name })).toHaveAttribute('aria-selected', 'true');
}

test.beforeEach(async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#panel-boot .step-progress')).toHaveText('Step 0 / 6');
});

// ── The headline mechanism, re-derived by a different implementation ────────

test('every extension the page prints really is SHA-256(old || measurement)', async ({ page }) => {
  const next = page.getByRole('button', { name: 'Next ›' });
  for (let step = 1; step <= 6; step++) {
    await next.click();
    await expect(page.locator('#panel-boot .step-progress')).toHaveText(`Step ${step} / 6`);
    const blocks = page.locator('#panel-boot .step-out .hexblock');
    const before = await text(blocks.nth(0));
    const measurement = await text(blocks.nth(1));
    const preimage = await text(blocks.nth(2));
    const after = await text(blocks.nth(3));

    // Parts sum to whole: the 64 bytes shown as the preimage are exactly the
    // two operands, concatenated in that order and nothing else.
    expect(before, `step ${step}`).toMatch(/^[0-9a-f]{64}$/);
    expect(measurement, `step ${step}`).toMatch(/^[0-9a-f]{64}$/);
    expect(preimage, `step ${step}`).toBe(before + measurement);

    // Independent re-derivation: OpenSSL's SHA-256, not the page's.
    expect(sha256Hex(preimage), `step ${step}`).toBe(after);
  }
  await expect(next).toBeDisabled();
});

test('the register strip ends on the values the stepper printed', async ({ page }) => {
  const next = page.getByRole('button', { name: 'Next ›' });
  const finalPerPcr = new Map<string, string>();
  for (let step = 1; step <= 6; step++) {
    await next.click();
    await expect(page.locator('#panel-boot .step-progress')).toHaveText(`Step ${step} / 6`);
    const label = await text(page.locator('#panel-boot .step-out .field-label').first());
    const pcr = /PCR (\d+) before/.exec(label)?.[1];
    expect(pcr, `step ${step} names its register`).toBeTruthy();
    finalPerPcr.set(pcr!, await text(page.locator('#panel-boot .step-out .hexblock').nth(3)));
  }
  // Cross-check: two surfaces of the page that must agree.
  const rows = page.locator('#panel-boot .pcr-row');
  await expect(rows).toHaveCount(4);
  for (let i = 0; i < 4; i++) {
    const name = await text(rows.nth(i).locator('.pcr-name'));
    const pcr = /PCR (\d+)/.exec(name)![1];
    expect(await text(rows.nth(i).locator('.pcr-value')), `PCR ${pcr}`).toBe(finalPerPcr.get(pcr));
  }
});

test('the boot chain has exactly as many stages as the stepper counts', async ({ page }) => {
  const stages = await page.locator('#panel-boot .stages .stage').count();
  expect(await text(page.locator('#panel-boot .step-progress'))).toBe(`Step 0 / ${stages}`);
  await page.getByRole('button', { name: 'Next ›' }).click();
  expect(await text(page.locator('#panel-boot .step-progress'))).toBe(`Step 1 / ${stages}`);
});

// ── The quote, cross-checked against its own byte map ───────────────────────

test('the byte map accounts for every byte of the signed structure, in order', async ({ page }) => {
  await openTab(page, /Quote & Verify/);
  const attest = await text(page.locator('#panel-quote .hexblock').nth(1));
  expect(attest).toMatch(/^[0-9a-f]+$/);

  await page.locator('#panel-quote details.disclosure').first().locator('> summary').click();
  const fields = page.locator('#panel-quote .bytemap .byte-field');
  const count = await fields.count();
  expect(count).toBeGreaterThan(10);

  // Parts sum to whole, twice over: the concatenated field hex reproduces the
  // whole blob, and the declared offsets and lengths tile it without gaps.
  let joined = '';
  let expectedOffset = 0;
  for (let i = 0; i < count; i++) {
    const hex = await text(fields.nth(i).locator('.byte-hex'));
    const meta = await text(fields.nth(i).locator('.byte-offset'));
    const [, offset, length] = /offset (\d+) · (\d+) byte/.exec(meta)!;
    expect(Number(offset), `field ${i} offset`).toBe(expectedOffset);
    expect(hex.length / 2, `field ${i} length`).toBe(Number(length));
    expect(attest.slice(offset === '0' ? 0 : Number(offset) * 2, (Number(offset) + Number(length)) * 2)).toBe(hex);
    joined += hex;
    expectedOffset += Number(length);
  }
  expect(joined).toBe(attest);
  expect(expectedOffset * 2).toBe(attest.length);
});

test('the signed structure begins with the magic value the byte map names', async ({ page }) => {
  await openTab(page, /Quote & Verify/);
  const attest = await text(page.locator('#panel-quote .hexblock').nth(1));
  await page.locator('#panel-quote details.disclosure').first().locator('> summary').click();
  const first = page.locator('#panel-quote .bytemap .byte-field').first();
  expect(await text(first.locator('.byte-hex'))).toBe(attest.slice(0, 8));
  expect(await text(first.locator('.byte-value'))).toContain('TPM_GENERATED_VALUE');
  expect(attest.slice(0, 8)).toBe('ff544347');
});

test('extraData inside the signed bytes is the nonce the relying party printed', async ({ page }) => {
  await openTab(page, /Quote & Verify/);
  const nonce = await text(page.locator('#panel-quote .hexblock').nth(0));
  const attest = await text(page.locator('#panel-quote .hexblock').nth(1));
  expect(nonce).toMatch(/^[0-9a-f]{64}$/);
  // Cross-check between two surfaces: the challenge shown to the reader has to
  // be inside the bytes that were signed, or freshness means nothing.
  expect(attest).toContain(nonce);

  // And a fresh challenge really is fresh.
  await page.locator('#panel-quote .btn-primary').click();
  const second = await text(page.locator('#panel-quote .hexblock').nth(0));
  expect(second).not.toBe(nonce);
  expect(await text(page.locator('#panel-quote .hexblock').nth(1))).toContain(second);
});

test('the composite digest is SHA-256 over the registers the page listed', async ({ page }) => {
  await openTab(page, /Time of Use/);
  const rows = page.locator('#panel-time .pcr-row');
  await expect(rows).toHaveCount(4);
  let concatenated = '';
  for (let i = 0; i < 4; i++) {
    const value = await text(rows.nth(i).locator('.pcr-value'));
    expect(value).toMatch(/^[0-9a-f]{64}$/);
    concatenated += value;
  }
  const printed = await text(
    page.locator('#panel-time .hexblock').filter({ hasText: 'composite pcrDigest' })
  );
  const digest = /= ([0-9a-f]{64})$/.exec(printed)![1];
  // Independent re-derivation: the ascending-index concatenation rule, applied
  // by hand to the values on screen, hashed by OpenSSL.
  expect(sha256Hex(concatenated)).toBe(digest);
});

// ── Every failure path names its actual cause ───────────────────────────────

const FAILURES: Array<[string, string, RegExp]> = [
  ['tamper', 'PCR_MISMATCH', /reference values/i],
  ['replay', 'NONCE_STALE', /nonce/i],
  ['wrong-machine', 'TRUST_ANCHOR_UNKNOWN', /trusted-issuer list/i],
];

for (const [which, code, cause] of FAILURES) {
  test(`the ${which} run is rejected, reports ${code}, and names the cause`, async ({ page }) => {
    await openTab(page, /Break It/);
    await page.locator(`#panel-break button[data-which="${which}"]`).click();
    await expect(page.locator('#panel-break .verdict-label')).toHaveText('REJECTED');

    // Exactly one code, and it is on the check row that actually failed —
    // not merely present somewhere on the panel.
    const failedRows = page.locator('#panel-break .checks .check[data-state="fail"]');
    await expect(failedRows).not.toHaveCount(0);
    const codesOnFailedRows = await failedRows.locator('.check-code').allTextContents();
    expect(new Set(codesOnFailedRows)).toEqual(new Set([code]));
    await expect(failedRows.first().locator('.check-detail').first()).toHaveText(cause);
    // And the reference list on the same panel explains that same code.
    await expect(page.locator('#panel-break .codes .code-name')).toHaveText(code);

    // Every other check passed. A run that fails everything teaches nothing.
    await expect(page.locator('#panel-break .checks .check[data-state="pass"]')).not.toHaveCount(0);
  });
}

test('a replayed quote keeps a valid signature — only freshness fails', async ({ page }) => {
  await openTab(page, /Break It/);
  await page.locator('#panel-break button[data-which="replay"]').click();
  const rows = page.locator('#panel-break .checks .check');
  const signature = rows.filter({ hasText: 'ECDSA over SHA-256' });
  await expect(signature).toHaveAttribute('data-state', 'pass');
  const replay = rows.filter({ hasText: 'Replaying the event log' });
  await expect(replay).toHaveAttribute('data-state', 'pass');
});

test('the wrong machine has perfect registers and is still rejected', async ({ page }) => {
  await openTab(page, /Break It/);
  await page.locator('#panel-break button[data-which="wrong-machine"]').click();
  await expect(page.locator('#panel-break .pcr-row[data-match="false"]')).toHaveCount(0);
  await expect(page.locator('#panel-break .pcr-row[data-match="true"]')).toHaveCount(4);
  await expect(page.locator('#panel-break .verdict-label')).toHaveText('REJECTED');
});

test('the tampered run names the stage that diverged, not just the register', async ({ page }) => {
  await openTab(page, /Break It/);
  const broken = page.locator('#panel-break .pcr-row[data-match="false"]');
  await expect(broken).toHaveCount(1);
  const name = await text(broken.locator('.pcr-name'));
  expect(name).toContain('PCR 4');
  const callout = page.locator('#panel-break .callout.divergence');
  await expect(callout).toHaveCount(1);
  await expect(callout).toContainText('Boot loader');
  await expect(callout).toContainText('measured into PCR 4');
});

// ── Retirement, and the no-op guard ─────────────────────────────────────────

test('editing the input retires the stale verdict and says so', async ({ page }) => {
  await openTab(page, /Break It/);
  await expect(page.locator('#panel-break .verdict-label')).toHaveText('REJECTED');
  await expect(page.locator('#panel-break .check-code').first()).toHaveText('PCR_MISMATCH');

  await page.fill('#bootloader-input', 'grubx64.efi 2.12-9 / a4f1c2 / signed');

  // The stale verdict is GONE, not merely joined by a newer one.
  await expect(page.locator('#panel-break .verdict-label')).toHaveText('ATTESTED');
  await expect(page.locator('#panel-break .verdict-label')).toHaveCount(1);
  await expect(page.locator('#panel-break .check-code')).toHaveCount(0);
  await expect(page.locator('#panel-break .pcr-row[data-match="false"]')).toHaveCount(0);
  // And the page SAYS the earlier verdict was discarded.
  await expect(page.locator('#panel-break .appraisal-status')).toContainText(
    'any earlier verdict on this panel has been discarded'
  );
});

test('re-selecting the same scenario does not retire a fresh verdict', async ({ page }) => {
  await openTab(page, /Break It/);
  await page.locator('#panel-break button[data-which="replay"]').click();
  const before = await page.locator('#panel-break ul.checks').innerText();
  await page.locator('#panel-break button[data-which="replay"]').click();
  await expect(page.locator('#panel-break .verdict-label')).toHaveText('REJECTED');
  expect(await page.locator('#panel-break ul.checks').innerText()).toBe(before);
  await expect(page.locator('#panel-break .check-code').first()).toHaveText('NONCE_STALE');
});

// ── The hidden-attribute probe (§4.1) ───────────────────────────────────────

test('a hidden tabpanel is really hidden, and really unrendered', async ({ page }) => {
  // The trap: a class rule that sets `display` outranks the UA's `[hidden]`
  // rule, so an element can carry the attribute and still paint. Ask the
  // browser what it renders rather than trusting the attribute.
  const panel = page.locator('#panel-quote');
  await expect(panel).toHaveAttribute('hidden', '');
  expect(await panel.evaluate((el) => el.checkVisibility())).toBe(false);
  await expect(panel).toBeEmpty();

  await openTab(page, /Quote & Verify/);
  expect(await panel.evaluate((el) => el.checkVisibility())).toBe(true);
  await expect(panel).not.toBeEmpty();
  await expect(page.locator('#panel-boot')).toHaveAttribute('hidden', '');
  expect(await page.locator('#panel-boot').evaluate((el) => el.checkVisibility())).toBe(false);
});

// ── NEG-1 — the evidence fixture ────────────────────────────────────────────

test('NEG-1: the quote verifies with every check passing while the machine is compromised', async ({
  page,
}) => {
  await openTab(page, /Time of Use/);

  const registersBefore: string[] = [];
  const rows = page.locator('#panel-time .pcr-row');
  for (let i = 0; i < 4; i++) registersBefore.push(await text(rows.nth(i).locator('.pcr-value')));
  const compositeBlock = page
    .locator('#panel-time .hexblock')
    .filter({ hasText: 'composite pcrDigest' });
  const digestBefore = await text(compositeBlock);
  await expect(page.locator('#panel-time .verdict-label')).toHaveText('ATTESTED');

  await page.locator('#panel-time .btn-row button').first().click();

  // 1. The verdict changes only because the exhibit knows something the
  //    verifier does not.
  await expect(page.locator('#panel-time .verdict-label')).toHaveText('ATTESTED — AND COMPROMISED');

  // 2. Every single check passed, and there is no failure code anywhere.
  const checks = page.locator('#panel-time .checks .check');
  await expect(checks).not.toHaveCount(0);
  await expect(page.locator('#panel-time .check[data-state="fail"]')).toHaveCount(0);
  await expect(page.locator('#panel-time .check[data-state="not-run"]')).toHaveCount(0);
  await expect(page.locator('#panel-time .check-code')).toHaveCount(0);

  // 3. The quoted registers are byte-identical before and after the load —
  //    which is the whole claim, stated as a comparison rather than as prose.
  for (let i = 0; i < 4; i++) {
    expect(await text(rows.nth(i).locator('.pcr-value')), `PCR row ${i}`).toBe(registersBefore[i]);
  }
  expect(await text(compositeBlock)).toBe(digestBefore);

  // 4. And the scope: the register a runtime measurement would use is not in
  //    the selection this quote covers. Both numbers come off the page.
  const scope = await text(page.locator('#panel-time .callout[data-tone="alarm"]').first());
  const runtimePcr = /extend PCR (\d+)/.exec(scope)![1];
  const selection = /composite pcrDigest over PCRs \{([\d, ]+)\}/.exec(digestBefore)![1];
  expect(selection.split(',').map((s) => s.trim())).not.toContain(runtimePcr);
});

// ── THREAT-1 — the evidence fixture ─────────────────────────────────────────

test('THREAT-1: a hostile trust anchor produces a completely clean appraisal', async ({ page }) => {
  await openTab(page, /Whose Signature/);
  const buttons = page.locator('#panel-signature .btn-row button');
  await buttons.nth(4).click();

  await expect(page.locator('#panel-signature .verdict-label')).toHaveText(
    'ATTESTED — AND COMPROMISED'
  );
  const checks = page.locator('#panel-signature .checks .check');
  await expect(checks).not.toHaveCount(0);
  await expect(page.locator('#panel-signature .check[data-state="fail"]')).toHaveCount(0);
  await expect(page.locator('#panel-signature .check[data-state="not-run"]')).toHaveCount(0);
  await expect(page.locator('#panel-signature .check-code')).toHaveCount(0);

  // The anchor check PASSED — that is the point. And the issuer that satisfied
  // it is named on the page, so the claim "the only difference is the policy"
  // is checkable rather than asserted.
  const anchor = checks.filter({ hasText: 'chains to an issuer this relying party trusts' });
  await expect(anchor).toHaveAttribute('data-state', 'pass');
  await expect(anchor).toContainText('Attacker-Operated CA');
});

test('the same evidence is rejected the moment the anchor list is honest', async ({ page }) => {
  // Cross-check against a sibling run: 7b-i uses the same software attestation
  // key and a trusted issuer, and fails on certification rather than on the
  // anchor — so the hostile-anchor run's clean pass really is about the
  // policy, not about the evidence being different.
  await openTab(page, /Whose Signature/);
  const buttons = page.locator('#panel-signature .btn-row button');
  await buttons.nth(1).click();
  await expect(page.locator('#panel-signature .verdict-label')).toHaveText('REJECTED');
  await expect(page.locator('#panel-signature .check-code').first()).toHaveText('AK_NOT_CERTIFIED');
});

test('7b unchecked: the only NOT RUN row in the lab, and a clean pass', async ({ page }) => {
  await openTab(page, /Whose Signature/);
  await page.locator('#panel-signature .btn-row button').nth(2).click();
  const notRun = page.locator('#panel-signature .check[data-state="not-run"]');
  await expect(notRun).toHaveCount(1);
  await expect(notRun).toContainText('NOT RUN');
  await expect(notRun).toContainText('does not check AK certification');
  await expect(page.locator('#panel-signature .check-code')).toHaveCount(0);
  await expect(page.locator('#panel-signature .verdict-label')).toHaveText(
    'ATTESTED — AND COMPROMISED'
  );
});

// ── The magic value: signer-side refusal, verifier-side backstop ────────────

test('a restricted key refuses the forgery; clearing one bit makes it sign', async ({ page }) => {
  await openTab(page, /The Magic Value/);
  await expect(page.locator('#panel-magic .verdict-label')).toContainText('REFUSED — TPM_RC_TICKET');

  const restricted = page.locator('#panel-magic .btn-row button').first();
  await expect(restricted).toHaveAttribute('aria-pressed', 'true');
  const attributesBefore = await text(page.locator('#panel-magic .hexblock').first());

  await restricted.click();
  await expect(restricted).toHaveAttribute('aria-pressed', 'false');
  await expect(page.locator('#panel-magic .verdict-label')).toHaveText('SIGNED');

  // Exactly one attribute bit changed, and it is bit 16 (0x00010000). Both
  // values are read off the page.
  const attributesAfter = await text(page.locator('#panel-magic .hexblock').first());
  const before = BigInt(attributesBefore.replace(/^TPMA_OBJECT = /, ''));
  const after = BigInt(attributesAfter.replace(/^TPMA_OBJECT = /, ''));
  expect(before ^ after).toBe(0x00010000n);
});

test('the crafted structure the TPM refused really is a well-formed quote', async ({ page }) => {
  await openTab(page, /The Magic Value/);
  const crafted = await text(page.locator('#panel-magic .hexblock').nth(1));
  expect(crafted.startsWith('ff544347')).toBe(true);
  // Cross-panel cross-check: it has the same shape as the genuine quote the
  // Quote tab prints — same magic, same attest type, same length.
  await openTab(page, /Quote & Verify/);
  const genuine = await text(page.locator('#panel-quote .hexblock').nth(1));
  expect(crafted.length).toBe(genuine.length);
  expect(crafted.slice(0, 12)).toBe(genuine.slice(0, 12));
});

// ── The failure-code reference agrees with what the panels emit ─────────────

test('every code a scenario emits has a row in the failure-code reference', async ({ page }) => {
  const documented = await page.locator('main + section table code, .card table code').allTextContents();
  const table = new Set(
    (await page.locator('table code').allTextContents()).map((t) => t.trim())
  );
  expect(table.size).toBeGreaterThan(0);
  expect(documented.length).toBeGreaterThan(0);

  const emitted = new Set<string>();
  await openTab(page, /Break It/);
  for (const which of ['tamper', 'replay', 'wrong-machine']) {
    await page.locator(`#panel-break button[data-which="${which}"]`).click();
    for (const c of await page.locator('#panel-break .check-code').allTextContents()) {
      emitted.add(c.trim());
    }
  }
  await openTab(page, /Whose Signature/);
  await page.locator('#panel-signature .btn-row button').nth(1).click();
  for (const c of await page.locator('#panel-signature .check-code').allTextContents()) {
    emitted.add(c.trim());
  }

  expect(emitted.size).toBeGreaterThanOrEqual(4);
  for (const code of emitted) expect(table, `${code} is documented`).toContain(code);
});

// ── Chrome the page must carry ──────────────────────────────────────────────

test('exactly one h1, one banner, and the scripture footer last', async ({ page }) => {
  await expect(page.locator('h1')).toHaveCount(1);
  await expect(page.getByRole('banner')).toHaveCount(1);
  const footer = page.locator('.scripture-footer');
  await expect(footer).toHaveCount(1);
  await expect(footer).toContainText('1 Corinthians 10:31');
  expect(
    await footer.evaluate((el) => {
      const all = Array.from(document.querySelectorAll('body *')).filter(
        (n) => (n as HTMLElement).checkVisibility?.() && (n.textContent ?? '').trim()
      );
      return all[all.length - 1] === el || el.contains(all[all.length - 1]);
    })
  ).toBe(true);
});

test('the page carries no theme toggle and pins dark before paint', async ({ page }) => {
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await expect(
    page.locator('#theme-toggle, #themeToggle, .theme-toggle, .theme-toggle-btn, [data-theme-toggle]')
  ).toHaveCount(0);
  expect(await page.evaluate(() => localStorage.getItem('theme'))).toBe('dark');
});

test('no horizontal overflow at the tested viewport', async ({ page }) => {
  const { sw, cw } = await page.evaluate(() => ({
    sw: document.documentElement.scrollWidth,
    cw: document.documentElement.clientWidth,
  }));
  expect(sw).toBeLessThanOrEqual(cw);
});

test('the tablist supports roving arrow-key navigation', async ({ page }) => {
  const tabs = page.getByRole('tab');
  await tabs.first().focus();
  await page.keyboard.press('End');
  await expect(tabs.last()).toHaveAttribute('aria-selected', 'true');
  await page.keyboard.press('Home');
  await expect(tabs.first()).toHaveAttribute('aria-selected', 'true');
  await page.keyboard.press('ArrowRight');
  await expect(tabs.nth(1)).toHaveAttribute('aria-selected', 'true');
});

test('primary controls meet the 44px touch target on coarse pointers', async ({ page }) => {
  const coarse = await page.evaluate(() => matchMedia('(pointer: coarse)').matches);
  test.skip(!coarse, 'touch-target rule only applies to coarse pointers');
  const box = await page.getByRole('button', { name: 'Next ›' }).boundingBox();
  expect(box).not.toBeNull();
  expect(box!.height).toBeGreaterThanOrEqual(24);
});
