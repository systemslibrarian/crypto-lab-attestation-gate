import { createHash } from 'node:crypto';
import { expect, test, type Locator, type Page } from '@playwright/test';
import { bls12_381 } from '@noble/curves/bls12-381.js';

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

// ── A-D-08 — named DAA construction, computed membership and link policy ──

const finalHexLine = async (locator: Locator): Promise<string> => {
  const lines = (await text(locator)).split(/\s+/);
  return lines[lines.length - 1];
};

test('the stable AK repeats while the DAA-shaped statement carries an empty signer Name', async ({
  page,
}) => {
  await openTab(page, /Anonymous Membership/);
  const first = await text(page.locator('[data-daa-value="stable-ak-one"]'));
  const second = await text(page.locator('[data-daa-value="stable-ak-two"]'));
  expect(first).toMatch(/^[0-9a-f]{68}$/);
  expect(second).toBe(first);
  await expect(page.locator('[data-daa-row="stable-ak"]')).toHaveAttribute('data-daa-row', 'stable-ak');
  await expect(page.locator('[data-daa-row="stable-ak"] [data-result="same"]')).toContainText(
    'SAME'
  );
  await expect(page.locator('[data-daa-row="anonymous"] [data-result="empty"]')).toContainText(
    'No AK Name'
  );

  await page.locator('#panel-daa details.disclosure').first().locator('> summary').click();
  const statement = await finalHexLine(page.locator('[data-daa-value="statement-bytes"]'));
  const digest = await finalHexLine(page.locator('[data-daa-value="statement-digest"]'));
  expect(statement).toMatch(/^[0-9a-f]+$/);
  // magic || type || TPM2B_NAME.size=0
  expect(statement.startsWith('ff54434780180000')).toBe(true);
  expect(statement).not.toContain(first);
  expect(createHash('sha256').update(Buffer.from(statement, 'hex')).digest('hex')).toBe(digest);
});

test('the displayed randomized issuer relation satisfies the pairing equation independently', async ({
  page,
}) => {
  await openTab(page, /Anonymous Membership/);
  await page.locator('#panel-daa details.disclosure').first().locator('> summary').click();
  const w = bls12_381.G2.Point.fromHex(
    await finalHexLine(page.locator('[data-daa-value="issuer-w"]'))
  );
  const aPrime = bls12_381.G1.Point.fromHex(
    await finalHexLine(page.locator('[data-daa-value="a-prime"]'))
  );
  const aBar = bls12_381.G1.Point.fromHex(
    await finalHexLine(page.locator('[data-daa-value="a-bar"]'))
  );
  const left = bls12_381.pairing(aPrime, w);
  const right = bls12_381.pairing(aBar, bls12_381.G2.Point.BASE);
  expect(bls12_381.fields.Fp12.eql(left, right)).toBe(true);
  await expect(page.locator('[data-daa-table="protocol-stages"] tr[data-state="fail"]')).toHaveCount(
    0
  );
});

test('basename Link outcomes agree with the four current-run pseudonyms', async ({ page }) => {
  await openTab(page, /Anonymous Membership/);
  await page.locator('#panel-daa details.disclosure').nth(1).locator('> summary').click();
  const serviceA1 = await finalHexLine(page.locator('[data-daa-nym="service-a-first"]'));
  const serviceA2 = await finalHexLine(page.locator('[data-daa-nym="service-a-second"]'));
  const researchA = await finalHexLine(page.locator('[data-daa-nym="research-a"]'));
  const serviceB = await finalHexLine(page.locator('[data-daa-nym="service-b"]'));
  for (const value of [serviceA1, serviceA2, researchA, serviceB]) {
    expect(value).toMatch(/^[0-9a-f]{96}$/);
  }
  expect(serviceA2).toBe(serviceA1);
  expect(researchA).not.toBe(serviceA1);
  expect(serviceB).not.toBe(serviceA1);
  await expect(page.locator('[data-daa-link="same-basename"] [data-result="linked"]')).toHaveText(
    'LINKED'
  );
  await expect(
    page.locator('[data-daa-link="different-basename"] [data-result="inapplicable"]')
  ).toContainText('INAPPLICABLE');
  await expect(
    page.locator('[data-daa-link="different-platform"] [data-result="not-linked"]')
  ).toHaveText('NOT LINKED');
});

test('credential, issuer epoch, re-Join, and exact rogue-list state drive the shown verdicts', async ({
  page,
}) => {
  await openTab(page, /Anonymous Membership/);
  await expect(page.locator('[data-daa-output="baseline"] .verdict-label')).toHaveText(
    'MEMBERSHIP ACCEPTED'
  );
  const credentialRows = page.locator('[data-daa-table="credential-control"] tbody tr');
  await expect(credentialRows.nth(0).locator('[data-result="pass"]')).toHaveText('PASS');
  await expect(credentialRows.nth(1).locator('[data-result="fail"]')).toHaveText('FAIL');

  await page.locator('button[data-daa-state="rotated"]').click();
  await expect(page.locator('[data-daa-output="rotated"] .verdict-label')).toHaveText(
    'MEMBERSHIP REJECTED'
  );
  await page.locator('button[data-daa-state="rejoined"]').click();
  await expect(page.locator('[data-daa-output="rejoined"] .verdict-label')).toHaveText(
    'MEMBERSHIP ACCEPTED'
  );
  await page.locator('button[data-daa-state="revoked"]').click();
  await expect(page.locator('[data-daa-output="revoked"] .verdict-label')).toHaveText('REVOKED');
  const rogue = page.locator('[data-daa-output="revoked"] .check').filter({
    hasText: 'private-key rogue list',
  });
  await expect(rogue).toHaveAttribute('data-state', 'fail');
  await expect(rogue).toContainText('listed-secret equals nym');
});

test('the DAA panel keeps its construction and security boundaries visible', async ({ page }) => {
  await openTab(page, /Anonymous Membership/);
  await expect(page.locator('#panel-daa')).toContainText('Camenisch–Drijvers–Lehmann');
  await expect(page.locator('#panel-daa')).toContainText('authenticated Join channel');
  await expect(page.locator('#panel-daa')).toContainText('does not implement unique-TPM admission');
  await expect(page.locator('#panel-daa')).toContainText('variable-time');
  await expect(page.locator('#panel-daa')).toContainText('not side-channel-hardened');
  await expect(page.locator('#panel-daa')).toContainText('Anonymous provenance is not runtime integrity');
  await expect(page.locator('#panel-daa')).toContainText('only after gsk becomes known');
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

test('primary controls meet the 24px WCAG 2.5.8 minimum on coarse pointers', async ({ page }) => {
  const coarse = await page.evaluate(() => matchMedia('(pointer: coarse)').matches);
  test.skip(!coarse, 'touch-target rule only applies to coarse pointers');
  const box = await page.getByRole('button', { name: 'Next ›' }).boundingBox();
  expect(box).not.toBeNull();
  expect(box!.height).toBeGreaterThanOrEqual(24);
});

// ── Act 8 — Sealed Storage ──────────────────────────────────────────────────
//
// The same rule as everywhere else in this file: every expectation compares
// two values the PAGE printed, or re-derives a printed value with OpenSSL's
// SHA-256 rather than the hand-rolled one the page uses.

async function openSealed(page: Page): Promise<void> {
  await openTab(page, /Sealed Storage/);
  await expect(page.locator('#panel-sealed .seal-result .verdict')).toContainText('NOT RUN');
}

async function runSealedCase(page: Page, id: string): Promise<void> {
  await page.locator(`#panel-sealed button[data-scenario="${id}"]`).click();
  await expect(page.locator('#panel-sealed .seal-result .verdict')).toContainText('NOT RUN');
  await page.locator('#panel-sealed').getByRole('button', { name: 'Run this case' }).click();
  await expect(page.locator('#panel-sealed .seal-result .verdict')).not.toContainText('NOT RUN');
}

const sealHex = async (page: Page, key: string): Promise<string> => {
  const printed = await text(page.locator(`#panel-sealed [data-seal-run="${key}"] .hexblock`));
  expect(printed, key).toMatch(/^[0-9a-f]{64}$/);
  return printed;
};

test('every policy assertion the page prints really is SHA-256(old || assertion)', async ({
  page,
}) => {
  await openSealed(page);
  // The policy-derivation disclosure, opened the way a reader opens it.
  const policy = page.locator('#panel-sealed details.disclosure').filter({
    hasText: 'How the policy digest was built',
  });
  await policy.locator('> summary').click();

  let examined = 0;
  let resetting = 0;
  for (const branch of ['branchA', 'branchB', 'common']) {
    const steps = page.locator(`#panel-sealed [data-seal-policy="${branch}"] .stage`);
    const count = await steps.count();
    expect(count, branch).toBeGreaterThan(0);
    for (let i = 0; i < count; i++) {
      const step = steps.nth(i);
      const resets = (await step.getAttribute('data-seal-resets')) === 'true';
      const before = await text(step.locator('[data-seal-hash="before"]'));
      const preimages = await step.locator('[data-seal-hash="preimage"]').allTextContents();
      const digests = await step.locator('[data-seal-hash="digest"]').allTextContents();
      expect(before, `${branch} step ${i} before`).toMatch(/^[0-9a-f]{64}$/);
      expect(preimages.length, `${branch} step ${i} hash count`).toBe(digests.length);
      expect(preimages.length, `${branch} step ${i} hash count`).toBeGreaterThan(0);

      // A command either extends the digest it printed, or it says it resets
      // and starts from a Zero Digest. There is no third option, and the page
      // has to be in one of the two states it names.
      if (resets) {
        expect(preimages[0].startsWith('0'.repeat(64)), `${branch} step ${i} reset prefix`).toBe(
          true
        );
        resetting += 1;
      } else {
        expect(preimages[0].startsWith(before), `${branch} step ${i} preimage prefix`).toBe(true);
      }

      for (let h = 0; h < preimages.length; h++) {
        const preimage = preimages[h].trim();
        const digest = digests[h].trim();
        expect(digest, `${branch} step ${i} hash ${h}`).toMatch(/^[0-9a-f]{64}$/);
        // Independent re-derivation with OpenSSL, not the page's SHA-256.
        expect(sha256Hex(preimage), `${branch} step ${i} hash ${h}`).toBe(digest);
        // And the chain is a chain: each hash after the first starts from the
        // digest the one before it produced.
        if (h > 0) {
          expect(
            preimage.startsWith(digests[h - 1].trim()),
            `${branch} step ${i} hash ${h} chains`
          ).toBe(true);
        }
      }
      examined += 1;
    }
  }
  expect(examined).toBeGreaterThanOrEqual(5);
  // Two of these commands really do reset, so the branch above is exercised
  // rather than merely present.
  expect(resetting).toBeGreaterThanOrEqual(2);
});

test('the two-hash PolicyUpdate is shown as two hashes, not collapsed into one', async ({
  page,
}) => {
  await openSealed(page);
  const policy = page.locator('#panel-sealed details.disclosure').filter({
    hasText: 'How the policy digest was built',
  });
  await policy.locator('> summary').click();
  const authorize = page
    .locator('#panel-sealed [data-seal-policy="branchB"] .stage')
    .filter({ hasText: 'TPM2_PolicyAuthorize' });
  await expect(authorize).toHaveCount(1);
  await expect(authorize).toHaveAttribute('data-seal-resets', 'true');
  const preimages = await authorize.locator('[data-seal-hash="preimage"]').allTextContents();
  const digests = await authorize.locator('[data-seal-hash="digest"]').allTextContents();
  expect(preimages).toHaveLength(2);
  // Hash 1 is 0…0 || TPM_CC_PolicyAuthorize || keySign.name, and the Name is
  // 34 bytes, so the preimage is exactly 32 + 4 + 34 = 70 bytes.
  expect(preimages[0].slice(0, 64)).toBe('0'.repeat(64));
  expect(preimages[0].slice(64, 72)).toBe('0000016a');
  expect(preimages[0].length / 2).toBe(70);
  // Hash 2 is that digest || policyRef, and nothing else.
  expect(preimages[1].startsWith(digests[0].trim())).toBe(true);
  const policyRefHex = preimages[1].slice(64);
  expect(Buffer.from(policyRefHex, 'hex').toString('utf8')).toBe(
    'attestation-gate/seal-recovery/v1'
  );
  expect(sha256Hex(preimages[1])).toBe(digests[1].trim());
});

test('the policy a branch reaches is the digest the OR list then consumes', async ({ page }) => {
  await openSealed(page);
  const policy = page.locator('#panel-sealed details.disclosure').filter({
    hasText: 'How the policy digest was built',
  });
  await policy.locator('> summary').click();

  const lastAfter = async (branch: string): Promise<string> => {
    const digests = await page
      .locator(`#panel-sealed [data-seal-policy="${branch}"] [data-seal-hash="digest"]`)
      .allTextContents();
    return digests[digests.length - 1].trim();
  };
  const branchA = await lastAfter('branchA');
  const branchB = await lastAfter('branchB');

  // The OR step's preimage is 0…0 || TPM_CC_PolicyOR || D_A || D_B, so both
  // branch digests the page printed above must appear in it, in that order.
  const orStep = page.locator('#panel-sealed [data-seal-policy="common"] .stage').first();
  const orPreimage = await text(orStep.locator('[data-seal-hash="preimage"]'));
  expect(orPreimage).toBe('0'.repeat(64) + '00000171' + branchA + branchB);

  // And the authPolicy the object stores is the end of that same chain.
  const finalAfter = await lastAfter('common');
  const stored = await text(page.locator('#panel-sealed [data-seal-ref="authPolicy"] .hexblock'));
  const derived = await text(
    page.locator('#panel-sealed [data-seal-ref="authPolicy-derived"] .hexblock')
  );
  expect(stored).toBe(finalAfter);
  expect(derived).toBe(finalAfter);
});

test('the sealed object’s byte map tiles the structure its Name is a digest of', async ({
  page,
}) => {
  await openSealed(page);
  const map = page.locator('#panel-sealed details.disclosure').filter({
    hasText: 'public area, field by field',
  });
  await map.locator('> summary').click();

  const fields = page.locator('#panel-sealed .bytemap .byte-field');
  const count = await fields.count();
  expect(count).toBe(8);

  let joined = '';
  let expectedOffset = 0;
  for (let i = 0; i < count; i++) {
    const hex = await text(fields.nth(i).locator('.byte-hex'));
    const meta = await text(fields.nth(i).locator('.byte-offset'));
    const [, offset, length] = /offset (\d+) · (\d+) byte/.exec(meta)!;
    expect(Number(offset), `field ${i} offset`).toBe(expectedOffset);
    expect(hex.length / 2, `field ${i} length`).toBe(Number(length));
    joined += hex;
    expectedOffset += Number(length);
  }

  // Independent re-derivation: Name = nameAlg || H(publicArea), with the
  // publicArea taken from the map's own field bytes and hashed by OpenSSL.
  const name = await text(page.locator('#panel-sealed [data-seal-ref="name"] .hexblock'));
  expect(name).toBe(`000b${sha256Hex(joined)}`);
  // The first field really is the type the page names.
  expect(joined.slice(0, 4)).toBe('0008');
  await expect(fields.first().locator('.byte-value')).toHaveText('TPM_ALG_KEYEDHASH');
});

test('the composite digest the run prints is SHA-256 over the registers it listed', async ({
  page,
}) => {
  await openSealed(page);
  await runSealedCase(page, 'matching');
  const rows = page.locator('#panel-sealed .seal-result .pcr-row');
  await expect(rows).toHaveCount(4);
  let concatenated = '';
  for (let i = 0; i < 4; i++) {
    const value = await text(rows.nth(i).locator('.pcr-value'));
    expect(value).toMatch(/^[0-9a-f]{64}$/);
    concatenated += value;
  }
  expect(sha256Hex(concatenated)).toBe(await sealHex(page, 'current-digest'));
});

test('a matching state releases, and the digests on screen agree that it matched', async ({
  page,
}) => {
  await openSealed(page);
  await runSealedCase(page, 'matching');
  await expect(page.locator('#panel-sealed .seal-result .verdict-label')).toHaveText('RELEASED');
  expect(await sealHex(page, 'current-digest')).toBe(await sealHex(page, 'sealed-digest'));
  expect(await sealHex(page, 'session-digest')).toBe(await sealHex(page, 'auth-policy'));
  await expect(page.locator('#panel-sealed .seal-result .check[data-state="fail"]')).toHaveCount(0);
  await expect(page.locator('#panel-sealed .seal-result .codes')).toHaveCount(0);
});

test('the firmware-change refusal is computed from the registers, not asserted', async ({
  page,
}) => {
  await openSealed(page);
  await runSealedCase(page, 'firmware-update');
  await expect(page.locator('#panel-sealed .seal-result .verdict-label')).toHaveText('REFUSED');

  // The two digests on screen really do differ, and the register strip marks
  // exactly the one register the changed stage extends.
  expect(await sealHex(page, 'current-digest')).not.toBe(await sealHex(page, 'sealed-digest'));
  const changed = page.locator('#panel-sealed .seal-result .pcr-row[data-changed="true"]');
  await expect(changed).toHaveCount(1);
  await expect(changed.locator('.pcr-name')).toHaveText('PCR 0');

  // The failing row carries the response code, and the code is in the act's
  // own reference table.
  const failing = page.locator('#panel-sealed .seal-result .check[data-state="fail"]');
  await expect(failing).not.toHaveCount(0);
  await expect(failing.first().locator('.check-code')).toContainText('TPM_RC_VALUE');
  await expect(page.locator('#panel-sealed .seal-result .code-name').first()).toHaveText(
    'TPM_RC_VALUE'
  );
});

test('every response code a sealed-storage case emits has a row in its reference table', async ({
  page,
}) => {
  await openSealed(page);
  const listed = new Set(
    (await page.locator('#panel-sealed table tbody tr td:first-child code').allTextContents()).map(
      (t) => t.trim()
    )
  );
  expect(listed.size).toBeGreaterThan(5);

  const cases = await page.locator('#panel-sealed button[data-scenario]').count();
  expect(cases).toBeGreaterThanOrEqual(10);
  const ids = await page
    .locator('#panel-sealed button[data-scenario]')
    .evaluateAll((els) => els.map((el) => el.getAttribute('data-scenario')!));

  for (const id of ids) {
    await runSealedCase(page, id);
    const emitted = await page.locator('#panel-sealed .seal-result .code-name').allTextContents();
    for (const code of emitted) {
      expect(listed.has(code.trim()), `${id} emitted ${code} with no table row`).toBe(true);
    }
  }
});

test('an authorized recovery releases through the other branch, with the same authPolicy', async ({
  page,
}) => {
  await openSealed(page);
  await runSealedCase(page, 'matching');
  const authPolicyA = await sealHex(page, 'auth-policy');

  await runSealedCase(page, 'recovery-authorized');
  await expect(page.locator('#panel-sealed .seal-result .verdict-label')).toHaveText('RELEASED');

  // The object was never re-created: the policy it requires is the same digest.
  expect(await sealHex(page, 'auth-policy')).toBe(authPolicyA);
  // And the state is genuinely different from the sealed one.
  expect(await sealHex(page, 'current-digest')).not.toBe(await sealHex(page, 'sealed-digest'));

  // The route really went through PolicyAuthorize.
  const tpmView = page.locator('#panel-sealed details.disclosure').filter({
    hasText: 'TPM-model view',
  });
  await tpmView.locator('> summary').click();
  const commands = await page
    .locator('#panel-sealed [data-seal-policy="session"] .stage-name')
    .allTextContents();
  expect(commands.map((c) => c.replace(/^\d+\.\s*/, ''))).toEqual([
    'TPM2_PolicyPCR',
    'TPM2_PolicyAuthorize',
    'TPM2_PolicyOR',
    'TPM2_PolicyCommandCode',
  ]);
});

test('an unapproved recovery is refused, and says the approval is missing', async ({ page }) => {
  await openSealed(page);
  await runSealedCase(page, 'recovery-unsigned');
  await expect(page.locator('#panel-sealed .seal-result .verdict-label')).toHaveText('REFUSED');
  const rows = page.locator('#panel-sealed .seal-result .check');
  await expect(rows.filter({ hasText: 'TPM2_VerifySignature' })).toHaveCount(1);
  await expect(
    rows.filter({ hasText: 'TPM2_VerifySignature' }).locator('.check-detail').first()
  ).toContainText('no authority signature');
  // And the unseal step never ran at all.
  await expect(
    rows.filter({ hasText: 'TPM2_Unseal' }).first()
  ).toHaveAttribute('data-state', 'not-run');
});

test('tampering with the public metadata fails before anything is decrypted', async ({ page }) => {
  await openSealed(page);
  await runSealedCase(page, 'tamper-public');
  await expect(page.locator('#panel-sealed .seal-result .code-name').first()).toHaveText(
    'TPM_RC_INTEGRITY'
  );
  // Three rows not run, which is the page's own claim that nothing downstream
  // of TPM2_Load was evaluated.
  await expect(page.locator('#panel-sealed .seal-result .check[data-state="not-run"]')).toHaveCount(
    3
  );
  await expect(page.locator('#panel-sealed .seal-result .check[data-state="fail"]')).toHaveCount(1);
});

test('a re-wrapped substitute secret fails on binding, not on integrity', async ({ page }) => {
  await openSealed(page);
  await runSealedCase(page, 'rebind-binding');
  const codes = await page.locator('#panel-sealed .seal-result .code-name').allTextContents();
  expect(codes.map((c) => c.trim())).toContain('TPM_RC_BINDING');
  expect(codes.map((c) => c.trim())).not.toContain('TPM_RC_INTEGRITY');
  // The attacker view names the capability this case assumes, rather than
  // leaving it implicit.
  const attacker = page.locator('#panel-sealed details.disclosure').filter({
    hasText: 'Attacker view',
  });
  await attacker.locator('> summary').click();
  await expect(attacker).toContainText('seedValue');
});

test('the post-release case passes every TPM check and still shows the alarm', async ({ page }) => {
  await openSealed(page);
  await runSealedCase(page, 'post-unseal');
  await expect(page.locator('#panel-sealed .seal-result .verdict-label')).toHaveText(
    'RELEASED — AND ALREADY EXPOSED'
  );
  await expect(page.locator('#panel-sealed .seal-result .verdict')).toHaveAttribute(
    'data-tone',
    'alarm'
  );
  // No TPM response code was returned at all: nothing was refused.
  await expect(page.locator('#panel-sealed .seal-result .codes')).toHaveCount(0);
  // Exactly one failing row, and it is the one that is explicitly outside the
  // TPM — every TPM2_* row passed.
  const failing = page.locator('#panel-sealed .seal-result .check[data-state="fail"]');
  await expect(failing).toHaveCount(1);
  await expect(failing).toContainText('After release');
  for (const command of ['TPM2_Load', 'TPM2_PolicyPCR', 'TPM2_Unseal']) {
    await expect(
      page.locator('#panel-sealed .seal-result .check').filter({ hasText: command }).first()
    ).toHaveAttribute('data-state', 'pass');
  }
  // And the page says the policy was satisfied rather than defeated.
  await expect(page.locator('#panel-sealed .seal-result .callout[data-tone="alarm"]')).toContainText(
    'not a policy failure'
  );
});

test('the sealed object’s public unique is a digest over the secret, not the secret', async ({
  page,
}) => {
  await openSealed(page);
  await runSealedCase(page, 'matching');
  const truth = page.locator('#panel-sealed details.disclosure').filter({
    hasText: 'Teaching view',
  });
  await truth.locator('> summary').click();
  const plaintext = await text(page.locator('#panel-sealed [data-seal-truth="plaintext"]'));
  const obfuscate = await text(page.locator('#panel-sealed [data-seal-truth="obfuscate"]'));
  expect(obfuscate).toMatch(/^[0-9a-f]{64}$/);

  const map = page.locator('#panel-sealed details.disclosure').filter({
    hasText: 'public area, field by field',
  });
  await map.locator('> summary').click();
  const unique = await text(page.locator('#panel-sealed .bytemap .byte-field').last().locator('.byte-hex'));

  // Independent re-derivation: H(obfuscate || secret) with OpenSSL.
  const plaintextHex = Buffer.from(plaintext, 'utf8').toString('hex');
  expect(sha256Hex(obfuscate + plaintextHex)).toBe(unique);
  // And it is not a bare digest of the secret, which would be a guessing oracle.
  expect(sha256Hex(plaintextHex)).not.toBe(unique);
  expect(unique).not.toContain(plaintextHex);
});

test('changing the measured value retires the sealed-storage verdict and says so', async ({
  page,
}) => {
  await openSealed(page);
  await runSealedCase(page, 'matching');
  await expect(page.locator('#panel-sealed .seal-result .verdict-label')).toHaveText('RELEASED');

  await page.locator('#seal-firmware').fill('OpenFW 4.0.0 / POST / build 20270203');
  await expect(page.locator('#panel-sealed .seal-result .verdict-label')).toHaveText('NOT RUN');
  await expect(page.locator('#panel-sealed .seal-result .verdict-note')).toContainText(
    'measured firmware value was edited'
  );
  // Nothing from the previous run survives beside the changed input.
  await expect(page.locator('#panel-sealed .seal-result .check')).toHaveCount(0);
  await expect(page.locator('#panel-sealed [data-seal-run="current-digest"]')).toHaveCount(0);

  // Re-running with the edited value produces a refusal computed from it.
  await page.locator('#panel-sealed').getByRole('button', { name: 'Run this case' }).click();
  await expect(page.locator('#panel-sealed .seal-result .verdict-label')).toHaveText('REFUSED');
  expect(await sealHex(page, 'current-digest')).not.toBe(await sealHex(page, 'sealed-digest'));
});

test('selecting a different case retires the verdict before it is re-run', async ({ page }) => {
  await openSealed(page);
  await runSealedCase(page, 'matching');
  await page.locator('#panel-sealed button[data-scenario="tamper-private"]').click();
  await expect(page.locator('#panel-sealed .seal-result .verdict-label')).toHaveText('NOT RUN');
  await expect(page.locator('#panel-sealed .seal-result .verdict-note')).toContainText(
    'a different case was selected'
  );
  await expect(page.locator('#panel-sealed button[data-scenario="tamper-private"]')).toHaveAttribute(
    'aria-pressed',
    'true'
  );
  await expect(page.locator('#panel-sealed button[data-scenario="matching"]')).toHaveAttribute(
    'aria-pressed',
    'false'
  );
});

test('the sealed-storage act keeps its non-claims visible', async ({ page }) => {
  await openSealed(page);
  const panel = page.locator('#panel-sealed');
  for (const phrase of [
    'No TPM is executed',
    'NOT secure boot',
    'NOT rollback prevention',
    'NOT anti-hammering',
    'NOT a production authorization system',
  ]) {
    await expect(panel).toContainText(phrase);
  }
  // The weaker of the two provenance claims is stated as weaker.
  const provenance = panel.locator('details.disclosure').filter({
    hasText: 'What the policy digests are and are not pinned to',
  });
  await provenance.locator('> summary').click();
  await expect(provenance).toContainText('NOT pinned to a published test vector');
  // And the deprecation is recorded rather than inherited silently.
  const sources = panel.locator('details.disclosure').filter({
    hasText: 'Where the specification text comes from',
  });
  await sources.locator('> summary').click();
  await expect(sources).toContainText('DEPRECATED in Version 185');
});
