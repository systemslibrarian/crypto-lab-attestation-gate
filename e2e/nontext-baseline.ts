/**
 * Known WCAG 1.4.11 / generated-content findings in this lab, captured through
 * the gate's own path so the baseline and the check cannot disagree.
 *
 * THIS FILE IS A TO-DO LIST, NOT A SET OF EXEMPTIONS. The gate ratchets on it:
 *   - a finding NOT listed here fails the run, so a regression cannot land;
 *   - a listed finding whose ratio gets WORSE fails, so the list cannot rot;
 *   - a listed finding that no longer appears ALSO fails, so a fixed entry must
 *     be deleted and the file can only shrink toward empty.
 * The last rule is what stops an allowlist becoming a permanent exemption.
 *
 * `unverified: true` marks an absolutely-positioned pseudo-element. It can paint
 * outside its host and the oracle measures it against the host's backdrop, so
 * that ratio is NOT trustworthy — hand-measure before acting on it.
 *
 * IT IS EMPTY, AND THAT IS THE POINT — this is the terminal state of the
 * ratchet, not an unrun check. The gate's first full drive found findings and
 * every one was fixed in `src/style.css` rather than listed here: five text
 * inputs and five tab buttons whose boundary was drawn in the decorative
 * `--border`/`--border-strong` tokens (2.03:1 and 2.90:1 against the surfaces
 * they sit on), and a pressed-and-hovered `.btn` whose accent fill was
 * repainted by `.btn:hover` while its dark `--accent-ink` stayed, for 1.36:1.
 * The two entries most of this fleet carries for the shared top bar's
 * `.cl-btn` are absent because that control draws its edge from `--cl-ink`
 * here and clears 3:1.
 *
 * A run with `NT_BASELINE_CAPTURE=1` set prints every finding through this
 * same path and asserts nothing, which is how this file is regenerated; the
 * capture run after those fixes printed zero findings.
 */
export const NONTEXT_BASELINE: Record<
  string,
  { ratio: number; required: number; unverified: boolean }
> = {};
