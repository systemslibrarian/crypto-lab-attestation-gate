/**
 * Platform Configuration Registers — the one-way accumulator measured boot is
 * built on.
 *
 * A PCR is a fixed-width register with no write operation. The only way to
 * change it is Extend:
 *
 *     PCR_new := H( PCR_old || measurement )
 *
 * The old value is an INPUT. That is the entire mechanism, and it is why a
 * later stage of boot cannot un-say what an earlier stage recorded: to land on
 * a chosen final value you would have to find a measurement that hashes the
 * current register onto your target, which is a second-preimage problem.
 *
 * SCOPE, stated here because the loose version of this claim is false.
 * "You can never rewind a PCR" is NOT true of TPMs in general, for four
 * spec-sanctioned reasons: TPM2_PCR_Reset exists; the D-RTM sequence resets
 * PCR 17 and zeroes 18-22 mid-run at locality 4; a TPM Reset returns every
 * PCR to its initial condition (which for 17-22 is all-ones, a value no
 * amount of extending can reach); and TPM Resume RESTORES the saved values of
 * PCR 0-15, which is literally loading an earlier state back in.
 *
 * What IS one-way is the EXTEND OPERATION, because landing on a chosen target
 * means finding d with H(PCR_old || d) = target. And on a PC Client platform
 * the no-rewind claim holds for PCR 0-15 and only for PCR 0-15: TCG PC Client
 * Platform TPM Profile Table 6 gives them "no" in both the D-RTM-reset and
 * the TPM2_PCR_Reset columns, at every locality. This lab's measured set --
 * PCR 0, 4, 8 and 9 -- is inside that range, which is why the exhibit can say
 * "one-way" about ITS registers without saying it about TPMs.
 *
 * `resetRule` below is the executable form of the distinction; the UI shows
 * it rather than claiming the absolute.
 */

import { concatBytes, toHex } from '../core/bytes';
import { sha256, SHA256_LEN } from '../core/sha256';
import { PCR_COUNT } from './constants';

/** A single Extend, kept so the UI can show its exact preimage. */
export interface ExtendRecord {
  pcr: number;
  /** The register before this extension. */
  before: Uint8Array;
  /** The measurement being folded in (already a digest). */
  measurement: Uint8Array;
  /** `before || measurement` — the exact bytes hashed. */
  preimage: Uint8Array;
  /** The register afterwards. */
  after: Uint8Array;
  /** What was measured, in words. */
  event: string;
}

/**
 * The value a PCR holds after TPM2_Startup(CLEAR), per TCG PC Client Platform
 * TPM Profile Table 7.
 *
 * PCR 0-16 and 23 come up all-zero; the D-RTM set 17-22 comes up all-ONES.
 * (PCR 0 is strictly the "locality indicator" — the locality at which
 * TPM2_Startup was received, in the last octet — which on a normal boot at
 * locality 0 is indistinguishable from all-zero. `startupLocality` makes that
 * visible instead of hiding it behind the coincidence.)
 */
export function resetValue(pcr: number, startupLocality = 0): Uint8Array {
  const out = new Uint8Array(SHA256_LEN);
  if (pcr >= 17 && pcr <= 22) {
    out.fill(0xff);
    return out;
  }
  if (pcr === 0) out[SHA256_LEN - 1] = startupLocality;
  return out;
}

export interface ResetRule {
  /** Whether TPM2_PCR_Reset can ever succeed on this PCR. */
  resettable: boolean;
  /** Localities at which TPM2_PCR_Reset is permitted. */
  localities: number[];
  /** Whether the hardware D-RTM sequence zeroes it at locality 4. */
  drtmReset: boolean;
  /** One line for the UI. */
  summary: string;
}

/**
 * Who may rewind which PCR — TCG PC Client Platform TPM Profile Table 6.
 *
 * The detail most summaries get wrong is that 17-22 are not one group.
 * PCR 17, 18 and 19 are NOT resettable by TPM2_PCR_Reset at ANY locality;
 * only the hardware D-RTM event sequence clears them. PCR 20, 21 and 22 are
 * resettable by TPM2_PCR_Reset, but only at localities 2 and 3. And
 * TPM2_PCR_Reset is never permitted at locality 4 at all — the profile
 * repurposes that column to record the register's initial state rather than a
 * permission, which is why "resettable at locality 4" is a category error.
 *
 * A second sharp corner: for PCR 20-22 the RESET value (all zeros) is not the
 * INITIAL value (all ones). "Reset" and "power-on" are two different values
 * for the same register.
 */
export function resetRule(pcr: number): ResetRule {
  if (pcr >= 0 && pcr <= 15) {
    return {
      resettable: false,
      localities: [],
      drtmReset: false,
      summary: 'no reset authorisation at any locality — only a TPM Reset restarts it',
    };
  }
  if (pcr === 16 || pcr === 23) {
    return {
      resettable: true,
      localities: [0, 1, 2, 3],
      drtmReset: false,
      summary: 'TPM2_PCR_Reset at localities 0-3 — ordinary software can zero it',
    };
  }
  if (pcr >= 17 && pcr <= 19) {
    return {
      resettable: false,
      localities: [],
      drtmReset: true,
      summary: 'never by TPM2_PCR_Reset; zeroed only by the D-RTM sequence at locality 4',
    };
  }
  // 20, 21, 22
  return {
    resettable: true,
    localities: [2, 3],
    drtmReset: true,
    summary: 'TPM2_PCR_Reset at localities 2-3, and zeroed by the D-RTM sequence',
  };
}

/**
 * Whether TPM2_PCR_Reset can ever succeed on this PCR, at any locality. The
 * complement of this predicate is the set the "you can never rewind a PCR"
 * shorthand is actually true for.
 */
export function isResettableGuard(pcr: number): boolean {
  return resetRule(pcr).resettable;
}

/** A SHA-256 PCR bank plus its extension log. */
export class PcrBank {
  private readonly values: Uint8Array[];
  readonly log: ExtendRecord[] = [];

  constructor(readonly startupLocality = 0) {
    this.values = Array.from({ length: PCR_COUNT }, (_, i) => resetValue(i, startupLocality));
  }

  read(pcr: number): Uint8Array {
    this.assertIndex(pcr);
    return this.values[pcr].slice();
  }

  /**
   * TPM2_PCR_Extend. The measurement must already be a digest of the bank's
   * size — a TPM extends a digest, not arbitrary data, which is why a caller
   * that wants to measure a blob hashes it first (TPM2_PCR_Event does both).
   */
  extend(pcr: number, measurement: Uint8Array, event: string): ExtendRecord {
    this.assertIndex(pcr);
    if (measurement.length !== SHA256_LEN) {
      throw new Error(
        `a SHA-256 bank extends a ${SHA256_LEN}-byte digest; got ${measurement.length} bytes`
      );
    }
    const before = this.values[pcr].slice();
    const preimage = concatBytes(before, measurement);
    const after = sha256(preimage);
    this.values[pcr] = after;
    const record: ExtendRecord = { pcr, before, measurement, preimage, after, event };
    this.log.push(record);
    return record;
  }

  /**
   * TPM2_PCR_Reset, at a stated locality. Refuses where the profile refuses,
   * which is the fail-closed behaviour and is also what keeps the scope note
   * above an assertion the code has to satisfy rather than a comment.
   *
   * Note the value: TPM2_PCR_Reset sets the register to ZERO in every bank
   * (Part 3 §22.8), which for PCR 20-22 is NOT the all-ones value they power
   * on to.
   */
  reset(pcr: number, locality = 0): void {
    this.assertIndex(pcr);
    const rule = resetRule(pcr);
    if (!rule.resettable) {
      throw new Error(`PCR ${pcr} has no reset authorisation: ${rule.summary}`);
    }
    if (!rule.localities.includes(locality)) {
      throw new Error(
        `TPM2_PCR_Reset on PCR ${pcr} is not permitted at locality ${locality} ` +
          `(permitted: ${rule.localities.join(', ')})`
      );
    }
    this.values[pcr] = new Uint8Array(SHA256_LEN);
  }

  /**
   * The digest a quote carries: H over the selected PCR values concatenated in
   * ASCENDING INDEX ORDER. Order is normative — a verifier that concatenates
   * in selection order instead would compute a different digest for the same
   * machine state.
   */
  digest(selection: readonly number[]): Uint8Array {
    const sorted = [...new Set(selection)].sort((a, b) => a - b);
    for (const i of sorted) this.assertIndex(i);
    return sha256(concatBytes(...sorted.map((i) => this.values[i])));
  }

  /** A snapshot of the selected registers, for display and for diffing. */
  snapshot(selection: readonly number[]): Array<{ pcr: number; value: string }> {
    return [...new Set(selection)]
      .sort((a, b) => a - b)
      .map((pcr) => ({ pcr, value: toHex(this.read(pcr)) }));
  }

  private assertIndex(pcr: number): void {
    if (!Number.isInteger(pcr) || pcr < 0 || pcr >= PCR_COUNT) {
      throw new Error(`PCR index out of range: ${pcr}`);
    }
  }
}
