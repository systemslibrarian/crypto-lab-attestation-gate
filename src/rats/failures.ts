/**
 * The failure codes this exhibit reports, as one exported table.
 *
 * HONEST NAMING NOTE, because it matters for anyone carrying these back to
 * real tooling: this vocabulary is THIS LAB'S. There is no standard registry
 * of attestation failure codes, and in particular there is no implementation
 * anywhere that emits `AK_NOT_CERTIFIED` — tpm2-tools, Keylime and
 * go-attestation all express these conditions either as raw TPM response
 * codes or as free-text validation errors. Each entry below therefore carries
 * the closest real-world analogue alongside it, so the mapping is visible
 * rather than implied.
 */

export const FAILURE = {
  PCR_MISMATCH: 'PCR_MISMATCH',
  NONCE_STALE: 'NONCE_STALE',
  TRUST_ANCHOR_UNKNOWN: 'TRUST_ANCHOR_UNKNOWN',
  AK_NOT_CERTIFIED: 'AK_NOT_CERTIFIED',
  QUOTE_BAD_SIGNATURE: 'QUOTE_BAD_SIGNATURE',
  REFERENCE_MISSING: 'REFERENCE_MISSING',
  ALG_MISMATCH: 'ALG_MISMATCH',
  /**
   * The verifier-side magic backstop from Act 2a. It is listed apart from the
   * six above because it is NOT the mechanism that stops quote forgery — the
   * signing-side refusal is. It catches only a forgery careless enough to omit
   * the magic. CVE-2024-29038 is what happens when a verifier drops it, and
   * CVE-2024-29038 is also proof of how little it was carrying: an attacker
   * with use of a suitable key simply includes the magic.
   */
  NOT_TPM_GENERATED: 'NOT_TPM_GENERATED',
} as const;

export type FailureCode = (typeof FAILURE)[keyof typeof FAILURE];

export interface FailureMeta {
  code: FailureCode;
  /** What the verifier actually found. */
  meaning: string;
  /** What a real implementation calls this condition. */
  realWorld: string;
}

export const FAILURE_TABLE: Record<FailureCode, FailureMeta> = {
  [FAILURE.PCR_MISMATCH]: {
    code: FAILURE.PCR_MISMATCH,
    meaning:
      'The composite digest inside the signed quote does not equal the digest computed from the ' +
      'verifier’s reference values. Something in the measured set is not what the fleet expects — ' +
      'the quote says WHICH SET changed, never which stage.',
    realWorld:
      'tpm2_checkquote exits non-zero with "Error validating PCR composite against quote"; ' +
      'Keylime reports a failed measured-boot policy evaluation.',
  },
  [FAILURE.NONCE_STALE]: {
    code: FAILURE.NONCE_STALE,
    meaning:
      'The quote’s extraData is not the nonce this relying party issued for this exchange. The ' +
      'signature may be perfectly valid — for an older question.',
    realWorld:
      'tpm2_checkquote -q mismatch: "Error validating nonce from quote"; go-attestation returns ' +
      '"nonce mismatch".',
  },
  [FAILURE.TRUST_ANCHOR_UNKNOWN]: {
    code: FAILURE.TRUST_ANCHOR_UNKNOWN,
    meaning:
      'The attestation key that signed this quote is not one this relying party has any reason to ' +
      'trust. Nothing about the Evidence establishes that — trust anchors are an input.',
    realWorld:
      'An X.509 chain-building failure at the relying party; Keylime: "must contain a certificate ' +
      'issued by a CA present in the trust store".',
  },
  [FAILURE.AK_NOT_CERTIFIED]: {
    code: FAILURE.AK_NOT_CERTIFIED,
    meaning:
      'The attestation key has no certificate asserting that a CA proved TPM residency and the ' +
      'restricted attribute. The signature is fine; what is missing is any reason to believe the ' +
      'private half is inside a TPM.',
    realWorld:
      'No implementation emits this name. TCG requires the relying party to check for the ' +
      'tcg-cap-verifiedTPMRestricted policy OID 2.23.133.11.1.3; go-attestation’s nearest string ' +
      'is "provided key is not limited to attestation". CVE-2021-3406 (Keylime) is this check ' +
      'missing in production.',
  },
  [FAILURE.QUOTE_BAD_SIGNATURE]: {
    code: FAILURE.QUOTE_BAD_SIGNATURE,
    meaning:
      'ECDSA verification over SHA-256 of the marshalled TPMS_ATTEST failed under the presented ' +
      'attestation key. The bytes and the signature do not correspond.',
    realWorld: 'tpm2_checkquote: "Error validating signature"; any library’s Verify returning false.',
  },
  [FAILURE.REFERENCE_MISSING]: {
    code: FAILURE.REFERENCE_MISSING,
    meaning:
      'The quote covers a PCR for which this verifier holds no reference value. It cannot decide ' +
      'whether that register is acceptable, so it does not pretend to.',
    realWorld:
      'A missing golden value in a Keylime allowlist / measured-boot policy; the appraisal simply ' +
      'has nothing to appraise against.',
  },
  [FAILURE.ALG_MISMATCH]: {
    code: FAILURE.ALG_MISMATCH,
    meaning:
      'The quote selects a different PCR bank from the one the reference values describe. ' +
      'Comparing a SHA-1 register against a SHA-256 reference is not a comparison.',
    realWorld:
      'CVE-2024-29039: tpm2_checkquote did not compare the TPML_PCR_SELECTION in the PCR input ' +
      'file against the one inside the signed attest, so digests could be remapped across banks.',
  },
  [FAILURE.NOT_TPM_GENERATED]: {
    code: FAILURE.NOT_TPM_GENERATED,
    meaning:
      'The signed structure does not begin with TPM_GENERATED_VALUE, so it is not something a TPM ' +
      'produced. A backstop, not the mechanism — see Act 2a.',
    realWorld:
      'CVE-2024-29038: tpm2_checkquote stopped comparing this field in 4.1-rc0 and was not fixed ' +
      'until 5.5.1 / 5.6.1 / 5.7. go-attestation: "creation attestation was not produced by a TPM".',
  },
};

export const FAILURE_CODES = Object.keys(FAILURE_TABLE) as FailureCode[];
