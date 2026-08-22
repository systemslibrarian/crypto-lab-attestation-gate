/**
 * The Verifier: appraise Evidence against an Appraisal Policy, and produce an
 * Attestation Result.
 *
 * Two things this file is built to make unmissable.
 *
 * FIRST, THE VERIFIER NEVER SHORT-CIRCUITS. Every check runs and every check
 * is reported, because a verdict that stops at the first failure teaches that
 * attestation is a single yes/no. It is a list of independent questions, and
 * which ones you chose to ask is the security-relevant decision. A check that
 * genuinely cannot run — because an earlier one denied it its input — is
 * reported as NOT RUN rather than silently passing.
 *
 * SECOND, THE VERIFIER'S TRUST ANCHORS ARE AN INPUT, NOT A RESULT. Nothing in
 * the Evidence establishes them. `policy.trustAnchors` is a parameter, and the
 * exhibit's THREAT-1 fixture is a completely clean verification under a
 * hostile one. RFC 9334 is explicit that the Verifier's trust in the Attester
 * comes from Endorsements and Verifier Owner policy, never from the Evidence.
 *
 * What this function deliberately does NOT do is decide whether the machine is
 * safe. It decides whether the Evidence appraises clean. Act 6 exists because
 * those are different questions, and the difference is not detectable here.
 */

import { bytesEqual, toHex } from '../core/bytes';
import { sha256 } from '../core/sha256';
import { TPM_ALG, TPM_ALG_NAMES, TPM_GENERATED_VALUE } from '../tpm/constants';
import { computeName, unmarshalAttest } from '../tpm/marshal';
import { verifyOverDigest } from '../tpm/key';
import { resetValue } from '../tpm/pcr';
import { concatBytes } from '../core/bytes';
import { FAILURE, type FailureCode } from './failures';
import { replayEventLog, type Evidence, type EventLogEntry } from './evidence';

export type CheckState = 'pass' | 'fail' | 'not-run';

export interface Check {
  id: string;
  name: string;
  state: CheckState;
  /** What was compared, in words. Always names the actual cause on failure. */
  detail: string;
  code?: FailureCode;
  /** The two values, when the check is a comparison. */
  computed?: string;
  presented?: string;
}

/**
 * An AK certificate, as presented by the attester.
 *
 * `verifiedTpmRestricted` models the TCG certificate policy OID
 * 2.23.133.11.1.3, which asserts that the issuing CA verified BOTH the
 * fixedTPM and the restricted attributes of the key. TCG states as a normative
 * MUST that "a relying party evaluating signed data purporting to be TPM
 * internal data MUST check for the presence of tcg-cap-verifiedTPMRestricted".
 *
 * `residency` records HOW the CA satisfied itself the key lives in a TPM.
 * `credential-activation` is the EK-backed challenge modelled in
 * `tpm/credential.ts`; `unproven` is a CA that issued on the strength of a CSR
 * alone, which is a real and common misconfiguration and is exactly the
 * scenario Act 7b starts from.
 */
export interface AkCertificate {
  issuer: string;
  /** The public key the certificate is about. */
  subjectPublicKey: Uint8Array;
  /** The AK Name the certificate is about: nameAlg || H(TPMT_PUBLIC). */
  subjectName: Uint8Array;
  verifiedTpmRestricted: boolean;
  residency: 'credential-activation' | 'unproven';
}

export interface AppraisalPolicy {
  /** The nonce this relying party issued for THIS exchange. */
  expectedNonce: Uint8Array;
  /** Golden PCR values from the Reference Value Provider. */
  referenceValues: Map<number, string>;
  /** Which bank those reference values describe. */
  referenceBankAlg: number;
  /**
   * The certificate issuers this relying party trusts.
   *
   * This is the trust anchor, and it is a PARAMETER. Nothing in the Evidence
   * establishes it, nothing in the Evidence can be inspected to check it, and
   * a quote signed under a hostile entry here verifies completely clean. That
   * is THREAT-1, and it is a property of the type signature.
   */
  trustedIssuers: string[];
  /** PCRs this relying party insists a quote must cover. */
  requiredPcrs: number[];
  /** Act 7b: whether this relying party checks AK certification at all. */
  checkAkCertification: boolean;
  /** Act 2a: whether this relying party applies the verifier-side magic backstop. */
  checkMagic: boolean;
}

export interface PcrComparison {
  pcr: number;
  expected: string | undefined;
  actual: string | undefined;
  match: boolean;
}

export interface AttestationResult {
  /** The Verifier's own answer. Not a judgement about the machine. */
  verdict: 'ATTESTED' | 'REJECTED';
  checks: Check[];
  codes: FailureCode[];
  pcrs: PcrComparison[];
  /** The event-log entry at which the presented log first diverges from the reference. */
  divergence?: { index: number; entry: EventLogEntry; expected: EventLogEntry | undefined };
  /** The certificate that satisfied the anchor check, when one did. */
  matchedCertificate?: AkCertificate;
}

/** The first event-log entry where two logs disagree. */
export function firstDivergence(
  reference: readonly EventLogEntry[],
  presented: readonly EventLogEntry[]
): { index: number; entry: EventLogEntry; expected: EventLogEntry | undefined } | undefined {
  const n = Math.max(reference.length, presented.length);
  for (let i = 0; i < n; i++) {
    const a = reference[i];
    const b = presented[i];
    if (!b) return { index: i, entry: a, expected: a };
    if (!a || a.pcr !== b.pcr || !bytesEqual(a.digest, b.digest)) {
      return { index: i, entry: b, expected: a };
    }
  }
  return undefined;
}

export function verifyEvidence(
  evidence: Evidence,
  policy: AppraisalPolicy,
  /** The reference event log, so a mismatch can name the stage that broke. */
  referenceLog?: readonly EventLogEntry[]
): AttestationResult {
  const checks: Check[] = [];
  const add = (c: Check): Check => {
    checks.push(c);
    return c;
  };

  // ── 1. Structure ────────────────────────────────────────────────────────
  // A relying party receives BYTES. It parses them itself; it never takes the
  // attester's in-memory object.
  let attest;
  try {
    attest = unmarshalAttest(evidence.quote.attestBytes);
    add({
      id: 'structure',
      name: 'TPMS_ATTEST parses, and consumes every byte',
      state: 'pass',
      detail: `${evidence.quote.attestBytes.length} bytes, no trailing data`,
    });
  } catch (e) {
    add({
      id: 'structure',
      name: 'TPMS_ATTEST parses, and consumes every byte',
      state: 'fail',
      detail: String(e instanceof Error ? e.message : e),
    });
    return {
      verdict: 'REJECTED',
      checks,
      codes: [],
      pcrs: [],
    };
  }

  // ── 2. The magic backstop ───────────────────────────────────────────────
  if (!policy.checkMagic) {
    add({
      id: 'magic',
      name: 'Structure begins with TPM_GENERATED_VALUE',
      state: 'not-run',
      detail:
        'this relying party does not check the magic value. That is what tpm2_checkquote did from ' +
        '4.1-rc0 until it was fixed in 5.5.1 / 5.6.1 / 5.7 (CVE-2024-29038). It is a backstop, not ' +
        'the mechanism — see the signer-side rule.',
    });
  } else {
    const ok = attest.magic === TPM_GENERATED_VALUE;
    add({
      id: 'magic',
      name: 'Structure begins with TPM_GENERATED_VALUE',
      state: ok ? 'pass' : 'fail',
      code: ok ? undefined : FAILURE.NOT_TPM_GENERATED,
      detail: ok
        ? 'FF 54 43 47 at offset 0 — this is the shape of a TPM-generated structure'
        : `offset 0 is 0x${attest.magic.toString(16).padStart(8, '0')}, not 0xff544347`,
      computed: 'ff544347',
      presented: attest.magic.toString(16).padStart(8, '0'),
    });
  }

  // ── 3. Trust anchor ─────────────────────────────────────────────────────
  // Three things have to line up: the certificate must come from an issuer
  // this relying party trusts, and it must actually be ABOUT the key that
  // signed — both its public key and the Name recomputed from the presented
  // public area. A certificate that chains beautifully to the wrong key is the
  // shape of CVE-2021-3406.
  const cert = evidence.akCertificate;
  const recomputedName = computeName(evidence.akPublicArea);
  const issuerTrusted = !!cert && policy.trustedIssuers.includes(cert.issuer);
  const bindsKey = !!cert && bytesEqual(cert.subjectPublicKey, evidence.quote.akPublicKey);
  const bindsName = !!cert && bytesEqual(cert.subjectName, recomputedName);
  const anchorOk = issuerTrusted && bindsKey && bindsName;
  add({
    id: 'anchor',
    name: 'Attestation key chains to an issuer this relying party trusts',
    state: anchorOk ? 'pass' : 'fail',
    code: anchorOk ? undefined : FAILURE.TRUST_ANCHOR_UNKNOWN,
    detail: anchorOk
      ? `certificate from "${cert!.issuer}", which is in this verifier's trusted-issuer list, ` +
        'and it binds both the signing public key and the Name recomputed from the presented ' +
        'public area'
      : !cert
        ? 'the attester presented no AK certificate, so there is nothing to chain'
        : !issuerTrusted
          ? `"${cert.issuer}" is not in this verifier's trusted-issuer list. Evidence never ` +
            'establishes a trust anchor — it is an input, and choosing it is the security decision.'
          : !bindsKey
            ? 'the certificate is about a different public key from the one that signed'
            : 'the certificate’s subject Name is not the Name recomputed from the presented ' +
              'public area',
    computed: toHex(recomputedName.slice(0, 8)) + '…',
    presented: cert ? toHex(cert.subjectName.slice(0, 8)) + '…' : '(none)',
  });

  // ── 4. AK certification ─────────────────────────────────────────────────
  if (!policy.checkAkCertification) {
    add({
      id: 'ak-cert',
      name: 'Attestation key is certified as TPM-resident and restricted',
      state: 'not-run',
      detail:
        'this relying party does not check AK certification. There is no error and no signal — ' +
        'an uncertified key produces a perfectly clean verification. That absence is the finding.',
    });
  } else {
    const ok = !!cert && cert.verifiedTpmRestricted && cert.residency === 'credential-activation';
    add({
      id: 'ak-cert',
      name: 'Attestation key is certified as TPM-resident and restricted',
      state: ok ? 'pass' : 'fail',
      code: ok ? undefined : FAILURE.AK_NOT_CERTIFIED,
      detail: ok
        ? `certificate from ${cert!.issuer} asserts TPM residency (credential activation) and ` +
          'the restricted attribute (TCG OID 2.23.133.11.1.3)'
        : cert
          ? `certificate from ${cert.issuer} does not assert both TPM residency and the ` +
            `restricted attribute (residency: ${cert.residency}, ` +
            `verifiedTPMRestricted: ${cert.verifiedTpmRestricted})`
          : 'no AK certificate at all — nothing says this key’s private half is inside a TPM',
    });
  }

  // ── 5. Signature ────────────────────────────────────────────────────────
  const digest = sha256(evidence.quote.attestBytes);
  const sigOk = verifyOverDigest(evidence.quote.akPublicKey, digest, evidence.quote.signature);
  add({
    id: 'signature',
    name: 'ECDSA over SHA-256 of the marshalled TPMS_ATTEST',
    state: sigOk ? 'pass' : 'fail',
    code: sigOk ? undefined : FAILURE.QUOTE_BAD_SIGNATURE,
    detail: sigOk
      ? 'the signature covers exactly these bytes, magic value included — the TPM2B_ATTEST size ' +
        'prefix is not part of the signed message'
      : 'verification failed: these bytes and this signature do not correspond under the ' +
        'presented key',
    computed: toHex(digest).slice(0, 16) + '…',
  });

  // ── 6. Freshness ────────────────────────────────────────────────────────
  const nonceOk = bytesEqual(attest.extraData, policy.expectedNonce);
  add({
    id: 'nonce',
    name: 'extraData is the nonce this relying party issued',
    state: nonceOk ? 'pass' : 'fail',
    code: nonceOk ? undefined : FAILURE.NONCE_STALE,
    detail: nonceOk
      ? 'the quote answers the question that was asked'
      : 'the signed extraData is a different nonce. The signature can be perfectly valid and the ' +
        'quote still be an answer to an older question.',
    computed: toHex(policy.expectedNonce),
    presented: toHex(attest.extraData),
  });

  // ── 7. Bank algorithm ───────────────────────────────────────────────────
  const algOk = attest.attested.hashAlg === policy.referenceBankAlg;
  add({
    id: 'alg',
    name: 'Quoted PCR bank matches the reference values’ bank',
    state: algOk ? 'pass' : 'fail',
    code: algOk ? undefined : FAILURE.ALG_MISMATCH,
    detail: algOk
      ? `both are ${TPM_ALG_NAMES[policy.referenceBankAlg] ?? policy.referenceBankAlg}`
      : `the quote selects ${TPM_ALG_NAMES[attest.attested.hashAlg] ?? attest.attested.hashAlg} ` +
        `while the reference values describe ` +
        `${TPM_ALG_NAMES[policy.referenceBankAlg] ?? policy.referenceBankAlg}. Comparing a ` +
        'register from one bank against a reference from another is not a comparison.',
    computed: TPM_ALG_NAMES[policy.referenceBankAlg] ?? '?',
    presented: TPM_ALG_NAMES[attest.attested.hashAlg] ?? '?',
  });

  // ── 8. Coverage ─────────────────────────────────────────────────────────
  const selected = new Set(attest.attested.pcrSelect);
  const uncovered = policy.requiredPcrs.filter((p) => !selected.has(p));
  const unreferenced = attest.attested.pcrSelect.filter((p) => !policy.referenceValues.has(p));
  const coverageOk = uncovered.length === 0 && unreferenced.length === 0;
  add({
    id: 'coverage',
    name: 'Every required PCR is covered, and every covered PCR has a reference value',
    state: coverageOk ? 'pass' : 'fail',
    code: coverageOk ? undefined : FAILURE.REFERENCE_MISSING,
    detail: coverageOk
      ? `selection {${attest.attested.pcrSelect.join(', ')}} matches the required set and every ` +
        'one has a golden value'
      : [
          uncovered.length
            ? `the quote does not cover required PCR ${uncovered.join(', ')} — a quote says ` +
              'nothing whatever about a PCR whose selection bit is clear'
            : '',
          unreferenced.length
            ? `no reference value held for PCR ${unreferenced.join(', ')} — this verifier cannot ` +
              'appraise it, so it does not pretend to'
            : '',
        ]
          .filter(Boolean)
          .join('; '),
  });

  // ── 9. The event log replays to the signed composite digest ─────────────
  // This is what makes an UNSIGNED log safe to send: it has to reproduce a
  // number that is inside the signature.
  const replayed = replayEventLog(evidence.eventLog, (pcr) => resetValue(pcr));
  const ordered = [...attest.attested.pcrSelect].sort((a, b) => a - b);
  const replayComposite = sha256(
    concatBytes(...ordered.map((pcr) => replayed.get(pcr) ?? resetValue(pcr)))
  );
  const replayOk = bytesEqual(replayComposite, attest.attested.pcrDigest);
  add({
    id: 'replay',
    name: 'Replaying the event log reproduces the signed composite digest',
    state: replayOk ? 'pass' : 'fail',
    code: replayOk ? undefined : FAILURE.PCR_MISMATCH,
    detail: replayOk
      ? 'the log is bound to the signature by arithmetic, not by a second signature'
      : 'the log does not replay to the digest inside the quote, so the log has been altered or ' +
        'belongs to a different boot',
    computed: toHex(replayComposite),
    presented: toHex(attest.attested.pcrDigest),
  });

  // ── 10. Replayed PCRs against the reference values ──────────────────────
  const pcrs: PcrComparison[] = ordered.map((pcr) => {
    const expected = policy.referenceValues.get(pcr);
    const actual = replayed.has(pcr) ? toHex(replayed.get(pcr)!) : toHex(resetValue(pcr));
    return { pcr, expected, actual, match: expected !== undefined && expected === actual };
  });
  const comparable = pcrs.filter((p) => p.expected !== undefined);
  const mismatched = comparable.filter((p) => !p.match);
  add({
    id: 'reference',
    name: 'Every appraisable PCR equals its reference value',
    state: comparable.length === 0 ? 'not-run' : mismatched.length === 0 ? 'pass' : 'fail',
    code: mismatched.length === 0 ? undefined : FAILURE.PCR_MISMATCH,
    detail:
      comparable.length === 0
        ? 'no reference values to compare against'
        : mismatched.length === 0
          ? `PCR ${comparable.map((p) => p.pcr).join(', ')} all match`
          : `PCR ${mismatched.map((p) => p.pcr).join(', ')} differ from the reference values`,
  });

  // ── 11. The EAT is bound to the quote ───────────────────────────────────
  const eatNonceOk = bytesEqual(evidence.eat.input.nonce, attest.extraData);
  add({
    id: 'eat-nonce',
    name: 'EAT eat_nonce equals the quote’s extraData',
    state: eatNonceOk ? 'pass' : 'fail',
    code: eatNonceOk ? undefined : FAILURE.NONCE_STALE,
    detail: eatNonceOk
      ? 'the claims-set and the signed structure answer the same challenge'
      : 'the EAT carries a different nonce from the quote, so it is not bound to this signature. ' +
        'The EAT is not signed here; these two equalities are what make it Evidence rather than ' +
        'assertions.',
  });

  const eatMatchesLog =
    evidence.components.length === evidence.eventLog.length &&
    evidence.components.every((c, i) => {
      const d = c.digest?.value;
      return !!d && bytesEqual(d, evidence.eventLog[i].digest);
    });
  add({
    id: 'eat-measurements',
    name: 'Every EAT measured component matches the event log',
    state: eatMatchesLog ? 'pass' : 'fail',
    code: eatMatchesLog ? undefined : FAILURE.PCR_MISMATCH,
    detail: eatMatchesLog
      ? `${evidence.components.length} RFC 10013 measured components, digest for digest`
      : 'the EAT claims measurements the event log does not contain',
  });

  const codes = Array.from(
    new Set(checks.filter((c) => c.state === 'fail' && c.code).map((c) => c.code!))
  );
  const failed = checks.some((c) => c.state === 'fail');

  return {
    verdict: failed ? 'REJECTED' : 'ATTESTED',
    checks,
    codes,
    pcrs,
    matchedCertificate: anchorOk ? cert : undefined,
    divergence: referenceLog ? firstDivergence(referenceLog, evidence.eventLog) : undefined,
  };
}

/** The reference bank this lab's reference values are always for. */
export const REFERENCE_BANK = TPM_ALG.SHA256;
