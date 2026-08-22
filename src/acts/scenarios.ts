/**
 * The acts, as buildable fixtures.
 *
 * Each one produces real Evidence, runs the real verifier against a real
 * policy, and reports what the verifier concluded — plus, separately, the
 * ground truth the verifier could not see. Keeping those two apart is the
 * whole design of this file. `AttestationResult.verdict` is the VERIFIER'S
 * answer and never contains the word "compromised"; the exhibit's headline
 * verdict is composed from the verifier's answer and the ground truth, and
 * the page says which is which.
 */

import { bytesEqual, toHex, utf8 } from '../core/bytes';
import { sha256 } from '../core/sha256';
import { TPM_ALG } from '../tpm/constants';
import {
  cloneStages,
  DEFAULT_STAGES,
  QUOTED_PCRS,
  referenceValues,
  RUNTIME_MEASUREMENT_PCR,
  runMeasuredBoot,
} from '../boot/stages';
import { marshalAttest } from '../tpm/marshal';
import { craftAttest } from '../tpm/quote';
import { signInternalStructure } from '../tpm/key';
import { buildEvidence, eventLogFrom, type EventLogEntry } from '../rats/evidence';
import type { Evidence } from '../rats/evidence';
import {
  verifyEvidence,
  type AkCertificate,
  type AppraisalPolicy,
  type AttestationResult,
} from '../rats/verify';
import { labelledNonce, Machine } from './machine';
import {
  activateCredentialInSoftware,
  makeCredential,
  type CredentialBlob,
} from '../tpm/credential';

export const FLEET_CA = 'Fleet Attestation CA';
export const SELF_SERVICE_CA = 'Self-Service Enrollment CA';
export const OTHER_FLEET_CA = 'Continental Robotics Device CA';
export const HOSTILE_CA = 'Attacker-Operated CA';

/** A certificate the fleet CA issues after a successful credential activation. */
const RESIDENCY_PROVEN: Omit<AkCertificate, 'subjectPublicKey' | 'subjectName'> = {
  issuer: FLEET_CA,
  verifiedTpmRestricted: true,
  residency: 'credential-activation',
};

/** What the exhibit knows and the verifier does not. */
export interface GroundTruth {
  compromised: boolean;
  /** One line, shown beside the verifier's verdict and clearly attributed. */
  headline: string;
  explanation: string;
  /** For Act 6: what ran after the last boot measurement. */
  runtimeEvent?: { name: string; digest: string; wouldMeasureInto: number };
}

export interface ScenarioRun {
  id: string;
  act: string;
  title: string;
  /** Plain language, before any hex. */
  premise: string;
  evidence: Evidence;
  policy: AppraisalPolicy;
  referenceLog: EventLogEntry[];
  result: AttestationResult;
  groundTruth: GroundTruth;
  /** The headline the exhibit shows, composed from both. */
  headlineVerdict: 'ATTESTED' | 'REJECTED' | 'ATTESTED — AND COMPROMISED';
}

function basePolicy(overrides: Partial<AppraisalPolicy> = {}): AppraisalPolicy {
  return {
    expectedNonce: labelledNonce('today'),
    referenceValues: referenceValues(DEFAULT_STAGES),
    referenceBankAlg: TPM_ALG.SHA256,
    trustedIssuers: [FLEET_CA, SELF_SERVICE_CA],
    requiredPcrs: [...QUOTED_PCRS],
    checkAkCertification: true,
    checkMagic: true,
    ...overrides,
  };
}

export const REFERENCE_LOG = eventLogFrom(DEFAULT_STAGES);

function compose(result: AttestationResult, ground: GroundTruth): ScenarioRun['headlineVerdict'] {
  if (result.verdict === 'REJECTED') return 'REJECTED';
  return ground.compromised ? 'ATTESTED — AND COMPROMISED' : 'ATTESTED';
}

function run(
  partial: Omit<ScenarioRun, 'result' | 'headlineVerdict'>
): ScenarioRun {
  const result = verifyEvidence(partial.evidence, partial.policy, partial.referenceLog);
  return { ...partial, result, headlineVerdict: compose(result, partial.groundTruth) };
}

const CLEAN: GroundTruth = {
  compromised: false,
  headline: 'The machine is running exactly what it measured.',
  explanation:
    'Nothing outside the measured set has executed, the attestation key is inside the TPM, and ' +
    'the relying party’s trust anchors are the ones it meant to configure.',
};

// ── Act 2 — the honest baseline ─────────────────────────────────────────────

export function scenarioClean(): ScenarioRun {
  const m = new Machine({ serial: 'A7-3391', certificate: RESIDENCY_PROVEN });
  return run({
    id: 'clean',
    act: 'Act 2',
    title: 'Quote and verify',
    premise:
      'The relying party issues a fresh nonce. The attester boots, measures every stage into its ' +
      'PCRs, and returns a signed quote. The verifier appraises it against reference values.',
    evidence: m.attest(labelledNonce('today')),
    policy: basePolicy(),
    referenceLog: REFERENCE_LOG,
    groundTruth: CLEAN,
  });
}

// ── Act 3 — change one byte ─────────────────────────────────────────────────

export function scenarioTamperedBootloader(bootloaderContent?: string): ScenarioRun {
  const stages = cloneStages(DEFAULT_STAGES);
  const target = stages.find((s) => s.id === 'bootloader')!;
  const reference = DEFAULT_STAGES.find((s) => s.id === 'bootloader')!.content;
  target.content = bootloaderContent ?? 'grubx64.efi 2.12-9 / a4f1c3 / signed';
  // Ground truth is DERIVED, not asserted. Hand this act the reference image
  // back and the machine really is running what it measured, so the exhibit
  // must stop claiming otherwise -- a fixture that says "compromised" no
  // matter what its own input is teaches the reader to ignore the label.
  const tampered = target.content !== reference;
  const m = new Machine({ serial: 'A7-3391', stages, certificate: RESIDENCY_PROVEN });
  return run({
    id: 'tampered-bootloader',
    act: 'Act 3',
    title: 'Change one byte',
    premise:
      'One character of the boot loader changes. Nothing else about the machine is touched — the ' +
      'same firmware, the same kernel, the same initrd.',
    evidence: m.attest(labelledNonce('today')),
    policy: basePolicy(),
    referenceLog: REFERENCE_LOG,
    groundTruth: tampered
      ? {
          compromised: true,
          headline: 'A modified boot loader ran, and the quote could not hide it.',
          explanation:
            'The register the loader was measured into diverged, and every value computed from ' +
            'it diverged with it. The verifier learns that the measured set changed; the event ' +
            'log is what tells it which stage.',
        }
      : CLEAN,
  });
}

// ── Act 4 — replay ──────────────────────────────────────────────────────────

export function scenarioReplay(): ScenarioRun {
  const m = new Machine({ serial: 'A7-3391', certificate: RESIDENCY_PROVEN });
  // A genuine quote, genuinely signed -- yesterday, for yesterday's challenge.
  const yesterday = m.attest(labelledNonce('yesterday'));
  return run({
    id: 'replay',
    act: 'Act 4',
    title: 'Replay',
    premise:
      'An attacker records a quote that verified perfectly yesterday and presents it again today, ' +
      'unchanged. Every byte of it is genuine.',
    evidence: yesterday,
    policy: basePolicy(),
    referenceLog: REFERENCE_LOG,
    groundTruth: {
      compromised: true,
      headline: 'The machine has been re-flashed since this quote was taken.',
      explanation:
        'A signature has no expiry. Freshness comes from one place only: the relying party’s ' +
        'nonce, carried in extraData inside the signed bytes.',
    },
  });
}

// ── Act 5 — wrong machine ───────────────────────────────────────────────────

export function scenarioWrongMachine(): ScenarioRun {
  const other = new Machine({
    serial: 'K2-8804',
    certificate: { issuer: OTHER_FLEET_CA, verifiedTpmRestricted: true, residency: 'credential-activation' },
  });
  return run({
    id: 'wrong-machine',
    act: 'Act 5',
    title: 'Wrong machine',
    premise:
      'A different device — a real TPM, a real attestation key, the same golden image — answers ' +
      'the challenge. Its PCRs match the reference values exactly.',
    evidence: other.attest(labelledNonce('today')),
    policy: basePolicy(),
    referenceLog: REFERENCE_LOG,
    groundTruth: {
      compromised: true,
      headline: 'The device that answered is not the device that was asked.',
      explanation:
        'Integrity and identity are separate questions. Every PCR matches and the signature is ' +
        'sound, because the quote is honest — about a machine nobody asked about.',
    },
  });
}

// ── Act 6 — time of check, time of use (the climax) ─────────────────────────

export function scenarioTimeOfUse(): ScenarioRun {
  const m = new Machine({ serial: 'A7-3391', certificate: RESIDENCY_PROVEN });
  const payload = 'ld.so.preload → /opt/vendor/telemetry.so';
  return run({
    id: 'time-of-use',
    act: 'Act 6',
    title: 'Time of check, time of use',
    premise:
      'A clean, correctly-measured kernel boots. After the last boot measurement lands, userspace ' +
      'loads something that is not in this exhibit’s measured set. Then the relying party asks ' +
      'for a quote.',
    evidence: m.attest(labelledNonce('today')),
    policy: basePolicy(),
    referenceLog: REFERENCE_LOG,
    groundTruth: {
      compromised: true,
      headline: 'Something that was never measured is running right now.',
      explanation:
        'The quote describes the measurements in PCR 0, 4, 8 and 9 at the moment they were taken. ' +
        'Nothing extended those registers afterwards, because nothing was measured into them ' +
        'afterwards. That is a statement about this exhibit’s measured set, not about attestation: ' +
        'a runtime measurement architecture would extend PCR 10 on this event, and this quote does ' +
        'not select PCR 10.',
      runtimeEvent: {
        name: payload,
        digest: toHex(sha256(utf8(payload))),
        wouldMeasureInto: RUNTIME_MEASUREMENT_PCR,
      },
    },
  });
}

// ── Act 7a — compromised attesting environment ──────────────────────────────

/**
 * The attestation key's private half is in the attacker's hands.
 *
 * Note precisely what that removes: the restricted-key rule of Act 2a is
 * enforced BY THE TPM. Once the scalar is outside, there is no signing side
 * left to enforce anything — the attacker signs a structure they built with
 * ordinary ECDSA, magic value and all. This is why key extraction is
 * categorically worse than key USE, and why a real AK sets fixedTPM.
 */
export function scenarioCompromisedAk(): ScenarioRun {
  // The machine that actually exists: a tampered boot loader.
  const tampered = cloneStages(DEFAULT_STAGES);
  tampered.find((s) => s.id === 'bootloader')!.content =
    'grubx64.efi 2.12-9 / PATCHED / unsigned';
  const real = new Machine({ serial: 'A7-3391', stages: tampered, certificate: RESIDENCY_PROVEN });

  // The machine the attacker describes: the golden image.
  const golden = runMeasuredBoot(DEFAULT_STAGES).bank;
  const nonce = labelledNonce('today');
  const crafted = craftAttest({
    qualifiedSigner: real.ak.qualifiedSigner,
    nonce,
    clockInfo: real.clockInfo,
    firmwareVersion: real.firmwareVersion,
    selection: QUOTED_PCRS,
    claimedPcrValues: [...QUOTED_PCRS].map((pcr) => golden.read(pcr)),
  });
  // Signed with the raw scalar, outside any TPM. `signInternalStructure` is
  // the plain-ECDSA path -- which is exactly what an attacker holding key
  // material has, and exactly what the TPM's ticket rule cannot reach.
  const { signature, digest } = signInternalStructure(real.ak, crafted.bytes);
  const { fields } = marshalAttest(crafted.attest);

  const evidence = buildEvidence(
    {
      attest: crafted.attest,
      attestBytes: crafted.bytes,
      fields,
      digest,
      signature,
      akPublicArea: real.ak.publicArea,
      akPublicKey: real.ak.publicKey,
      akQualifiedSigner: real.ak.qualifiedSigner,
      provenance: 'externally crafted',
    },
    // The attacker sends the GOLDEN event log, because they know it -- it is
    // the fleet's published reference image. The log replays to the composite
    // digest they claimed, so the log check passes too.
    DEFAULT_STAGES,
    real.identity,
    real.ak.publicArea,
    real.certificate
  );

  return run({
    id: 'compromised-ak',
    act: 'Act 7a',
    title: 'Whose signature — the attesting environment is compromised',
    premise:
      'The attacker holds the attestation key itself. They write the quote they want, sign it, ' +
      'and send the fleet’s own golden event log alongside it.',
    evidence,
    policy: basePolicy(),
    referenceLog: REFERENCE_LOG,
    groundTruth: {
      compromised: true,
      headline: 'Valid signatures over false statements.',
      explanation:
        'Nothing here is cryptographically wrong. The signature is sound, the key is genuinely ' +
        'certified, the nonce is fresh and the log replays. A signature says a key was used; it ' +
        'has never said the statement is true. Once the key is outside the TPM, the signing-side ' +
        'rule that stops forgeries has nothing left to enforce.',
    },
  });
}

// ── Act 7b — endorsement, not signing ───────────────────────────────────────

export interface EnrollmentTrace {
  akName: Uint8Array;
  credential: Uint8Array;
  blob: CredentialBlob;
  recovered: Uint8Array;
  matched: boolean;
  /** The derived values, so the page can show the Name binding rather than claim it. */
  derivation: { z: string; seed: string; symKey: string; hmacKey: string };
}

/**
 * Run credential activation for real, in software, using a stolen EK private
 * key and an attacker-generated AK.
 *
 * Every step is the arithmetic a TPM would do; that is the finding. The
 * specification states it outright: "The credential provider could have
 * produced the credential with no information from the TPM as the TPM did not
 * need to provide a proof-of-possession of any private key."
 */
export function runHostileEnrollment(): EnrollmentTrace {
  const victim = new Machine({ serial: 'A7-3391' });
  // An AK the attacker generated in software. Its TPMT_PUBLIC carries all the
  // right attribute bits -- they are just bits in a structure the attacker
  // marshals -- so a CA's attribute check passes.
  const hostile = new Machine({ serial: 'HOSTILE-SOFTWARE-AK' });
  const akName = hostile.ak.name;
  const credential = sha256(utf8('crypto-lab-attestation-gate/ca-challenge/2026'));

  const { blob } = makeCredential(
    victim.ek.publicKey,
    akName,
    credential,
    'ca-ephemeral/2026'
  );
  // No TPM anywhere in this call.
  const { credential: recovered, derivation } = activateCredentialInSoftware(
    victim.ek.secretKey,
    victim.ek.publicKey,
    akName,
    blob
  );
  return {
    akName,
    credential,
    blob,
    recovered,
    matched: bytesEqual(recovered, credential),
    derivation: {
      z: toHex(derivation.z),
      seed: toHex(derivation.seed),
      symKey: toHex(derivation.symKey),
      hmacKey: toHex(derivation.hmacKey),
    },
  };
}

/**
 * 7b-i — a hostile AK enrolled at a CA that never proved TPM residency.
 * The certificate chains; it just does not assert what a relying party needs.
 */
export function scenarioUncertifiedAk(checkAkCertification = true): ScenarioRun {
  const hostile = new Machine({
    serial: 'HOSTILE-SOFTWARE-AK',
    certificate: {
      issuer: SELF_SERVICE_CA,
      verifiedTpmRestricted: false,
      residency: 'unproven',
    },
  });
  return run({
    id: checkAkCertification ? 'uncertified-ak' : 'uncertified-ak-unchecked',
    act: 'Act 7b-i',
    title: checkAkCertification
      ? 'A software key, and the relying party checks'
      : 'A software key, and the relying party does not check',
    premise:
      'The attacker generates an attestation key in ordinary memory and enrols it at a CA that ' +
      'issues on the strength of a certificate request alone. The key’s public area carries every ' +
      'attribute bit an attestation key should have — they are just bits in a structure.',
    evidence: hostile.attest(labelledNonce('today')),
    policy: basePolicy({ checkAkCertification }),
    referenceLog: REFERENCE_LOG,
    groundTruth: {
      compromised: true,
      headline: 'The key that signed this quote lives in ordinary memory, not in a TPM.',
      explanation: checkAkCertification
        ? 'The certificate does not assert TPM residency or the restricted attribute, so the ' +
          'relying party has no reason to believe the private half is inside a TPM. TCG makes ' +
          'this check a normative MUST on the relying party precisely because the protocol ' +
          'produces no error on its own.'
        : 'A relying party that does not check AK certification gets a completely clean pass. ' +
          'There is no TPM response code for this, no protocol signal, and nothing in the ' +
          'Evidence to inspect. The failure is a missing check, which is the shape of ' +
          'CVE-2021-3406.',
    },
  });
}

/**
 * 7b-ii — the same hostile AK, but the attacker holds the EK private key and
 * completes credential activation in software. The CA now issues a GENUINE
 * certificate, with residency and the restricted attribute both asserted.
 */
export function scenarioEkBackedEnrollment(): ScenarioRun {
  const hostile = new Machine({
    serial: 'HOSTILE-SOFTWARE-AK',
    certificate: RESIDENCY_PROVEN,
  });
  return run({
    id: 'ek-backed-enrollment',
    act: 'Act 7b-ii',
    title: 'The endorsement key does not sign — it enrols',
    premise:
      'Same software attestation key. This time the attacker also holds the endorsement key’s ' +
      'private half, completes the CA’s credential-activation challenge in software, and receives ' +
      'a genuine certificate asserting TPM residency.',
    evidence: hostile.attest(labelledNonce('today')),
    policy: basePolicy(),
    referenceLog: REFERENCE_LOG,
    groundTruth: {
      compromised: true,
      headline: 'The endorsement key never signed a quote — and it did not have to.',
      explanation:
        'An EK is a restricted DECRYPTION key; asking it to sign returns TPM_RC_KEY. Its role is ' +
        'at enrolment: MakeCredential wraps a challenge to the EK and binds it to the candidate ' +
        'key’s Name. Whoever can decrypt that challenge gets certified. The end state is the same ' +
        'as stealing an attestation key; the mechanism is completely different, and the mechanism ' +
        'is what you have to defend.',
    },
  });
}

// ── THREAT-1 — the hostile trust anchor ─────────────────────────────────────

/**
 * The verifier's trust anchors are an assumption, not a result.
 *
 * This fixture is the evidence for that claim: an attacker-operated CA is in
 * the relying party's trusted-issuer list, and everything else is genuine. The
 * appraisal is completely clean — not "clean except for a warning". There is
 * nothing in the Evidence that could have revealed it, because Evidence never
 * establishes a trust anchor.
 */
export function scenarioHostileAnchor(): ScenarioRun {
  const attacker = new Machine({
    serial: 'HOSTILE-SOFTWARE-AK',
    certificate: {
      issuer: HOSTILE_CA,
      verifiedTpmRestricted: true,
      residency: 'credential-activation',
    },
  });
  return run({
    id: 'hostile-anchor',
    act: 'THREAT-1',
    title: 'A hostile trust anchor',
    premise:
      'Everything about this exchange is genuine except one line of the relying party’s ' +
      'configuration: the attacker’s CA is in its trusted-issuer list.',
    evidence: attacker.attest(labelledNonce('today')),
    policy: basePolicy({ trustedIssuers: [FLEET_CA, SELF_SERVICE_CA, HOSTILE_CA] }),
    referenceLog: REFERENCE_LOG,
    groundTruth: {
      compromised: true,
      headline: 'The certificate authority that vouched for this key is the attacker.',
      explanation:
        'Evidence never establishes who to trust. RFC 9334 puts that decision with the Verifier ' +
        'Owner, supplied out of band, and no amount of appraisal can check it — appraisal is what ' +
        'happens after it has been assumed.',
    },
  });
}

export const SCENARIOS = {
  clean: scenarioClean,
  tamperedBootloader: () => scenarioTamperedBootloader(),
  replay: scenarioReplay,
  wrongMachine: scenarioWrongMachine,
  timeOfUse: scenarioTimeOfUse,
  compromisedAk: scenarioCompromisedAk,
  uncertifiedAk: () => scenarioUncertifiedAk(true),
  uncertifiedAkUnchecked: () => scenarioUncertifiedAk(false),
  ekBackedEnrollment: scenarioEkBackedEnrollment,
  hostileAnchor: scenarioHostileAnchor,
} as const;

export type ScenarioId = keyof typeof SCENARIOS;
