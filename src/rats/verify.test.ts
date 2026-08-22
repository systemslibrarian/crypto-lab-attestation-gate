import { describe, expect, it } from 'vitest';
import {
  scenarioClean,
  scenarioCompromisedAk,
  scenarioEkBackedEnrollment,
  scenarioHostileAnchor,
  scenarioReplay,
  scenarioTamperedBootloader,
  scenarioTimeOfUse,
  scenarioUncertifiedAk,
  scenarioWrongMachine,
  runHostileEnrollment,
  REFERENCE_LOG,
} from '../acts/scenarios';
import { FAILURE, FAILURE_CODES, FAILURE_TABLE } from './failures';
import { verifyEvidence } from './verify';
import { replayEventLog } from './evidence';
import { resetValue } from '../tpm/pcr';
import { concatBytes, toHex } from '../core/bytes';
import { sha256 } from '../core/sha256';
import { TPM_ALG } from '../tpm/constants';
import { referenceValues, DEFAULT_STAGES, QUOTED_PCRS } from '../boot/stages';

describe('Act 2 — the honest baseline', () => {
  const run = scenarioClean();

  it('appraises clean, with no failure codes', () => {
    expect(run.result.verdict).toBe('ATTESTED');
    expect(run.result.codes).toEqual([]);
    expect(run.headlineVerdict).toBe('ATTESTED');
  });

  it('runs every check rather than stopping at the first answer', () => {
    expect(run.result.checks.filter((c) => c.state === 'not-run')).toHaveLength(0);
    expect(run.result.checks.length).toBeGreaterThanOrEqual(10);
  });

  it('replays the event log to the digest inside the signature', () => {
    const replayed = replayEventLog(run.evidence.eventLog, resetValue);
    const composite = sha256(
      concatBytes(...[...QUOTED_PCRS].map((pcr) => replayed.get(pcr) ?? resetValue(pcr)))
    );
    expect(toHex(composite)).toBe(toHex(run.evidence.quote.attest.attested.pcrDigest));
  });

  it('agrees with reference values computed independently of the attester', () => {
    const refs = referenceValues(DEFAULT_STAGES);
    for (const p of run.result.pcrs) {
      expect(p.actual, `PCR ${p.pcr}`).toBe(refs.get(p.pcr));
      expect(p.match).toBe(true);
    }
  });
});

describe('Act 3 — change one byte', () => {
  const run = scenarioTamperedBootloader();

  it('reports PCR_MISMATCH and nothing else', () => {
    expect(run.result.verdict).toBe('REJECTED');
    expect(run.result.codes).toEqual([FAILURE.PCR_MISMATCH]);
  });

  it('names the register that broke, and only that one', () => {
    const broken = run.result.pcrs.filter((p) => !p.match).map((p) => p.pcr);
    expect(broken).toEqual([4]);
  });

  it('names the STAGE that broke, from the event log', () => {
    expect(run.result.divergence?.entry.eventName).toMatch(/Boot loader/);
    expect(run.result.divergence?.index).toBe(2);
  });

  it('still passes every check that has nothing to do with the boot chain', () => {
    const byId = Object.fromEntries(run.result.checks.map((c) => [c.id, c]));
    expect(byId.signature.state).toBe('pass');
    expect(byId.nonce.state).toBe('pass');
    expect(byId.anchor.state).toBe('pass');
    expect(byId.magic.state).toBe('pass');
  });
});

describe('Act 4 — replay', () => {
  const run = scenarioReplay();

  it('reports NONCE_STALE', () => {
    expect(run.result.verdict).toBe('REJECTED');
    expect(run.result.codes).toEqual([FAILURE.NONCE_STALE]);
  });

  it('accepts the signature — the quote is genuine, just not fresh', () => {
    const byId = Object.fromEntries(run.result.checks.map((c) => [c.id, c]));
    expect(byId.signature.state).toBe('pass');
    expect(byId.replay.state).toBe('pass');
    expect(byId.reference.state).toBe('pass');
  });

  it('fails on freshness alone — the EAT is still correctly bound to the quote', () => {
    const failed = run.result.checks.filter((c) => c.state === 'fail').map((c) => c.id);
    expect(failed).toEqual(['nonce']);
    // The replayed bundle is internally consistent: its EAT carries the same
    // (old) nonce as its quote. What is stale is the exchange, not the binding.
    expect(run.result.checks.find((c) => c.id === 'eat-nonce')?.state).toBe('pass');
  });
});

describe('Act 5 — wrong machine', () => {
  const run = scenarioWrongMachine();

  it('reports TRUST_ANCHOR_UNKNOWN', () => {
    expect(run.result.verdict).toBe('REJECTED');
    expect(run.result.codes).toEqual([FAILURE.TRUST_ANCHOR_UNKNOWN]);
  });

  it('has a valid signature and matching PCRs — identity is not integrity', () => {
    const byId = Object.fromEntries(run.result.checks.map((c) => [c.id, c]));
    expect(byId.signature.state).toBe('pass');
    expect(byId.reference.state).toBe('pass');
    expect(run.result.pcrs.every((p) => p.match)).toBe(true);
  });
});

describe('Act 6 — time of check, time of use (NEG-1)', () => {
  const run = scenarioTimeOfUse();

  it('verifies completely clean — every check passes and every one is honest', () => {
    expect(run.result.verdict).toBe('ATTESTED');
    expect(run.result.codes).toEqual([]);
    expect(run.result.checks.every((c) => c.state === 'pass')).toBe(true);
  });

  it('is nonetheless compromised, and the exhibit says so separately', () => {
    expect(run.groundTruth.compromised).toBe(true);
    expect(run.headlineVerdict).toBe('ATTESTED — AND COMPROMISED');
  });

  it('scopes the claim: what ran would be measured into a PCR this quote omits', () => {
    expect(run.groundTruth.runtimeEvent?.wouldMeasureInto).toBe(10);
    expect(run.evidence.quote.attest.attested.pcrSelect).not.toContain(10);
  });
});

describe('Act 7a — a compromised attesting environment', () => {
  const run = scenarioCompromisedAk();

  it('produces a completely clean appraisal from a hand-built structure', () => {
    expect(run.result.verdict).toBe('ATTESTED');
    expect(run.result.codes).toEqual([]);
    expect(run.evidence.quote.provenance).toBe('externally crafted');
  });

  it('carries the magic value, because the attacker put it there', () => {
    const byId = Object.fromEntries(run.result.checks.map((c) => [c.id, c]));
    expect(byId.magic.state).toBe('pass');
  });

  it('describes a machine that is not the one running', () => {
    expect(run.groundTruth.compromised).toBe(true);
    expect(run.headlineVerdict).toBe('ATTESTED — AND COMPROMISED');
  });
});

describe('Act 7b — endorsement, not signing', () => {
  it('7b-i, checked: AK_NOT_CERTIFIED and nothing else', () => {
    const run = scenarioUncertifiedAk(true);
    expect(run.result.codes).toEqual([FAILURE.AK_NOT_CERTIFIED]);
    expect(run.result.verdict).toBe('REJECTED');
  });

  it('7b-i, unchecked: nothing at all', () => {
    const run = scenarioUncertifiedAk(false);
    expect(run.result.verdict).toBe('ATTESTED');
    expect(run.result.codes).toEqual([]);
    expect(run.result.checks.find((c) => c.id === 'ak-cert')?.state).toBe('not-run');
    expect(run.headlineVerdict).toBe('ATTESTED — AND COMPROMISED');
  });

  it('7b-ii: an EK-backed enrolment produces a certificate that satisfies the check', () => {
    const run = scenarioEkBackedEnrollment();
    expect(run.result.verdict).toBe('ATTESTED');
    expect(run.result.checks.find((c) => c.id === 'ak-cert')?.state).toBe('pass');
    expect(run.headlineVerdict).toBe('ATTESTED — AND COMPROMISED');
  });

  it('the enrolment really runs: the stolen EK key recovers the CA’s challenge', () => {
    const trace = runHostileEnrollment();
    expect(trace.matched).toBe(true);
    expect(toHex(trace.recovered)).toBe(toHex(trace.credential));
    expect(trace.derivation.seed).toMatch(/^[0-9a-f]{64}$/);
    expect(trace.derivation.symKey).toMatch(/^[0-9a-f]{32}$/);
  });
});

describe('THREAT-1 — the verifier’s trust anchors are an assumption', () => {
  const run = scenarioHostileAnchor();

  it('verifies completely clean under a hostile anchor', () => {
    expect(run.result.verdict).toBe('ATTESTED');
    expect(run.result.codes).toEqual([]);
    expect(run.result.checks.every((c) => c.state === 'pass')).toBe(true);
  });

  it('differs from the honest run in the POLICY, not in the Evidence', () => {
    expect(run.policy.trustedIssuers).toContain('Attacker-Operated CA');
    expect(run.result.matchedCertificate?.issuer).toBe('Attacker-Operated CA');
  });

  it('would be rejected the moment the anchor list is corrected', () => {
    const corrected = verifyEvidence(
      run.evidence,
      { ...run.policy, trustedIssuers: ['Fleet Attestation CA'] },
      REFERENCE_LOG
    );
    expect(corrected.codes).toContain(FAILURE.TRUST_ANCHOR_UNKNOWN);
  });
});

describe('The remaining failure codes', () => {
  const run = scenarioClean();

  it('REFERENCE_MISSING when the verifier holds no golden value for a quoted PCR', () => {
    const thin = new Map(run.policy.referenceValues);
    thin.delete(9);
    const out = verifyEvidence(run.evidence, { ...run.policy, referenceValues: thin }, REFERENCE_LOG);
    expect(out.codes).toContain(FAILURE.REFERENCE_MISSING);
  });

  it('REFERENCE_MISSING when the quote does not cover a required PCR', () => {
    const out = verifyEvidence(
      run.evidence,
      { ...run.policy, requiredPcrs: [0, 4, 8, 9, 7] },
      REFERENCE_LOG
    );
    expect(out.codes).toContain(FAILURE.REFERENCE_MISSING);
    expect(out.checks.find((c) => c.id === 'coverage')?.detail).toMatch(/does not cover required PCR 7/);
  });

  it('ALG_MISMATCH when the quoted bank is not the reference bank', () => {
    const out = verifyEvidence(
      run.evidence,
      { ...run.policy, referenceBankAlg: TPM_ALG.SHA1 },
      REFERENCE_LOG
    );
    expect(out.codes).toContain(FAILURE.ALG_MISMATCH);
  });

  it('QUOTE_BAD_SIGNATURE when a signature byte is flipped', () => {
    const signature = run.evidence.quote.signature.slice();
    signature[10] ^= 0x01;
    const out = verifyEvidence(
      { ...run.evidence, quote: { ...run.evidence.quote, signature } },
      run.policy,
      REFERENCE_LOG
    );
    expect(out.codes).toEqual([FAILURE.QUOTE_BAD_SIGNATURE]);
  });

  it('QUOTE_BAD_SIGNATURE when a byte of the signed structure is flipped', () => {
    const attestBytes = run.evidence.quote.attestBytes.slice();
    attestBytes[attestBytes.length - 1] ^= 0x01;
    const out = verifyEvidence(
      { ...run.evidence, quote: { ...run.evidence.quote, attestBytes } },
      run.policy,
      REFERENCE_LOG
    );
    expect(out.codes).toContain(FAILURE.QUOTE_BAD_SIGNATURE);
  });

  it('NOT_TPM_GENERATED when the magic is absent and the backstop is on', () => {
    const attestBytes = run.evidence.quote.attestBytes.slice();
    attestBytes.set([0, 0, 0, 0], 0);
    const evidence = { ...run.evidence, quote: { ...run.evidence.quote, attestBytes } };
    const on = verifyEvidence(evidence, run.policy, REFERENCE_LOG);
    expect(on.codes).toContain(FAILURE.NOT_TPM_GENERATED);
    const off = verifyEvidence(evidence, { ...run.policy, checkMagic: false }, REFERENCE_LOG);
    expect(off.codes).not.toContain(FAILURE.NOT_TPM_GENERATED);
    expect(off.checks.find((c) => c.id === 'magic')?.state).toBe('not-run');
  });

  it('NONCE_STALE when an EAT is bolted onto a quote it was not issued with', () => {
    // The other half of the freshness check: the EAT here is fresh, the quote
    // is fresh, and they are not the same exchange.
    const evidence = {
      ...run.evidence,
      eat: { ...run.evidence.eat, input: { ...run.evidence.eat.input, nonce: new Uint8Array(32) } },
    };
    const out = verifyEvidence(evidence, run.policy, REFERENCE_LOG);
    expect(out.checks.find((c) => c.id === 'eat-nonce')?.state).toBe('fail');
    expect(out.codes).toContain(FAILURE.NONCE_STALE);
  });

  it('PCR_MISMATCH when the EAT claims a measurement the log does not contain', () => {
    const components = run.evidence.components.map((c) => ({
      ...c,
      digest: c.digest ? { ...c.digest, value: c.digest.value.slice() } : undefined,
    }));
    components[0].digest!.value[0] ^= 0x01;
    const out = verifyEvidence({ ...run.evidence, components }, run.policy, REFERENCE_LOG);
    expect(out.checks.find((c) => c.id === 'eat-measurements')?.state).toBe('fail');
    expect(out.codes).toContain(FAILURE.PCR_MISMATCH);
  });

  it('PCR_MISMATCH when the event log is edited to tell a different story', () => {
    const eventLog = run.evidence.eventLog.map((e) => ({ ...e, digest: e.digest.slice() }));
    eventLog[2].digest[0] ^= 0x01;
    const out = verifyEvidence({ ...run.evidence, eventLog }, run.policy, REFERENCE_LOG);
    // The unsigned log cannot be edited: it stops replaying to the signed digest.
    expect(out.checks.find((c) => c.id === 'replay')?.state).toBe('fail');
    expect(out.codes).toContain(FAILURE.PCR_MISMATCH);
  });

  it('fails closed on a structurally malformed attest', () => {
    const attestBytes = run.evidence.quote.attestBytes.slice(0, 40);
    const out = verifyEvidence(
      { ...run.evidence, quote: { ...run.evidence.quote, attestBytes } },
      run.policy,
      REFERENCE_LOG
    );
    expect(out.verdict).toBe('REJECTED');
    expect(out.checks[0].state).toBe('fail');
  });
});

describe('The failure-code table', () => {
  it('documents every code it exports, with a real-world analogue', () => {
    for (const code of FAILURE_CODES) {
      const meta = FAILURE_TABLE[code];
      expect(meta.code).toBe(code);
      expect(meta.meaning.length).toBeGreaterThan(40);
      expect(meta.realWorld.length).toBeGreaterThan(20);
    }
  });

  it('is honest that AK_NOT_CERTIFIED is this lab’s own name', () => {
    expect(FAILURE_TABLE.AK_NOT_CERTIFIED.realWorld).toMatch(/No implementation emits this name/);
  });
});
