import { describe, expect, test } from 'vitest';
import { DEFAULT_STAGES, QUOTED_PCRS, runMeasuredBoot } from '../boot/stages';
import { bytesEqual, toHex, utf8 } from '../core/bytes';
import { sha256 } from '../core/sha256';
import { labelledNonce } from '../acts/machine';
import { TPM_GENERATED_VALUE, TPM_ST } from '../tpm/constants';
import { createDaaAttestation } from './attestation';
import { runDaaLesson } from './lesson';
import { DAA_POLICY_ID, SERVICE_BASENAME } from './lesson';
import { verify } from './protocol';

const CLOCK = { clock: 42_000n, resetCount: 1, restartCount: 2, safe: true };

function statement(label = 'one') {
  return createDaaAttestation({
    bank: runMeasuredBoot(DEFAULT_STAGES).bank,
    selection: QUOTED_PCRS,
    nonce: labelledNonce(`daa-test-${label}`),
    clockInfo: CLOCK,
    firmwareVersion: 0x0001_0002_0000_0003n,
  });
}

describe('DAA-shaped attestation bytes', () => {
  test('the complete TPMS_ATTEST is marshalled with an empty qualifiedSigner', () => {
    const value = statement();
    expect(value.attest.magic).toBe(TPM_GENERATED_VALUE);
    expect(value.attest.type).toBe(TPM_ST.ATTEST_QUOTE);
    expect(value.attest.qualifiedSigner).toHaveLength(0);
    expect(toHex(value.bytes).startsWith('ff54434780180000')).toBe(true);
    const size = value.fields.find((field) => field.path === 'qualifiedSigner.size');
    const name = value.fields.find((field) => field.path === 'qualifiedSigner.name');
    expect(size?.hex).toBe('0000');
    expect(name?.length).toBe(0);
    expect(name?.value).toMatch(/Empty Buffer/);
  });

  test('nonce, selected PCR digest, clock, and firmware are inside the signed bytes', () => {
    const value = statement();
    expect(bytesEqual(value.attest.extraData, labelledNonce('daa-test-one'))).toBe(true);
    expect(
      bytesEqual(
        value.attest.attested.pcrDigest,
        runMeasuredBoot(DEFAULT_STAGES).bank.digest(QUOTED_PCRS)
      )
    ).toBe(true);
    expect(toHex(value.bytes)).toContain(toHex(value.attest.extraData));
    expect(toHex(value.bytes)).toContain(toHex(value.attest.attested.pcrDigest));
    expect(bytesEqual(value.digest, sha256(value.bytes))).toBe(true);
  });

  test('changing the challenge retires the old signature rather than preserving a scenario verdict', () => {
    const run = runDaaLesson();
    const changed = statement('changed-challenge');
    expect(run.baseline.valid).toBe(true);
    expect(
      verify(
        run.issuer,
        run.signature1,
        changed.bytes,
        SERVICE_BASENAME,
        DAA_POLICY_ID
      ).valid
    ).toBe(false);
  });

  test('the deterministic statement has a pinned byte-level evidence vector', () => {
    const value = statement();
    expect(toHex(sha256(value.bytes))).toBe(
      '7c577def59d03848a5c7d01fc07f60a7914c5e1e408ec0c9da6143bcc841bfe4'
    );
  });
});
describe('the lesson compares identity and membership without conflating them', () => {
  test('the stable AK Name repeats while the DAA statement omits it', () => {
    const run = runDaaLesson();
    expect(run.stableAk.firstQualifiedSigner.length).toBeGreaterThan(0);
    expect(bytesEqual(run.stableAk.firstQualifiedSigner, run.stableAk.secondQualifiedSigner)).toBe(
      true
    );
    expect(run.stableAk.linked).toBe(true);
    expect(run.statement1.attest.qualifiedSigner).toHaveLength(0);
    expect(run.statement2.attest.qualifiedSigner).toHaveLength(0);
  });

  test('acceptance changes under credential, issuer, and revocation state', () => {
    const run = runDaaLesson();
    expect(run.credentialControl.originalAccepted).toBe(true);
    expect(run.credentialControl.changedRejected).toBe(true);
    expect(run.rotation.oldStillTrusted.valid).toBe(true);
    expect(run.rotation.oldAgainstNewIssuer.valid).toBe(false);
    expect(run.rotation.rejoinedUnderNewIssuer.valid).toBe(true);
    expect(run.revocation.before.valid).toBe(true);
    expect(run.revocation.unrelated.valid).toBe(true);
    expect(run.revocation.exact.valid).toBe(false);
    expect(run.revocation.exact.revoked).toBe(true);
  });

  test('same/different basename and platform outcomes come from computed pseudonyms', () => {
    const run = runDaaLesson();
    expect(run.sameBasename.linked).toBe(true);
    expect(run.differentBasename.applicable).toBe(false);
    expect(run.differentBasename.linked).toBe(null);
    expect(run.otherPlatform.applicable).toBe(true);
    expect(run.otherPlatform.linked).toBe(false);
    expect(run.nymHex(run.signature1.nym)).toBe(run.nymHex(run.signature2.nym));
    expect(run.nymHex(run.signature1.nym)).not.toBe(
      run.nymHex(run.differentBasenameSignature.nym)
    );
    expect(run.nymHex(run.signature1.nym)).not.toBe(run.nymHex(run.otherPlatformSignature.nym));
  });

  test('plain-language data is not mistaken for a cryptographic secret', () => {
    const run = runDaaLesson();
    expect(run.revocation.publishedSecret).toMatch(/^[0-9a-f]{64}$/);
    expect(toHex(utf8(run.revocation.publishedSecret))).not.toBe(run.revocation.publishedSecret);
  });
});
