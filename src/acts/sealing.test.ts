import { describe, expect, it } from 'vitest';
import { toHex, utf8 } from '../core/bytes';
import { sha256 } from '../core/sha256';
import { DEFAULT_STAGES } from '../boot/stages';
import { TPM_ALG } from '../tpm/constants';
import { marshalPcrSelection, startPolicySession, policyPCR, TPM_RC } from '../tpm/policy';
import { keyedHashUnique } from '../tpm/seal';
import {
  approve,
  tpm2VerifySignature,
  computePolicy,
  describeResponseCode,
  SEAL_RESPONSE_CODES,
  IMPOSTOR_AUTHORITY,
  measure,
  OEM_AUTHORITY,
  OTHER_PURPOSE,
  RECOVERY_PURPOSE,
  referenceSealedObject,
  referenceUnique,
  runSealing,
  SCENARIOS,
  scenario,
  SEALED_PCRS,
  SEALED_SECRET,
  SEAL_FIXTURES,
  withStage,
} from './sealing';

/**
 * The eight controls S11 exists to execute, asserted as outcomes rather than
 * as the absence of an exception.
 *
 * Every expectation here is the SCENARIO'S OWN result, computed by the same
 * `runSealing` the page calls. There is no second engine and no fixture of
 * expected verdicts: a scenario that stopped exercising its control would
 * change its own verdict and fail here.
 */

const run = (id: string) => runSealing(scenario(id).config);

describe('the sealed-storage controls', () => {
  it('releases the secret when the measured state matches the sealed state', () => {
    const r = run('matching');
    expect(r.verdict).toBe('RELEASED');
    expect(r.released).toBe(SEALED_SECRET);
    expect(r.codes).toEqual([]);
    expect(r.checks.filter((c) => c.state === 'fail')).toEqual([]);
    expect(toHex(r.sessionDigest)).toBe(toHex(r.plan.authPolicy));
  });

  it('refuses from the actual register mismatch after a firmware change, not from a flag', () => {
    const r = run('firmware-update');
    expect(r.verdict).toBe('REFUSED');
    expect(r.released).toBeUndefined();
    // The refusal is TPM_RC_VALUE on TPM2_PolicyPCR parameter 1, and
    // policyDigest is left unchanged — Part 3 §23.7.
    expect(r.codes[0].name).toBe('TPM_RC_VALUE');
    expect(r.codes[0].note).toContain('TPM_RC_P');
    expect(r.codes[0].note).toContain('parameter 1');
    // And the mismatch is real: the two composite digests differ.
    expect(toHex(r.current.digestTPM)).not.toBe(toHex(r.sealed.digestTPM));
    const policyCheck = r.checks.find((c) => c.id === 'policy');
    expect(policyCheck?.state).toBe('fail');
    expect(policyCheck?.computed).toBe(toHex(r.sealed.digestTPM));
    expect(policyCheck?.presented).toBe(toHex(r.current.digestTPM));
    // Only PCR 0 moved: the firmware stage extends PCR 0 and nothing else.
    const moved = r.current.pcrs.filter(
      (p, i) => p.value !== r.sealed.pcrs[i].value
    );
    expect(moved.map((p) => p.pcr)).toEqual([0]);
  });

  it('refuses at use time when the caller does not supply the expected digest', () => {
    const r = run('firmware-update-late');
    expect(r.verdict).toBe('REFUSED');
    // The session completes every assertion and still cannot reach authPolicy.
    expect(r.checks.find((c) => c.id === 'policy')?.state).toBe('pass');
    expect(r.codes.map((c) => c.name)).toContain('TPM_RC_POLICY_FAIL');
    expect(toHex(r.sessionDigest)).not.toBe(toHex(r.plan.authPolicy));
  });

  it('refuses a different PCR selection even when every register value is right', () => {
    const r = run('wrong-selection');
    expect(r.verdict).toBe('REFUSED');
    // Both the selection bytes AND the composite digest differ, and the
    // selection bytes are the point: they are inside the policy digest.
    expect(toHex(marshalPcrSelection(TPM_ALG.SHA256, [0, 4, 8]))).not.toBe(toHex(r.plan.pcrs));
    expect(r.codes.map((c) => c.name)).toContain('TPM_RC_POLICY_FAIL');
  });

  it('refuses a sealed object whose authPolicy differs by one bit, before decrypting anything', () => {
    const r = run('tamper-public');
    expect(r.verdict).toBe('REFUSED');
    expect(r.codes[0].name).toBe('TPM_RC_INTEGRITY');
    // Exactly one bit of the public area was changed.
    const diff = [...r.object.publicArea].filter((b, i) => b !== r.presented.publicArea[i]);
    expect(diff).toHaveLength(1);
    // And nothing downstream of TPM2_Load ran at all.
    expect(r.checks.filter((c) => c.state === 'not-run').map((c) => c.id)).toEqual([
      'policy',
      'authorize',
      'unseal',
    ]);
  });

  it('refuses tampered ciphertext on the integrity value rather than on a decryption result', () => {
    const r = run('tamper-private');
    expect(r.verdict).toBe('REFUSED');
    expect(r.codes[0].name).toBe('TPM_RC_INTEGRITY');
    const diff = [...r.object.priv].filter((b, i) => b !== r.presented.priv[i]);
    expect(diff).toHaveLength(1);
    expect(r.checks.find((c) => c.id === 'load')?.detail).toContain('before anything is');
  });

  it('accepts an attacker-chosen substitute after the fixedTPM parent seed is extracted', () => {
    const r = run('rebind-fixed-parent');
    expect(r.verdict).toBe('RELEASED');
    expect(r.released).toBe('attacker-chosen-value');
    expect(r.released).not.toBe(SEALED_SECRET);
    expect(r.codes).toEqual([]);
    expect(r.checks.find((c) => c.id === 'load')?.detail).toContain('does not recompute unique');
    expect(r.views.ground.headline).toContain('original secret stayed hidden');
  });

  it('refuses recovery signed by a key the policy does not name', () => {
    const r = run('recovery-unauthorized');
    expect(r.verdict).toBe('REFUSED');
    expect(r.checks.find((c) => c.id === 'ticket')?.state).toBe('pass');
    // The impostor's signature verifies under the impostor's own key; what
    // fails is that the branch digest names a different authority.
    expect(r.checks.find((c) => c.id === 'authorize-step')?.state).toBe('pass');
    expect(r.codes.map((c) => c.name)).toContain('TPM_RC_POLICY_FAIL');
    expect(IMPOSTOR_AUTHORITY.name).not.toEqual(OEM_AUTHORITY.name);
  });

  it('refuses recovery approved for a different purpose', () => {
    const r = run('recovery-wrong-purpose');
    expect(r.verdict).toBe('REFUSED');
    expect(r.codes.map((c) => c.name)).toContain('TPM_RC_POLICY_FAIL');
    expect(OTHER_PURPOSE).not.toBe(RECOVERY_PURPOSE);
  });

  it('refuses recovery with a NULL ticket — the "accept any mismatch" case', () => {
    const r = run('recovery-unsigned');
    expect(r.verdict).toBe('REFUSED');
    expect(r.checks.find((c) => c.id === 'ticket')?.state).toBe('fail');
    const authorize = r.checks.find((c) => c.id === 'authorize-step');
    expect(authorize?.state).toBe('fail');
    expect(authorize?.code).toContain('TPM_RC_VALUE');
    expect(authorize?.code).toContain('parameter 4');
    expect(r.checks.find((c) => c.id === 'unseal')?.state).toBe('not-run');
  });

  it('refuses an approval the authority really signed, for a state this machine is not in', () => {
    const r = run('recovery-other-state');
    expect(r.verdict).toBe('REFUSED');
    expect(r.checks.find((c) => c.id === 'ticket')?.state).toBe('pass');
    const authorize = r.checks.find((c) => c.id === 'authorize-step');
    expect(authorize?.state).toBe('fail');
    expect(authorize?.code).toContain('TPM_RC_VALUE');
    expect(authorize?.code).toContain('parameter 1');
    expect(authorize?.detail).toContain('does not apply to this state');
  });

  it('releases under the recovery branch when the named authority approved this exact state', () => {
    const r = run('recovery-authorized');
    expect(r.verdict).toBe('RELEASED');
    expect(r.released).toBe(SEALED_SECRET);
    expect(r.codes).toEqual([]);
    // The object was never re-created: its authPolicy is the same digest the
    // matching-state run requires.
    expect(toHex(r.plan.authPolicy)).toBe(toHex(run('matching').plan.authPolicy));
    // And it got there through the OTHER branch.
    expect(r.steps.map((s) => s.command)).toEqual([
      'TPM2_PolicyPCR',
      'TPM2_PolicyAuthorize',
      'TPM2_PolicyOR',
      'TPM2_PolicyCommandCode',
    ]);
  });

  it('refuses a password where the object requires a policy session', () => {
    const r = run('password-instead-of-policy');
    expect(r.verdict).toBe('REFUSED');
    const unseal = r.checks.find((c) => c.id === 'unseal');
    expect(unseal?.state).toBe('fail');
    expect(unseal?.code).toContain('TPM_RC_POLICY_FAIL');
    expect(unseal?.detail).toContain('userWithAuth CLEAR');
    // The object really does carry the attribute CLEAR.
    expect(r.object.pub.attributes.userWithAuth).toBe(false);
  });

  it('refuses when any PCR is extended after the policy read the registers', () => {
    const r = run('extend-after-policy');
    expect(r.verdict).toBe('REFUSED');
    // The digest still matches; what moved is pcrUpdateCounter.
    expect(toHex(r.sessionDigest)).toBe(toHex(r.plan.authPolicy));
    expect(r.codes.map((c) => c.name)).toContain('TPM_RC_PCR_CHANGED');
    expect(r.codes.find((c) => c.name === 'TPM_RC_PCR_CHANGED')?.note).toContain('RC_VER1');
  });

  it('shows a post-release compromise reaching only what was already released', () => {
    const r = run('post-unseal');
    expect(r.verdict).toBe('RELEASED — AND ALREADY EXPOSED');
    expect(r.released).toBe(SEALED_SECRET);
    // Every TPM check passed. The policy was satisfied, not defeated.
    expect(r.codes).toEqual([]);
    for (const id of ['load', 'policy', 'authorize', 'unseal']) {
      expect(r.checks.find((c) => c.id === id)?.state).toBe('pass');
    }
    expect(r.checks.find((c) => c.id === 'post-release')?.state).toBe('fail');
    expect(r.views.ground.explanation).toContain('not a policy failure');
    // The sealed blob itself is untouched and still requires the policy.
    expect(toHex(r.presented.priv)).toBe(toHex(r.object.priv));
    expect(toHex(r.object.pub.authPolicy)).toBe(toHex(r.plan.authPolicy));
  });

  it('exposes nothing when the same release is not followed by a compromise', () => {
    const r = run('matching');
    expect(r.exposed).toBe(false);
    expect(r.checks.find((c) => c.id === 'post-release')?.state).toBe('pass');
  });
});

describe('the policy the object carries', () => {
  it('binds the selection, the expected digest, the authority and the purpose', () => {
    const base = referenceSealedObject().plan;

    // A different selection is a different policy, with identical registers.
    const otherSelection = computePolicy({
      expectedDigest: base.expectedDigest,
      selection: [0, 4, 8],
    });
    expect(toHex(otherSelection.authPolicy)).not.toBe(toHex(base.authPolicy));

    // A different expected state is a different policy.
    const otherState = computePolicy({
      expectedDigest: sha256(utf8('a different measured state')),
    });
    expect(toHex(otherState.authPolicy)).not.toBe(toHex(base.authPolicy));

    // A different recovery authority is a different policy.
    const otherAuthority = computePolicy({
      expectedDigest: base.expectedDigest,
      authority: IMPOSTOR_AUTHORITY,
    });
    expect(toHex(otherAuthority.authPolicy)).not.toBe(toHex(base.authPolicy));

    // A different purpose is a different policy.
    const otherPurpose = computePolicy({
      expectedDigest: base.expectedDigest,
      policyRef: OTHER_PURPOSE,
    });
    expect(toHex(otherPurpose.authPolicy)).not.toBe(toHex(base.authPolicy));
  });

  it('reaches branch B by a digest that does not mention the state at all', () => {
    const base = referenceSealedObject().plan;
    const elsewhere = computePolicy({ expectedDigest: sha256(utf8('some other state')) });
    // Branch A moves with the state; branch B does not. That is Figure 16's
    // whole point, and the cost of the recovery route.
    expect(toHex(elsewhere.branchA)).not.toBe(toHex(base.branchA));
    expect(toHex(elsewhere.branchB)).toBe(toHex(base.branchB));
  });

  it('computes the sealed state from the shipped boot chain', () => {
    const sealed = measure(DEFAULT_STAGES);
    expect(sealed.pcrs.map((p) => p.pcr)).toEqual([...SEALED_PCRS]);
    expect(toHex(referenceSealedObject().plan.expectedDigest)).toBe(toHex(sealed.digestTPM));
  });
});

describe('the four layers the exhibit separates', () => {
  it('keeps the secret out of the policy digest and the public area', () => {
    const { object, plan } = referenceSealedObject();
    const secret = toHex(utf8(SEALED_SECRET));
    expect(toHex(plan.authPolicy)).not.toContain(secret);
    expect(toHex(object.publicArea)).not.toContain(secret);
    expect(toHex(object.priv)).not.toContain(secret);
    // `unique` is a digest over the secret, so it is in the public area and is
    // not the secret.
    expect(toHex(object.pub.unique)).toBe(toHex(referenceUnique()));
    expect(toHex(object.pub.unique)).not.toBe(secret);
  });

  it('puts the obfuscation value in front of the secret, so unique is not a guessing oracle', () => {
    // Without the obfuscation value, `unique` would be H(secret) and a short
    // secret would be recoverable by search. Part 1 §24.5.3.1 says so.
    expect(toHex(referenceUnique())).not.toBe(toHex(sha256(utf8(SEALED_SECRET))));
    expect(toHex(referenceUnique())).toBe(
      toHex(keyedHashUnique(SEAL_FIXTURES.obfuscate, utf8(SEALED_SECRET)))
    );
  });
});

describe('the scenario set', () => {
  it('has a unique id and a non-empty intent for every scenario', () => {
    const ids = SCENARIOS.map((s) => s.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const s of SCENARIOS) {
      expect(s.label.length).toBeGreaterThan(0);
      expect(s.intent.length).toBeGreaterThan(20);
    }
  });

  it('runs every scenario to a verdict with no thrown error', () => {
    for (const s of SCENARIOS) {
      const r = runSealing(s.config);
      expect(['RELEASED', 'REFUSED', 'RELEASED — AND ALREADY EXPOSED']).toContain(r.verdict);
      expect(r.checks.length).toBeGreaterThan(2);
    }
  });

  it('releases data in exactly four scenarios and refuses in the rest', () => {
    const released = SCENARIOS.filter((s) => runSealing(s.config).released !== undefined);
    expect(released.map((s) => s.id).sort()).toEqual([
      'matching',
      'post-unseal',
      'rebind-fixed-parent',
      'recovery-authorized',
    ]);
  });

  it('names a TPM response code for every refusal', () => {
    for (const s of SCENARIOS) {
      const r = runSealing(s.config);
      if (r.verdict !== 'REFUSED') continue;
      expect(r.codes.length, `${s.id} refused with no response code`).toBeGreaterThan(0);
      expect(r.codes[0].name).toMatch(/^TPM_RC_/);
    }
  });
});

describe('TPM2_VerifySignature, as this model performs it', () => {
  it('issues a ticket for a real signature and TPM_RC_SIGNATURE for a forged one', () => {
    const approvedPolicy = sha256(utf8('an approved policy digest'));
    const policyRef = utf8(RECOVERY_PURPOSE);
    const approval = approve(OEM_AUTHORITY, approvedPolicy, policyRef);

    const good = tpm2VerifySignature(OEM_AUTHORITY, approvedPolicy, policyRef, approval.signature);
    expect(good.ok).toBe(true);
    if (good.ok) expect(good.ticket.digest.length).toBe(32);

    // One flipped bit of the signature, and the ticket is never minted.
    const forged = approval.signature.slice();
    forged[forged.length - 1] ^= 0x01;
    const bad = tpm2VerifySignature(OEM_AUTHORITY, approvedPolicy, policyRef, forged);
    expect(bad.ok).toBe(false);
    if (!bad.ok) expect(bad.rcName).toBe('TPM_RC_SIGNATURE');

    // The same genuine signature does not verify under a different key, which
    // is what makes the authority's Name in the policy load-bearing.
    const wrongKey = tpm2VerifySignature(
      IMPOSTOR_AUTHORITY,
      approvedPolicy,
      policyRef,
      approval.signature
    );
    expect(wrongKey.ok).toBe(false);
    if (!wrongKey.ok) expect(wrongKey.rcName).toBe('TPM_RC_SIGNATURE');
  });

  it('signs H(approvedPolicy || policyRef) and nothing else', () => {
    const approvedPolicy = sha256(utf8('a state'));
    const policyRef = utf8(RECOVERY_PURPOSE);
    const approval = approve(OEM_AUTHORITY, approvedPolicy, policyRef);
    expect(toHex(approval.aHash)).toBe(
      toHex(sha256(new Uint8Array([...approvedPolicy, ...policyRef])))
    );
    // A different purpose is a different aHash, so an approval cannot be moved
    // between purposes even with the same key and the same state.
    const other = approve(OEM_AUTHORITY, approvedPolicy, utf8(OTHER_PURPOSE));
    expect(toHex(other.aHash)).not.toBe(toHex(approval.aHash));
  });
});

describe('the response-code reference table', () => {
  it('decodes every listed value back to the name it is listed under', () => {
    for (const row of SEAL_RESPONSE_CODES) {
      if (row.name === 'TPM_RC_SIGNATURE') continue; // modelled, not composed here
      const decoded = describeResponseCode(row.code, undefined);
      expect(decoded.name, `${row.name} 0x${row.code.toString(16)}`).toBe(row.name);
      expect(row.when.length).toBeGreaterThan(20);
      expect(row.from.length).toBeGreaterThan(5);
    }
  });

  it('lists every code the scenarios actually return', () => {
    const listed = new Set(SEAL_RESPONSE_CODES.map((r) => r.name));
    for (const s of SCENARIOS) {
      for (const code of runSealing(s.config).codes) {
        expect(listed.has(code.name), `${code.name} returned by ${s.id} but not listed`).toBe(true);
      }
    }
  });

  it('shows the format-one decomposition rather than a bare hex number', () => {
    const policyFail = SEAL_RESPONSE_CODES.find((r) => r.name === 'TPM_RC_POLICY_FAIL');
    expect(describeResponseCode(policyFail!.code).note).toContain('RC_FMT1');
    expect(describeResponseCode(policyFail!.code).note).toContain('session 1');
    const pcrChanged = SEAL_RESPONSE_CODES.find((r) => r.name === 'TPM_RC_PCR_CHANGED');
    expect(describeResponseCode(pcrChanged!.code).note).toContain('RC_VER1');
  });
});

describe('verdict retirement', () => {
  it('produces a different result for a changed input, so a stale verdict is detectable', () => {
    const clean = runSealing({});
    const changed = runSealing({
      runStages: withStage(DEFAULT_STAGES, 'kernel', 'vmlinuz-6.12.9 / 5e0b71 / UNSIGNED'),
    });
    expect(clean.verdict).not.toBe(changed.verdict);
    expect(toHex(clean.current.digestTPM)).not.toBe(toHex(changed.current.digestTPM));
  });
});

describe('the policy session cannot be short-circuited', () => {
  it('leaves policyDigest untouched when TPM2_PolicyPCR rejects the expected digest', () => {
    const session = startPolicySession();
    const before = toHex(session.policyDigest);
    const outcome = policyPCR(session, {
      hashAlg: TPM_ALG.SHA256,
      indices: SEALED_PCRS,
      pcrDigest: sha256(utf8('not the current state')),
      digestTPM: measure(DEFAULT_STAGES).digestTPM,
      pcrUpdateCounter: 11,
    });
    expect(outcome.ok).toBe(false);
    expect(toHex(session.policyDigest)).toBe(before);
    expect(session.steps).toEqual([]);
    expect(session.pcrUpdateCounter).toBeUndefined();
    if (!outcome.ok) expect(outcome.rc & 0x03f).toBe(TPM_RC.VALUE & 0x03f);
  });
});
