/**
 * Act 8 — sealed storage, as one executable engine.
 *
 * Everything the panel shows comes out of `runSealing`, so a scenario is a
 * configuration rather than a separate code path and no displayed verdict can
 * be produced by a route the other scenarios do not share.
 *
 * THE POLICY, which is the whole lesson:
 *
 *   branch A (the sealed state)
 *     0…0 --PolicyPCR(pcrs, D_expected)--------------------------> D_A
 *
 *   branch B (the authorized update/recovery route)
 *     0…0 --PolicyPCR(pcrs, D_new)--> D_new
 *         --PolicyAuthorize(approved = D_new, policyRef, OEM Name)-> D_B
 *
 *   both branches
 *         --PolicyOR[D_A, D_B]-------------------------------------> D_OR
 *         --PolicyCommandCode(TPM_CC_Unseal)-----------------------> authPolicy
 *
 * This is the shape the specification itself prescribes for exactly this
 * problem. v185 Part 1 §16.7.11 (1.83 §19.7.11) names the failure mode —
 * "if there is a BIOS update, the PCR will change, and the sealed data value
 * can no longer be retrieved" — calls it brittleness, and gives Figure 16, in
 * which a `PolicyPCR` assertion is followed by `PolicyAuthorize` so that any
 * state the authority has signed converges on the same final digest.
 *
 * TWO CONSEQUENCES WORTH SAYING OUT LOUD, because they are the honest cost of
 * the recovery route and a reader should not have to derive them:
 *
 *   - `D_B` does not depend on which PCR state preceded it. `PolicyAuthorize`
 *     resets the digest to zero and replaces it with a digest over the
 *     AUTHORITY'S NAME and the policyRef. So branch B authorizes "a state this
 *     authority approved", not "this state" — the authority's signature is the
 *     entire security of that branch.
 *   - `authPolicy` still depends on `D_A`, so the object really is bound to one
 *     explicit PCR selection and one expected composite digest. The recovery
 *     route widens the policy; it does not remove the pin.
 *
 * And what the recovery route is NOT: it is not "accept a mismatch". Reaching
 * `D_B` requires a `TPMT_TK_VERIFIED` over `H(approvedPolicy || policyRef)`
 * under the named authority's key. A different authority, a different purpose
 * string, or an unsigned state each fail, and the scenarios execute all three.
 */

import { bytesEqual, concatBytes, toHex, u32be, utf8 } from '../core/bytes';
import { sha256, SHA256_LEN } from '../core/sha256';
import { TPM_ALG, TPM_RH } from '../tpm/constants';
import {
  cloneStages,
  DEFAULT_STAGES,
  QUOTED_PCRS,
  runMeasuredBoot,
  type BootStage,
} from '../boot/stages';
import {
  hierarchyQualifiedName,
  makeAttestationKey,
  verifyOverDigest,
  type TpmObject,
} from '../tpm/key';
import { p256 } from '@noble/curves/nist.js';
import {
  approvedPolicyHash,
  decodeRc,
  rcHandle,
  rcParameter,
  rcSession,
  marshalPcrSelection,
  policyAuthorize,
  policyCommandCode,
  policyOR,
  policyPCR,
  startPolicySession,
  TPM_CC,
  TPM_RC,
  TPM_ST_VERIFIED,
  verifiedTicketDigest,
  type PolicySession,
  type PolicyStep,
  type VerifiedTicket,
} from '../tpm/policy';
import {
  keyedHashUnique,
  marshalSensitive,
  outerHmac,
  sealObject,
  storageKey,
  tpm2Load,
  tpm2Unseal,
  type SealedObject,
  type StorageParent,
} from '../tpm/seal';
import { cfb } from '@noble/ciphers/aes.js';

/**
 * The sealed payload. A synthetic ASCII fixture, deliberately: nothing here is
 * key material for anything, and a reader who copies it has copied a string.
 */
export const SEALED_SECRET = 'fleet-wrap-key/v1 2f8c6a41d0b7e359';

/** The PCRs this lesson seals to — the same static boot set the quote selects. */
export const SEALED_PCRS = QUOTED_PCRS;

/** The policyRef that scopes the recovery authority's approvals to this purpose. */
export const RECOVERY_PURPOSE = 'attestation-gate/seal-recovery/v1';

/** A purpose string the authority is NOT trusted for, used by one scenario. */
export const OTHER_PURPOSE = 'attestation-gate/seal-duplicate/v1';

/** The PCR generation counter's value before this lesson's boot runs. */
const PCR_COUNTER_BASE = 7;

function labelledBytes(label: string, length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i += SHA256_LEN) {
    out.set(sha256(concatBytes(utf8(label), u32be(i))).slice(0, Math.min(SHA256_LEN, length - i)), i);
  }
  return out;
}

/**
 * The modelled storage parent. Its `seedValue` is the one value in this whole
 * exhibit whose confinement cannot be modelled: in hardware it is generated
 * inside the TPM from the Storage Primary Seed and never leaves. Here it is a
 * deterministic page-local value, which is why one scenario can show an
 * attacker who holds it — and why no protection below should be read as
 * hardware isolation.
 */
export const SEAL_PARENT: StorageParent = {
  label: 'SRK (storage root key, owner hierarchy)',
  nameAlg: TPM_ALG.SHA256,
  fixedTPM: true,
  seedValue: labelledBytes('crypto-lab-attestation-gate/seal/srk-seed', SHA256_LEN),
};

/**
 * The owner hierarchy's `shProof`. Tickets are HMACs under it (Part 2 §10.7
 * Table 102), which is what makes a ticket unforgeable off-chip and cheap to
 * re-check on-chip.
 */
const OWNER_PROOF = labelledBytes('crypto-lab-attestation-gate/seal/shProof', SHA256_LEN);

const OBFUSCATE = labelledBytes('crypto-lab-attestation-gate/seal/obfuscate', SHA256_LEN);
const SEAL_IV = labelledBytes('crypto-lab-attestation-gate/seal/symIv', 16);

export interface SealingAuthority {
  id: 'oem' | 'impostor';
  label: string;
  key: TpmObject;
  /** TPM2B_NAME content: nameAlg || H(TPMT_PUBLIC). What the policy binds to. */
  name: Uint8Array;
}

/**
 * A policy authority. Modelled as an ordinary (unrestricted) signing key
 * loaded with `TPM2_LoadExternal`, which is how a verifier-side key with no
 * TPM parent gets a Name the TPM can compute — and a Name is all
 * `TPM2_PolicyAuthorize` binds to.
 *
 * `restricted` is CLEAR because this key signs a policy digest, which is
 * externally-supplied data and not a TPM-generated structure; a restricted key
 * would refuse (that is Act 3's lesson, and it applies here in the opposite
 * direction).
 */
function authority(id: SealingAuthority['id'], label: string): SealingAuthority {
  const key = makeAttestationKey(
    `seal-authority/${id}`,
    hierarchyQualifiedName(TPM_RH.NULL),
    false
  );
  return { id, label, key, name: concatBytes(new Uint8Array([0x00, 0x0b]), sha256(key.publicArea)) };
}

export const OEM_AUTHORITY = authority('oem', 'Platform OEM firmware-release key');
export const IMPOSTOR_AUTHORITY = authority('impostor', 'An unrelated key that signed the same bytes');

// ── The policy ──────────────────────────────────────────────────────────────

export interface MeasuredState {
  stages: BootStage[];
  /** PCR values for the selection, ascending. */
  pcrs: Array<{ pcr: number; value: string }>;
  /** H(selected PCR values, ascending index order). */
  digestTPM: Uint8Array;
  /** How many extends the bank has seen, as the TPM's generation counter. */
  pcrUpdateCounter: number;
}

/** Run the boot chain and read out exactly what a policy would check. */
export function measure(stages: readonly BootStage[], selection: readonly number[] = SEALED_PCRS): MeasuredState {
  const { bank } = runMeasuredBoot(stages);
  return {
    stages: cloneStages(stages),
    pcrs: bank.snapshot(selection),
    digestTPM: bank.digest(selection),
    pcrUpdateCounter: PCR_COUNTER_BASE + bank.log.length,
  };
}

export interface PolicyPlan {
  selection: readonly number[];
  /** The composite digest branch A pins. */
  expectedDigest: Uint8Array;
  /** The marshalled TPML_PCR_SELECTION that goes inside the policy digest. */
  pcrs: Uint8Array;
  branchA: Uint8Array;
  branchB: Uint8Array;
  orDigest: Uint8Array;
  authPolicy: Uint8Array;
  policyRef: Uint8Array;
  authority: SealingAuthority;
  /** The trial-session steps, so the page can show how each value was reached. */
  steps: { branchA: PolicyStep[]; branchB: PolicyStep[]; common: PolicyStep[] };
}

/**
 * Compute the sealed object's `authPolicy` with TRIAL policy sessions.
 *
 * Part 3 §23.1 and §23.7: a trial session updates `policyDigest` from the
 * values the caller supplies instead of from the TPM's own state, which is the
 * only way to compute a policy for a machine state the TPM is not currently
 * in. That is not a shortcut around a check — a trial session authorizes
 * nothing, and `checkPolicyAuthorization` refuses one outright.
 */
export function computePolicy(options: {
  expectedDigest: Uint8Array;
  selection?: readonly number[];
  authority?: SealingAuthority;
  policyRef?: string;
}): PolicyPlan {
  const selection = options.selection ?? SEALED_PCRS;
  const auth = options.authority ?? OEM_AUTHORITY;
  const policyRef = utf8(options.policyRef ?? RECOVERY_PURPOSE);

  const trial = (): PolicySession => startPolicySession({ trial: true });

  const a = trial();
  const aPcr = policyPCR(a, {
    hashAlg: TPM_ALG.SHA256,
    indices: selection,
    pcrDigest: options.expectedDigest,
    digestTPM: options.expectedDigest,
    pcrUpdateCounter: 0,
  });
  if (!aPcr.ok) throw new Error(`trial branch A failed: ${aPcr.reason}`);
  const branchA = a.policyDigest.slice();

  // Branch B's PCR step binds a placeholder state: PolicyAuthorize resets the
  // digest, so WHICH state it was is not in the result. The step is kept in
  // the plan anyway, because a reader needs to see that the branch really does
  // check the registers before the authority's approval is consulted.
  const b = trial();
  const bPcr = policyPCR(b, {
    hashAlg: TPM_ALG.SHA256,
    indices: selection,
    pcrDigest: options.expectedDigest,
    digestTPM: options.expectedDigest,
    pcrUpdateCounter: 0,
  });
  if (!bPcr.ok) throw new Error(`trial branch B failed: ${bPcr.reason}`);
  const bAuthorize = policyAuthorize(b, {
    approvedPolicy: b.policyDigest.slice(),
    policyRef,
    keySignName: auth.name,
    checkTicket: { tag: TPM_ST_VERIFIED, hierarchy: TPM_RH.OWNER, digest: new Uint8Array(0) },
    proof: OWNER_PROOF,
  });
  if (!bAuthorize.ok) throw new Error(`trial branch B authorize failed: ${bAuthorize.reason}`);
  const branchB = b.policyDigest.slice();

  const common = trial();
  common.policyDigest = branchA.slice();
  const or = policyOR(common, [branchA, branchB]);
  if (!or.ok) throw new Error(`trial OR failed: ${or.reason}`);
  const orDigest = common.policyDigest.slice();
  const cc = policyCommandCode(common, TPM_CC.Unseal);
  if (!cc.ok) throw new Error(`trial command code failed: ${cc.reason}`);

  return {
    selection,
    expectedDigest: options.expectedDigest,
    pcrs: marshalPcrSelection(TPM_ALG.SHA256, selection),
    branchA,
    branchB,
    orDigest,
    authPolicy: common.policyDigest.slice(),
    policyRef,
    authority: auth,
    steps: { branchA: a.steps, branchB: b.steps, common: common.steps },
  };
}

// ── The authority's approval ────────────────────────────────────────────────

export interface Approval {
  authority: SealingAuthority;
  /** The policyDigest the authority signed: a branch-B PolicyPCR result. */
  approvedPolicy: Uint8Array;
  policyRef: Uint8Array;
  /** ECDSA P-256 over aHash, deterministic per RFC 6979. */
  signature: Uint8Array;
  aHash: Uint8Array;
}

/**
 * The authority signs `toBeSigned := (approvedPolicy || policyRef)`.
 *
 * v185 Part 3 §23.16 states it that way; 1.83 §23.16 states the equivalent
 * `aHash := H_aHashAlg(approvedPolicy || policyRef)` with `aHashAlg` required
 * to be the `nameAlg` of the signing key. With SHA-256 and ECDSA-SHA256 those
 * are the same bytes, which is what this function computes.
 */
export function approve(
  auth: SealingAuthority,
  approvedPolicy: Uint8Array,
  policyRef: Uint8Array
): Approval {
  const aHash = approvedPolicyHash(approvedPolicy, policyRef);
  return {
    authority: auth,
    approvedPolicy,
    policyRef,
    aHash,
    signature: p256.sign(aHash, auth.key.secretKey, { lowS: false, prehash: false }),
  };
}

export type TicketOutcome =
  | { ok: true; ticket: VerifiedTicket }
  | { ok: false; rc: number; rcName: string; reason: string };

/**
 * `TPM2_VerifySignature` — check a signature and mint a `TPMT_TK_VERIFIED`.
 *
 * Part 3 §20.2, **deprecated in Version 185** in favour of §20.3
 * `TPM2_VerifySequenceComplete` and §20.4 `TPM2_VerifyDigestSignature` (whose
 * ticket carries the different tag `TPM_ST_DIGEST_VERIFIED`, 0x8027). v185
 * §23.16 accepts a ticket from any of the three. This model produces the
 * `TPM_ST_VERIFIED` ticket of the deprecated command because that is the one
 * 1.83 equation (35) specifies byte for byte, and the deprecation is recorded
 * here rather than silently inherited.
 *
 * The hierarchy matters and is easy to get wrong: §20.2 notes that a key in
 * the NULL hierarchy produces a ticket whose HMAC is the Empty Buffer, which
 * would be useless to `TPM2_PolicyAuthorize`. The authority key is therefore
 * verified under the OWNER hierarchy's `shProof`.
 */
export function tpm2VerifySignature(
  auth: SealingAuthority,
  approvedPolicy: Uint8Array,
  policyRef: Uint8Array,
  signature: Uint8Array
): TicketOutcome {
  const aHash = approvedPolicyHash(approvedPolicy, policyRef);
  if (!verifyOverDigest(auth.key.publicKey, aHash, signature)) {
    return {
      ok: false,
      rc: 0x1db, // TPM_RC_SIGNATURE (RC_FMT1 + 0x05B) is out of this model's set;
      rcName: 'TPM_RC_SIGNATURE',
      reason: `${auth.label} did not sign H(approvedPolicy || policyRef) = ${toHex(aHash)}`,
    };
  }
  return {
    ok: true,
    ticket: {
      tag: TPM_ST_VERIFIED,
      hierarchy: TPM_RH.OWNER,
      digest: verifiedTicketDigest(OWNER_PROOF, aHash, auth.name),
    },
  };
}

// ── The run ─────────────────────────────────────────────────────────────────

export type SealTamper = 'none' | 'public' | 'private' | 'rebind';

export interface SealingConfig {
  /** The measured state the secret was sealed to. */
  sealStages?: BootStage[];
  /** The measured state the machine is in when it tries to unseal. */
  runStages?: BootStage[];
  /** The selection the policy session asserts. Differing from the sealed one is a scenario. */
  sessionSelection?: readonly number[];
  route?: 'sealed-state' | 'recovery';
  /**
   * Whether the caller supplies its expected composite digest to
   * `TPM2_PolicyPCR`. Supplying it stops the session early with
   * `TPM_RC_VALUE`; omitting it lets the session complete over whatever the
   * registers hold and fail at use time with `TPM_RC_POLICY_FAIL`. Both are
   * legal and the lesson shows both.
   */
  assertExpectedDigest?: boolean;
  /** For the recovery route. */
  approvalAuthority?: SealingAuthority;
  approvalPurpose?: string;
  /** The state the authority actually approved. Defaults to the run state. */
  approvedStages?: BootStage[];
  /** Drop the authority's signature entirely: an unsigned "recovery". */
  approvalUnsigned?: boolean;
  tamper?: SealTamper;
  /** Present a password instead of a policy session. */
  sessionKind?: 'policy' | 'hmac-or-password';
  /** Extend a PCR after the policy has checked the registers. */
  extendAfterPolicy?: boolean;
  /** After a successful unseal, an attacker reads the plaintext out of memory. */
  postUnsealCompromise?: boolean;
}

export interface SealCheck {
  id: string;
  name: string;
  state: 'pass' | 'fail' | 'not-run';
  detail: string;
  code?: string;
  computed?: string;
  presented?: string;
}

export interface SealingRun {
  /** The reference state the object was sealed to. */
  sealed: MeasuredState;
  /** The state at unseal time. */
  current: MeasuredState;
  plan: PolicyPlan;
  object: SealedObject;
  /** The public area and private blob actually presented to TPM2_Load. */
  presented: { publicArea: Uint8Array; priv: Uint8Array; name: Uint8Array };
  /** The assertions the policy session executed, in order. */
  steps: PolicyStep[];
  sessionDigest: Uint8Array;
  route: 'sealed-state' | 'recovery';
  checks: SealCheck[];
  verdict: 'RELEASED' | 'REFUSED' | 'RELEASED — AND ALREADY EXPOSED';
  /** The response codes the model returned, in order. */
  codes: Array<{ rc: number; name: string; note: string }>;
  released?: string;
  /** Whether a post-release compromise read the plaintext. */
  exposed: boolean;
  views: {
    attacker: { holds: string[]; learns: string[]; cannot: string[] };
    platform: string[];
    tpm: string[];
    ground: { headline: string; explanation: string };
  };
}

function rcEntry(rc: number, name?: string): { rc: number; name: string; note: string } {
  const d = decodeRc(rc);
  const hex = `0x${rc.toString(16).padStart(3, '0')}`;
  const note =
    d.subject === 'none'
      ? `${hex} = ${d.format === 0 ? 'RC_VER1' : 'RC_FMT1'} + 0x${d.number.toString(16).padStart(3, '0')}`
      : `${hex} = RC_FMT1 + 0x${d.number.toString(16).padStart(3, '0')}` +
        `${d.subject === 'parameter' ? ' + TPM_RC_P' : ''} + ${d.subject} ${d.index}`;
  return { rc, name: name ?? d.name, note };
}

/** Flip one bit of a copy, so a tamper is exactly one bit and nothing else. */
function flipBit(bytes: Uint8Array, index: number): Uint8Array {
  const out = bytes.slice();
  out[index] ^= 0x01;
  return out;
}

/**
 * Re-wrap a DIFFERENT secret under the same public area, using the storage
 * parent's seed.
 *
 * This is only possible for an attacker who holds `seedValue`, which in
 * hardware never leaves the TPM. It produces a blob whose outer HMAC is
 * perfectly valid and whose `unique` no longer matches. Because the SRK has
 * `fixedTPM` SET, Part 4 `ObjectLoad` trusts the premise that this TPM created
 * or import-validated the blob and skips `CryptValidateKeys`; extracting the
 * parent seed invalidates that premise and makes substitution possible.
 */
function rebindSecret(object: SealedObject, substitute: string): Uint8Array {
  const sensitive = marshalSensitive({
    sensitiveType: TPM_ALG.KEYEDHASH,
    authValue: new Uint8Array(0),
    seedValue: OBFUSCATE,
    data: utf8(substitute),
  });
  const encSensitive = cfb(storageKey(SEAL_PARENT, object.name), SEAL_IV).encrypt(sensitive);
  const integrity = outerHmac(SEAL_PARENT, SEAL_IV, encSensitive, object.name);
  return concatBytes(
    new Uint8Array([0x00, integrity.length]),
    integrity,
    new Uint8Array([0x00, SEAL_IV.length]),
    SEAL_IV,
    encSensitive
  );
}

export function runSealing(config: SealingConfig = {}): SealingRun {
  const sealStages = config.sealStages ?? cloneStages(DEFAULT_STAGES);
  const runStages = config.runStages ?? cloneStages(sealStages);
  const route = config.route ?? 'sealed-state';
  const sessionSelection = config.sessionSelection ?? SEALED_PCRS;
  const assertExpected = config.assertExpectedDigest ?? true;
  const tamper = config.tamper ?? 'none';

  const sealed = measure(sealStages);
  const current = measure(runStages, sessionSelection);
  const plan = computePolicy({ expectedDigest: sealed.digestTPM });

  const object = sealObject({
    parent: SEAL_PARENT,
    secret: utf8(SEALED_SECRET),
    authPolicy: plan.authPolicy,
    obfuscate: OBFUSCATE,
    iv: SEAL_IV,
  });

  // What is actually handed to TPM2_Load.
  let publicArea = object.publicArea;
  let priv = object.priv;
  if (tamper === 'public') {
    // One bit of authPolicy inside TPM2B_PUBLIC. offset 10 is authPolicy.buffer[0].
    publicArea = flipBit(publicArea, 10);
  } else if (tamper === 'private') {
    // One bit of the ciphertext, past the 34-byte integrity TPM2B and the
    // 18-byte TPM2B_IV.
    priv = flipBit(priv, 2 + SHA256_LEN + 2 + SEAL_IV.length + 4);
  } else if (tamper === 'rebind') {
    priv = rebindSecret(object, 'attacker-chosen-value');
  }

  const checks: SealCheck[] = [];
  const codes: Array<{ rc: number; name: string; note: string }> = [];
  const steps: PolicyStep[] = [];

  // ── TPM2_Load ─────────────────────────────────────────────────────────────
  const load = tpm2Load(SEAL_PARENT, publicArea, priv);
  checks.push({
    id: 'load',
    name: 'TPM2_Load — the private blob passes the checks applicable to its parent',
    state: load.ok ? 'pass' : 'fail',
    detail: load.ok
      ? tamper === 'rebind'
        ? 'the outer HMAC verifies. Because the parent has fixedTPM SET, Part 4 ObjectLoad ' +
          'trusts the blob was created or import-validated by this TPM and does not recompute ' +
          'unique. Extracting the parent seed broke that premise, so the substitute loaded.'
        : 'the outer HMAC over symIv || encSensitive || Name verifies. Because the parent has ' +
          'fixedTPM SET, Part 4 ObjectLoad relies on creation or import having validated the ' +
          'public/sensitive binding.'
      : load.reason,
    code: load.ok ? undefined : `${load.rcName} · ${load.rcNote}`,
  });
  if (!load.ok) {
    codes.push(rcEntry(load.rc, load.rcName));
    for (const id of ['policy', 'authorize', 'unseal'] as const) {
      checks.push({
        id,
        name:
          id === 'policy'
            ? 'TPM2_PolicyPCR — the registers match the sealed state'
            : id === 'authorize'
              ? 'TPM2_PolicyOR / TPM2_PolicyCommandCode — the session reaches the object’s authPolicy'
              : 'TPM2_Unseal — the loaded object’s data is released',
        state: 'not-run',
        detail: 'the object never loaded, so no session was evaluated against it',
      });
    }
    return assemble({
      sealed,
      current,
      plan,
      object,
      presented: { publicArea, priv, name: object.name },
      steps,
      sessionDigest: new Uint8Array(SHA256_LEN),
      route,
      checks,
      codes,
      config,
      loaded: false,
      released: undefined,
      exposed: false,
    });
  }

  // ── The policy session ────────────────────────────────────────────────────
  const session = startPolicySession();
  const pcrStep = policyPCR(session, {
    hashAlg: TPM_ALG.SHA256,
    indices: sessionSelection,
    pcrDigest: assertExpected ? sealed.digestTPM : new Uint8Array(0),
    digestTPM: current.digestTPM,
    pcrUpdateCounter: current.pcrUpdateCounter,
  });
  const selectionMatches = bytesEqual(
    marshalPcrSelection(TPM_ALG.SHA256, sessionSelection),
    plan.pcrs
  );
  checks.push({
    id: 'policy',
    name: 'TPM2_PolicyPCR — the registers match the sealed state',
    state: pcrStep.ok ? 'pass' : 'fail',
    detail: pcrStep.ok
      ? `PCRs {${[...sessionSelection].join(', ')}} hash to ${toHex(current.digestTPM)}` +
        (selectionMatches
          ? ''
          : ' — but this is NOT the selection the object was sealed to, and the marshalled ' +
            'selection is inside the policy digest')
      : pcrStep.reason,
    code: pcrStep.ok ? undefined : `${pcrStep.rcName} · ${rcEntry(pcrStep.rc, pcrStep.rcName).note}`,
    computed: toHex(sealed.digestTPM),
    presented: toHex(current.digestTPM),
  });
  if (!pcrStep.ok) {
    codes.push(rcEntry(pcrStep.rc, pcrStep.rcName));
    checks.push(
      {
        id: 'authorize',
        name: 'TPM2_PolicyOR / TPM2_PolicyCommandCode — the session reaches the object’s authPolicy',
        state: 'not-run',
        detail:
          'TPM2_PolicyPCR left policyDigest unchanged, so there is no satisfied branch to OR. ' +
          'Part 3 §23.7: a pcrDigest mismatch returns TPM_RC_VALUE and makes no change.',
      },
      {
        id: 'unseal',
        name: 'TPM2_Unseal — the loaded object’s data is released',
        state: 'not-run',
        detail: 'the session never reached the object’s authPolicy',
      }
    );
    return assemble({
      sealed,
      current,
      plan,
      object,
      presented: { publicArea, priv, name: object.name },
      steps: session.steps,
      sessionDigest: session.policyDigest,
      route,
      checks,
      codes,
      config,
      loaded: true,
      released: undefined,
      exposed: false,
    });
  }
  steps.push(pcrStep.step);

  // ── The recovery route's extra assertion ─────────────────────────────────
  if (route === 'recovery') {
    const auth = config.approvalAuthority ?? OEM_AUTHORITY;
    const purpose = utf8(config.approvalPurpose ?? RECOVERY_PURPOSE);
    const approvedState = measure(config.approvedStages ?? runStages, sessionSelection);

    // What the authority signed: the branch-B PolicyPCR digest for the state
    // it chose to approve, computed the same way the TPM just computed it.
    const trial = startPolicySession({ trial: true });
    const trialStep = policyPCR(trial, {
      hashAlg: TPM_ALG.SHA256,
      indices: sessionSelection,
      pcrDigest: approvedState.digestTPM,
      digestTPM: approvedState.digestTPM,
      pcrUpdateCounter: 0,
    });
    if (!trialStep.ok) throw new Error('the approved state could not be expressed as a policy');
    const approvedPolicy = trial.policyDigest.slice();

    let ticket: VerifiedTicket = { tag: TPM_ST_VERIFIED, hierarchy: TPM_RH.NULL, digest: new Uint8Array(0) };
    let ticketReason = 'no authority signature was presented at all — the ticket is NULL';
    let ticketOk = false;
    if (!config.approvalUnsigned) {
      const approval = approve(auth, approvedPolicy, purpose);
      const verified = tpm2VerifySignature(auth, approvedPolicy, purpose, approval.signature);
      if (verified.ok) {
        ticket = verified.ticket;
        ticketOk = true;
        ticketReason =
          `${auth.label} signed H(approvedPolicy || policyRef) and TPM2_VerifySignature issued a ` +
          'TPM_ST_VERIFIED ticket under the owner hierarchy proof';
      } else {
        ticketReason = verified.reason;
      }
    }
    checks.push({
      id: 'ticket',
      name: 'TPM2_VerifySignature — a named authority approved this exact state, for this purpose',
      state: ticketOk ? 'pass' : 'fail',
      detail: ticketReason,
      code: ticketOk ? undefined : 'TPM_RC_SIGNATURE',
    });

    const authorized = policyAuthorize(session, {
      approvedPolicy,
      policyRef: purpose,
      keySignName: auth.name,
      checkTicket: ticket,
      proof: OWNER_PROOF,
    });
    checks.push({
      id: 'authorize-step',
      name: 'TPM2_PolicyAuthorize — the approval applies to the state this session reached',
      state: authorized.ok ? 'pass' : 'fail',
      detail: authorized.ok
        ? `policyDigest is reset to 0…0 and replaced by a digest over the authority Name ` +
          `${toHex(auth.name)} and the purpose "${config.approvalPurpose ?? RECOVERY_PURPOSE}"`
        : authorized.reason,
      code: authorized.ok
        ? undefined
        : `${authorized.rcName} · ${rcEntry(authorized.rc, authorized.rcName).note}`,
    });
    if (!authorized.ok) {
      codes.push(rcEntry(authorized.rc, authorized.rcName));
      checks.push({
        id: 'unseal',
        name: 'TPM2_Unseal — the loaded object’s data is released',
        state: 'not-run',
        detail: 'the recovery branch was not satisfied, so the session never reached authPolicy',
      });
      return assemble({
        sealed,
        current,
        plan,
        object,
        presented: { publicArea, priv, name: object.name },
        steps: session.steps,
        sessionDigest: session.policyDigest,
        route,
        checks,
        codes,
        config,
        loaded: true,
        released: undefined,
        exposed: false,
      });
    }
    steps.push(authorized.step);
  }

  // ── Converge the branches and pin the command ────────────────────────────
  const or = policyOR(session, [plan.branchA, plan.branchB]);
  if (or.ok) steps.push(or.step);
  const cc = or.ok ? policyCommandCode(session, TPM_CC.Unseal) : undefined;
  if (cc?.ok) steps.push(cc.step);

  const sessionReached = session.policyDigest.slice();
  const reachedAuthPolicy = or.ok && cc?.ok === true && bytesEqual(sessionReached, plan.authPolicy);
  checks.push({
    id: 'authorize',
    name: 'TPM2_PolicyOR / TPM2_PolicyCommandCode — the session reaches the object’s authPolicy',
    state: reachedAuthPolicy ? 'pass' : 'fail',
    detail: !or.ok
      ? or.reason
      : cc && !cc.ok
        ? cc.reason
        : reachedAuthPolicy
          ? `one of the two authorized branches was satisfied, the digest was reset to 0…0 and ` +
            're-extended over both branch digests, then restricted to TPM_CC_Unseal'
          : `the session accumulated ${toHex(sessionReached)} and the object requires ` +
            `${toHex(plan.authPolicy)}`,
    code: !or.ok
      ? `${or.rcName} · ${rcEntry(or.rc, or.rcName).note}`
      : cc && !cc.ok
        ? `${cc.rcName} · ${rcEntry(cc.rc, cc.rcName).note}`
        : undefined,
    computed: toHex(plan.authPolicy),
    presented: toHex(sessionReached),
  });
  if (!or.ok) codes.push(rcEntry(or.rc, or.rcName));
  else if (cc && !cc.ok) codes.push(rcEntry(cc.rc, cc.rcName));

  // ── TPM2_Unseal, after the §5.6 authorization checks ────────────────────
  const useCounter = config.extendAfterPolicy
    ? current.pcrUpdateCounter + 1
    : current.pcrUpdateCounter;
  const unseal = tpm2Unseal(load.object, {
    session,
    pcrUpdateCounter: useCounter,
    sessionKind: config.sessionKind ?? 'policy',
  });
  checks.push({
    id: 'unseal',
    name: 'TPM2_Unseal — the loaded object’s data is released',
    state: unseal.ok ? 'pass' : 'fail',
    detail: unseal.ok
      ? 'Part 3 §5.6 compared policySession→policyDigest with the object’s authPolicy and they ' +
        'are equal, so the USER-role authorization succeeded and the command returned outData'
      : unseal.reason,
    code: unseal.ok ? undefined : `${unseal.rcName} · ${unseal.rcNote}`,
  });
  if (!unseal.ok) codes.push(rcEntry(unseal.rc, unseal.rcName));

  const released = unseal.ok ? new TextDecoder().decode(unseal.outData) : undefined;
  const exposed = unseal.ok && (config.postUnsealCompromise ?? false);
  if (released !== undefined) {
    checks.push({
      id: 'post-release',
      name: 'After release — what a runtime compromise can reach',
      state: exposed ? 'fail' : 'pass',
      detail: config.tamper === 'rebind'
        ? 'the caller received the attacker-chosen replacement, not the original secret. The ' +
          'failure was loss of the fixedTPM parent’s seed-confinement premise, before policy use.'
        : exposed
        ? 'the plaintext is in the platform’s own memory, where the TPM has no further say. ' +
          'The policy was satisfied, not defeated — and it has nothing left to protect.'
        : 'nothing has read the released plaintext. The sealed blob on disk is unchanged and ' +
          'still requires the policy.',
      code: exposed ? 'no TPM response code — this is outside the TPM' : undefined,
    });
  }

  return assemble({
    sealed,
    current,
    plan,
    object,
    presented: { publicArea, priv, name: object.name },
    steps,
    sessionDigest: sessionReached,
    route,
    checks,
    codes,
    config,
    loaded: true,
    released,
    exposed,
  });
}

// ── The four views ──────────────────────────────────────────────────────────

function assemble(input: {
  sealed: MeasuredState;
  current: MeasuredState;
  plan: PolicyPlan;
  object: SealedObject;
  presented: { publicArea: Uint8Array; priv: Uint8Array; name: Uint8Array };
  steps: PolicyStep[];
  sessionDigest: Uint8Array;
  route: 'sealed-state' | 'recovery';
  checks: SealCheck[];
  codes: Array<{ rc: number; name: string; note: string }>;
  config: SealingConfig;
  loaded: boolean;
  released?: string;
  exposed: boolean;
}): SealingRun {
  const released = input.released;
  const verdict: SealingRun['verdict'] =
    released === undefined ? 'REFUSED' : input.exposed ? 'RELEASED — AND ALREADY EXPOSED' : 'RELEASED';

  const statesMatch = bytesEqual(input.sealed.digestTPM, input.current.digestTPM);

  return {
    ...input,
    verdict,
    views: {
      attacker: {
        holds: [
          'the sealed object’s TPM2B_PUBLIC — type, attributes, authPolicy and unique',
          'the sealed object’s TPM2B_PRIVATE — the outer HMAC, the IV and the ciphertext',
          'every PCR value, which are public and unsigned',
          'the event log, so the measured state can be replayed and predicted',
          ...(input.config.tamper === 'rebind'
            ? ['the storage parent’s seedValue — modelled here, never extractable in hardware']
            : []),
        ],
        learns: [
          released === undefined
            ? 'nothing about the secret: a refused TPM2_Unseal returns a response code and no data'
            : input.config.tamper === 'rebind'
              ? 'the platform received the attacker-chosen substitute; the original sealed ' +
                'secret was not recovered or revealed'
            : input.exposed
              ? 'the plaintext — but only because the platform had already been given it'
              : 'nothing yet; the plaintext exists only inside the platform that asked for it',
          'the length of the sealed data, from the blob’s size',
          'that unique = H(obfuscate || secret) — a non-invertible digest over a value it ' +
            'does not know, with a 32-byte TPM-generated obfuscation value in front of it',
        ],
        cannot: [
          'reconstruct the secret from unique, authPolicy, or the ciphertext',
          'compute a policyDigest the object accepts without being in an authorized state',
          'forge the authority’s approval for a state it did not sign',
          ...(input.config.tamper === 'rebind'
            ? []
            : ['derive symKey or HMACkey, which both come from the parent’s seedValue']),
        ],
      },
      platform: [
        `the boot chain produced PCRs {${input.plan.selection.join(', ')}} hashing to ${toHex(input.current.digestTPM)}`,
        statesMatch
          ? 'that is byte-identical to the state the secret was sealed to'
          : `the sealed state hashed to ${toHex(input.sealed.digestTPM)} — this machine is in a different state`,
        input.loaded
          ? input.config.tamper === 'rebind'
            ? 'TPM2_Load accepted the forged blob because its fixedTPM-parent assumption no ' +
              'longer held after the parent seed was extracted'
            : 'TPM2_Load accepted the object under the fixedTPM-parent trust boundary'
          : 'TPM2_Load refused the object, so nothing could be attempted',
        released === undefined
          ? 'the platform holds a response code and no plaintext'
          : 'the platform holds the released plaintext, and the TPM has no further say over it',
      ],
      tpm: [
        `policyDigest started at ${'00'.repeat(4)}… (a Zero Digest) and ran ${input.steps.length} assertion(s)`,
        `the session reached ${toHex(input.sessionDigest)}`,
        `the object requires ${toHex(input.plan.authPolicy)}`,
        input.codes.length === 0
          ? 'every authorization check of Part 3 §5.6 passed'
          : `the first refusal was ${input.codes[0].name} (${input.codes[0].note})`,
      ],
      ground: {
        headline:
          released === undefined
            ? 'The sealed secret was never released.'
            : input.config.tamper === 'rebind'
              ? 'The original secret stayed hidden, but an attacker-chosen replacement was released.'
            : input.exposed
              ? 'The secret was released to an authorized state, and then read by something ' +
                'running in that state.'
              : 'The secret was released to the state it was sealed to.',
        explanation:
          released === undefined
            ? 'The plaintext is still only inside the encrypted sensitive area. No part of it ' +
              'reached the caller.'
            : input.config.tamper === 'rebind'
              ? 'The storage parent had fixedTPM SET, so ObjectLoad trusted that an authenticated ' +
                'child blob came from this TPM and skipped the unique binding recomputation. That ' +
                'premise fails once the parent seed is extracted: the attacker can authenticate a ' +
                'replacement sensitive area, and a valid policy then unseals those replacement bytes.'
            : input.exposed
              ? 'This is not a policy failure. The policy did exactly what it says: it released ' +
                'the bytes to a machine in an approved state. Everything that happens to those ' +
                'bytes afterwards happens outside the TPM, and sealing has no opinion about it. ' +
                'What is exposed is the material already released — the sealed object on disk is ' +
                'unchanged and still requires the policy.'
              : 'The policy was satisfied by the measured state, not by a password or a ' +
                'signature over a claim about that state.',
      },
    },
  };
}

// ── The named scenarios ─────────────────────────────────────────────────────

export interface Scenario {
  id: string;
  label: string;
  /** What the control is demonstrating, in one line. */
  intent: string;
  config: SealingConfig;
}

/** Edit one stage's content, returning a fresh array. */
export function withStage(stages: readonly BootStage[], id: string, content: string): BootStage[] {
  return cloneStages(stages).map((s) => (s.id === id ? { ...s, content } : s));
}

const UPDATED_FIRMWARE = 'OpenFW 3.5.0 / POST / build 20260930';

export const SCENARIOS: Scenario[] = [
  {
    id: 'matching',
    label: 'Matching state — the secret is released',
    intent:
      'The machine boots exactly what it booted when the secret was sealed, so TPM2_PolicyPCR ' +
      'reproduces the sealed composite digest and the session reaches the object’s authPolicy.',
    config: {},
  },
  {
    id: 'firmware-update',
    label: 'Firmware updated — refused from the actual mismatch',
    intent:
      'One measured value changes. PCR 0 diverges, the composite digest diverges, and the ' +
      'refusal is computed from the registers rather than from a flag.',
    config: { runStages: withStage(DEFAULT_STAGES, 'firmware', UPDATED_FIRMWARE) },
  },
  {
    id: 'firmware-update-late',
    label: 'Firmware updated, and the caller does not guess the state',
    intent:
      'The same mismatch, with the expected digest omitted from TPM2_PolicyPCR. The session ' +
      'completes over the state the machine is actually in and is refused at use time instead.',
    config: {
      runStages: withStage(DEFAULT_STAGES, 'firmware', UPDATED_FIRMWARE),
      assertExpectedDigest: false,
    },
  },
  {
    id: 'wrong-selection',
    label: 'Wrong PCR selection — the same registers, a different policy',
    intent:
      'Every register holds the right value, but the session asserts PCRs {0, 4, 8} instead of ' +
      '{0, 4, 8, 9}. The marshalled selection is inside the policy digest, so this is a ' +
      'different policy.',
    config: { sessionSelection: [0, 4, 8], assertExpectedDigest: false },
  },
  {
    id: 'tamper-public',
    label: 'Public metadata tampered — one bit of authPolicy',
    intent:
      'The sealed object’s public area is not confidential, and it is not unprotected either: ' +
      'the Name is a digest of it and the Name is inside the private blob’s HMAC.',
    config: { tamper: 'public' },
  },
  {
    id: 'tamper-private',
    label: 'Ciphertext tampered — one bit of encSensitive',
    intent:
      'TPM2_Load checks the integrity value before it decrypts anything, so a fuzzed sensitive ' +
      'area produces one response code rather than a decryption oracle.',
    config: { tamper: 'private' },
  },
  {
    id: 'rebind-fixed-parent',
    label: 'Parent seed extracted — a substituted secret is accepted',
    intent:
      'An attacker holding the storage parent’s seed can produce a blob with a valid outer HMAC. ' +
      'Because that parent has fixedTPM SET, ObjectLoad trusts the TPM-created-blob premise and ' +
      'skips the binding recheck; the original secret remains hidden, but the substitute loads.',
    config: { tamper: 'rebind' },
  },
  {
    id: 'recovery-unauthorized',
    label: 'Recovery attempted by the wrong authority',
    intent:
      'The recovery branch names one key. A different key signing the same approved policy for ' +
      'the same purpose does not satisfy it.',
    config: {
      runStages: withStage(DEFAULT_STAGES, 'firmware', UPDATED_FIRMWARE),
      route: 'recovery',
      approvalAuthority: IMPOSTOR_AUTHORITY,
      assertExpectedDigest: false,
    },
  },
  {
    id: 'recovery-wrong-purpose',
    label: 'Recovery attempted for a different purpose',
    intent:
      'The right authority, the right state, and a policyRef the object’s branch does not name. ' +
      'The policyRef is inside the branch digest, so an approval cannot be moved between ' +
      'purposes.',
    config: {
      runStages: withStage(DEFAULT_STAGES, 'firmware', UPDATED_FIRMWARE),
      route: 'recovery',
      approvalPurpose: OTHER_PURPOSE,
      assertExpectedDigest: false,
    },
  },
  {
    id: 'recovery-unsigned',
    label: 'Recovery attempted with no approval at all',
    intent:
      'A NULL ticket. This is the case that would turn the recovery route into "accept any ' +
      'mismatch" if it were permitted, and it is refused.',
    config: {
      runStages: withStage(DEFAULT_STAGES, 'firmware', UPDATED_FIRMWARE),
      route: 'recovery',
      approvalUnsigned: true,
      assertExpectedDigest: false,
    },
  },
  {
    id: 'recovery-other-state',
    label: 'Recovery with an approval for a different state',
    intent:
      'The named authority really did sign something, for the right purpose — just not for the ' +
      'state this machine is in. TPM2_PolicyAuthorize compares the approval against the digest ' +
      'the session actually reached.',
    config: {
      runStages: withStage(DEFAULT_STAGES, 'firmware', UPDATED_FIRMWARE),
      route: 'recovery',
      approvedStages: withStage(DEFAULT_STAGES, 'kernel', 'vmlinuz-6.13.1 / 7ab329 / signed'),
      assertExpectedDigest: false,
    },
  },
  {
    id: 'recovery-authorized',
    label: 'Recovery, correctly authorized — released under the stated policy',
    intent:
      'The OEM signs the new firmware’s policy digest for this purpose. The sealed object is ' +
      'never re-created and its authPolicy never changes; the new state becomes reachable ' +
      'through the branch the object already carried.',
    config: {
      runStages: withStage(DEFAULT_STAGES, 'firmware', UPDATED_FIRMWARE),
      route: 'recovery',
      assertExpectedDigest: false,
    },
  },
  {
    id: 'password-instead-of-policy',
    label: 'A password offered instead of a policy session',
    intent:
      'userWithAuth is CLEAR on this object, so Part 3 §5.6 refuses USER-role authorization by ' +
      'HMAC or password outright. Without that bit the PCR policy would be optional.',
    config: { sessionKind: 'hmac-or-password' },
  },
  {
    id: 'extend-after-policy',
    label: 'A PCR extended after the policy checked the registers',
    intent:
      'The policy pinned pcrUpdateCounter when it read the registers. Anything that extends any ' +
      'PCR afterwards invalidates that reading, and the authorization fails even though the ' +
      'digest still matches.',
    config: { extendAfterPolicy: true },
  },
  {
    id: 'post-unseal',
    label: 'Released, then the running system is compromised',
    intent:
      'Every check passed honestly and the policy was never defeated. What a compromise reaches ' +
      'is the plaintext the TPM had already handed over.',
    config: { postUnsealCompromise: true },
  },
];

export function scenario(id: string): Scenario {
  const found = SCENARIOS.find((s) => s.id === id);
  if (!found) throw new Error(`unknown sealing scenario: ${id}`);
  return found;
}

/** The sealed object as it ships, for the structural exhibits. */
export function referenceSealedObject(): { plan: PolicyPlan; object: SealedObject; sealed: MeasuredState } {
  const sealed = measure(DEFAULT_STAGES);
  const plan = computePolicy({ expectedDigest: sealed.digestTPM });
  return {
    plan,
    sealed,
    object: sealObject({
      parent: SEAL_PARENT,
      secret: utf8(SEALED_SECRET),
      authPolicy: plan.authPolicy,
      obfuscate: OBFUSCATE,
      iv: SEAL_IV,
    }),
  };
}

/** Exported for the tests: the obfuscation value and IV the fixtures use. */
export const SEAL_FIXTURES = { obfuscate: OBFUSCATE, iv: SEAL_IV, ownerProof: OWNER_PROOF };

/** Exported for the tests: `unique` over the shipped secret. */
export function referenceUnique(): Uint8Array {
  return keyedHashUnique(OBFUSCATE, utf8(SEALED_SECRET));
}

/**
 * Every TPM response code this model can return, with the condition that
 * produces it. Rendered as the act's own reference table, and asserted in the
 * unit tests so a listed code cannot drift from what `decodeRc` says it is.
 *
 * These are real `TPM_RC` values from Part 2's response-code tables, not this
 * lab's own vocabulary — unlike the RATS appraisal codes the other acts use,
 * which have no standard registry and say so.
 */
export const SEAL_RESPONSE_CODES: Array<{
  name: string;
  code: number;
  from: string;
  when: string;
}> = [
  {
    name: 'TPM_RC_SUCCESS',
    code: TPM_RC.SUCCESS,
    from: 'any command',
    when: 'the policy session reached the object’s authPolicy and the command ran',
  },
  {
    name: 'TPM_RC_VALUE',
    code: rcParameter(TPM_RC.VALUE, 1),
    from: 'TPM2_PolicyPCR §23.7 · TPM2_PolicyOR §23.6 · TPM2_PolicyAuthorize §23.16',
    when:
      'the expected composite digest does not match the registers; or the session matches no ' +
      'OR branch; or the authority’s approval is for a state this session did not reach',
  },
  {
    name: 'TPM_RC_VALUE',
    code: rcParameter(TPM_RC.VALUE, 4),
    from: 'TPM2_PolicyAuthorize §23.16, parameter 4 (checkTicket)',
    when: 'the verification ticket does not match this approvedPolicy, policyRef and keySign',
  },
  {
    name: 'TPM_RC_POLICY_FAIL',
    code: rcSession(TPM_RC.POLICY_FAIL, 1),
    from: 'the authorization checks of Part 3 §5.6',
    when:
      'policySession→policyDigest does not equal the object’s authPolicy; or userWithAuth is ' +
      'CLEAR and a password or HMAC session was presented instead of a policy',
  },
  {
    name: 'TPM_RC_POLICY_CC',
    code: rcSession(TPM_RC.POLICY_CC, 1),
    from: 'the authorization checks of Part 3 §5.6',
    when: 'the policy restricted the session to one command and a different one was attempted',
  },
  {
    name: 'TPM_RC_PCR_CHANGED',
    code: TPM_RC.PCR_CHANGED,
    from: 'TPM2_PolicyPCR §23.7 and Part 3 §5.6',
    when: 'any PCR was extended after the policy read the registers',
  },
  {
    name: 'TPM_RC_INTEGRITY',
    code: rcParameter(TPM_RC.INTEGRITY, 1),
    from: 'TPM2_Load §12.2',
    when:
      'the outer HMAC over symIv ‖ encSensitive ‖ Name does not verify — which covers both a ' +
      'tampered ciphertext and a tampered public area, since the Name is a digest of the latter',
  },
  {
    name: 'TPM_RC_BINDING',
    code: TPM_RC.BINDING,
    from: 'TPM2_Load §12.2 EXAMPLE 1',
    when:
      'under a parent without fixedTPM, the public area’s unique is not ' +
      'H(obfuscate ‖ secret) over the sensitive area; Part 4 ObjectLoad skips this recheck for a ' +
      'fixedTPM parent because it assumes the TPM created or import-validated the blob',
  },
  {
    name: 'TPM_RC_TYPE',
    code: rcHandle(TPM_RC.TYPE, 1),
    from: 'TPM2_Unseal §12.7',
    when: 'itemHandle is not a TPM_ALG_KEYEDHASH data object',
  },
  {
    name: 'TPM_RC_ATTRIBUTES',
    code: rcHandle(TPM_RC.ATTRIBUTES, 1),
    from: 'TPM2_Unseal §12.7',
    when: 'restricted, decrypt or sign is SET on itemHandle, so it is a key rather than sealed data',
  },
  {
    name: 'TPM_RC_SIGNATURE',
    code: 0x1db,
    from: 'TPM2_VerifySignature §20.2',
    when:
      'the authority did not sign H(approvedPolicy ‖ policyRef), so no ticket was issued. ' +
      'Modelled rather than composed from this file’s own table.',
  },
];

/** Exported for the tests: the response-code decomposition the UI prints. */
export { rcEntry as describeResponseCode };
export { TPM_RC as SEAL_TPM_RC };
