/**
 * Enhanced Authorization — the policy-session arithmetic a TPM runs before it
 * will release anything.
 *
 * A policy is one 32-byte digest. That is the whole trick, and it is why a
 * sealed secret can be bound to a machine state without the TPM storing the
 * state: `policyDigest` starts at a Zero Digest when the session opens and
 * every assertion EXTENDS it, so the final value is characteristic of the
 * exact sequence of assertions that were satisfied. At use time the TPM
 * compares that accumulated value against the object's `authPolicy` and
 * releases nothing if they differ.
 *
 *     policyDigest_new := H_policyAlg(policyDigest_old || assertion)
 *
 * Specification, exactly — two revisions are cited because their clause
 * numbering differs and because the reference C code is published only in the
 * older one:
 *
 *   v185 = Trusted Platform Module 2.0 Library, Version 185, March 12, 2026
 *   1.83 = Trusted Platform Module Library, Family "2.0", Level 00
 *          Revision 01.83, January 25, 2024 (Part 3 "Commands with Code")
 *
 *   - Zero Digest start, "essentially an Extend":
 *       v185 Part 1 §16.7.3 Policy AND   /   1.83 Part 1 §19.7.3
 *   - PolicyUpdate(commandCode, arg2, arg3), TWO hashes, sizes NOT hashed:
 *       Part 3 §23.2.3, equations (10) and (11)
 *   - TPM2_PolicyOR:    Part 3 §23.6, eq (17)(18), code §23.6.3.1
 *   - TPM2_PolicyPCR:   Part 3 §23.7, eq (19)(20), code §23.7.3.1
 *   - TPM2_PolicyCommandCode: Part 3 §23.11, eq (27), code §23.11.3.1
 *   - TPM2_PolicyAuthorize:   Part 3 §23.16, eq (34)(35)(36), code §23.16.3.1
 *   - Authorization checks at use time: Part 3 §5.6
 *   - Selecting Multiple PCR (the composite digest):
 *       v185 Part 1 §14.5   /   1.83 Part 1 §17.5
 *
 * THE DETAIL MOST IMPLEMENTATIONS GET WRONG, and the reason the reference code
 * is transcribed here rather than paraphrased: the reference implementation
 * hashes `policyDigest` and every TPM2B through `CryptDigestUpdate2B`, which
 * adds the BUFFER ONLY — the UINT16 size field is not hashed. Command codes go
 * in through `CryptDigestUpdateInt(sizeof(TPM_CC))`, i.e. four octets
 * big-endian. But `pcrs` in TPM2_PolicyPCR is the MARSHALLED
 * TPML_PCR_SELECTION including its UINT32 count and its UINT8 sizeofSelect,
 * because the reference code marshals the structure and hashes the result. Get
 * that one wrong and every digest in this file is wrong while still looking
 * perfectly plausible.
 *
 * WHAT THIS IS NOT. No TPM is executed. There is no command buffer, no session
 * HMAC, no parameter encryption and no transport, so nothing here is wire
 * interoperable — only the policy arithmetic and the structures it hashes are
 * byte-exact. A `policyDigest` computed in JavaScript is a number, not an
 * enforcement boundary; in hardware the enforcement comes from the session
 * context living inside the chip, which is precisely what this file cannot
 * model.
 */

import { concatBytes, bytesEqual, toHex, u8, u16be, u32be } from '../core/bytes';
import { hmacSha256 } from '../core/hmac';
import { sha256, SHA256_LEN } from '../core/sha256';
import { PCR_SELECT_BYTES, TPM_ALG } from './constants';
import { pcrSelectionBitmap } from './marshal';

// ── Command codes. Part 2, "TPM_CC Constants" ───────────────────────────────

export const TPM_CC = {
  PolicySecret: 0x00000151,
  Quote: 0x00000158,
  Unseal: 0x0000015e,
  PolicyAuthorize: 0x0000016a,
  PolicyAuthValue: 0x0000016b,
  PolicyCommandCode: 0x0000016c,
  PolicyOR: 0x00000171,
  PolicyPCR: 0x0000017f,
  PCR_Extend: 0x00000182,
} as const;

export const TPM_CC_NAMES: Record<number, string> = {
  [TPM_CC.PolicySecret]: 'TPM_CC_PolicySecret',
  [TPM_CC.Quote]: 'TPM_CC_Quote',
  [TPM_CC.Unseal]: 'TPM_CC_Unseal',
  [TPM_CC.PolicyAuthorize]: 'TPM_CC_PolicyAuthorize',
  [TPM_CC.PolicyAuthValue]: 'TPM_CC_PolicyAuthValue',
  [TPM_CC.PolicyCommandCode]: 'TPM_CC_PolicyCommandCode',
  [TPM_CC.PolicyOR]: 'TPM_CC_PolicyOR',
  [TPM_CC.PolicyPCR]: 'TPM_CC_PolicyPCR',
  [TPM_CC.PCR_Extend]: 'TPM_CC_PCR_Extend',
};

/** TPM_ST_VERIFIED — the tag of a TPMT_TK_VERIFIED. Part 2, "TPM_ST Constants". */
export const TPM_ST_VERIFIED = 0x8022;

// ── Response codes. Part 2, Tables 14-16 ────────────────────────────────────

/** Set for every format-ZERO response code. */
export const RC_VER1 = 0x100;
/** Set for every format-ONE response code (bit 7). */
export const RC_FMT1 = 0x080;
/** Added when a format-one error is about a command PARAMETER rather than a handle. */
export const TPM_RC_P = 0x040;

/**
 * Base response-code numbers. A format-one code on the wire also carries an
 * index: `rcParameter`, `rcHandle` and `rcSession` compose it the way the
 * reference implementation's `RC_Command_argName` constants do.
 */
export const TPM_RC = {
  SUCCESS: 0x000,
  AUTH_TYPE: RC_VER1 + 0x024,
  POLICY: RC_VER1 + 0x026,
  PCR_CHANGED: RC_VER1 + 0x028,
  ATTRIBUTES: RC_FMT1 + 0x002,
  HASH: RC_FMT1 + 0x003,
  VALUE: RC_FMT1 + 0x004,
  TYPE: RC_FMT1 + 0x00a,
  SIZE: RC_FMT1 + 0x015,
  POLICY_FAIL: RC_FMT1 + 0x01d,
  INTEGRITY: RC_FMT1 + 0x01f,
  POLICY_CC: RC_FMT1 + 0x024,
  BINDING: RC_FMT1 + 0x025,
} as const;

export const TPM_RC_NAMES: Record<number, string> = {
  [TPM_RC.SUCCESS]: 'TPM_RC_SUCCESS',
  [TPM_RC.AUTH_TYPE]: 'TPM_RC_AUTH_TYPE',
  [TPM_RC.POLICY]: 'TPM_RC_POLICY',
  [TPM_RC.PCR_CHANGED]: 'TPM_RC_PCR_CHANGED',
  [TPM_RC.ATTRIBUTES]: 'TPM_RC_ATTRIBUTES',
  [TPM_RC.HASH]: 'TPM_RC_HASH',
  [TPM_RC.VALUE]: 'TPM_RC_VALUE',
  [TPM_RC.TYPE]: 'TPM_RC_TYPE',
  [TPM_RC.SIZE]: 'TPM_RC_SIZE',
  [TPM_RC.POLICY_FAIL]: 'TPM_RC_POLICY_FAIL',
  [TPM_RC.INTEGRITY]: 'TPM_RC_INTEGRITY',
  [TPM_RC.POLICY_CC]: 'TPM_RC_POLICY_CC',
  [TPM_RC.BINDING]: 'TPM_RC_BINDING',
};

function assertFmt1(base: number): void {
  if ((base & RC_FMT1) === 0 || base >= RC_VER1) {
    throw new Error(`not a format-one response code: 0x${base.toString(16)}`);
  }
  if (base >= RC_FMT1 + 0x040) {
    throw new Error(`format-one error number must fit 6 bits: 0x${base.toString(16)}`);
  }
}

function assertIndex(n: number, limit: number): void {
  if (!Number.isInteger(n) || n < 1 || n > limit) {
    throw new Error(`index out of range for a response code: ${n}`);
  }
}

/** A format-one code about command parameter `n` (1-based): base + TPM_RC_P + (n << 8). */
export function rcParameter(base: number, n: number): number {
  assertFmt1(base);
  assertIndex(n, 15);
  return base + TPM_RC_P + (n << 8);
}

/** A format-one code about handle `n` (1-based): base + (n << 8), P CLEAR. */
export function rcHandle(base: number, n: number): number {
  assertFmt1(base);
  assertIndex(n, 7);
  return base + (n << 8);
}

/** A format-one code about session `n` (1-based): N carries 8 + n. */
export function rcSession(base: number, n: number): number {
  assertFmt1(base);
  assertIndex(n, 7);
  return base + ((8 + n) << 8);
}

export interface DecodedRc {
  code: number;
  format: 0 | 1;
  /** The error number: the low 6 bits for format one, the low 7 for format zero. */
  number: number;
  base: number;
  name: string;
  subject: 'parameter' | 'handle' | 'session' | 'none';
  /** 1-based index of the parameter/handle/session, when one is designated. */
  index?: number;
}

/**
 * Split a response code back into its parts, so the page can show the
 * composition rather than printing an opaque hex number. Part 2 Table 15: for
 * a format-one code, P SET means a parameter error with N the parameter
 * number; P CLEAR means N in 0-7 is a handle and N in 8-15 is 8 + the session
 * number. P and N both zero means the TPM declined to designate one.
 */
export function decodeRc(code: number): DecodedRc {
  if ((code & RC_FMT1) === 0) {
    const base = code;
    return {
      code,
      format: 0,
      number: code & 0x07f,
      base,
      name: TPM_RC_NAMES[base] ?? `0x${code.toString(16)}`,
      subject: 'none',
    };
  }
  const base = RC_FMT1 + (code & 0x03f);
  const n = (code >> 8) & 0x0f;
  const parameter = (code & TPM_RC_P) !== 0;
  const name = TPM_RC_NAMES[base] ?? `0x${base.toString(16)}`;
  if (parameter) return { code, format: 1, number: code & 0x03f, base, name, subject: 'parameter', index: n };
  if (n === 0) return { code, format: 1, number: code & 0x03f, base, name, subject: 'none' };
  if (n >= 8) return { code, format: 1, number: code & 0x03f, base, name, subject: 'session', index: n - 8 };
  return { code, format: 1, number: code & 0x03f, base, name, subject: 'handle', index: n };
}

// ── The policy session ──────────────────────────────────────────────────────

/** The initial value of `policySession→policyDigest`: 0…0, nameAlg-sized. */
export const ZERO_DIGEST = new Uint8Array(SHA256_LEN);

/**
 * One satisfied assertion, kept so the page can show the exact preimage of
 * every extension rather than only the running digest.
 *
 * `hashes` is a LIST because two of these commands do not perform one hash.
 * `PolicyUpdate` (Part 3 §23.2.3) is deliberately two, and `TPM2_PolicyOR` and
 * `TPM2_PolicyAuthorize` RESET the digest to a Zero Digest before extending —
 * so a single `preimage` field would either hide the second hash or print a
 * preimage that does not begin with the digest it claims to extend. Both of
 * those would read as a mistake to anyone checking the arithmetic, which is
 * exactly who this field exists for.
 */
export interface PolicyStep {
  command: string;
  commandCode: number;
  /** The digest the session held before this command. */
  before: Uint8Array;
  /** Whether the command discards `before` and restarts from a Zero Digest. */
  resets: boolean;
  /** Every hash this command performs, in order, each with its exact input. */
  hashes: Array<{ preimage: Uint8Array; digest: Uint8Array }>;
  after: Uint8Array;
  /** What the assertion asserted, in words. */
  detail: string;
}

export interface PolicySession {
  /** Fixed at TPM2_StartAuthSession; must equal the object's nameAlg to satisfy a policy. */
  readonly policyAlg: number;
  /** TPM_SE_TRIAL: computes digests without checking anything. Part 3 §23.1. */
  readonly trial: boolean;
  policyDigest: Uint8Array;
  /** Set once by the first PolicyPCR; moves only via TPM2_PolicyRestart. */
  pcrUpdateCounter?: number;
  /** Set once by PolicyCommandCode; a different value is TPM_RC_VALUE. */
  commandCode?: number;
  readonly steps: PolicyStep[];
}

/**
 * TPM2_StartAuthSession(sessionType = TPM_SE_POLICY | TPM_SE_TRIAL).
 * Part 3 §11.1; the Zero Digest start is Part 1 §16.7.3 / 1.83 §19.7.3.
 */
export function startPolicySession(options: { trial?: boolean } = {}): PolicySession {
  return {
    policyAlg: TPM_ALG.SHA256,
    trial: options.trial ?? false,
    policyDigest: ZERO_DIGEST.slice(),
    steps: [],
  };
}

export type PolicyOutcome =
  | { ok: true; step: PolicyStep }
  | { ok: false; rc: number; rcName: string; reason: string };

function fail(rc: number, reason: string): PolicyOutcome {
  return { ok: false, rc, rcName: decodeRc(rc).name, reason };
}

function extend(
  session: PolicySession,
  parts: readonly Uint8Array[],
  command: string,
  commandCode: number,
  detail: string,
  options: { before?: Uint8Array; resets?: boolean } = {}
): PolicyOutcome {
  // `chainFrom` is what actually goes into the hash; `before` is what the
  // session held when the command arrived. They differ only for a command that
  // resets, and keeping them apart is what lets the page show a reset as a
  // reset instead of as an inexplicable preimage.
  const chainFrom = session.policyDigest.slice();
  const preimage = concatBytes(chainFrom, ...parts);
  const digest = sha256(preimage);
  session.policyDigest = digest;
  const step: PolicyStep = {
    command,
    commandCode,
    before: (options.before ?? chainFrom).slice(),
    resets: options.resets ?? false,
    hashes: [{ preimage, digest }],
    after: digest,
    detail,
  };
  session.steps.push(step);
  return { ok: true, step };
}

// ── TPML_PCR_SELECTION, marshalled ──────────────────────────────────────────

/**
 * The marshalled TPML_PCR_SELECTION that TPM2_PolicyPCR hashes.
 *
 * Part 2 §10.8.7 (1.83 §10.9.7) Table 119 and §10.5.2 (1.83 §10.6.2) Table
 * 101: a UINT32 count, then per bank a TPMI_ALG_HASH, a UINT8 `sizeofSelect`
 * and that many bitmap octets. Ten bytes for one SHA-256 bank over 24 PCRs,
 * and all ten are inside the policy digest — which is why selecting a
 * different set of registers changes the policy even when the registers
 * themselves have not moved.
 */
export function marshalPcrSelection(hashAlg: number, indices: readonly number[]): Uint8Array {
  return concatBytes(
    u32be(1),
    u16be(hashAlg),
    u8(PCR_SELECT_BYTES),
    pcrSelectionBitmap(indices)
  );
}

// ── The assertions ──────────────────────────────────────────────────────────

export interface PolicyPcrInput {
  hashAlg: number;
  /** The PCR this assertion selects. */
  indices: readonly number[];
  /**
   * The caller's expected composite digest. A zero-length value means "do not
   * check, just bind whatever the registers hold" — legal, and the reason
   * Part 3 §23.7 NOTE 1 exists.
   */
  pcrDigest: Uint8Array;
  /** What the registers actually hold right now: H(selected values, ascending). */
  digestTPM: Uint8Array;
  /** The TPM's global PCR generation counter. */
  pcrUpdateCounter: number;
}

/**
 * TPM2_PolicyPCR. Part 3 §23.7.
 *
 *   policyDigest_new := H(policyDigest_old || TPM_CC_PolicyPCR || pcrs || digestTPM)
 *
 * Three behaviours are load-bearing and all three are in the spec text rather
 * than invented here:
 *
 *  1. A `pcrDigest` that does not match `digestTPM` returns TPM_RC_VALUE and
 *     makes NO CHANGE to policyDigest. The session is not poisoned, it is
 *     simply not advanced — so a caller who guesses the state wrong learns
 *     that immediately instead of at use time.
 *  2. `pcrs` is the marshalled selection, so the selection is part of the
 *     policy. Quoting or sealing to a different set of registers is a
 *     different policy even if every register value is identical.
 *  3. `pcrUpdateCounter` is pinned on first use. If any PCR is extended
 *     afterwards the authorization fails with TPM_RC_PCR_CHANGED — even a PCR
 *     this policy never selected (NOTE 2).
 */
export function policyPCR(session: PolicySession, input: PolicyPcrInput): PolicyOutcome {
  const pcrs = marshalPcrSelection(input.hashAlg, input.indices);
  let bound = input.digestTPM;

  if (!session.trial) {
    if (session.pcrUpdateCounter !== undefined && session.pcrUpdateCounter !== input.pcrUpdateCounter) {
      return fail(
        TPM_RC.PCR_CHANGED,
        `a previous TPM2_PolicyPCR pinned pcrUpdateCounter at ${session.pcrUpdateCounter} and it is ` +
          `now ${input.pcrUpdateCounter}, so the earlier PCR check is no longer valid`
      );
    }
    if (input.pcrDigest.length !== 0 && !bytesEqual(input.pcrDigest, input.digestTPM)) {
      return fail(
        rcParameter(TPM_RC.VALUE, 1),
        `the expected composite digest for PCRs {${[...input.indices].join(', ')}} is ` +
          `${toHex(input.pcrDigest)} and the registers currently produce ${toHex(input.digestTPM)}; ` +
          'policyDigest is left unchanged'
      );
    }
  } else if (input.pcrDigest.length !== 0) {
    // Part 3 §23.7: a trial session computes from the SUPPLIED values, which
    // is how a policy for a state the TPM is not in can be calculated at all.
    bound = input.pcrDigest;
  }

  if (session.pcrUpdateCounter === undefined && !session.trial) {
    session.pcrUpdateCounter = input.pcrUpdateCounter;
  }

  return extend(
    session,
    [u32be(TPM_CC.PolicyPCR), pcrs, bound],
    'TPM2_PolicyPCR',
    TPM_CC.PolicyPCR,
    `PCRs {${[...input.indices].join(', ')}} in the SHA-256 bank hash to ${toHex(bound)}`
  );
}

/**
 * TPM2_PolicyOR. Part 3 §23.6.
 *
 * The current digest must appear in the list, else TPM_RC_VALUE. Then the
 * digest is RESET to a Zero Digest and extended with the command code and the
 * whole concatenated list — so every branch of an OR converges on one value,
 * and that value names the complete set of alternatives rather than the branch
 * that was taken. A verifier reading an `authPolicy` therefore cannot tell
 * which branch satisfied it, which is a property, not an omission.
 */
export function policyOR(session: PolicySession, branches: readonly Uint8Array[]): PolicyOutcome {
  if (branches.length < 2 || branches.length > 8) {
    // Part 3 §23.6: at least eight tagged values are supported; a one-entry
    // list is a malformed policy rather than a tighter one.
    return fail(
      rcParameter(TPM_RC.SIZE, 1),
      `TPM2_PolicyOR takes 2 to 8 branches; this list has ${branches.length}`
    );
  }
  const matched = branches.some((d) => bytesEqual(d, session.policyDigest));
  if (!session.trial && !matched) {
    return fail(
      rcParameter(TPM_RC.VALUE, 1),
      `the session has reached ${toHex(session.policyDigest)}, which is none of the ` +
        `${branches.length} authorized branches`
    );
  }
  const digests = concatBytes(...branches);
  const before = session.policyDigest.slice();
  session.policyDigest = ZERO_DIGEST.slice();
  return extend(
    session,
    [u32be(TPM_CC.PolicyOR), digests],
    'TPM2_PolicyOR',
    TPM_CC.PolicyOR,
    `one of ${branches.length} authorized branches was satisfied; the digest is reset to 0…0 ` +
      'and re-extended over the whole list',
    { before, resets: true }
  );
}

/**
 * TPM2_PolicyCommandCode. Part 3 §23.11.
 *
 *   policyDigest_new := H(policyDigest_old || TPM_CC_PolicyCommandCode || code)
 *
 * It also pins `policySession→commandCode`, and Part 3 §5.6 then refuses the
 * session for any other command. That is what stops a policy written to
 * release a sealed secret from being reused to, say, duplicate the object.
 */
export function policyCommandCode(session: PolicySession, code: number): PolicyOutcome {
  if (session.commandCode !== undefined && session.commandCode !== code) {
    return fail(
      rcParameter(TPM_RC.VALUE, 1),
      `this session is already restricted to ${TPM_CC_NAMES[session.commandCode] ?? session.commandCode}`
    );
  }
  if (!TPM_CC_NAMES[code]) {
    return fail(rcParameter(TPM_RC.POLICY_CC, 1), `command code 0x${code.toString(16)} is not implemented`);
  }
  session.commandCode = code;
  return extend(
    session,
    [u32be(TPM_CC.PolicyCommandCode), u32be(code)],
    'TPM2_PolicyCommandCode',
    TPM_CC.PolicyCommandCode,
    `this authorization is usable only for ${TPM_CC_NAMES[code]}`
  );
}

/**
 * PolicyUpdate(commandCode, arg2, arg3). Part 3 §23.2.3, equations (10)(11).
 *
 *   d1 := H(policyDigest_old || commandCode || arg2.name)
 *   d2 := H(d1 || arg3.buffer)
 *
 * TWO hashes, deliberately: arg2 and arg3 are both variable length, so a
 * single concatenation would let `arg2 = 1 2 3, arg3 = 4 5 6` collide with
 * `arg2 = 1 2, arg3 = 3 4 5 6` (the spec's own NOTE 3). The TPM2B size fields
 * are not hashed — NOTE 2.
 */
export function policyUpdate(
  before: Uint8Array,
  commandCode: number,
  arg2: Uint8Array,
  arg3: Uint8Array
): { first: Uint8Array; second: Uint8Array } {
  const first = sha256(concatBytes(before, u32be(commandCode), arg2));
  return { first, second: sha256(concatBytes(first, arg3)) };
}

/** aHash := H_aHashAlg(approvedPolicy || policyRef). Part 3 §23.16, eq (34). */
export function approvedPolicyHash(approvedPolicy: Uint8Array, policyRef: Uint8Array): Uint8Array {
  return sha256(concatBytes(approvedPolicy, policyRef));
}

/**
 * TPMT_TK_VERIFIED's digest. Part 3 §23.16, eq (35):
 *
 *   HMAC(proof, (TPM_ST_VERIFIED || aHash || keySign→name))
 *
 * `proof` is a hierarchy secret that never leaves a real TPM, which is the
 * only reason a ticket is cheaper to check than a signature AND still
 * unforgeable. Here it is a page-local value, so the ticket is a model of that
 * fact rather than that fact.
 */
export function verifiedTicketDigest(
  proof: Uint8Array,
  aHash: Uint8Array,
  keySignName: Uint8Array
): Uint8Array {
  return hmacSha256(proof, concatBytes(u16be(TPM_ST_VERIFIED), aHash, keySignName));
}

export interface VerifiedTicket {
  /** TPM_ST_VERIFIED for a real ticket; a NULL ticket carries no digest. */
  tag: number;
  hierarchy: number;
  digest: Uint8Array;
}

export interface PolicyAuthorizeInput {
  /** The policyDigest the authority signed. */
  approvedPolicy: Uint8Array;
  /** A policy qualifier, so one authority key can approve policies for distinct purposes. */
  policyRef: Uint8Array;
  /** TPM2B_NAME content of the authorizing key: nameAlg || H(TPMT_PUBLIC). */
  keySignName: Uint8Array;
  checkTicket: VerifiedTicket;
  /** The hierarchy proof the ticket was made under. */
  proof: Uint8Array;
}

/**
 * TPM2_PolicyAuthorize. Part 3 §23.16.
 *
 * This is the command that lets a fixed `authPolicy` survive a measurement
 * change, and the spec says so in its own words: Part 1 §16.7.11 (1.83
 * §19.7.11) calls a policy that cannot accommodate new PCR values "brittle",
 * gives the BIOS-update case as the example, and Figure 16 is exactly the
 * shape used by this lab's recovery route.
 *
 * The order matters. The session must ALREADY have reached the digest the
 * authority signed; only then is the digest reset to zero and replaced by a
 * digest of the AUTHORITY'S NAME and the policyRef. So the resulting value
 * says "someone the object trusts approved some state", and says nothing about
 * which state — which is why one recovery branch can cover every future
 * firmware version without the sealed object being re-created, and equally why
 * the authority's signature is the whole of the security.
 */
export function policyAuthorize(session: PolicySession, input: PolicyAuthorizeInput): PolicyOutcome {
  if (input.keySignName.length < 2) {
    return fail(rcParameter(TPM_RC.SIZE, 3), 'keySign is too short to carry a nameAlg');
  }
  const nameAlg = (input.keySignName[0] << 8) | input.keySignName[1];
  if (nameAlg !== TPM_ALG.SHA256) {
    return fail(
      rcParameter(TPM_RC.HASH, 3),
      `keySign names hash algorithm 0x${nameAlg.toString(16)}; this model implements SHA-256 only`
    );
  }
  if (input.keySignName.length - 2 !== SHA256_LEN) {
    return fail(
      rcParameter(TPM_RC.SIZE, 3),
      `keySign is ${input.keySignName.length} bytes; a SHA-256 Name is ${SHA256_LEN + 2}`
    );
  }

  if (!session.trial) {
    if (!bytesEqual(session.policyDigest, input.approvedPolicy)) {
      return fail(
        rcParameter(TPM_RC.VALUE, 1),
        `the authority approved ${toHex(input.approvedPolicy)} but this session has reached ` +
          `${toHex(session.policyDigest)}, so the approval does not apply to this state`
      );
    }
    const aHash = approvedPolicyHash(input.approvedPolicy, input.policyRef);
    const expected = verifiedTicketDigest(input.proof, aHash, input.keySignName);
    if (input.checkTicket.tag !== TPM_ST_VERIFIED || !bytesEqual(input.checkTicket.digest, expected)) {
      return fail(
        rcParameter(TPM_RC.VALUE, 4),
        'the verification ticket does not match this approvedPolicy, policyRef and keySign — ' +
          'either a different authority signed it, it was signed for a different purpose, or ' +
          'nobody signed it at all'
      );
    }
  }

  // Part 3 §23.16: reset to a Zero Digest, then PolicyUpdate.
  const before = session.policyDigest.slice();
  const { first, second } = policyUpdate(
    ZERO_DIGEST,
    TPM_CC.PolicyAuthorize,
    input.keySignName,
    input.policyRef
  );
  session.policyDigest = second;
  const step: PolicyStep = {
    command: 'TPM2_PolicyAuthorize',
    commandCode: TPM_CC.PolicyAuthorize,
    before,
    resets: true,
    // PolicyUpdate is two hashes (Part 3 §23.2.3 NOTE 3), over a digest that
    // has just been reset to zero. Both are shown.
    hashes: [
      {
        preimage: concatBytes(ZERO_DIGEST, u32be(TPM_CC.PolicyAuthorize), input.keySignName),
        digest: first,
      },
      { preimage: concatBytes(first, input.policyRef), digest: second },
    ],
    after: second,
    detail:
      `the authority named ${toHex(input.keySignName)} approved this state for purpose ` +
      `"${new TextDecoder().decode(input.policyRef)}"; the digest is replaced by one over the ` +
      'authority Name, so it no longer mentions the state at all',
  };
  session.steps.push(step);
  return { ok: true, step };
}

// ── Use time. Part 3 §5.6 Authorization Checks ──────────────────────────────

export interface AuthorizedEntity {
  /** The entity's authPolicy, from its public area. Empty means no policy. */
  authPolicy: Uint8Array;
  /** TPMA_OBJECT userWithAuth. CLEAR forces a policy session for USER role. */
  userWithAuth: boolean;
  /** The nameAlg the authPolicy was computed under. */
  nameAlg: number;
}

export interface AuthorizationAttempt {
  /** The command the session is being used to authorize. */
  commandCode: number;
  /** The TPM's current PCR generation counter at use time. */
  pcrUpdateCounter: number;
  /** Whether a policy session is being presented at all. */
  sessionKind: 'policy' | 'hmac-or-password';
}

export type AuthorizationResult =
  | { ok: true }
  | { ok: false; rc: number; rcName: string; reason: string };

/**
 * The checks a TPM performs on an authorization session BEFORE the command
 * runs, in the order Part 3 §5.6 states them, restricted to the ones a sealed
 * data object with a PCR policy can fail.
 *
 * This function is where the lesson's whole claim lives, so it is worth being
 * exact about which failures belong here rather than to the command:
 *
 *   - `userWithAuth` CLEAR and an HMAC/password presented → TPM_RC_POLICY_FAIL
 *     (§5.6, USER role, item 1). This is why the sealed object in this lab has
 *     the attribute CLEAR: with it SET, knowing an authValue would be enough
 *     and the PCR policy would be decoration.
 *   - `policySession→commandCode` set and a different command → TPM_RC_POLICY_CC.
 *   - `policySession→policyDigest` not equal to the entity's `authPolicy` →
 *     TPM_RC_POLICY_FAIL. This is the comparison the sealed secret rests on,
 *     and nothing about it is in TPM2_Unseal: the command never sees a policy.
 *   - `policySession→pcrUpdateCounter` moved → TPM_RC_PCR_CHANGED.
 */
export function checkPolicyAuthorization(
  session: PolicySession,
  entity: AuthorizedEntity,
  attempt: AuthorizationAttempt
): AuthorizationResult {
  const sessionFail = (rc: number, reason: string): AuthorizationResult => ({
    ok: false,
    rc,
    rcName: decodeRc(rc).name,
    reason,
  });

  if (!entity.userWithAuth && attempt.sessionKind !== 'policy') {
    return sessionFail(
      rcSession(TPM_RC.POLICY_FAIL, 1),
      'this object has userWithAuth CLEAR, so USER-role authorization may not be given with an ' +
        'HMAC session or a password — only a satisfied policy session will do'
    );
  }
  // TPM_RC_AUTH_TYPE is a format-ZERO code (RC_VER1 + 0x024), so it carries no
  // handle/parameter/session index: only format-one codes have an N field
  // (Part 2 Tables 14-15). Composing one would be a category error.
  if (attempt.sessionKind !== 'policy') {
    return sessionFail(TPM_RC.AUTH_TYPE, 'this model only evaluates policy sessions');
  }
  if (session.trial) {
    return sessionFail(
      TPM_RC.AUTH_TYPE,
      'a trial session computes digests and authorizes nothing — Part 3 §23.1'
    );
  }
  if (session.policyAlg !== entity.nameAlg) {
    return sessionFail(
      rcSession(TPM_RC.POLICY_FAIL, 1),
      'the session digest algorithm and the entity nameAlg differ, so the two digests are not ' +
        'comparable (Part 1 §16.7.1 NOTE)'
    );
  }
  if (session.commandCode !== undefined && session.commandCode !== attempt.commandCode) {
    return sessionFail(
      rcSession(TPM_RC.POLICY_CC, 1),
      `the policy restricted this authorization to ` +
        `${TPM_CC_NAMES[session.commandCode] ?? session.commandCode}, and the command is ` +
        `${TPM_CC_NAMES[attempt.commandCode] ?? attempt.commandCode}`
    );
  }
  if (entity.authPolicy.length === 0) {
    return sessionFail(
      rcSession(TPM_RC.POLICY_FAIL, 1),
      'this entity has no authPolicy, so a policy session cannot authorize it'
    );
  }
  if (!bytesEqual(session.policyDigest, entity.authPolicy)) {
    return sessionFail(
      rcSession(TPM_RC.POLICY_FAIL, 1),
      `the session accumulated ${toHex(session.policyDigest)} and the object requires ` +
        `${toHex(entity.authPolicy)}`
    );
  }
  if (session.pcrUpdateCounter !== undefined && session.pcrUpdateCounter !== attempt.pcrUpdateCounter) {
    return sessionFail(
      TPM_RC.PCR_CHANGED,
      `the PCR generation counter was ${session.pcrUpdateCounter} when the policy checked the ` +
        `registers and is ${attempt.pcrUpdateCounter} now`
    );
  }
  return { ok: true };
}
