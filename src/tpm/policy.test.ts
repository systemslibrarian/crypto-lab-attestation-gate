import { describe, expect, it } from 'vitest';
import { sha256 as nobleSha256 } from '@noble/hashes/sha2.js';
import { hmac as nobleHmac } from '@noble/hashes/hmac.js';
import { fromHex, toHex, utf8 } from '../core/bytes';
import { sha256 } from '../core/sha256';
import { TPM_ALG, TPM_RH } from './constants';
import { EK_AUTH_POLICY } from './key';
import {
  checkPolicyAuthorization,
  decodeRc,
  marshalPcrSelection,
  policyAuthorize,
  policyCommandCode,
  policyOR,
  policyPCR,
  policyUpdate,
  rcHandle,
  rcParameter,
  rcSession,
  RC_FMT1,
  startPolicySession,
  TPM_CC,
  TPM_RC,
  TPM_ST_VERIFIED,
  verifiedTicketDigest,
  ZERO_DIGEST,
  type PolicySession,
} from './policy';

/**
 * Enhanced-authorization arithmetic, checked three ways.
 *
 * 1. AGAINST A PUBLISHED CONSTANT. The TCG EK Credential Profile's authPolicy
 *    is the digest of a one-assertion policy, `TPM2_PolicySecret` against the
 *    endorsement hierarchy. Re-deriving it through `policyUpdate` pins the
 *    Zero-Digest start, the four-octet big-endian command code, the
 *    "TPM2B sizes are not hashed" rule and the two-hash `PolicyUpdate`
 *    structure to a value TCG publishes — not to this file's own output.
 *
 * 2. AGAINST A PUBLISHED WORKED EXAMPLE. Part 2's response-code clause works
 *    one composition out longhand: "TPM_RC_VALUE (RC_FMT1 (0x080) + 0x004) +
 *    RC_Startup_startupType is thus 0x080 + 0x004 + 0x140 = 0x1c4". That is
 *    asserted literally.
 *
 * 3. AGAINST AN INDEPENDENT RE-IMPLEMENTATION. Every policy equation is
 *    recomputed here from the specification text using `@noble/hashes` rather
 *    than this repo's hand-rolled SHA-256, so a shared bug in the primitive
 *    cannot make both sides agree.
 *
 * No published test vector for `TPM2_PolicyPCR`, `TPM2_PolicyOR` or
 * `TPM2_PolicyCommandCode` was located, so those three are checked by (3) and
 * by their structural properties, and that limitation is recorded in the
 * handoff rather than papered over.
 */

const be32 = (v: number): Uint8Array =>
  new Uint8Array([(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff]);
const be16 = (v: number): Uint8Array => new Uint8Array([(v >>> 8) & 0xff, v & 0xff]);
const cat = (...parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
};
/** An independent H(), from a separately written library. */
const refH = (...parts: Uint8Array[]): Uint8Array => nobleSha256(cat(...parts));
const ZERO = new Uint8Array(32);

describe('the published anchor', () => {
  it('re-derives the TCG EK Credential Profile authPolicy through policyUpdate', () => {
    // PolicyUpdate(TPM_CC_PolicySecret, authObject->Name, policyRef). The
    // authorizing entity is TPM_RH_ENDORSEMENT, a permanent handle, whose Name
    // is the four octets of the handle itself. policyRef is the Empty Buffer.
    const { first, second } = policyUpdate(
      ZERO_DIGEST,
      TPM_CC.PolicySecret,
      be32(TPM_RH.ENDORSEMENT),
      new Uint8Array(0)
    );
    expect(toHex(second)).toBe(toHex(EK_AUTH_POLICY));
    expect(toHex(second)).toBe('837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa');
    // And independently, with a different SHA-256.
    expect(toHex(first)).toBe(toHex(refH(ZERO, be32(0x00000151), be32(0x4000000b))));
    expect(toHex(second)).toBe(toHex(refH(refH(ZERO, be32(0x00000151), be32(0x4000000b)))));
  });

  it('is two hashes, which is what stops arg2/arg3 from colliding', () => {
    // Part 3 §23.2.3 NOTE 3's own example: a single concatenation would make
    // these two calls produce the same digest. They must not.
    const a = policyUpdate(ZERO_DIGEST, TPM_CC.PolicyAuthorize, new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6]));
    const b = policyUpdate(ZERO_DIGEST, TPM_CC.PolicyAuthorize, new Uint8Array([1, 2]), new Uint8Array([3, 4, 5, 6]));
    expect(toHex(a.second)).not.toBe(toHex(b.second));
    // The single-hash version this guards against really does collide, so the
    // test above is discriminating rather than vacuously true.
    const naive = (x: Uint8Array, y: Uint8Array): string =>
      toHex(refH(ZERO, be32(TPM_CC.PolicyAuthorize), x, y));
    expect(naive(new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6]))).toBe(
      naive(new Uint8Array([1, 2]), new Uint8Array([3, 4, 5, 6]))
    );
  });
});

describe('response code composition', () => {
  it('matches Part 2’s own worked example: 0x080 + 0x004 + 0x140 = 0x1c4', () => {
    expect(rcParameter(TPM_RC.VALUE, 1)).toBe(0x1c4);
  });

  it('reproduces this lab’s existing TPM_RC_TICKET on TPM2_Sign parameter 3', () => {
    // 0x080 + 0x020 (TPM_RC_TICKET) + TPM_RC_P + TPM_RC_3 = 0x3e0, the value
    // `key.ts` already ships as TPM_RC_TICKET_ON_SIGN.
    expect(rcParameter(0x080 + 0x020, 3)).toBe(0x3e0);
  });

  it('distinguishes a parameter, a handle and a session in the N field', () => {
    expect(decodeRc(rcParameter(TPM_RC.VALUE, 4))).toMatchObject({
      format: 1,
      name: 'TPM_RC_VALUE',
      subject: 'parameter',
      index: 4,
    });
    expect(decodeRc(rcHandle(TPM_RC.TYPE, 1))).toMatchObject({
      format: 1,
      name: 'TPM_RC_TYPE',
      subject: 'handle',
      index: 1,
    });
    expect(decodeRc(rcSession(TPM_RC.POLICY_FAIL, 1))).toMatchObject({
      format: 1,
      name: 'TPM_RC_POLICY_FAIL',
      subject: 'session',
      index: 1,
    });
    // A format-ZERO code designates nothing.
    expect(decodeRc(TPM_RC.PCR_CHANGED)).toMatchObject({
      format: 0,
      name: 'TPM_RC_PCR_CHANGED',
      subject: 'none',
    });
  });

  it('refuses to compose a format-zero code as if it were format one', () => {
    expect(() => rcParameter(TPM_RC.PCR_CHANGED, 1)).toThrow(/format-one/);
    expect(() => rcHandle(TPM_RC.AUTH_TYPE, 1)).toThrow(/format-one/);
  });

  it('refuses an error number that does not fit the six bits Table 15 gives it', () => {
    expect(() => rcParameter(RC_FMT1 + 0x040, 1)).toThrow(/must fit 6 bits/);
  });

  it('refuses an index outside the range the N field can carry', () => {
    expect(() => rcParameter(TPM_RC.VALUE, 0)).toThrow(/index out of range/);
    expect(() => rcHandle(TPM_RC.TYPE, 8)).toThrow(/index out of range/);
    expect(() => rcSession(TPM_RC.POLICY_FAIL, 8)).toThrow(/index out of range/);
  });

  it('carries the specification’s own base numbers', () => {
    expect(TPM_RC.VALUE).toBe(0x084);
    expect(TPM_RC.TYPE).toBe(0x08a);
    expect(TPM_RC.ATTRIBUTES).toBe(0x082);
    expect(TPM_RC.POLICY_FAIL).toBe(0x09d);
    expect(TPM_RC.INTEGRITY).toBe(0x09f);
    expect(TPM_RC.BINDING).toBe(0x0a5);
    expect(TPM_RC.POLICY_CC).toBe(0x0a4);
    expect(TPM_RC.PCR_CHANGED).toBe(0x128);
    expect(TPM_RC.AUTH_TYPE).toBe(0x124);
  });

  it('carries the specification’s own command codes', () => {
    expect(TPM_CC.Unseal).toBe(0x0000015e);
    expect(TPM_CC.PolicySecret).toBe(0x00000151);
    expect(TPM_CC.PolicyAuthorize).toBe(0x0000016a);
    expect(TPM_CC.PolicyCommandCode).toBe(0x0000016c);
    expect(TPM_CC.PolicyOR).toBe(0x00000171);
    expect(TPM_CC.PolicyPCR).toBe(0x0000017f);
    expect(TPM_ST_VERIFIED).toBe(0x8022);
  });
});

describe('the marshalled TPML_PCR_SELECTION', () => {
  it('is ten bytes for one SHA-256 bank over 24 PCRs', () => {
    expect(marshalPcrSelection(TPM_ALG.SHA256, [0, 4, 8, 9]).length).toBe(10);
  });

  it('matches Part 1’s worked bitmap example for PCR 0 and PCR 13', () => {
    // "An array to select PCR[0] and PCR[13] ... would be 01 20" — here inside
    // the full structure: count 1, SHA-256, three octets, 01 20 00.
    expect(toHex(marshalPcrSelection(TPM_ALG.SHA256, [0, 13]))).toBe('00000001000b03012000');
  });

  it('matches Part 2’s worked bitmap example for PCR 19 alone', () => {
    expect(toHex(marshalPcrSelection(TPM_ALG.SHA256, [19]))).toBe('00000001000b03000008');
  });

  it('is a different structure for a different selection of the same registers', () => {
    expect(toHex(marshalPcrSelection(TPM_ALG.SHA256, [0, 4, 8]))).not.toBe(
      toHex(marshalPcrSelection(TPM_ALG.SHA256, [0, 4, 8, 9]))
    );
  });
});

describe('TPM2_PolicyPCR', () => {
  const pcrs = marshalPcrSelection(TPM_ALG.SHA256, [0, 4, 8, 9]);
  const digestTPM = sha256(utf8('a measured state'));

  const run = (overrides: Partial<Parameters<typeof policyPCR>[1]> = {}, trial = false) => {
    const session = startPolicySession({ trial });
    const outcome = policyPCR(session, {
      hashAlg: TPM_ALG.SHA256,
      indices: [0, 4, 8, 9],
      pcrDigest: digestTPM,
      digestTPM,
      pcrUpdateCounter: 11,
      ...overrides,
    });
    return { session, outcome };
  };

  it('starts from a Zero Digest', () => {
    const session = startPolicySession();
    expect(toHex(session.policyDigest)).toBe('00'.repeat(32));
    expect(session.policyAlg).toBe(TPM_ALG.SHA256);
  });

  it('extends policyDigest_old || TPM_CC_PolicyPCR || pcrs || digestTPM', () => {
    const { session, outcome } = run();
    expect(outcome.ok).toBe(true);
    expect(toHex(session.policyDigest)).toBe(
      toHex(refH(ZERO, be32(0x0000017f), pcrs, digestTPM))
    );
  });

  it('returns TPM_RC_VALUE and changes nothing when the expected digest is wrong', () => {
    const { session, outcome } = run({ pcrDigest: sha256(utf8('a different state')) });
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.rc).toBe(rcParameter(TPM_RC.VALUE, 1));
      expect(outcome.rcName).toBe('TPM_RC_VALUE');
    }
    expect(toHex(session.policyDigest)).toBe('00'.repeat(32));
    expect(session.steps).toEqual([]);
  });

  it('binds whatever the registers hold when pcrDigest is zero length', () => {
    const { session, outcome } = run({ pcrDigest: new Uint8Array(0) });
    expect(outcome.ok).toBe(true);
    expect(toHex(session.policyDigest)).toBe(toHex(refH(ZERO, be32(0x0000017f), pcrs, digestTPM)));
  });

  it('pins pcrUpdateCounter on first use and refuses when it has moved', () => {
    const { session } = run();
    expect(session.pcrUpdateCounter).toBe(11);
    const second = policyPCR(session, {
      hashAlg: TPM_ALG.SHA256,
      indices: [0, 4, 8, 9],
      pcrDigest: digestTPM,
      digestTPM,
      pcrUpdateCounter: 12,
    });
    expect(second.ok).toBe(false);
    if (!second.ok) expect(second.rc).toBe(TPM_RC.PCR_CHANGED);
  });

  it('computes from the SUPPLIED digest in a trial session, and pins no counter', () => {
    const supplied = sha256(utf8('a state this TPM is not in'));
    const { session, outcome } = run({ pcrDigest: supplied, digestTPM }, true);
    expect(outcome.ok).toBe(true);
    expect(toHex(session.policyDigest)).toBe(toHex(refH(ZERO, be32(0x0000017f), pcrs, supplied)));
    expect(session.pcrUpdateCounter).toBeUndefined();
  });

  it('is a different policy for a different selection with identical registers', () => {
    const a = run().session.policyDigest;
    const b = run({ indices: [0, 4, 8] }).session.policyDigest;
    expect(toHex(a)).not.toBe(toHex(b));
  });
});

describe('TPM2_PolicyOR', () => {
  const branchA = sha256(utf8('branch A'));
  const branchB = sha256(utf8('branch B'));

  const at = (digest: Uint8Array): PolicySession => {
    const session = startPolicySession();
    session.policyDigest = digest.slice();
    return session;
  };

  it('resets to a Zero Digest and extends over the whole list', () => {
    const session = at(branchA);
    const outcome = policyOR(session, [branchA, branchB]);
    expect(outcome.ok).toBe(true);
    expect(toHex(session.policyDigest)).toBe(
      toHex(refH(ZERO, be32(0x00000171), branchA, branchB))
    );
  });

  it('converges: both branches reach the same digest', () => {
    const fromA = at(branchA);
    const fromB = at(branchB);
    policyOR(fromA, [branchA, branchB]);
    policyOR(fromB, [branchA, branchB]);
    expect(toHex(fromA.policyDigest)).toBe(toHex(fromB.policyDigest));
  });

  it('depends on the ORDER of the list, because the digests are concatenated', () => {
    const forward = at(branchA);
    const reversed = at(branchA);
    policyOR(forward, [branchA, branchB]);
    policyOR(reversed, [branchB, branchA]);
    expect(toHex(forward.policyDigest)).not.toBe(toHex(reversed.policyDigest));
  });

  it('returns TPM_RC_VALUE when the session matches no branch', () => {
    const session = at(sha256(utf8('somewhere else')));
    const outcome = policyOR(session, [branchA, branchB]);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.rc).toBe(rcParameter(TPM_RC.VALUE, 1));
  });

  it('assumes a match in a trial session', () => {
    const session = startPolicySession({ trial: true });
    session.policyDigest = sha256(utf8('somewhere else'));
    expect(policyOR(session, [branchA, branchB]).ok).toBe(true);
  });

  it('refuses a one-entry list and a nine-entry list', () => {
    expect(policyOR(at(branchA), [branchA]).ok).toBe(false);
    expect(policyOR(at(branchA), Array.from({ length: 9 }, () => branchA)).ok).toBe(false);
  });
});

describe('TPM2_PolicyCommandCode', () => {
  it('extends policyDigest_old || TPM_CC_PolicyCommandCode || code', () => {
    const session = startPolicySession();
    const outcome = policyCommandCode(session, TPM_CC.Unseal);
    expect(outcome.ok).toBe(true);
    expect(toHex(session.policyDigest)).toBe(
      toHex(refH(ZERO, be32(0x0000016c), be32(0x0000015e)))
    );
    expect(session.commandCode).toBe(TPM_CC.Unseal);
  });

  it('refuses a second, different command code', () => {
    const session = startPolicySession();
    policyCommandCode(session, TPM_CC.Unseal);
    const again = policyCommandCode(session, TPM_CC.Quote);
    expect(again.ok).toBe(false);
    if (!again.ok) expect(again.rc).toBe(rcParameter(TPM_RC.VALUE, 1));
  });

  it('reports TPM_RC_POLICY_CC for a command this model does not implement', () => {
    const outcome = policyCommandCode(startPolicySession(), 0x00000999);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.rcName).toBe('TPM_RC_POLICY_CC');
  });
});

describe('TPM2_PolicyAuthorize', () => {
  const proof = sha256(utf8('an owner hierarchy proof'));
  const keyName = new Uint8Array([0x00, 0x0b, ...sha256(utf8('an authority key public area'))]);
  const policyRef = utf8('a stated purpose');
  const approved = sha256(utf8('the state the authority approved'));

  const ticketFor = (
    policy: Uint8Array,
    ref: Uint8Array = policyRef,
    name: Uint8Array = keyName
  ) => ({
    tag: TPM_ST_VERIFIED,
    hierarchy: TPM_RH.OWNER,
    digest: verifiedTicketDigest(proof, refH(policy, ref), name),
  });

  const sessionAt = (digest: Uint8Array): PolicySession => {
    const s = startPolicySession();
    s.policyDigest = digest.slice();
    return s;
  };

  it('computes the ticket as HMAC(proof, TPM_ST_VERIFIED || aHash || keySign.name)', () => {
    const aHash = refH(approved, policyRef);
    expect(toHex(verifiedTicketDigest(proof, aHash, keyName))).toBe(
      toHex(nobleHmac(nobleSha256, proof, cat(be16(0x8022), aHash, keyName)))
    );
  });

  it('replaces the digest with one over the authority Name and the policyRef', () => {
    const session = sessionAt(approved);
    const outcome = policyAuthorize(session, {
      approvedPolicy: approved,
      policyRef,
      keySignName: keyName,
      checkTicket: ticketFor(approved),
      proof,
    });
    expect(outcome.ok).toBe(true);
    // Reset to zero, then PolicyUpdate(TPM_CC_PolicyAuthorize, keySign, policyRef).
    expect(toHex(session.policyDigest)).toBe(
      toHex(refH(refH(ZERO, be32(0x0000016a), keyName), policyRef))
    );
  });

  it('reaches the same digest from any approved state — Part 1 Figure 16', () => {
    const other = sha256(utf8('a completely different approved state'));
    const first = sessionAt(approved);
    const second = sessionAt(other);
    policyAuthorize(first, {
      approvedPolicy: approved,
      policyRef,
      keySignName: keyName,
      checkTicket: ticketFor(approved),
      proof,
    });
    policyAuthorize(second, {
      approvedPolicy: other,
      policyRef,
      keySignName: keyName,
      checkTicket: ticketFor(other),
      proof,
    });
    expect(toHex(first.policyDigest)).toBe(toHex(second.policyDigest));
  });

  it('refuses when the approval is for a state this session did not reach', () => {
    const session = sessionAt(sha256(utf8('where this machine actually is')));
    const outcome = policyAuthorize(session, {
      approvedPolicy: approved,
      policyRef,
      keySignName: keyName,
      checkTicket: ticketFor(approved),
      proof,
    });
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.rc).toBe(rcParameter(TPM_RC.VALUE, 1));
  });

  it('refuses a ticket minted for a different purpose', () => {
    const session = sessionAt(approved);
    const outcome = policyAuthorize(session, {
      approvedPolicy: approved,
      policyRef,
      keySignName: keyName,
      checkTicket: ticketFor(approved, utf8('some other purpose')),
      proof,
    });
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.rc).toBe(rcParameter(TPM_RC.VALUE, 4));
  });

  it('refuses a ticket minted for a different authority', () => {
    const session = sessionAt(approved);
    const outcome = policyAuthorize(session, {
      approvedPolicy: approved,
      policyRef,
      keySignName: keyName,
      checkTicket: ticketFor(approved, policyRef, new Uint8Array([0x00, 0x0b, ...sha256(utf8('someone else'))])),
      proof,
    });
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.rc).toBe(rcParameter(TPM_RC.VALUE, 4));
  });

  it('refuses a NULL ticket', () => {
    const session = sessionAt(approved);
    const outcome = policyAuthorize(session, {
      approvedPolicy: approved,
      policyRef,
      keySignName: keyName,
      checkTicket: { tag: TPM_ST_VERIFIED, hierarchy: TPM_RH.NULL, digest: new Uint8Array(0) },
      proof,
    });
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.rc).toBe(rcParameter(TPM_RC.VALUE, 4));
  });

  it('refuses a keySign Name too short to carry a nameAlg at all', () => {
    const session = sessionAt(approved);
    const outcome = policyAuthorize(session, {
      approvedPolicy: approved,
      policyRef,
      keySignName: new Uint8Array([0x00]),
      checkTicket: ticketFor(approved),
      proof,
    });
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.rcName).toBe('TPM_RC_SIZE');
  });

  it('refuses a keySign Name with an unsupported hash or a wrong length', () => {
    const session = sessionAt(approved);
    const badAlg = policyAuthorize(session, {
      approvedPolicy: approved,
      policyRef,
      keySignName: new Uint8Array([0x00, 0x04, ...sha256(utf8('sha1-named key')).slice(0, 20)]),
      checkTicket: ticketFor(approved),
      proof,
    });
    expect(badAlg.ok).toBe(false);
    if (!badAlg.ok) expect(badAlg.rcName).toBe('TPM_RC_HASH');
    const badLength = policyAuthorize(session, {
      approvedPolicy: approved,
      policyRef,
      keySignName: new Uint8Array([0x00, 0x0b, 1, 2, 3]),
      checkTicket: ticketFor(approved),
      proof,
    });
    expect(badLength.ok).toBe(false);
    if (!badLength.ok) expect(badLength.rcName).toBe('TPM_RC_SIZE');
  });
});

describe('the authorization checks of Part 3 §5.6', () => {
  const authPolicy = sha256(utf8('an authPolicy'));
  const entity = { authPolicy, userWithAuth: false, nameAlg: TPM_ALG.SHA256 };
  const attempt = {
    commandCode: TPM_CC.Unseal,
    pcrUpdateCounter: 11,
    sessionKind: 'policy' as const,
  };

  const satisfied = (): PolicySession => {
    const s = startPolicySession();
    s.policyDigest = authPolicy.slice();
    s.commandCode = TPM_CC.Unseal;
    s.pcrUpdateCounter = 11;
    return s;
  };

  it('authorizes a session whose digest equals the authPolicy', () => {
    expect(checkPolicyAuthorization(satisfied(), entity, attempt)).toEqual({ ok: true });
  });

  it('refuses a password when userWithAuth is CLEAR', () => {
    const result = checkPolicyAuthorization(satisfied(), entity, {
      ...attempt,
      sessionKind: 'hmac-or-password',
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.rcName).toBe('TPM_RC_POLICY_FAIL');
      expect(result.rc).toBe(rcSession(TPM_RC.POLICY_FAIL, 1));
    }
  });

  it('refuses a digest that differs from the authPolicy', () => {
    const session = satisfied();
    session.policyDigest = sha256(utf8('a different policy'));
    const result = checkPolicyAuthorization(session, entity, attempt);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.rcName).toBe('TPM_RC_POLICY_FAIL');
  });

  it('refuses a command the policy did not permit', () => {
    const result = checkPolicyAuthorization(satisfied(), entity, {
      ...attempt,
      commandCode: TPM_CC.Quote,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.rcName).toBe('TPM_RC_POLICY_CC');
  });

  it('refuses when pcrUpdateCounter has moved since the policy read the registers', () => {
    const result = checkPolicyAuthorization(satisfied(), entity, {
      ...attempt,
      pcrUpdateCounter: 12,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.rcName).toBe('TPM_RC_PCR_CHANGED');
  });

  it('refuses a password even when userWithAuth is SET, since this model has no authValue', () => {
    // A different refusal from the userWithAuth-CLEAR case above, and a
    // different code: TPM_RC_AUTH_TYPE is format ZERO, so it designates no
    // handle, parameter or session.
    const result = checkPolicyAuthorization(
      satisfied(),
      { ...entity, userWithAuth: true },
      { ...attempt, sessionKind: 'hmac-or-password' }
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.rcName).toBe('TPM_RC_AUTH_TYPE');
      expect(result.rc).toBe(TPM_RC.AUTH_TYPE);
      expect(decodeRc(result.rc).subject).toBe('none');
    }
  });

  it('refuses a trial session outright', () => {
    const session = startPolicySession({ trial: true });
    session.policyDigest = authPolicy.slice();
    session.commandCode = TPM_CC.Unseal;
    const result = checkPolicyAuthorization(session, entity, attempt);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.rcName).toBe('TPM_RC_AUTH_TYPE');
  });

  it('refuses an entity with no authPolicy', () => {
    const result = checkPolicyAuthorization(
      satisfied(),
      { ...entity, authPolicy: new Uint8Array(0) },
      attempt
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.rcName).toBe('TPM_RC_POLICY_FAIL');
  });

  it('refuses when the session hash and the entity nameAlg differ', () => {
    const result = checkPolicyAuthorization(
      satisfied(),
      { ...entity, nameAlg: TPM_ALG.SHA384 },
      attempt
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.rcName).toBe('TPM_RC_POLICY_FAIL');
  });
});

describe('the step record every panel renders from', () => {
  const digestTPM = sha256(utf8('a measured state'));
  const branchA = sha256(utf8('branch A'));
  const branchB = sha256(utf8('branch B'));
  const proof = sha256(utf8('a proof'));
  const keyName = new Uint8Array([0x00, 0x0b, ...sha256(utf8('an authority'))]);
  const policyRef = utf8('a purpose');

  it('records one hash whose preimage begins with the digest it extends', () => {
    const session = startPolicySession();
    const outcome = policyPCR(session, {
      hashAlg: TPM_ALG.SHA256,
      indices: [0, 4],
      pcrDigest: digestTPM,
      digestTPM,
      pcrUpdateCounter: 1,
    });
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    const step = outcome.step;
    expect(step.resets).toBe(false);
    expect(step.hashes).toHaveLength(1);
    expect(toHex(step.hashes[0].preimage).startsWith(toHex(step.before))).toBe(true);
    expect(toHex(step.hashes[0].digest)).toBe(toHex(step.after));
    expect(toHex(sha256(step.hashes[0].preimage))).toBe(toHex(step.after));
  });

  it('marks TPM2_PolicyOR as a reset, and keeps the real prior digest in `before`', () => {
    const session = startPolicySession();
    session.policyDigest = branchA.slice();
    const outcome = policyOR(session, [branchA, branchB]);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    const step = outcome.step;
    expect(step.resets).toBe(true);
    // `before` is where the session really was...
    expect(toHex(step.before)).toBe(toHex(branchA));
    // ...and the bytes hashed start from zero, not from there.
    expect(toHex(step.hashes[0].preimage).startsWith('00'.repeat(32))).toBe(true);
    expect(toHex(step.hashes[0].preimage).startsWith(toHex(step.before))).toBe(false);
    expect(toHex(sha256(step.hashes[0].preimage))).toBe(toHex(step.after));
  });

  it('records BOTH hashes of TPM2_PolicyAuthorize, chained', () => {
    const session = startPolicySession();
    const approved = sha256(utf8('an approved state'));
    session.policyDigest = approved.slice();
    const outcome = policyAuthorize(session, {
      approvedPolicy: approved,
      policyRef,
      keySignName: keyName,
      checkTicket: {
        tag: TPM_ST_VERIFIED,
        hierarchy: TPM_RH.OWNER,
        digest: verifiedTicketDigest(proof, refH(approved, policyRef), keyName),
      },
      proof,
    });
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    const step = outcome.step;
    expect(step.resets).toBe(true);
    expect(step.hashes).toHaveLength(2);
    expect(toHex(step.before)).toBe(toHex(approved));
    // Hash 1 starts from zero; hash 2 starts from hash 1's digest.
    expect(toHex(step.hashes[0].preimage).startsWith('00'.repeat(32))).toBe(true);
    expect(toHex(sha256(step.hashes[0].preimage))).toBe(toHex(step.hashes[0].digest));
    expect(toHex(step.hashes[1].preimage)).toBe(
      toHex(step.hashes[0].digest) + toHex(policyRef)
    );
    expect(toHex(sha256(step.hashes[1].preimage))).toBe(toHex(step.after));
    expect(toHex(step.hashes[1].digest)).toBe(toHex(step.after));
  });
});

describe('the sha256 this module uses', () => {
  it('agrees with the independent implementation these tests check against', () => {
    // Without this, a shared bug in `refH` and `sha256` would make every
    // equation above agree with itself.
    expect(toHex(sha256(fromHex('616263')))).toBe(toHex(nobleSha256(fromHex('616263'))));
  });
});
