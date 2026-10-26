import { describe, expect, test } from 'vitest';
import { bytesEqual, concatBytes, toHex, utf8 } from '../core/bytes';
import { sha256 } from '../core/sha256';
import {
  G1,
  SCALAR_ORDER,
  basenamePoint,
  g1,
  g2,
  h0,
  h1,
  invert,
  issuerProofBase,
  mul,
  point1Bytes,
  scale1,
  scalarBytes,
  seededScalar,
  sub,
} from './groups';
import {
  completeJoin,
  createJoinRequest,
  issueCredential,
  issuerKeyProofChallenge,
  joinProofChallenge,
  link,
  setupIssuer,
  sign,
  signatureFingerprint,
  signatureProofChallenge,
  verify,
  verifyCredential,
  verifyIssuer,
  verifyJoinRequest,
  type DaaCredential,
  type DaaSignature,
} from './protocol';

const ISSUER_ID = 'Example University Attestation Issuer';
const POLICY_ID = 'course-lab/access-policy/v1';
const NONCE = sha256(utf8('join nonce 2026-10-26'));
const MESSAGE = utf8('attestation statement: nonce and PCR digest');
const BASENAME = utf8('verifier.example/attestation');

function fixture() {
  const issuer = setupIssuer(ISSUER_ID, 7, utf8('issuer seed/v1'));
  const joined = completeJoin(
    issuer,
    NONCE,
    utf8('platform A seed'),
    utf8('platform A credential issuance')
  );
  const signature = sign(
    issuer.publicKey,
    joined.membership,
    MESSAGE,
    BASENAME,
    POLICY_ID,
    utf8('platform A proof 1')
  );
  return { issuer, ...joined, signature };
}

function withProof(signature: DaaSignature, changes: Partial<DaaSignature['proof']>): DaaSignature {
  return { ...signature, proof: { ...signature.proof, ...changes } };
}

describe('issuer setup and the Join proof (authenticated channel assumed)', () => {
  test('the issuer proves one exponent binds its G1 and G2 public points', () => {
    const { issuer } = fixture();
    expect(verifyIssuer(issuer.publicKey)).toBe(true);
    expect(
      verifyIssuer({
        ...issuer.publicKey,
        proof: {
          ...issuer.publicKey.proof,
          response: (issuer.publicKey.proof.response + 1n) % SCALAR_ORDER,
        },
      })
    ).toBe(false);
    expect(verifyIssuer({ ...issuer.publicKey, epoch: issuer.publicKey.epoch + 1 })).toBe(false);
    expect(verifyIssuer({ ...issuer.publicKey, w: issuer.publicKey.w.add(g2) })).toBe(false);
    expect(
      verifyIssuer({ ...issuer.publicKey, proofPoint: issuer.publicKey.proofPoint.add(g1) })
    ).toBe(false);

    const r = 41n;
    const wrongG1 = {
      ...issuer.publicKey,
      proofPoint: issuer.publicKey.proofPoint.add(g1),
      proof: {
        commitmentG1: scale1(issuerProofBase, r),
        commitmentG2: scale2ForTest(g2, r),
        response: 0n,
      },
    };
    wrongG1.proof.response = addForTest(
      r,
      mul(issuerKeyProofChallenge(wrongG1), issuer.secretKey.x)
    );
    expect(verifyIssuer(wrongG1)).toBe(false);

    const wrongG2 = {
      ...issuer.publicKey,
      w: issuer.publicKey.w.add(g2),
      proof: {
        commitmentG1: scale1(issuerProofBase, r),
        commitmentG2: scale2ForTest(g2, r),
        response: 0n,
      },
    };
    wrongG2.proof.response = addForTest(
      r,
      mul(issuerKeyProofChallenge(wrongG2), issuer.secretKey.x)
    );
    expect(verifyIssuer(wrongG2)).toBe(false);
  });

  test('reusing an external issuer seed across epochs does not reuse the proof witness', () => {
    const seed = utf8('same external issuer fixture seed');
    const first = setupIssuer(ISSUER_ID, 1, seed);
    const second = setupIssuer(ISSUER_ID, 2, seed);
    // Same seed intentionally models the same issuer secret, but each complete
    // proof context gets a different secret-keyed deterministic nonce.
    expect(first.publicKey.w.equals(second.publicKey.w)).toBe(true);
    expect(
      first.publicKey.proof.commitmentG1.equals(second.publicKey.proof.commitmentG1)
    ).toBe(false);
    expect(
      first.publicKey.proof.commitmentG2.equals(second.publicKey.proof.commitmentG2)
    ).toBe(false);
    expect(verifyIssuer(first.publicKey)).toBe(true);
    expect(verifyIssuer(second.publicKey)).toBe(true);
  });

  test('Join proves possession of gsk and binds the issuer nonce', () => {
    const issuer = setupIssuer(ISSUER_ID, 7, utf8('issuer seed/v1'));
    const { request } = createJoinRequest(issuer.publicKey, NONCE, utf8('platform A seed'));
    expect(verifyJoinRequest(issuer.publicKey, NONCE, request)).toBe(true);
    expect(verifyJoinRequest(issuer.publicKey, sha256(utf8('other nonce')), request)).toBe(false);
    const rewrittenNonce = sha256(utf8('rewritten nonce'));
    expect(
      verifyJoinRequest(issuer.publicKey, rewrittenNonce, {
        ...request,
        nonce: rewrittenNonce,
      })
    ).toBe(false);
    expect(
      verifyJoinRequest(issuer.publicKey, NONCE, {
        ...request,
        proof: { ...request.proof, response: (request.proof.response + 1n) % SCALAR_ORDER },
      })
    ).toBe(false);
  });

  test('same platform seed and nonce across issuers never repeats the Join commitment', () => {
    const platformSeed = utf8('one platform seed reused by its owner');
    const nonce = sha256(utf8('issuer happened to choose the same nonce'));
    const firstIssuer = setupIssuer('Issuer A', 1, utf8('issuer A seed'));
    const secondIssuer = setupIssuer('Issuer B', 1, utf8('issuer B seed'));
    const first = createJoinRequest(firstIssuer.publicKey, nonce, platformSeed);
    const second = createJoinRequest(secondIssuer.publicKey, nonce, platformSeed);
    expect(first.secret.gsk).toBe(second.secret.gsk);
    expect(first.request.proof.commitment.equals(second.request.proof.commitment)).toBe(false);
    expect(verifyJoinRequest(firstIssuer.publicKey, nonce, first.request)).toBe(true);
    expect(verifyJoinRequest(secondIssuer.publicKey, nonce, second.request)).toBe(true);

    // The textbook reused-witness extraction formula must not recover gsk.
    const c1 = joinProofChallenge(firstIssuer.publicKey, first.request);
    const c2 = joinProofChallenge(secondIssuer.publicKey, second.request);
    const extracted = mul(
      sub(first.request.proof.response, second.request.proof.response),
      invert(sub(c1, c2))
    );
    expect(extracted).not.toBe(first.secret.gsk);
  });

  test('the host independently checks the issued BBS+ credential', () => {
    const { issuer, membership, request } = fixture();
    expect(verifyCredential(issuer.publicKey, membership.credential, request.Q)).toBe(true);

    const variants: DaaCredential[] = [
      { ...membership.credential, A: membership.credential.A.add(g1) },
      { ...membership.credential, e: (membership.credential.e + 1n) % SCALAR_ORDER },
      { ...membership.credential, s: (membership.credential.s + 1n) % SCALAR_ORDER },
    ];
    for (const credential of variants) {
      expect(verifyCredential(issuer.publicKey, credential, request.Q)).toBe(false);
    }
  });

  test('an invalid Join proof cannot obtain a credential', () => {
    const issuer = setupIssuer(ISSUER_ID, 7, utf8('issuer seed/v1'));
    const { request } = createJoinRequest(issuer.publicKey, NONCE, utf8('platform A seed'));
    const tampered = {
      ...request,
      proof: { ...request.proof, response: (request.proof.response + 1n) % SCALAR_ORDER },
    };
    expect(() =>
      issueCredential(issuer, tampered, NONCE, utf8('credential issuance'))
    ).toThrow(/refused an invalid Join/);
  });

  test('same external issuance seed on two Q values does not repeat e and s or enable interpolation', () => {
    const issuer = setupIssuer(ISSUER_ID, 7, utf8('issuer seed/v1'));
    const issuanceSeed = utf8('caller accidentally reused issuance seed');
    const firstJoin = createJoinRequest(issuer.publicKey, NONCE, utf8('platform A seed'));
    // Deliberately reuse the external nonce too, isolating Q as the only
    // credential-issuance context difference.
    const secondNonce = NONCE;
    const secondJoin = createJoinRequest(
      issuer.publicKey,
      secondNonce,
      utf8('platform B seed')
    );
    const first = issueCredential(issuer, firstJoin.request, NONCE, issuanceSeed);
    const second = issueCredential(issuer, secondJoin.request, secondNonce, issuanceSeed);
    // Repeating e alone is enough for an affine credential forgery, even when
    // s differs. This assertion is intentionally stricter than comparing the
    // pair (e,s).
    expect(first.e).not.toBe(second.e);

    const thirdSecret = seededScalar(utf8('platform C seed'), 'platform/gsk');
    const denominator = sub(firstJoin.secret.gsk, secondJoin.secret.gsk);
    const lambda = mul(sub(thirdSecret, secondJoin.secret.gsk), invert(denominator));
    const oneMinusLambda = sub(1n, lambda);
    const attemptedForgery: DaaCredential = {
      ...first,
      A: scale1(first.A, lambda).add(scale1(second.A, oneMinusLambda)),
      s: addForTest(mul(lambda, first.s), mul(oneMinusLambda, second.s)),
    };
    expect(
      verifyCredential(issuer.publicKey, attemptedForgery, scale1(h1, thirdSecret))
    ).toBe(false);
  });
});

describe('CDL Pi_DAA+ signing and verification', () => {
  test('a real credential produces a valid proof derived from the current message', () => {
    const { issuer, signature } = fixture();
    const result = verify(issuer.publicKey, signature, MESSAGE, BASENAME, POLICY_ID);
    expect(result.valid).toBe(true);
    expect(result.revoked).toBe(false);
    expect(result.checks.every((check) => check.ok)).toBe(true);
  });

  test('message, basename, policy, issuer, and every proof response are bound', () => {
    const { issuer, signature } = fixture();
    expect(
      verify(issuer.publicKey, signature, utf8('different message'), BASENAME, POLICY_ID).valid
    ).toBe(false);
    expect(
      verify(issuer.publicKey, signature, MESSAGE, utf8('other.example'), POLICY_ID).valid
    ).toBe(false);
    expect(verify(issuer.publicKey, signature, MESSAGE, BASENAME, 'other-policy').valid).toBe(false);

    const otherIssuer = setupIssuer('Other issuer', 7, utf8('other issuer seed'));
    expect(verify(otherIssuer.publicKey, signature, MESSAGE, BASENAME, POLICY_ID).valid).toBe(false);

    for (const field of [
      'challenge',
      'responseGsk',
      'responseE',
      'responseR2',
      'responseR3',
      'responseSPrime',
    ] as const) {
      const changed = withProof(signature, {
        [field]: (signature.proof[field] + 1n) % SCALAR_ORDER,
      });
      expect(verify(issuer.publicKey, changed, MESSAGE, BASENAME, POLICY_ID).valid, field).toBe(
        false
      );
    }
  });

  test('reusing an external proof seed on two messages does not expose gsk', () => {
    const { issuer, membership } = fixture();
    const reusedSeed = utf8('caller reused proof fixture seed');
    const first = sign(
      issuer.publicKey,
      membership,
      utf8('message one'),
      BASENAME,
      POLICY_ID,
      reusedSeed
    );
    const second = sign(
      issuer.publicKey,
      membership,
      utf8('message two'),
      BASENAME,
      POLICY_ID,
      reusedSeed
    );
    expect(first.APrime.equals(second.APrime)).toBe(false);
    expect(
      verify(issuer.publicKey, first, utf8('message one'), BASENAME, POLICY_ID).valid
    ).toBe(true);
    expect(
      verify(issuer.publicKey, second, utf8('message two'), BASENAME, POLICY_ID).valid
    ).toBe(true);
    const extracted = mul(
      sub(first.proof.responseGsk, second.proof.responseGsk),
      invert(sub(first.proof.challenge, second.proof.challenge))
    );
    expect(extracted).not.toBe(membership.secret.gsk);

    const otherBasename = sign(
      issuer.publicKey,
      membership,
      utf8('message one'),
      utf8('other.example/attestation'),
      POLICY_ID,
      reusedSeed
    );
    expect(first.APrime.equals(otherBasename.APrime)).toBe(false);
    const crossBasenameExtracted = mul(
      sub(first.proof.responseGsk, otherBasename.proof.responseGsk),
      invert(sub(first.proof.challenge, otherBasename.proof.challenge))
    );
    expect(crossBasenameExtracted).not.toBe(membership.secret.gsk);
  });

  test('noncanonical scalars, identity points, and invalid curve points fail closed', () => {
    const { issuer, signature } = fixture();
    expect(
      verify(
        issuer.publicKey,
        withProof(signature, { challenge: signature.proof.challenge + SCALAR_ORDER }),
        MESSAGE,
        BASENAME,
        POLICY_ID
      ).valid
    ).toBe(false);
    expect(
      verify(
        issuer.publicKey,
        withProof(signature, { responseGsk: signature.proof.responseGsk + SCALAR_ORDER }),
        MESSAGE,
        BASENAME,
        POLICY_ID
      ).valid
    ).toBe(false);
    expect(
      verify(issuer.publicKey, { ...signature, APrime: G1.ZERO }, MESSAGE, BASENAME, POLICY_ID)
        .valid
    ).toBe(false);
    const invalid = G1.fromAffine({ x: 1n, y: 1n });
    expect(
      verify(issuer.publicKey, { ...signature, nym: invalid }, MESSAGE, BASENAME, POLICY_ID).valid
    ).toBe(false);
  });

  test('point and transcript tampering do not become ordinary byte-tamper demos', () => {
    const { issuer, signature } = fixture();
    for (const changed of [
      { ...signature, APrime: signature.APrime.add(h0) },
      { ...signature, ABar: signature.ABar.add(h0) },
      { ...signature, d: signature.d.add(h0) },
      { ...signature, nym: signature.nym.add(h0) },
    ]) {
      expect(verify(issuer.publicKey, changed, MESSAGE, BASENAME, POLICY_ID).valid).toBe(false);
    }
    // Same concatenated bytes, different field boundaries: length framing keeps
    // message="ab", basename="c" distinct from message="a", basename="bc".
    const split = sign(
      issuer.publicKey,
      fixture().membership,
      utf8('ab'),
      utf8('c'),
      POLICY_ID,
      utf8('split-field proof')
    );
    expect(verify(issuer.publicKey, split, utf8('a'), utf8('bc'), POLICY_ID).valid).toBe(false);
  });

  test('a Sigma-valid witness without the issuer pairing relation is rejected only by pairing', () => {
    const { issuer, membership, signature: template } = fixture();
    const witness = {
      gsk: membership.secret.gsk,
      e: 5n,
      r2: 7n,
      r3: 11n,
      sPrime: 13n,
    };
    const d = scale1(
      g1.add(scale1(h0, witness.sPrime)).add(scale1(h1, witness.gsk)),
      invert(witness.r3)
    );
    const APrime = scale1(g1, 17n);
    const ABar = d.subtract(scale1(APrime, witness.e)).add(scale1(h0, witness.r2));
    const nym = scale1(basenamePoint(BASENAME), witness.gsk);
    const randomness = {
      gsk: 19n,
      e: 23n,
      r2: 29n,
      r3: 31n,
      sPrime: 37n,
    };
    const t1 = scale1(APrime, randomness.e).add(scale1(h0, randomness.r2));
    const t2 = scale1(d, randomness.r3)
      .add(scale1(h0, randomness.sPrime))
      .subtract(scale1(h1, randomness.gsk));
    const L = scale1(basenamePoint(BASENAME), randomness.gsk);
    const unsigned: Omit<DaaSignature, 'proof'> = {
      ...template,
      APrime,
      ABar,
      d,
      nym,
    };
    const challenge = signatureProofChallenge(
      issuer.publicKey,
      unsigned,
      MESSAGE,
      BASENAME,
      { t1, t2, L }
    );
    const forged: DaaSignature = {
      ...unsigned,
      proof: {
        challenge,
        responseGsk: addForTest(randomness.gsk, mul(challenge, witness.gsk)),
        responseE: sub(randomness.e, mul(challenge, witness.e)),
        responseR2: addForTest(randomness.r2, mul(challenge, witness.r2)),
        responseR3: addForTest(randomness.r3, mul(challenge, witness.r3)),
        responseSPrime: sub(randomness.sPrime, mul(challenge, witness.sPrime)),
      },
    };
    const result = verify(issuer.publicKey, forged, MESSAGE, BASENAME, POLICY_ID);
    expect(result.valid).toBe(false);
    expect(result.checks.find((check) => check.name === 'randomized BBS+ issuer relation')?.ok).toBe(
      false
    );
    expect(result.checks.find((check) => check.name === 'CDL proof and Fiat-Shamir transcript')?.ok).toBe(
      true
    );
  });

  test('deterministic fixture mode pins the complete proof, not a scenario label', () => {
    const { signature } = fixture();
    const digest = toHex(sha256(signatureFingerprint(signature)));
    expect(digest).toBe('8680613691066537fc0a04903f99044599566a312cd694d833275a01eee52d75');
  });
});

describe('basename linkability and private-key rogue-list revocation', () => {
  test('same platform plus same basename links while proofs remain randomized', () => {
    const { issuer, membership, signature } = fixture();
    const secondMessage = utf8('second, independently fresh attestation statement');
    const second = sign(
      issuer.publicKey,
      membership,
      secondMessage,
      BASENAME,
      POLICY_ID,
      utf8('platform A proof 2')
    );
    const result = link(
      issuer.publicKey,
      { signature, message: MESSAGE, basename: BASENAME },
      { signature: second, message: secondMessage, basename: BASENAME },
      POLICY_ID
    );
    expect(result.applicable).toBe(true);
    expect(result.linked).toBe(true);
    expect(signature.nym.equals(second.nym)).toBe(true);
    expect(bytesEqual(signatureFingerprint(signature), signatureFingerprint(second))).toBe(false);
  });

  test('different basenames produce different pseudonyms but Link is inapplicable', () => {
    const { issuer, membership, signature } = fixture();
    const otherBasename = utf8('research.example/attestation');
    const other = sign(
      issuer.publicKey,
      membership,
      MESSAGE,
      otherBasename,
      POLICY_ID,
      utf8('different basename proof')
    );
    const result = link(
      issuer.publicKey,
      { signature, message: MESSAGE, basename: BASENAME },
      { signature: other, message: MESSAGE, basename: otherBasename },
      POLICY_ID
    );
    expect(signature.nym.equals(other.nym)).toBe(false);
    expect(result.applicable).toBe(false);
    expect(result.linked).toBe(null);
    expect(result.reason).toMatch(/not an unlinkability proof/);
  });

  test('two platforms under the same basename do not link', () => {
    const { issuer, signature } = fixture();
    const otherMembership = completeJoin(
      issuer,
      sha256(utf8('other Join nonce')),
      utf8('platform B seed'),
      utf8('platform B issuance')
    ).membership;
    const other = sign(
      issuer.publicKey,
      otherMembership,
      MESSAGE,
      BASENAME,
      POLICY_ID,
      utf8('platform B proof')
    );
    const result = link(
      issuer.publicKey,
      { signature, message: MESSAGE, basename: BASENAME },
      { signature: other, message: MESSAGE, basename: BASENAME },
      POLICY_ID
    );
    expect(result.applicable).toBe(true);
    expect(result.linked).toBe(false);
  });

  test('the same existing signature changes verdict when its exact secret enters the rogue list', () => {
    const { issuer, membership, signature } = fixture();
    const unrelated = seededScalar(utf8('unrelated platform'), 'platform/gsk');
    expect(verify(issuer.publicKey, signature, MESSAGE, BASENAME, POLICY_ID, []).valid).toBe(true);
    expect(
      verify(issuer.publicKey, signature, MESSAGE, BASENAME, POLICY_ID, [unrelated]).valid
    ).toBe(true);
    const revoked = verify(
      issuer.publicKey,
      signature,
      MESSAGE,
      BASENAME,
      POLICY_ID,
      [membership.secret.gsk]
    );
    expect(revoked.valid).toBe(false);
    expect(revoked.revoked).toBe(true);
  });

  test('an invalid proof with a copied revoked nym is not misclassified as revocation', () => {
    const { issuer, membership, signature } = fixture();
    const broken = withProof(signature, {
      responseE: (signature.proof.responseE + 1n) % SCALAR_ORDER,
    });
    const result = verify(
      issuer.publicKey,
      broken,
      MESSAGE,
      BASENAME,
      POLICY_ID,
      [membership.secret.gsk]
    );
    expect(result.valid).toBe(false);
    expect(result.revoked).toBe(false);
    expect(result.checks.some((check) => check.name === 'private-key rogue list')).toBe(false);
  });

  test('the signature exposes a pseudonym, not gsk itself', () => {
    const { membership, signature } = fixture();
    expect(Object.keys(signature)).not.toContain('gsk');
    expect(Object.keys(signature.proof)).not.toContain('gsk');
    const raw = signatureFingerprint(signature);
    const secret = scalarBytes(membership.secret.gsk);
    expect(toHex(raw)).not.toContain(toHex(secret));
    expect(signature.nym.equals(scale1(h1, membership.secret.gsk))).toBe(false);
  });
});

describe('issuer rotation is explicit trust policy, not retroactive magic', () => {
  test('old signatures remain valid under the old trusted key and fail under the new epoch', () => {
    const { issuer: oldIssuer, signature } = fixture();
    const nextIssuer = setupIssuer(ISSUER_ID, 8, utf8('issuer seed/v2'));
    expect(verify(oldIssuer.publicKey, signature, MESSAGE, BASENAME, POLICY_ID).valid).toBe(true);
    expect(verify(nextIssuer.publicKey, signature, MESSAGE, BASENAME, POLICY_ID).valid).toBe(false);

    const rejoined = completeJoin(
      nextIssuer,
      sha256(utf8('new epoch Join nonce')),
      utf8('platform A seed'),
      utf8('platform A epoch 8 issuance')
    ).membership;
    const nextSignature = sign(
      nextIssuer.publicKey,
      rejoined,
      MESSAGE,
      BASENAME,
      POLICY_ID,
      utf8('platform A epoch 8 proof')
    );
    expect(verify(nextIssuer.publicKey, nextSignature, MESSAGE, BASENAME, POLICY_ID).valid).toBe(
      true
    );
  });

  test('credential verification rejects a Q from another platform', () => {
    const { issuer, membership } = fixture();
    const otherGsk = seededScalar(utf8('platform B seed'), 'platform/gsk');
    expect(
      verifyCredential(issuer.publicKey, membership.credential, scale1(h1, otherGsk))
    ).toBe(false);
  });
});

test('the canonical point encoding is stable and compressed', () => {
  const bytes = point1Bytes(g1);
  expect(bytes).toHaveLength(48);
  expect(toHex(bytes)).toMatch(/^[0-9a-f]{96}$/);
  expect(concatBytes(bytes, bytes)).toHaveLength(96);
});

function addForTest(a: bigint, b: bigint): bigint {
  return (a + b) % SCALAR_ORDER;
}

function scale2ForTest(point: typeof g2, scalar: bigint): typeof g2 {
  return point.multiplyUnsafe(scalar % SCALAR_ORDER);
}
