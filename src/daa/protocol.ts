/**
 * A no-application-attribute specialization of CDL Pi_DAA+.
 *
 * Primary construction: Camenisch, Drijvers, Lehmann, "Anonymous Attestation
 * Using the Strong Diffie Hellman Assumption Revisited", full version,
 * IACR ePrint 2016/663, section 5.1. The paper's h1/gsk term remains: "no
 * application attributes" does not mean "no platform secret".
 */

import { bytesEqual, concatBytes, u32be, utf8 } from '../core/bytes';
import {
  add,
  basenamePoint,
  g1,
  g2,
  h0,
  h1,
  invert,
  isCanonicalScalar,
  issuerProofBase,
  mul,
  pairingEqual,
  point1Bytes,
  point2Bytes,
  scalarBytes,
  scalarFromTranscript,
  scale1,
  scale2,
  secretScalarFromTranscript,
  seededScalar,
  sub,
  utf8Field,
  type G1Point,
  type G2Point,
} from './groups';

const PROTOCOL_ID = 'CDL-Pi_DAA+-no-application-attributes/v1';

export interface IssuerKnowledgeProof {
  commitmentG1: G1Point;
  commitmentG2: G2Point;
  response: bigint;
}

export interface DaaIssuerPublicKey {
  issuerId: string;
  epoch: number;
  w: G2Point;
  proofPoint: G1Point;
  proof: IssuerKnowledgeProof;
}

export interface DaaIssuerSecretKey {
  x: bigint;
}

export interface DaaIssuer {
  publicKey: DaaIssuerPublicKey;
  secretKey: DaaIssuerSecretKey;
}

export interface JoinKnowledgeProof {
  commitment: G1Point;
  response: bigint;
}

export interface JoinRequest {
  issuerId: string;
  epoch: number;
  nonce: Uint8Array;
  Q: G1Point;
  proof: JoinKnowledgeProof;
}

// The CDL construction assumes this exchange runs over an authenticated Join
// channel and that the issuer enforces one-platform admission. This module
// proves knowledge of gsk and binds the issuer nonce; it does not implement that
// external EK-backed authorization channel. The learner UI states this limit.

/** Secret state stays on the platform side of the Join boundary. */
export interface PlatformSecret {
  gsk: bigint;
}

export interface DaaCredential {
  issuerId: string;
  epoch: number;
  A: G1Point;
  e: bigint;
  s: bigint;
}

export interface DaaMembership {
  secret: PlatformSecret;
  credential: DaaCredential;
}

export interface DaaProof {
  challenge: bigint;
  responseGsk: bigint;
  responseE: bigint;
  responseR2: bigint;
  responseR3: bigint;
  responseSPrime: bigint;
}

export interface DaaSignature {
  protocol: typeof PROTOCOL_ID;
  issuerId: string;
  epoch: number;
  policyId: string;
  APrime: G1Point;
  ABar: G1Point;
  d: G1Point;
  nym: G1Point;
  proof: DaaProof;
}

export interface VerificationCheck {
  name: string;
  ok: boolean;
  detail: string;
}

export interface DaaVerification {
  valid: boolean;
  revoked: boolean;
  checks: VerificationCheck[];
}

export interface SignedDaaMessage {
  signature: DaaSignature;
  message: Uint8Array;
  basename: Uint8Array;
}

export interface LinkResult {
  applicable: boolean;
  linked: boolean | null;
  reason: string;
  left: DaaVerification;
  right: DaaVerification;
}

function issuerBinding(publicKey: DaaIssuerPublicKey): Uint8Array[] {
  return [
    utf8Field(PROTOCOL_ID),
    utf8Field(publicKey.issuerId),
    u32be(publicKey.epoch),
    point2Bytes(publicKey.w),
    point1Bytes(issuerProofBase),
    point1Bytes(publicKey.proofPoint),
  ];
}

/** Public because participants must validate the issuer key proof. */
export function issuerKeyProofChallenge(publicKey: DaaIssuerPublicKey): bigint {
  return scalarFromTranscript('crypto-lab/daa/v1/issuer-key-proof', [
    ...issuerBinding(publicKey),
    point1Bytes(publicKey.proof.commitmentG1),
    point2Bytes(publicKey.proof.commitmentG2),
  ]);
}

export function setupIssuer(
  issuerId: string,
  epoch: number,
  seed: Uint8Array
): DaaIssuer {
  if (issuerId.length === 0) throw new Error('issuerId must not be empty');
  if (!Number.isSafeInteger(epoch) || epoch < 0 || epoch > 0xffff_ffff) {
    throw new Error('issuer epoch must be a uint32');
  }
  const x = seededScalar(seed, 'issuer/x');
  const proofRandomness = secretScalarFromTranscript(
    x,
    'crypto-lab/daa/v1/issuer-key-proof-nonce',
    [seed, utf8(issuerId), u32be(epoch)]
  );
  const publicKey: DaaIssuerPublicKey = {
    issuerId,
    epoch,
    w: scale2(g2, x),
    proofPoint: scale1(issuerProofBase, x),
    proof: {
      commitmentG1: scale1(issuerProofBase, proofRandomness),
      commitmentG2: scale2(g2, proofRandomness),
      response: 0n,
    },
  };
  const challenge = issuerKeyProofChallenge(publicKey);
  publicKey.proof.response = add(proofRandomness, mul(challenge, x));
  return { publicKey, secretKey: { x } };
}

export function verifyIssuer(publicKey: DaaIssuerPublicKey): boolean {
  try {
    if (publicKey.issuerId.length === 0) return false;
    if (!Number.isSafeInteger(publicKey.epoch) || publicKey.epoch < 0) return false;
    if (!isCanonicalScalar(publicKey.proof.response)) return false;
    const challenge = issuerKeyProofChallenge(publicKey);
    const lhsG1 = scale1(issuerProofBase, publicKey.proof.response);
    const rhsG1 = publicKey.proof.commitmentG1.add(scale1(publicKey.proofPoint, challenge));
    const lhsG2 = scale2(g2, publicKey.proof.response);
    const rhsG2 = publicKey.proof.commitmentG2.add(scale2(publicKey.w, challenge));
    return lhsG1.equals(rhsG1) && lhsG2.equals(rhsG2);
  } catch {
    return false;
  }
}

/** Public because the verifier recomputes this Fiat-Shamir challenge. */
export function joinProofChallenge(publicKey: DaaIssuerPublicKey, request: JoinRequest): bigint {
  return scalarFromTranscript('crypto-lab/daa/v1/join-proof', [
    ...issuerBinding(publicKey),
    request.nonce,
    point1Bytes(request.Q),
    point1Bytes(request.proof.commitment),
  ]);
}

export function createJoinRequest(
  publicKey: DaaIssuerPublicKey,
  nonce: Uint8Array,
  platformSeed: Uint8Array
): { request: JoinRequest; secret: PlatformSecret } {
  if (!verifyIssuer(publicKey)) throw new Error('issuer key proof is invalid');
  if (nonce.length < 16) throw new Error('Join nonce must be at least 16 bytes');
  const gsk = seededScalar(platformSeed, 'platform/gsk');
  const request: JoinRequest = {
    issuerId: publicKey.issuerId,
    epoch: publicKey.epoch,
    nonce: nonce.slice(),
    Q: scale1(h1, gsk),
    proof: { commitment: h1, response: 0n },
  };
  const proofRandomness = secretScalarFromTranscript(
    gsk,
    'crypto-lab/daa/v1/join-proof-nonce',
    [...issuerBinding(publicKey), platformSeed, nonce, point1Bytes(request.Q)]
  );
  request.proof.commitment = scale1(h1, proofRandomness);
  const challenge = joinProofChallenge(publicKey, request);
  request.proof.response = add(proofRandomness, mul(challenge, gsk));
  return { request, secret: { gsk } };
}

export function verifyJoinRequest(
  publicKey: DaaIssuerPublicKey,
  expectedNonce: Uint8Array,
  request: JoinRequest
): boolean {
  try {
    if (!verifyIssuer(publicKey)) return false;
    if (request.issuerId !== publicKey.issuerId || request.epoch !== publicKey.epoch) return false;
    if (!bytesEqual(request.nonce, expectedNonce)) return false;
    if (!isCanonicalScalar(request.proof.response)) return false;
    const challenge = joinProofChallenge(publicKey, request);
    const lhs = scale1(h1, request.proof.response);
    const rhs = request.proof.commitment.add(scale1(request.Q, challenge));
    return lhs.equals(rhs);
  } catch {
    return false;
  }
}

function credentialBase(credential: Pick<DaaCredential, 's'>, Q: G1Point): G1Point {
  return g1.add(scale1(h0, credential.s)).add(Q);
}

export function issueCredential(
  issuer: DaaIssuer,
  request: JoinRequest,
  expectedNonce: Uint8Array,
  issuanceSeed: Uint8Array
): DaaCredential {
  if (!verifyJoinRequest(issuer.publicKey, expectedNonce, request)) {
    throw new Error('issuer refused an invalid Join proof or nonce');
  }
  if (!scale2(g2, issuer.secretKey.x).equals(issuer.publicKey.w)) {
    throw new Error('issuer secret does not match the public key');
  }
  const issuanceContext = [
    ...issuerBinding(issuer.publicKey),
    issuanceSeed,
    request.nonce,
    point1Bytes(request.Q),
  ];
  let e = secretScalarFromTranscript(
    issuer.secretKey.x,
    'crypto-lab/daa/v1/credential/e',
    issuanceContext
  );
  let counter = 0;
  while (add(e, issuer.secretKey.x) === 0n) {
    counter += 1;
    e = secretScalarFromTranscript(
      issuer.secretKey.x,
      'crypto-lab/daa/v1/credential/e-resample',
      [...issuanceContext, u32be(counter)]
    );
  }
  const s = secretScalarFromTranscript(
    issuer.secretKey.x,
    'crypto-lab/daa/v1/credential/s',
    issuanceContext,
    true
  );
  const partial: DaaCredential = {
    issuerId: issuer.publicKey.issuerId,
    epoch: issuer.publicKey.epoch,
    A: g1,
    e,
    s,
  };
  const b = credentialBase(partial, request.Q);
  partial.A = scale1(b, invert(add(e, issuer.secretKey.x)));
  if (!verifyCredential(issuer.publicKey, partial, request.Q)) {
    throw new Error('issuer produced a credential that failed its pairing equation');
  }
  return partial;
}

export function verifyCredential(
  publicKey: DaaIssuerPublicKey,
  credential: DaaCredential,
  Q: G1Point
): boolean {
  try {
    if (!verifyIssuer(publicKey)) return false;
    if (credential.issuerId !== publicKey.issuerId || credential.epoch !== publicKey.epoch) {
      return false;
    }
    if (!isCanonicalScalar(credential.e) || !isCanonicalScalar(credential.s)) return false;
    credential.A.assertValidity();
    Q.assertValidity();
    if (credential.A.is0() || Q.is0()) return false;
    const b = credentialBase(credential, Q);
    return pairingEqual(
      credential.A,
      publicKey.w.add(scale2(g2, credential.e)),
      b,
      g2
    );
  } catch {
    return false;
  }
}

export function completeJoin(
  issuer: DaaIssuer,
  nonce: Uint8Array,
  platformSeed: Uint8Array,
  issuanceSeed: Uint8Array
): { membership: DaaMembership; request: JoinRequest } {
  const { request, secret } = createJoinRequest(issuer.publicKey, nonce, platformSeed);
  const credential = issueCredential(issuer, request, nonce, issuanceSeed);
  return { membership: { secret, credential }, request };
}

/** Public because every verifier reconstructs and hashes these commitments. */
export function signatureProofChallenge(
  publicKey: DaaIssuerPublicKey,
  signature: Omit<DaaSignature, 'proof'>,
  message: Uint8Array,
  basename: Uint8Array,
  commitments: { t1: G1Point; t2: G1Point; L: G1Point }
): bigint {
  return scalarFromTranscript('crypto-lab/daa/v1/signature-proof', [
    ...issuerBinding(publicKey),
    utf8(signature.policyId),
    message,
    basename,
    point1Bytes(signature.APrime),
    point1Bytes(signature.ABar),
    point1Bytes(signature.d),
    point1Bytes(signature.nym),
    point1Bytes(commitments.t1),
    point1Bytes(commitments.t2),
    point1Bytes(commitments.L),
  ]);
}

export function sign(
  publicKey: DaaIssuerPublicKey,
  membership: DaaMembership,
  message: Uint8Array,
  basename: Uint8Array,
  policyId: string,
  proofSeed: Uint8Array
): DaaSignature {
  if (policyId.length === 0) throw new Error('policyId must not be empty');
  const { credential, secret } = membership;
  const Q = scale1(h1, secret.gsk);
  if (!verifyCredential(publicKey, credential, Q)) {
    throw new Error('cannot sign with an invalid credential');
  }
  const B = basenamePoint(basename);
  const b = credentialBase(credential, Q);
  const signingContext = [
    ...issuerBinding(publicKey),
    proofSeed,
    utf8(policyId),
    message,
    basename,
    point1Bytes(credential.A),
    scalarBytes(credential.e),
    scalarBytes(credential.s),
  ];
  const r1 = secretScalarFromTranscript(
    secret.gsk,
    'crypto-lab/daa/v1/signature/r1',
    signingContext
  );
  const r2 = secretScalarFromTranscript(
    secret.gsk,
    'crypto-lab/daa/v1/signature/r2',
    signingContext,
    true
  );
  const r3 = invert(r1);
  const sPrime = sub(credential.s, mul(r2, r3));

  const APrime = scale1(credential.A, r1);
  const ABar = scale1(APrime, sub(0n, credential.e)).add(scale1(b, r1));
  const d = scale1(b, r1).subtract(scale1(h0, r2));
  const nym = scale1(B, secret.gsk);

  const randomGsk = secretScalarFromTranscript(
    secret.gsk,
    'crypto-lab/daa/v1/signature/proof/gsk',
    signingContext,
    true
  );
  const randomE = secretScalarFromTranscript(
    secret.gsk,
    'crypto-lab/daa/v1/signature/proof/e',
    signingContext,
    true
  );
  const randomR2 = secretScalarFromTranscript(
    secret.gsk,
    'crypto-lab/daa/v1/signature/proof/r2',
    signingContext,
    true
  );
  const randomR3 = secretScalarFromTranscript(
    secret.gsk,
    'crypto-lab/daa/v1/signature/proof/r3',
    signingContext,
    true
  );
  const randomSPrime = secretScalarFromTranscript(
    secret.gsk,
    'crypto-lab/daa/v1/signature/proof/s-prime',
    signingContext,
    true
  );

  const t1 = scale1(APrime, randomE).add(scale1(h0, randomR2));
  const t2 = scale1(d, randomR3)
    .add(scale1(h0, randomSPrime))
    .subtract(scale1(h1, randomGsk));
  const L = scale1(B, randomGsk);
  const unsigned: Omit<DaaSignature, 'proof'> = {
    protocol: PROTOCOL_ID,
    issuerId: publicKey.issuerId,
    epoch: publicKey.epoch,
    policyId,
    APrime,
    ABar,
    d,
    nym,
  };
  const challenge = signatureProofChallenge(publicKey, unsigned, message, basename, { t1, t2, L });
  return {
    ...unsigned,
    proof: {
      challenge,
      responseGsk: add(randomGsk, mul(challenge, secret.gsk)),
      responseE: sub(randomE, mul(challenge, credential.e)),
      responseR2: add(randomR2, mul(challenge, r2)),
      responseR3: add(randomR3, mul(challenge, r3)),
      responseSPrime: sub(randomSPrime, mul(challenge, sPrime)),
    },
  };
}

function failed(name: string, detail: string): DaaVerification {
  return { valid: false, revoked: false, checks: [{ name, ok: false, detail }] };
}

export function verify(
  publicKey: DaaIssuerPublicKey,
  signature: DaaSignature,
  message: Uint8Array,
  basename: Uint8Array,
  expectedPolicyId: string,
  rogueSecrets: readonly bigint[] = []
): DaaVerification {
  const checks: VerificationCheck[] = [];
  try {
    const issuerOk = verifyIssuer(publicKey);
    checks.push({
      name: 'issuer key proof',
      ok: issuerOk,
      detail: issuerOk ? 'the issuer proves one exponent binds its G1 and G2 public points' : 'invalid issuer proof',
    });
    const contextOk =
      signature.protocol === PROTOCOL_ID &&
      signature.issuerId === publicKey.issuerId &&
      signature.epoch === publicKey.epoch &&
      signature.policyId === expectedPolicyId;
    checks.push({
      name: 'issuer epoch and policy context',
      ok: contextOk,
      detail: contextOk ? `${publicKey.issuerId}, epoch ${publicKey.epoch}, ${expectedPolicyId}` : 'signature context does not match verifier policy',
    });
    if (!issuerOk || !contextOk) return { valid: false, revoked: false, checks };

    for (const point of [signature.APrime, signature.ABar, signature.d, signature.nym]) {
      point.assertValidity();
      if (point.is0()) return failed('non-identity subgroup points', 'an identity point is forbidden');
    }
    const pointsOk = true;
    checks.push({
      name: 'non-identity subgroup points',
      ok: pointsOk,
      detail: 'A\u2032, A-bar, d, and nym are valid BLS12-381 G1 subgroup points',
    });

    const pairingOk = pairingEqual(signature.APrime, publicKey.w, signature.ABar, g2);
    checks.push({
      name: 'randomized BBS+ issuer relation',
      ok: pairingOk,
      detail: pairingOk ? 'e(A\u2032, w) = e(A-bar, g2)' : 'pairing equation failed',
    });

    const proofScalars = [
      signature.proof.challenge,
      signature.proof.responseGsk,
      signature.proof.responseE,
      signature.proof.responseR2,
      signature.proof.responseR3,
      signature.proof.responseSPrime,
    ];
    if (!proofScalars.every((value) => isCanonicalScalar(value))) {
      checks.push({ name: 'canonical proof scalars', ok: false, detail: 'a proof scalar is outside Fr' });
      return { valid: false, revoked: false, checks };
    }
    checks.push({ name: 'canonical proof scalars', ok: true, detail: 'all six proof scalars are canonical Fr elements' });

    const B = basenamePoint(basename);
    const c = signature.proof.challenge;
    const L = scale1(B, signature.proof.responseGsk).subtract(scale1(signature.nym, c));
    const t1 = scale1(signature.APrime, signature.proof.responseE)
      .add(scale1(h0, signature.proof.responseR2))
      .subtract(scale1(signature.ABar.subtract(signature.d), c));
    const t2 = scale1(signature.d, signature.proof.responseR3)
      .add(scale1(h0, signature.proof.responseSPrime))
      .subtract(scale1(h1, signature.proof.responseGsk))
      .subtract(scale1(g1, c));
    const unsigned: Omit<DaaSignature, 'proof'> = {
      protocol: signature.protocol,
      issuerId: signature.issuerId,
      epoch: signature.epoch,
      policyId: signature.policyId,
      APrime: signature.APrime,
      ABar: signature.ABar,
      d: signature.d,
      nym: signature.nym,
    };
    const recomputed = signatureProofChallenge(publicKey, unsigned, message, basename, { t1, t2, L });
    const proofOk = c === recomputed;
    checks.push({
      name: 'CDL proof and Fiat-Shamir transcript',
      ok: proofOk,
      detail: proofOk
        ? 'credential, platform secret, message, basename, issuer, epoch, and policy are bound'
        : 'recomputed challenge differs',
    });

    // A rogue-list match is meaningful only for an otherwise valid member
    // proof. Garbage carrying a copied nym must be reported as an invalid
    // proof, not misclassified as a revoked platform.
    if (!checks.every((check) => check.ok)) {
      return { valid: false, revoked: false, checks };
    }

    let revoked = false;
    for (const rogue of rogueSecrets) {
      if (!isCanonicalScalar(rogue, false)) {
        checks.push({ name: 'private-key rogue list', ok: false, detail: 'rogue-list scalar is malformed' });
        return { valid: false, revoked: false, checks };
      }
      if (scale1(B, rogue).equals(signature.nym)) revoked = true;
    }
    checks.push({
      name: 'private-key rogue list',
      ok: !revoked,
      detail: revoked
        ? 'H1(basename)^listed-secret equals nym: this platform secret is revoked'
        : `${rogueSecrets.length} exposed platform secret${rogueSecrets.length === 1 ? '' : 's'} checked; no match`,
    });

    return {
      valid: checks.every((check) => check.ok),
      revoked,
      checks,
    };
  } catch (error) {
    checks.push({
      name: 'canonical transcript and point parsing',
      ok: false,
      detail: error instanceof Error ? error.message : 'invalid proof input',
    });
    return { valid: false, revoked: false, checks };
  }
}

export function link(
  publicKey: DaaIssuerPublicKey,
  left: SignedDaaMessage,
  right: SignedDaaMessage,
  expectedPolicyId: string,
  rogueSecrets: readonly bigint[] = []
): LinkResult {
  const leftResult = verify(
    publicKey,
    left.signature,
    left.message,
    left.basename,
    expectedPolicyId,
    rogueSecrets
  );
  const rightResult = verify(
    publicKey,
    right.signature,
    right.message,
    right.basename,
    expectedPolicyId,
    rogueSecrets
  );
  if (!bytesEqual(left.basename, right.basename)) {
    return {
      applicable: false,
      linked: null,
      reason: 'Link is undefined across different basenames; pseudonym inequality is not an unlinkability proof.',
      left: leftResult,
      right: rightResult,
    };
  }
  if (!leftResult.valid || !rightResult.valid) {
    return {
      applicable: true,
      linked: null,
      reason: 'Both signatures must verify before their pseudonyms can be compared.',
      left: leftResult,
      right: rightResult,
    };
  }
  const linked = left.signature.nym.equals(right.signature.nym);
  return {
    applicable: true,
    linked,
    reason: linked
      ? 'Both valid signatures have the same basename pseudonym.'
      : 'Both are valid under this basename, but their pseudonyms come from different platform secrets.',
    left: leftResult,
    right: rightResult,
  };
}

export function signatureFingerprint(signature: DaaSignature): Uint8Array {
  return concatBytes(
    point1Bytes(signature.APrime),
    point1Bytes(signature.ABar),
    point1Bytes(signature.d),
    point1Bytes(signature.nym),
    scalarBytes(signature.proof.challenge),
    scalarBytes(signature.proof.responseGsk),
    scalarBytes(signature.proof.responseE),
    scalarBytes(signature.proof.responseR2),
    scalarBytes(signature.proof.responseR3),
    scalarBytes(signature.proof.responseSPrime)
  );
}
