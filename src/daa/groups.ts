/**
 * Group and transcript plumbing for the bounded CDL Pi_DAA+ lesson.
 *
 * Camenisch, Drijvers, and Lehmann write the source groups multiplicatively.
 * Noble exposes elliptic-curve groups additively, so the code uses:
 *
 *   paper: g^x h^y     code: x*g + y*h
 *   paper: g^-x        code: -(x*g)
 *
 * BLS12-381 is a Type-3 algebraic instantiation for the browser lesson. It is
 * not the paper's benchmark curve and it is not a TPM 2.0 ECDAA wire profile.
 */

import { bls12_381 } from '@noble/curves/bls12-381.js';
import { concatBytes, u32be, utf8 } from '../core/bytes';
import { hmacSha256 } from '../core/hmac';
import { sha256 } from '../core/sha256';

export type G1Point = typeof bls12_381.G1.Point.BASE;
export type G2Point = typeof bls12_381.G2.Point.BASE;

export const CURVE_NAME = 'BLS12-381 Type-3 pairing (algebraic teaching instantiation)';
export const SCALAR_ORDER = bls12_381.fields.Fr.ORDER;
export const G1 = bls12_381.G1.Point;
export const G2 = bls12_381.G2.Point;
export const g1 = G1.BASE;
export const g2 = G2.BASE;

const H0_DST = utf8('CRYPTO-LAB-ATTESTATION-GATE-DAA-V1-H0_XMD:SHA-256_SSWU_RO_');
const H1_DST = utf8('CRYPTO-LAB-ATTESTATION-GATE-DAA-V1-H1_XMD:SHA-256_SSWU_RO_');
const ISSUER_PROOF_DST = utf8(
  'CRYPTO-LAB-ATTESTATION-GATE-DAA-V1-ISSUER-PROOF_XMD:SHA-256_SSWU_RO_'
);
const BASENAME_DST = utf8(
  'CRYPTO-LAB-ATTESTATION-GATE-DAA-V1-BASENAME_XMD:SHA-256_SSWU_RO_'
);

/** Independent public generators, obtained with RFC 9380 hash_to_curve. */
export const h0 = bls12_381.G1.hashToCurve(utf8('CDL-Pi_DAA+-h0'), { DST: H0_DST });
export const h1 = bls12_381.G1.hashToCurve(utf8('CDL-Pi_DAA+-h1'), { DST: H1_DST });
export const issuerProofBase = bls12_381.G1.hashToCurve(
  utf8('CDL-Pi_DAA+-issuer-proof-base'),
  { DST: ISSUER_PROOF_DST }
);

export function basenamePoint(basename: Uint8Array): G1Point {
  if (basename.length === 0) {
    throw new Error('This bounded lesson implements named-basename mode only; bsn = ⊥ is out of scope');
  }
  return bls12_381.G1.hashToCurve(basename, { DST: BASENAME_DST });
}

export function mod(value: bigint): bigint {
  const reduced = value % SCALAR_ORDER;
  return reduced >= 0n ? reduced : reduced + SCALAR_ORDER;
}

export function isCanonicalScalar(value: bigint, allowZero = true): boolean {
  return value >= (allowZero ? 0n : 1n) && value < SCALAR_ORDER;
}

export function add(a: bigint, b: bigint): bigint {
  return mod(a + b);
}

export function sub(a: bigint, b: bigint): bigint {
  return mod(a - b);
}

export function mul(a: bigint, b: bigint): bigint {
  return mod(a * b);
}

export function invert(value: bigint): bigint {
  const reduced = mod(value);
  if (reduced === 0n) throw new Error('zero has no inverse in Fr');
  return bls12_381.fields.Fr.inv(reduced);
}

/**
 * Variable-time algebra helper that deliberately supports the zero scalar.
 * The lesson uses it for both public and software-held teaching values. Noble's
 * `multiplyUnsafe` and JavaScript bigint arithmetic are not side-channel
 * hardened; the UI and README make that limitation explicit.
 */
export function scale1(point: G1Point, scalar: bigint): G1Point {
  return point.multiplyUnsafe(mod(scalar));
}

/** Variable-time G2 counterpart of `scale1`; not hardened secret handling. */
export function scale2(point: G2Point, scalar: bigint): G2Point {
  return point.multiplyUnsafe(mod(scalar));
}

export function scalarBytes(value: bigint): Uint8Array {
  let remaining = mod(value);
  const out = new Uint8Array(32);
  for (let i = out.length - 1; i >= 0; i--) {
    out[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return out;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let out = 0n;
  for (const byte of bytes) out = (out << 8n) | BigInt(byte);
  return out;
}

/**
 * Canonical length-prefixed transcript encoding. There is no ambiguous string
 * concatenation: the domain and field count are framed, then every field is.
 */
export function transcript(domain: string, fields: readonly Uint8Array[]): Uint8Array {
  const domainBytes = utf8(domain);
  const framed = [u32be(domainBytes.length), domainBytes, u32be(fields.length)];
  for (const field of fields) framed.push(u32be(field.length), field);
  return concatBytes(...framed);
}

/**
 * Deterministic rejection sampling into Fr. Determinism keeps every displayed
 * value reproducible; it is a teaching fixture, not production randomness.
 */
export function scalarFromTranscript(
  domain: string,
  fields: readonly Uint8Array[],
  allowZero = false
): bigint {
  const base = transcript(domain, fields);
  for (let counter = 0; counter <= 0xffff_ffff; counter++) {
    const candidate = bytesToBigInt(sha256(concatBytes(base, u32be(counter))));
    if (candidate < SCALAR_ORDER && (allowZero || candidate !== 0n)) return candidate;
  }
  throw new Error('scalar rejection sampling exhausted its counter');
}

export function seededScalar(seed: Uint8Array, label: string, allowZero = false): bigint {
  return scalarFromTranscript('crypto-lab/daa/v1/deterministic-scalar', [seed, utf8(label)], allowZero);
}

/**
 * Secret-keyed deterministic nonce derivation over a complete framed context.
 * This is the lesson's reproducible analogue of fresh randomness. Binding the
 * full statement is essential: repeating a Schnorr witness across two
 * challenges reveals the witness secret by response subtraction.
 */
export function secretScalarFromTranscript(
  secret: bigint,
  domain: string,
  fields: readonly Uint8Array[],
  allowZero = false
): bigint {
  if (!isCanonicalScalar(secret, false)) throw new Error('nonce-derivation key is not a scalar');
  const key = scalarBytes(secret);
  const base = transcript(domain, fields);
  for (let counter = 0; counter <= 0xffff_ffff; counter++) {
    const candidate = bytesToBigInt(hmacSha256(key, concatBytes(base, u32be(counter))));
    if (candidate < SCALAR_ORDER && (allowZero || candidate !== 0n)) return candidate;
  }
  throw new Error('secret-keyed scalar rejection sampling exhausted its counter');
}

export function point1Bytes(point: G1Point): Uint8Array {
  point.assertValidity();
  if (point.is0()) throw new Error('G1 identity is not a valid public protocol point');
  return point.toBytes(true);
}

export function point2Bytes(point: G2Point): Uint8Array {
  point.assertValidity();
  if (point.is0()) throw new Error('G2 identity is not a valid public protocol point');
  return point.toBytes(true);
}

export function pairingEqual(a1: G1Point, a2: G2Point, b1: G1Point, b2: G2Point): boolean {
  try {
    a1.assertValidity();
    a2.assertValidity();
    b1.assertValidity();
    b2.assertValidity();
    if (a1.is0() || a2.is0() || b1.is0() || b2.is0()) return false;
    return bls12_381.fields.Fp12.eql(
      bls12_381.pairing(a1, a2),
      bls12_381.pairing(b1, b2)
    );
  } catch {
    return false;
  }
}

export function utf8Field(value: string): Uint8Array {
  return utf8(value);
}
