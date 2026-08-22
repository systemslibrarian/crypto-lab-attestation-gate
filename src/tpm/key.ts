/**
 * TPM objects: their public areas, their Names, and the one rule that makes an
 * Attestation Key different from an ordinary signing key.
 *
 * THE RULE (TPM 2.0 Part 1 §11.4.6.1, §25.1.3; Part 3 §15.4, §17.6, §20.2):
 *
 *   A restricted signing key may only sign a digest the TPM produced. When the
 *   TPM hashes EXTERNALLY supplied data it checks whether the first four
 *   octets equal TPM_GENERATED_VALUE. If they do, it still returns a ticket —
 *   but a NULL one, with the hierarchy set to TPM_RH_NULL and an empty digest.
 *   TPM2_Sign with a restricted key requires a ticket that AFFIRMATIVELY says
 *   the hashed data did not start with the magic, so the signature never
 *   happens: TPM_RC_TICKET on parameter 3.
 *
 * Read that carefully, because the usual summary gets it backwards. The magic
 * value is not a marker a verifier authenticates — it is public, and an
 * attacker can put it anywhere. It is a DOMAIN SEPARATOR enforced by the
 * signing oracle, exactly like a hash-prefix domain separator. The spec's own
 * example: "If an attacker produced a message block that was identical to a
 * TPM-generated quote... the TPM notes that the first octets are the same as
 * TPM_GENERATED_VALUE. It will not generate the ticket... so an AK may not be
 * used to sign this digest."
 *
 * A verifier-side magic check is still required — Part 1 §9.5.3.2 introduces
 * it with "Similarly" — but its job is the converse: a restricted AK is
 * legitimately allowed to sign external digests WITH a valid ticket (a PKCS#10
 * CSR, for instance), so the verifier must confirm the blob it is parsing is
 * an attestation and not some other signature by the same key. Presenting that
 * check as the anti-forgery mechanism is the error CVE-2024-29038 punishes:
 * `tpm2_checkquote` stopped comparing `magic` in tpm2-tools 4.1-rc0 and did
 * not resume until 5.5.1/5.6.1/5.7.
 *
 * Everything below is real: P-256 keys, real ECDSA over the marshalled bytes.
 * The signatures are RFC 6979 deterministic so every hex string on the page is
 * reproducible; a real TPM draws its per-signature nonce from its own RNG.
 * Verification is identical either way.
 */

import { p256 } from '@noble/curves/nist.js';
import { concatBytes, fromHex, toHex, u16be, u32be, utf8 } from '../core/bytes';
import { sha256, SHA256_LEN } from '../core/sha256';
import { computeName, qualifiedName, type FieldSpan } from './marshal';
import { TPM_ALG, TPM_GENERATED_VALUE, TPM_RH } from './constants';

/** TPM_ECC_CURVE. Part 2, "TPM_ECC_CURVE Constants". */
export const TPM_ECC_NIST_P256 = 0x0003;
/** TPM_ALG_CFB — the mode the standard EK template names for its symmetric wrapper. */
export const TPM_ALG_CFB = 0x0043;

/**
 * TPMA_OBJECT bit positions. Part 2, "Definition of (UINT32) TPMA_OBJECT Bits".
 * Bits 0, 3 and 12–15 are reserved and must be zero.
 */
export const TPMA_OBJECT = {
  fixedTPM: 0x00000002,
  stClear: 0x00000004,
  fixedParent: 0x00000010,
  sensitiveDataOrigin: 0x00000020,
  userWithAuth: 0x00000040,
  adminWithPolicy: 0x00000080,
  noDA: 0x00000400,
  encryptedDuplication: 0x00000800,
  restricted: 0x00010000,
  decrypt: 0x00020000,
  sign: 0x00040000,
} as const;

export type AttributeName = keyof typeof TPMA_OBJECT;

export type ObjectAttributes = Record<AttributeName, boolean>;

const ATTRIBUTE_ORDER = Object.keys(TPMA_OBJECT) as AttributeName[];

export function attributesToUint32(a: ObjectAttributes): number {
  let v = 0;
  for (const name of ATTRIBUTE_ORDER) if (a[name]) v |= TPMA_OBJECT[name];
  return v >>> 0;
}

export function attributesFromUint32(v: number): ObjectAttributes {
  const out = {} as ObjectAttributes;
  for (const name of ATTRIBUTE_ORDER) out[name] = (v & TPMA_OBJECT[name]) !== 0;
  return out;
}

export function setAttributes(...names: AttributeName[]): ObjectAttributes {
  const out = {} as ObjectAttributes;
  for (const name of ATTRIBUTE_ORDER) out[name] = names.includes(name);
  return out;
}

/** The names of the attributes that are SET, for display. */
export function attributeList(a: ObjectAttributes): string[] {
  return ATTRIBUTE_ORDER.filter((n) => a[n]);
}

/** A TPMT_PUBLIC for an ECC object, reduced to the fields these templates use. */
export interface EccPublic {
  nameAlg: number;
  attributes: ObjectAttributes;
  authPolicy: Uint8Array;
  /** TPMT_SYM_DEF_OBJECT. `TPM_ALG_NULL` marshals as its two bytes and nothing else. */
  symmetric: { alg: number; keyBits?: number; mode?: number };
  /** TPMT_ECC_SCHEME. ECDSA carries its hash; NULL carries nothing. */
  scheme: { alg: number; hashAlg?: number };
  curveId: number;
  point: { x: Uint8Array; y: Uint8Array };
}

/**
 * Marshal a TPMT_PUBLIC.
 *
 * Field order (Part 2, "TPMT_PUBLIC"):
 *   type | nameAlg | objectAttributes | authPolicy | parameters | unique
 *
 * The parameters union for ECC is TPMS_ECC_PARMS:
 *   symmetric (TPMT_SYM_DEF_OBJECT) | scheme (TPMT_ECC_SCHEME) | curveID | kdf
 * and `unique` is a TPMS_ECC_POINT, i.e. two TPM2Bs.
 *
 * This is the exact byte string whose digest becomes the object's Name, which
 * is why marshalling it correctly matters far beyond display: the Name is what
 * credential activation binds to, and one wrong byte anywhere in here produces
 * a different Name and a failed activation.
 */
export function marshalPublic(p: EccPublic): { bytes: Uint8Array; fields: FieldSpan[] } {
  const parts: Array<{ bytes: Uint8Array; span: Omit<FieldSpan, 'offset' | 'length' | 'hex'> }> = [];
  const add = (
    bytes: Uint8Array,
    path: string,
    label: string,
    type: string,
    value: string,
    note: string,
    depth = 0
  ): void => {
    parts.push({ bytes, span: { path, label, type, value, note, depth } });
  };

  add(
    u16be(TPM_ALG.ECC),
    'type',
    'type',
    'TPMI_ALG_PUBLIC',
    'TPM_ALG_ECC',
    'Which algorithm this object is, and therefore which union members follow.'
  );
  add(
    u16be(p.nameAlg),
    'nameAlg',
    'nameAlg',
    'TPMI_ALG_HASH',
    'TPM_ALG_SHA256',
    'The hash used to compute this object’s Name. It is read out of THIS field, not chosen by ' +
      'the caller doing the computing.'
  );
  const attrs = attributesToUint32(p.attributes);
  add(
    u32be(attrs),
    'objectAttributes',
    'objectAttributes',
    'TPMA_OBJECT',
    `0x${attrs.toString(16).padStart(8, '0')} — ${attributeList(p.attributes).join(', ')}`,
    'The attribute bits. `restricted` + `sign` is what makes a key an Attestation Key; clearing ' +
      '`restricted` makes it an ordinary signing key that can sign a forged quote.'
  );
  add(
    u16be(p.authPolicy.length),
    'authPolicy.size',
    'authPolicy.size',
    'UINT16',
    `${p.authPolicy.length} bytes`,
    'Size prefix of the TPM2B_DIGEST that follows.',
    1
  );
  if (p.authPolicy.length) {
    add(
      p.authPolicy,
      'authPolicy.buffer',
      'authPolicy.buffer',
      'TPM2B_DIGEST',
      'policy digest',
      'The policy that must be satisfied to use this object. The standard EK template pins the ' +
        'well-known TPM2_PolicySecret(TPM_RH_ENDORSEMENT) digest here.',
      1
    );
  }

  add(
    u16be(p.symmetric.alg),
    'parameters.symmetric.algorithm',
    'symmetric.algorithm',
    'TPMI_ALG_SYM_OBJECT',
    p.symmetric.alg === TPM_ALG.NULL ? 'TPM_ALG_NULL' : 'TPM_ALG_AES',
    'The symmetric algorithm a storage key uses to wrap its children. A signing key has none.',
    1
  );
  if (p.symmetric.alg !== TPM_ALG.NULL) {
    add(
      u16be(p.symmetric.keyBits!),
      'parameters.symmetric.keyBits',
      'symmetric.keyBits',
      'TPMI_AES_KEY_BITS',
      `${p.symmetric.keyBits}`,
      'Symmetric key size in bits.',
      2
    );
    add(
      u16be(p.symmetric.mode!),
      'parameters.symmetric.mode',
      'symmetric.mode',
      'TPMI_ALG_SYM_MODE',
      'TPM_ALG_CFB',
      'The block cipher mode. CFB is what credential activation wraps the credential with.',
      2
    );
  }
  add(
    u16be(p.scheme.alg),
    'parameters.scheme.scheme',
    'scheme.scheme',
    'TPMI_ALG_ECC_SCHEME',
    p.scheme.alg === TPM_ALG.NULL ? 'TPM_ALG_NULL' : 'TPM_ALG_ECDSA',
    'The signing scheme. A restricted key’s scheme cannot be overridden per command — the ' +
      'object’s own scheme is the only one it will use.',
    1
  );
  if (p.scheme.alg !== TPM_ALG.NULL) {
    add(
      u16be(p.scheme.hashAlg!),
      'parameters.scheme.hashAlg',
      'scheme.hashAlg',
      'TPMI_ALG_HASH',
      'TPM_ALG_SHA256',
      'The scheme’s hash. This is also the hash used for a quote’s pcrDigest — NOT the quoted ' +
        'bank’s algorithm.',
      2
    );
  }
  add(
    u16be(p.curveId),
    'parameters.curveID',
    'curveID',
    'TPMI_ECC_CURVE',
    'TPM_ECC_NIST_P256',
    'The elliptic curve.',
    1
  );
  add(
    u16be(TPM_ALG.NULL),
    'parameters.kdf.scheme',
    'kdf.scheme',
    'TPMI_ALG_KDF',
    'TPM_ALG_NULL',
    'The KDF used for ECDH key exchange with this key. NULL for everything here.',
    1
  );

  add(u16be(p.point.x.length), 'unique.x.size', 'unique.x.size', 'UINT16', '32 bytes', 'Size prefix.', 1);
  add(p.point.x, 'unique.x.buffer', 'unique.x', 'TPM2B_ECC_PARAMETER', 'public point X', 'The public key’s X coordinate.', 1);
  add(u16be(p.point.y.length), 'unique.y.size', 'unique.y.size', 'UINT16', '32 bytes', 'Size prefix.', 1);
  add(p.point.y, 'unique.y.buffer', 'unique.y', 'TPM2B_ECC_PARAMETER', 'public point Y', 'The public key’s Y coordinate.', 1);

  const fields: FieldSpan[] = [];
  let at = 0;
  for (const { bytes, span } of parts) {
    fields.push({ ...span, offset: at, length: bytes.length, hex: toHex(bytes) });
    at += bytes.length;
  }
  return { bytes: concatBytes(...parts.map((p2) => p2.bytes)), fields };
}

// ── Deterministic teaching keys ─────────────────────────────────────────────

/**
 * Derive a P-256 secret key from a label, by rejection sampling over
 * SHA-256(label || counter).
 *
 * Deterministic so every byte the page prints is reproducible and every act
 * can be re-entered without the numbers moving. Rejection sampling rather than
 * a modular reduction because a reduction is measurably biased and there is no
 * reason to teach the biased version. A real TPM derives its keys from its own
 * seeds; this is a teaching stand-in and nothing in the exhibit's claims rests
 * on how the key was made.
 */
export function deterministicSecretKey(label: string): Uint8Array {
  const n = p256.Point.Fn.ORDER;
  for (let counter = 0; counter < 256; counter++) {
    const candidate = sha256(concatBytes(utf8(label), u32be(counter)));
    const value = BigInt(`0x${toHex(candidate)}`);
    if (value >= 1n && value < n) return candidate;
  }
  throw new Error('rejection sampling failed — statistically impossible');
}

/** A loaded TPM object: its public area, its private half, and its position. */
export class TpmObject {
  readonly publicArea: Uint8Array;
  readonly name: Uint8Array;
  readonly qualifiedName: Uint8Array;
  readonly fields: FieldSpan[];

  constructor(
    readonly label: string,
    readonly secretKey: Uint8Array,
    readonly pub: EccPublic,
    /** The Qualified Name of the parent. A Primary object's parent is its hierarchy handle. */
    readonly parentQualifiedName: Uint8Array
  ) {
    const marshalled = marshalPublic(pub);
    this.publicArea = marshalled.bytes;
    this.fields = marshalled.fields;
    this.name = computeName(this.publicArea, pub.nameAlg);
    this.qualifiedName = qualifiedName(parentQualifiedName, this.name);
  }

  /** The Qualified Name as it appears inside a TPMS_ATTEST: nameAlg || digest. */
  get qualifiedSigner(): Uint8Array {
    return concatBytes(u16be(this.pub.nameAlg), this.qualifiedName);
  }

  get publicKey(): Uint8Array {
    return concatBytes(new Uint8Array([0x04]), this.pub.point.x, this.pub.point.y);
  }
}

function publicPoint(secretKey: Uint8Array): { x: Uint8Array; y: Uint8Array } {
  const uncompressed = p256.getPublicKey(secretKey, false);
  return { x: uncompressed.slice(1, 33), y: uncompressed.slice(33, 65) };
}

/**
 * The Name of a permanent handle is the handle itself — Part 1, "Equations for
 * Computing Entity Names": "No hash is performed on the handle to produce the
 * name". So a Primary object's Qualified Name recursion bottoms out at four
 * bytes, not at a digest.
 */
export function hierarchyQualifiedName(handle: number): Uint8Array {
  return u32be(handle);
}

/**
 * The authPolicy of the standard EK templates (TCG EK Credential Profile
 * Templates L-1/L-2). It is the digest of TPM2_PolicySecret against the
 * endorsement hierarchy, and `key.test.ts` derives it from scratch rather than
 * trusting the constant.
 */
export const EK_AUTH_POLICY = fromHex(
  '837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa'
);

/** An Attestation Key: restricted, signing, not decrypting, fixedTPM. Attributes 0x00050072. */
export function makeAttestationKey(label: string, parentQn: Uint8Array, restricted = true): TpmObject {
  const secretKey = deterministicSecretKey(label);
  return new TpmObject(
    label,
    secretKey,
    {
      nameAlg: TPM_ALG.SHA256,
      attributes: restricted
        ? setAttributes('fixedTPM', 'fixedParent', 'sensitiveDataOrigin', 'userWithAuth', 'restricted', 'sign')
        : setAttributes('fixedTPM', 'fixedParent', 'sensitiveDataOrigin', 'userWithAuth', 'sign'),
      authPolicy: new Uint8Array(0),
      symmetric: { alg: TPM_ALG.NULL },
      scheme: { alg: TPM_ALG.ECDSA, hashAlg: TPM_ALG.SHA256 },
      curveId: TPM_ECC_NIST_P256,
      point: publicPoint(secretKey),
    },
    parentQn
  );
}

/**
 * An Endorsement Key on the ECC P-256 template (L-2): restricted DECRYPTION,
 * `sign` CLEAR, adminWithPolicy, the well-known authPolicy, and an AES-128-CFB
 * symmetric wrapper. Attributes 0x000300B2 — the exact mirror of an AK.
 *
 * The `unique` field of the published template is 64 zero bytes; a real EK is
 * created by TPM2_CreatePrimary from that template with the seed filling in
 * the point, which is what this models.
 */
export function makeEndorsementKey(label: string): TpmObject {
  const secretKey = deterministicSecretKey(label);
  return new TpmObject(
    label,
    secretKey,
    {
      nameAlg: TPM_ALG.SHA256,
      attributes: setAttributes(
        'fixedTPM',
        'fixedParent',
        'sensitiveDataOrigin',
        'adminWithPolicy',
        'restricted',
        'decrypt'
      ),
      authPolicy: EK_AUTH_POLICY,
      symmetric: { alg: TPM_ALG.AES, keyBits: 128, mode: TPM_ALG_CFB },
      scheme: { alg: TPM_ALG.NULL },
      curveId: TPM_ECC_NIST_P256,
      point: publicPoint(secretKey),
    },
    hierarchyQualifiedName(TPM_RH.ENDORSEMENT)
  );
}

/** A Storage Root Key: the AK's parent in the owner hierarchy. */
export function makeStorageRootKey(label: string): TpmObject {
  const secretKey = deterministicSecretKey(label);
  return new TpmObject(
    label,
    secretKey,
    {
      nameAlg: TPM_ALG.SHA256,
      attributes: setAttributes(
        'fixedTPM',
        'fixedParent',
        'sensitiveDataOrigin',
        'userWithAuth',
        'noDA',
        'restricted',
        'decrypt'
      ),
      authPolicy: new Uint8Array(0),
      symmetric: { alg: TPM_ALG.AES, keyBits: 128, mode: TPM_ALG_CFB },
      scheme: { alg: TPM_ALG.NULL },
      curveId: TPM_ECC_NIST_P256,
      point: publicPoint(secretKey),
    },
    hierarchyQualifiedName(TPM_RH.OWNER)
  );
}

// ── The restricted signing rule ─────────────────────────────────────────────

/**
 * `TicketIsSafe()` from the TPM reference implementation, transcribed.
 *
 * Note the short-buffer case: a buffer of fewer than four octets returns FALSE
 * — "not safe" — because the TPM cannot yet know what the first four octets
 * will be. (TPM2_Hash, which sees the whole message at once, short-circuits
 * the other way and does issue a ticket for a sub-four-byte message. That
 * asymmetry is Part 3 §17.6 NOTE 2, and it is real.)
 */
export function ticketIsSafe(data: Uint8Array): boolean {
  if (data.length < 4) return false;
  const magic = u32be(TPM_GENERATED_VALUE);
  for (let i = 0; i < 4; i++) if (data[i] !== magic[i]) return true;
  return false;
}

/**
 * TPMT_TK_HASHCHECK — the ticket a restricted signing key requires.
 *
 * A real ticket is `HMAC_contextAlg(proof, TPM_ST_HASHCHECK || digest)` under a
 * hierarchy proof value that never leaves the TPM. Here the ticket is modelled
 * as the fact of its issuance plus the digest it covers, because the exhibit is
 * about WHEN the TPM refuses to issue one, not about the HMAC that makes it
 * unforgeable off-chip. A NULL ticket is the refusal.
 */
export interface HashTicket {
  /** TPM_RH_NULL means the TPM declined; any other hierarchy means it vouched. */
  hierarchy: number;
  digest: Uint8Array;
}

export const NULL_TICKET: HashTicket = { hierarchy: TPM_RH.NULL, digest: new Uint8Array(0) };

export interface HashResult {
  digest: Uint8Array;
  ticket: HashTicket;
  /** Why the ticket came back NULL, when it did. */
  refusal?: string;
}

/**
 * TPM2_Hash over externally supplied data.
 *
 * This is the enforcement point. The TPM computes the digest either way — the
 * refusal is not to hash, it is to VOUCH.
 */
export function tpm2Hash(data: Uint8Array, hierarchy = TPM_RH.OWNER): HashResult {
  const digest = sha256(data);
  if (data.length >= 4 && !ticketIsSafe(data)) {
    return {
      digest,
      ticket: NULL_TICKET,
      refusal:
        'the data begins with TPM_GENERATED_VALUE (FF 54 43 47), so the TPM will not certify ' +
        'that this digest is safe for a restricted signing key',
    };
  }
  return { digest, ticket: { hierarchy, digest } };
}

/**
 * TPM_RC_TICKET as it appears on the wire from TPM2_Sign's third parameter:
 * RC_FMT1 (0x080) + 0x020 for "invalid ticket", plus TPM_RC_P (0x040) and
 * TPM_RC_3 (0x300) marking it as a parameter-3 error.
 */
export const TPM_RC_TICKET_ON_SIGN = 0x000003e0;

export type SignOutcome =
  | { ok: true; signature: Uint8Array; digest: Uint8Array; path: 'internal' | 'external' }
  | { ok: false; responseCode: number; responseName: string; reason: string };

/** Raw ECDSA over a digest, with no policy applied. Used by both paths below. */
function rawSign(key: TpmObject, digest: Uint8Array): Uint8Array {
  // lowS: false because a TPM applies no low-S normalisation; prehash: false
  // because the digest is already computed (the TPM signs a digest, not a
  // message). Deterministic per RFC 6979 — see this file's header.
  return p256.sign(digest, key.secretKey, { lowS: false, prehash: false });
}

/**
 * TPM2_Sign(keyHandle, digest, inScheme, validation).
 *
 * The whole of Act 2a is the four lines that check the ticket.
 */
export function tpm2Sign(key: TpmObject, digest: Uint8Array, validation: HashTicket): SignOutcome {
  if (!key.pub.attributes.sign) {
    return {
      ok: false,
      responseCode: 0x0000019c,
      responseName: 'TPM_RC_KEY',
      reason: `${key.label} has the sign attribute CLEAR — it is a decryption key and cannot sign anything`,
    };
  }
  if (key.pub.attributes.restricted && validation.hierarchy === TPM_RH.NULL) {
    return {
      ok: false,
      responseCode: TPM_RC_TICKET_ON_SIGN,
      responseName: 'TPM_RC_TICKET',
      reason:
        `${key.label} is a RESTRICTED signing key, so TPM2_Sign requires a validation ticket ` +
        'proving the TPM produced this digest from data that did not begin with ' +
        'TPM_GENERATED_VALUE. The ticket is NULL, so the signature does not happen.',
    };
  }
  return { ok: true, signature: rawSign(key, digest), digest, path: 'external' };
}

/**
 * The internal path: the TPM built the structure itself, so no ticket is
 * involved and the magic value is legitimately present.
 *
 * There is no way to reach this function with attacker-supplied bytes — that
 * is what makes the domain separation hold — so it is deliberately not
 * exported to the UI's forging controls.
 */
export function signInternalStructure(
  key: TpmObject,
  structure: Uint8Array
): { signature: Uint8Array; digest: Uint8Array } {
  const digest = sha256(structure);
  return { signature: rawSign(key, digest), digest };
}

/** Hash then sign externally supplied bytes — the full two-command sequence. */
export function signExternalData(key: TpmObject, data: Uint8Array): SignOutcome & { hash?: HashResult } {
  const hash = tpm2Hash(data);
  const outcome = tpm2Sign(key, hash.digest, hash.ticket);
  return { ...outcome, hash };
}

/** Verify an ECDSA signature over an already-computed digest. */
export function verifyOverDigest(
  publicKey: Uint8Array,
  digest: Uint8Array,
  signature: Uint8Array
): boolean {
  if (digest.length !== SHA256_LEN) return false;
  try {
    return p256.verify(signature, digest, publicKey, { lowS: false, prehash: false });
  } catch {
    return false;
  }
}
