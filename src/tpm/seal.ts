/**
 * Sealed Data Objects — the object format a PCR policy actually protects.
 *
 * A sealed secret is an ordinary TPM object with no key in it. Its public area
 * is a `TPMT_PUBLIC` of type `TPM_ALG_KEYEDHASH` with `sign` and `decrypt`
 * CLEAR, which Part 1 §24.3.3 (1.83 §27.3.3) says IS the definition of a
 * Sealed Data Object; its sensitive area holds the bytes to be released; and its
 * `authPolicy` is the single digest a policy session has to reproduce before
 * `TPM2_Unseal` will hand those bytes back.
 *
 * FOUR THINGS ARE DELIBERATELY SEPARATE HERE, because conflating any two of
 * them is how sealing gets explained wrongly:
 *
 *   1. The PCR VALUES. Public, unsigned, readable by anything on the machine.
 *   2. The POLICY DIGEST. A public 32-byte commitment to a CONDITION. It does
 *      not contain the PCR values and it says nothing about the secret.
 *   3. The sealed object's PUBLIC METADATA (`TPM2B_PUBLIC`): type, attributes,
 *      `authPolicy`, and `unique`. All public. `unique` is a non-invertible
 *      digest over the secret, and Part 1 §24.5.3.1 states exactly why it is
 *      built that way: a bare digest of low-entropy data would be an offline
 *      guessing oracle, and an identity not bound to the sensitive area would
 *      let an attacker pair someone else's public area with their own secret.
 *   4. The PROTECTED SECRET MATERIAL. Only ever inside `encSensitive`, and
 *      only recoverable with the storage parent's `seedValue`.
 *
 * Specification, exactly (v185 = Version 185, March 12, 2026; 1.83 = Family
 * "2.0" Level 00 Revision 01.83, January 25, 2024):
 *
 *   - `TPMT_PUBLIC` field order: Part 2 §12.2.4 Table 211
 *   - `TPMS_KEYEDHASH_PARMS`: Part 2 §12.2.3.3 Table 205
 *   - `TPMT_SENSITIVE` field order: Part 2 §12.3.2.4 Table 216
 *   - `_PRIVATE` / `TPM2B_PRIVATE`: Part 2 §12.3.6 Table 218, §12.3.7 Table 219
 *   - `unique := H_nameAlg(obfuscate || key)`:
 *       v185 Part 1 §24.5.3.2 Equation 48   /   1.83 Part 1 §27.5.3.2 eq (49)
 *   - `symKey := KDFa(pNameAlg, seedValue, "STORAGE", name, NULL, bits)` and
 *     `encSensitive := CFB(symKey, symIv, sensitive)`:
 *       v185 Part 1 §19.4 Equations 33-34   /   1.83 Part 1 §22.4 eq (33)(34)
 *   - `HMACkey := KDFa(pNameAlg, seedValue, "INTEGRITY", NULL, NULL, bits)` and
 *     `outerHMAC := HMAC(HMACkey, symIv || encSensitive || name.buffer)`:
 *       v185 Part 1 §19.5 Equations 35-36   /   1.83 Part 1 §22.5 eq (35)(36)
 *   - the seven-step assembly order: 1.83 Part 1 Figure 17
 *   - `TPM2_Load`: integrity checked BEFORE decrypt and unmarshal;
 *     `TPM_RC_BINDING` if public and sensitive are not cryptographically
 *     linked, with the KEYEDHASH `unique` check as its own EXAMPLE 1:
 *       Part 3 §12.2
 *   - exact `TPM2B_SENSITIVE` consumption and the post-integrity one-block IV
 *     check: 1.83 Part 4 `PrivateToSensitive` and `UnwrapOuter` reference code
 *   - `TPM2_Unseal`: `TPM_RC_TYPE` unless `TPM_ALG_KEYEDHASH`,
 *     `TPM_RC_ATTRIBUTES` if `restricted`, `decrypt` or `sign` is SET, Auth
 *     Role USER on `@itemHandle`: Part 3 §12.7 and its reference code §12.7.3.1
 *
 * WHAT THIS IS NOT, stated here because the code cannot show its own absence.
 * The storage parent's `seedValue` is a value in this page's memory. In real
 * hardware it never leaves the chip, and THAT — not any line below — is what
 * makes `TPM_RC_INTEGRITY` mean something. A JavaScript equality check is not
 * hardware isolation. There is no secure boot here (nothing verifies a
 * signature on firmware), no rollback prevention (no NV counter, no
 * `TPM2_PolicyNV`), no anti-hammering (`noDA` is SET and there is no lockout),
 * and no production authorization system (no authValue, no HMAC sessions, no
 * locality, no physical presence). No TPM command is executed or transmitted.
 */

import { cfb } from '@noble/ciphers/aes.js';
import { bytesEqual, concatBytes, u16be, toHex } from '../core/bytes';
import { hmacSha256 } from '../core/hmac';
import { sha256, SHA256_LEN } from '../core/sha256';
import { TPM_ALG, TPM_ALG_NAMES } from './constants';
import { kdfa } from './kdf';
import {
  attributeList,
  attributesFromUint32,
  attributesToUint32,
  setAttributes,
  type AttributeName,
  type ObjectAttributes,
} from './key';
import { computeName, type FieldSpan } from './marshal';
import {
  checkPolicyAuthorization,
  decodeRc,
  rcHandle,
  rcParameter,
  TPM_CC,
  TPM_RC,
  type AuthorizationAttempt,
  type PolicySession,
} from './policy';

/** The symmetric cipher of the storage parent in the standard SRK template. */
export const SRK_SYM_BITS = 128;
const AES_BLOCK = 16;

// ── The public area ─────────────────────────────────────────────────────────

export interface SealedPublic {
  nameAlg: number;
  attributes: ObjectAttributes;
  /** The policy digest a session must reproduce. Empty would mean no policy. */
  authPolicy: Uint8Array;
  /** `unique` — H(obfuscate || secret). Public, and non-invertible by construction. */
  unique: Uint8Array;
}

/**
 * The attribute set for a sealed data object in this lesson.
 *
 * `userWithAuth` is CLEAR, and that is the single most load-bearing bit in the
 * whole exhibit: Part 3 §5.6 says USER-role authorization for an object whose
 * `userWithAuth` is CLEAR may NOT be given with an HMAC session or a password.
 * With the bit SET, anyone who knew an authValue could unseal and the PCR
 * policy would be decoration.
 *
 * `sensitiveDataOrigin` is CLEAR because the caller supplies the data
 * (Part 2 §8.3.3.5: it shall be CLEAR exactly when `inSensitive.data` is
 * non-empty, and Part 1 §24.3.3 requires non-empty data for a sealed object).
 * `sign` and `decrypt` are CLEAR, which is what makes a KEYEDHASH object a
 * sealed data object rather than an HMAC key. `restricted` is CLEAR because
 * Part 3 §12.7 returns `TPM_RC_ATTRIBUTES` for an `itemHandle` that has it.
 */
export const SEALED_ATTRIBUTES: readonly AttributeName[] = ['fixedTPM', 'fixedParent', 'noDA'];

export function sealedAttributes(): ObjectAttributes {
  return setAttributes(...SEALED_ATTRIBUTES);
}

/** `unique` for a KEYEDHASH object. v185 Part 1 §24.5.3.2 Equation 48. */
export function keyedHashUnique(obfuscate: Uint8Array, secret: Uint8Array): Uint8Array {
  return sha256(concatBytes(obfuscate, secret));
}

const NOTE = {
  type:
    'TPM_ALG_KEYEDHASH (0x0008) with sign and decrypt both CLEAR is the definition of a Sealed ' +
    'Data Object — an object with no key in it, whose sensitive area is the bytes to be ' +
    'released. TPM2_Unseal returns TPM_RC_TYPE for anything else.',
  nameAlg:
    'The hash used to compute this object’s Name, and the hash the authPolicy must have been ' +
    'computed under. A policy session started with a different algorithm can never satisfy this ' +
    'object, however correct its assertions.',
  attributes:
    'userWithAuth is CLEAR here, which is what forces a policy session: Part 3 §5.6 refuses ' +
    'USER-role authorization by HMAC or password for such an object. fixedTPM and fixedParent ' +
    'say the object cannot be duplicated away from this TPM or re-parented. noDA exempts it from ' +
    'dictionary-attack lockout — appropriate when there is no authValue to guess, and a reminder ' +
    'that no anti-hammering is in play.',
  authPolicy:
    'The policy, as one digest. This is the value a policy session has to accumulate before the ' +
    'TPM will release anything. It does not contain the PCR values and it reveals nothing about ' +
    'the secret; it is a commitment to a condition.',
  schemeAlg:
    'TPMT_KEYEDHASH_SCHEME. TPM_ALG_NULL (0x0010) means no signing or XOR scheme — for a data ' +
    'object this field also fixes the maximum size of the sensitive data.',
  uniqueSize: 'UINT16 size prefix of the TPM2B_DIGEST that follows.',
  unique:
    'H(obfuscate || secret), where obfuscate is a TPM-generated value in the sensitive area. It ' +
    'binds the public area to this exact secret, so a public area cannot be paired with a ' +
    'different sensitive area (TPM2_Load returns TPM_RC_BINDING), and it is non-invertible so ' +
    'publishing it does not make a low-entropy secret guessable.',
};

/**
 * Marshal a `TPMT_PUBLIC` for a sealed data object.
 *
 * Part 2 §12.2.4 Table 211 field order:
 *   type | nameAlg | objectAttributes | authPolicy | parameters | unique
 *
 * For KEYEDHASH, `parameters` is a `TPMS_KEYEDHASH_PARMS` whose only member is
 * a `TPMT_KEYEDHASH_SCHEME`; `TPM_ALG_NULL` marshals as its two bytes and
 * nothing else. `unique` is a `TPM2B_DIGEST`.
 *
 * These are the exact bytes whose digest becomes the Name, and the Name is
 * inside the private blob's HMAC — so one changed byte anywhere in this
 * structure makes the object unloadable rather than merely different.
 */
export function marshalSealedPublic(p: SealedPublic): { bytes: Uint8Array; fields: FieldSpan[] } {
  const fields: FieldSpan[] = [];
  const chunks: Uint8Array[] = [];
  let at = 0;
  const add = (
    bytes: Uint8Array,
    path: string,
    type: string,
    value: string,
    note: string,
    depth = 0
  ): void => {
    fields.push({ path, label: path, type, offset: at, length: bytes.length, hex: toHex(bytes), value, note, depth });
    chunks.push(bytes);
    at += bytes.length;
  };

  const attributeValue = attributesToUint32(p.attributes);
  add(u16be(TPM_ALG.KEYEDHASH), 'type', 'TPMI_ALG_PUBLIC', 'TPM_ALG_KEYEDHASH', NOTE.type);
  add(
    u16be(p.nameAlg),
    'nameAlg',
    'TPMI_ALG_HASH',
    TPM_ALG_NAMES[p.nameAlg] ?? `0x${p.nameAlg.toString(16)}`,
    NOTE.nameAlg
  );
  add(
    new Uint8Array([
      (attributeValue >>> 24) & 0xff,
      (attributeValue >>> 16) & 0xff,
      (attributeValue >>> 8) & 0xff,
      attributeValue & 0xff,
    ]),
    'objectAttributes',
    'TPMA_OBJECT',
    attributeList(p.attributes).join(' | ') || '(none set)',
    NOTE.attributes
  );
  add(u16be(p.authPolicy.length), 'authPolicy.size', 'UINT16', `${p.authPolicy.length} bytes`, NOTE.authPolicy);
  add(p.authPolicy, 'authPolicy.buffer', 'TPM2B_DIGEST', 'the policy digest', NOTE.authPolicy);
  add(u16be(TPM_ALG.NULL), 'parameters.scheme.scheme', 'TPMT_KEYEDHASH_SCHEME', 'TPM_ALG_NULL', NOTE.schemeAlg, 1);
  add(u16be(p.unique.length), 'unique.size', 'UINT16', `${p.unique.length} bytes`, NOTE.uniqueSize);
  add(p.unique, 'unique.buffer', 'TPM2B_DIGEST', 'H(obfuscate || secret)', NOTE.unique);

  return { bytes: concatBytes(...chunks), fields };
}

// ── The sensitive area ──────────────────────────────────────────────────────

export interface SealedSensitive {
  /** Must equal the public area's `type`. Part 2 §12.3.2.4. */
  sensitiveType: number;
  authValue: Uint8Array;
  /** For a non-parent object this is the OBFUSCATION value, not a seed. */
  seedValue: Uint8Array;
  /** The bytes to be released: `sensitive.bits.buffer`. */
  data: Uint8Array;
}

/**
 * Marshal a `TPM2B_SENSITIVE` — a UINT16 size over a `TPMT_SENSITIVE`:
 *
 *   sensitiveType | authValue | seedValue | [sensitiveType]sensitive
 *
 * Part 2 §12.3.7 notes that a real TPM pads the `TPM2B_AUTH` to its maximum
 * size before returning a `TPM2B_PRIVATE`, so the blob length does not leak
 * the authValue length. That padding is NOT modelled here. The authValue in
 * this lesson is empty — the object's authorization is entirely the policy —
 * so nothing in the lesson turns on it, but the byte layout below is
 * therefore this model's, not a real TPM's private blob.
 */
export function marshalSensitive(s: SealedSensitive): Uint8Array {
  const inner = concatBytes(
    u16be(s.sensitiveType),
    u16be(s.authValue.length),
    s.authValue,
    u16be(s.seedValue.length),
    s.seedValue,
    u16be(s.data.length),
    s.data
  );
  return concatBytes(u16be(inner.length), inner);
}

// ── The storage parent and the private blob ─────────────────────────────────

export interface StorageParent {
  label: string;
  nameAlg: number;
  /**
   * The parent's symmetric protection seed. In hardware this never leaves the
   * TPM; here it is a page-local value, which is the one gap no amount of
   * correct arithmetic below can close.
   */
  seedValue: Uint8Array;
}

/** `symKey := KDFa(pNameAlg, seedValue, "STORAGE", name, NULL, bits)`. Eq 33. */
export function storageKey(parent: StorageParent, name: Uint8Array): Uint8Array {
  return kdfa(parent.seedValue, 'STORAGE', name, new Uint8Array(0), SRK_SYM_BITS);
}

/** `HMACkey := KDFa(pNameAlg, seedValue, "INTEGRITY", NULL, NULL, bits)`. Eq 35. */
export function integrityKey(parent: StorageParent): Uint8Array {
  return kdfa(parent.seedValue, 'INTEGRITY', new Uint8Array(0), new Uint8Array(0), SHA256_LEN * 8);
}

/** The marshalled `TPM2B_IV`: both the size and the buffer go into the HMAC. */
function marshalIv(iv: Uint8Array): Uint8Array {
  return concatBytes(u16be(iv.length), iv);
}

/**
 * `outerHMAC := HMAC_pNameAlg(HMACkey, symIv || encSensitive || name.buffer)`.
 * Eq 36. `name.buffer` carries no size field (v185 Part 1 §19.5).
 */
export function outerHmac(
  parent: StorageParent,
  iv: Uint8Array,
  encSensitive: Uint8Array,
  name: Uint8Array
): Uint8Array {
  return hmacSha256(integrityKey(parent), concatBytes(marshalIv(iv), encSensitive, name));
}

export interface SealedObject {
  pub: SealedPublic;
  /** The marshalled `TPMT_PUBLIC`. */
  publicArea: Uint8Array;
  publicFields: FieldSpan[];
  /** `nameAlg || H(publicArea)`. */
  name: Uint8Array;
  /** The marshalled `TPM2B_PRIVATE` content: outerHMAC | symIv | encSensitive. */
  priv: Uint8Array;
  /** The three pieces of `priv`, so the page can tamper with exactly one. */
  parts: { integrityOuter: Uint8Array; iv: Uint8Array; encSensitive: Uint8Array };
}

export interface SealInput {
  parent: StorageParent;
  secret: Uint8Array;
  authPolicy: Uint8Array;
  /** The TPM-generated obfuscation value. Deterministic here, by label. */
  obfuscate: Uint8Array;
  /** The per-object IV. Random in a real TPM; deterministic here. */
  iv: Uint8Array;
  nameAlg?: number;
  attributes?: ObjectAttributes;
}

/**
 * `TPM2_Create` for a sealed data object, followed by the protection of
 * 1.83 Part 1 Figure 17.
 *
 * The seven steps, in order, because the order is the thing that is easy to
 * get subtly wrong:
 *   1. marshal the sensitive area into a `TPM2B_SENSITIVE`;
 *   2. derive `symKey` from the parent seed AND THE OBJECT'S NAME;
 *   3. CFB-encrypt the whole `TPM2B_SENSITIVE`, size field included;
 *   4. put the marshalled `TPM2B_IV` in front of the ciphertext;
 *   5. derive `HMACkey` from the parent seed alone;
 *   6. HMAC over `symIv || encSensitive || name`;
 *   7. emit `TPM2B_DIGEST(outerHMAC) || symIv || encSensitive`.
 *
 * Step 2 is why tampering with the PUBLIC area breaks the PRIVATE one: the
 * Name is a digest of the public area, so changing one public byte changes the
 * key the ciphertext was encrypted under and the Name inside its HMAC.
 */
export function sealObject(input: SealInput): SealedObject {
  if (input.secret.length === 0) {
    // Part 1 §24.3.3 / Part 3 §12.1: a Sealed Data Object with an empty
    // inSensitive.data is TPM_RC_SIZE. Refusing rather than sealing nothing.
    throw new Error('a Sealed Data Object requires non-empty data (Part 3 §12.1, TPM_RC_SIZE)');
  }
  if (input.obfuscate.length !== SHA256_LEN) {
    throw new Error(`the obfuscation value is the nameAlg digest size: ${SHA256_LEN} bytes`);
  }
  if (input.iv.length !== AES_BLOCK) {
    throw new Error(`symIv is one AES block: ${AES_BLOCK} bytes`);
  }

  const pub: SealedPublic = {
    nameAlg: input.nameAlg ?? TPM_ALG.SHA256,
    attributes: input.attributes ?? sealedAttributes(),
    authPolicy: input.authPolicy,
    unique: keyedHashUnique(input.obfuscate, input.secret),
  };
  const { bytes: publicArea, fields: publicFields } = marshalSealedPublic(pub);
  const name = computeName(publicArea, pub.nameAlg);

  const sensitive = marshalSensitive({
    sensitiveType: TPM_ALG.KEYEDHASH,
    authValue: new Uint8Array(0),
    seedValue: input.obfuscate,
    data: input.secret,
  });
  const encSensitive = cfb(storageKey(input.parent, name), input.iv).encrypt(sensitive);
  const integrityOuter = outerHmac(input.parent, input.iv, encSensitive, name);
  const priv = concatBytes(
    u16be(integrityOuter.length),
    integrityOuter,
    marshalIv(input.iv),
    encSensitive
  );

  return {
    pub,
    publicArea,
    publicFields,
    name,
    priv,
    parts: { integrityOuter, iv: input.iv, encSensitive },
  };
}

// ── TPM2_Load ───────────────────────────────────────────────────────────────

export interface LoadedObject {
  publicArea: Uint8Array;
  pub: SealedPublic;
  name: Uint8Array;
  sensitive: SealedSensitive;
}

export type TpmOutcome<T> =
  | ({ ok: true } & T)
  | { ok: false; rc: number; rcName: string; rcNote: string; reason: string };

function rcFail(rc: number, reason: string): { ok: false; rc: number; rcName: string; rcNote: string; reason: string } {
  const d = decodeRc(rc);
  const note =
    d.subject === 'none'
      ? `0x${rc.toString(16).padStart(3, '0')} = ${d.format === 0 ? 'RC_VER1' : 'RC_FMT1'} + 0x${d.number.toString(16).padStart(3, '0')}`
      : `0x${rc.toString(16).padStart(3, '0')} = RC_FMT1 + 0x${d.number.toString(16).padStart(3, '0')}` +
        `${d.subject === 'parameter' ? ' + TPM_RC_P' : ''} + ${d.subject} ${d.index}`;
  return { ok: false, rc, rcName: d.name, rcNote: note, reason };
}

function unmarshalSealedPublic(bytes: Uint8Array): SealedPublic | null {
  // Fixed layout for this object type: 2 + 2 + 4 + (2 + n) + 2 + (2 + m).
  const read16 = (o: number): number => (bytes[o] << 8) | bytes[o + 1];
  if (bytes.length < 14) return null;
  if (read16(0) !== TPM_ALG.KEYEDHASH) return null;
  const nameAlg = read16(2);
  const attributeValue =
    ((bytes[4] << 24) | (bytes[5] << 16) | (bytes[6] << 8) | bytes[7]) >>> 0;
  const policyLen = read16(8);
  let at = 10 + policyLen;
  if (bytes.length < at + 4) return null;
  const authPolicy = bytes.slice(10, at);
  if (read16(at) !== TPM_ALG.NULL) return null;
  at += 2;
  const uniqueLen = read16(at);
  at += 2;
  if (bytes.length !== at + uniqueLen) return null;
  // `attributesFromUint32` is the shared decoder in `key.ts`; re-deriving the
  // bit positions here would be a second definition of them.
  return {
    nameAlg,
    attributes: attributesFromUint32(attributeValue),
    authPolicy,
    unique: bytes.slice(at),
  };
}

function unmarshalSensitive(bytes: Uint8Array): SealedSensitive | null {
  const read16 = (o: number): number => (bytes[o] << 8) | bytes[o + 1];
  if (bytes.length < 2) return null;
  const outer = read16(0);
  if (bytes.length !== 2 + outer) return null;
  const body = bytes.slice(2, 2 + outer);
  if (body.length < 8) return null;
  const sensitiveType = (body[0] << 8) | body[1];
  let at = 2;
  const authLen = (body[at] << 8) | body[at + 1];
  at += 2;
  const authValue = body.slice(at, at + authLen);
  at += authLen;
  if (body.length < at + 2) return null;
  const seedLen = (body[at] << 8) | body[at + 1];
  at += 2;
  const seedValue = body.slice(at, at + seedLen);
  at += seedLen;
  if (body.length < at + 2) return null;
  const dataLen = (body[at] << 8) | body[at + 1];
  at += 2;
  if (body.length !== at + dataLen) return null;
  return { sensitiveType, authValue, seedValue, data: body.slice(at, at + dataLen) };
}

/**
 * `TPM2_Load`. Part 3 §12.2.
 *
 * Three refusals, in the order the specification puts them, and the order is
 * itself a security property:
 *
 *   - the attribute consistency rules of Part 2 §8.3 → `TPM_RC_ATTRIBUTES`;
 *   - the integrity value is checked BEFORE the private area is decrypted or
 *     unmarshalled, "to prevent attacks on the sensitive area by fuzzing the
 *     data and looking at the differences in the response codes" (NOTE 3) →
 *     `TPM_RC_INTEGRITY`;
 *   - the public and sensitive portions must be cryptographically linked, and
 *     EXAMPLE 1 is this exact object type: "for a symmetric object, the unique
 *     value in the public area is the digest of the sensitive key and the
 *     obfuscation value" → `TPM_RC_BINDING`.
 *
 * The last one is reachable only by an attacker who holds the parent's
 * `seedValue` — anyone else fails the integrity check first. That it is
 * reachable AT ALL in this model is the honest consequence of modelling the
 * seed in page memory.
 */
export function tpm2Load(
  parent: StorageParent,
  publicArea: Uint8Array,
  priv: Uint8Array
): TpmOutcome<{ object: LoadedObject }> {
  if (priv.length === 0) {
    return rcFail(rcParameter(TPM_RC.SIZE, 1), 'inPrivate.size is zero, so there is nothing to load');
  }
  const pub = unmarshalSealedPublic(publicArea);
  if (!pub) {
    return rcFail(
      rcParameter(TPM_RC.SIZE, 2),
      'inPublic does not unmarshal as a TPMT_PUBLIC for a KEYEDHASH object'
    );
  }
  if (pub.attributes.sign || pub.attributes.decrypt) {
    return rcFail(
      rcParameter(TPM_RC.ATTRIBUTES, 2),
      'sign or decrypt is SET, so this is an HMAC or XOR key rather than a sealed data object'
    );
  }

  const read16 = (o: number): number => (priv[o] << 8) | priv[o + 1];
  if (priv.length < 2) return rcFail(rcParameter(TPM_RC.SIZE, 1), 'inPrivate is truncated');
  const integrityLen = read16(0);
  let at = 2 + integrityLen;
  if (priv.length < at + 2) return rcFail(rcParameter(TPM_RC.SIZE, 1), 'inPrivate is truncated');
  const integrityOuter = priv.slice(2, at);
  const ivLen = read16(at);
  at += 2;
  if (priv.length < at + ivLen) return rcFail(rcParameter(TPM_RC.SIZE, 1), 'inPrivate is truncated');
  const iv = priv.slice(at, at + ivLen);
  at += ivLen;
  const encSensitive = priv.slice(at);

  const name = computeName(publicArea, pub.nameAlg);
  const expected = outerHmac(parent, iv, encSensitive, name);
  if (!bytesEqual(expected, integrityOuter)) {
    return rcFail(
      rcParameter(TPM_RC.INTEGRITY, 1),
      `the outer HMAC over symIv || encSensitive || name is ${toHex(expected)} and the blob ` +
        `carries ${toHex(integrityOuter)}. The HMAC covers the object's Name, so a changed byte ` +
        'anywhere in the public area breaks it too — and this check runs before anything is ' +
        'decrypted.'
    );
  }

  // Part 4's UnwrapOuter checks integrity first, then requires symIv to be one
  // cipher block before decrypting. Keep that refusal inside the TPM result
  // model instead of letting the AES implementation throw on malformed input.
  if (iv.length !== AES_BLOCK) {
    return rcFail(
      rcParameter(TPM_RC.VALUE, 1),
      `symIv is ${iv.length} bytes; AES-128-CFB requires one ${AES_BLOCK}-byte block`
    );
  }

  const sensitive = unmarshalSensitive(cfb(storageKey(parent, name), iv).decrypt(encSensitive));
  if (!sensitive) {
    return rcFail(rcParameter(TPM_RC.SIZE, 1), 'the decrypted sensitive area does not unmarshal');
  }
  if (sensitive.sensitiveType !== TPM_ALG.KEYEDHASH) {
    return rcFail(
      rcParameter(TPM_RC.TYPE, 1),
      'the sensitive area declares a different type from the public area'
    );
  }
  if (!bytesEqual(keyedHashUnique(sensitive.seedValue, sensitive.data), pub.unique)) {
    return rcFail(
      rcParameter(TPM_RC.BINDING, 1),
      `the public area's unique is ${toHex(pub.unique)} and H(obfuscate || secret) over the ` +
        `sensitive area is ${toHex(keyedHashUnique(sensitive.seedValue, sensitive.data))}. The ` +
        'two halves of this object are not the same object.'
    );
  }

  return { ok: true, object: { publicArea, pub, name, sensitive } };
}

// ── TPM2_Unseal ─────────────────────────────────────────────────────────────

export interface UnsealAttempt {
  session: PolicySession;
  pcrUpdateCounter: number;
  sessionKind?: AuthorizationAttempt['sessionKind'];
}

/**
 * `TPM2_Unseal`. Part 3 §12.7.
 *
 * Note what this command does NOT contain: any mention of a policy. The
 * reference implementation's whole body is a type check, an attribute check
 * and a copy. The authorization is performed by the generic command-processing
 * layer first (Part 3 §5.6), on the strength of the `@itemHandle` decoration
 * and its Auth Role USER — which is why a sealed secret's protection is a
 * property of the SESSION rather than of the command, and why
 * `TPM_RC_POLICY_FAIL` and `TPM_RC_TYPE` come from two different places.
 */
export function tpm2Unseal(
  object: LoadedObject,
  attempt: UnsealAttempt
): TpmOutcome<{ outData: Uint8Array }> {
  const authorization = checkPolicyAuthorization(
    attempt.session,
    { authPolicy: object.pub.authPolicy, userWithAuth: object.pub.attributes.userWithAuth, nameAlg: object.pub.nameAlg },
    {
      commandCode: TPM_CC.Unseal,
      pcrUpdateCounter: attempt.pcrUpdateCounter,
      sessionKind: attempt.sessionKind ?? 'policy',
    }
  );
  if (!authorization.ok) return rcFail(authorization.rc, authorization.reason);

  if (object.sensitive.sensitiveType !== TPM_ALG.KEYEDHASH) {
    return rcFail(rcHandle(TPM_RC.TYPE, 1), 'itemHandle is not a KEYEDHASH data object');
  }
  if (object.pub.attributes.restricted || object.pub.attributes.decrypt || object.pub.attributes.sign) {
    return rcFail(
      rcHandle(TPM_RC.ATTRIBUTES, 1),
      'restricted, decrypt or sign is SET on itemHandle, so it is a key rather than sealed data'
    );
  }
  return { ok: true, outData: object.sensitive.data.slice() };
}
