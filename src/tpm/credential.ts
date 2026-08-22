/**
 * TPM2_MakeCredential and TPM2_ActivateCredential — the enrollment protocol
 * Act 7b turns on.
 *
 * The point of this act is a distinction people collapse constantly: the
 * Endorsement Key does NOT sign quotes. The standard EK templates have `sign`
 * CLEAR and `decrypt` + `restricted` SET — it is a restricted DECRYPTION key,
 * and asking it to sign returns TPM_RC_KEY. Its role is enrollment-time.
 *
 * What credential activation does:
 *
 *   1. A CA is given the EK public area and the candidate AK's PUBLIC AREA.
 *      It computes the AK's Name = nameAlg || H(TPMT_PUBLIC).
 *   2. It picks a secret, and derives a seed to an ECDH shared value with the
 *      EK's public point.
 *   3. It derives symKey = KDFa(seed, "STORAGE", akName) — the AK Name is the
 *      KDF context — and AES-128-CFB-encrypts the secret under it.
 *   4. It derives hmacKey = KDFa(seed, "INTEGRITY") and HMACs
 *      `encIdentity || akName`. The Name is therefore bound TWICE.
 *   5. Only a TPM holding the EK private key can recover the seed; and only
 *      with the AK whose Name was used can it pass the HMAC check.
 *
 * Returning the secret is the proof. And here is the sentence the whole act
 * exists for, from the TPM specification itself: "The credential provider
 * could have produced the credential with no information from the TPM as the
 * TPM did not need to provide a proof-of-possession of any private key in
 * order for the credential provider to create the credential."
 *
 * So an attacker holding the EK PRIVATE key does not forge a quote. They
 * submit a software-generated key whose TPMT_PUBLIC carries all the right
 * attribute bits — those are just bits in a structure the attacker marshals —
 * complete the challenge in software with the stolen EK key, and receive a
 * genuine AK certificate for a key whose private half lives in ordinary
 * memory. Every quote it then signs is cryptographically perfect.
 *
 * All the crypto here is real: real ECDH on P-256, real KDFa/KDFe, real
 * AES-128-CFB (from `@noble/ciphers`, a named audited implementation), real
 * HMAC-SHA-256. The one simplification is that the ephemeral key is derived
 * deterministically from a label rather than drawn from an RNG, so the page's
 * bytes are reproducible.
 */

import { cfb } from '@noble/ciphers/aes.js';
import { p256 } from '@noble/curves/nist.js';
import { bytesEqual, concatBytes, u16be } from '../core/bytes';
import { hmacSha256 } from '../core/hmac';
import { SHA256_LEN } from '../core/sha256';
import { kdfa, kdfe } from './kdf';
import { deterministicSecretKey, type TpmObject } from './key';

/** IV for the credential wrapper: CFB with an all-zero IV, per Part 1. */
const ZERO_IV = new Uint8Array(16);

export interface CredentialBlob {
  /** TPMS_ID_OBJECT.integrityHMAC. */
  integrityHmac: Uint8Array;
  /** TPMS_ID_OBJECT.encIdentity — the whole TPM2B_DIGEST is encrypted, size field included. */
  encIdentity: Uint8Array;
  /** TPM2B_ENCRYPTED_SECRET: the ephemeral public point, marshalled as a TPMS_ECC_POINT. */
  secret: Uint8Array;
}

/** Derived values, exposed so the UI can show the binding rather than assert it. */
export interface CredentialDerivation {
  z: Uint8Array;
  seed: Uint8Array;
  symKey: Uint8Array;
  hmacKey: Uint8Array;
  akName: Uint8Array;
}

function marshalEccPoint(x: Uint8Array, y: Uint8Array): Uint8Array {
  return concatBytes(u16be(x.length), x, u16be(y.length), y);
}

function unmarshalEccPoint(bytes: Uint8Array): { x: Uint8Array; y: Uint8Array } {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const xLen = view.getUint16(0, false);
  const x = bytes.slice(2, 2 + xLen);
  const yLen = view.getUint16(2 + xLen, false);
  const y = bytes.slice(4 + xLen, 4 + xLen + yLen);
  if (x.length !== xLen || y.length !== yLen) throw new Error('truncated TPMS_ECC_POINT');
  return { x, y };
}

/** Z is the X coordinate of the ECDH shared point; noble hands back a compressed point. */
function ecdhX(secretKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  return p256.getSharedSecret(secretKey, publicKey).slice(1, 33);
}

/**
 * TPM2_MakeCredential. Note what it does NOT take: any TPM secret, and any
 * authorization. The specification is explicit that this is "a convenience
 * function, using the TPM to perform cryptographic calculations that could be
 * done externally" — every input is public. That is mechanism 1 of Act 7b.
 */
export function makeCredential(
  ekPublic: Uint8Array,
  akName: Uint8Array,
  credential: Uint8Array,
  ephemeralLabel: string
): { blob: CredentialBlob; derivation: CredentialDerivation } {
  if (credential.length > SHA256_LEN) {
    throw new Error('credential must be no larger than the EK nameAlg digest (TPM_RC_SIZE)');
  }
  const ephemeralSecret = deterministicSecretKey(ephemeralLabel);
  const ephemeralPublic = p256.getPublicKey(ephemeralSecret, false);
  const ephemeralX = ephemeralPublic.slice(1, 33);
  const ephemeralY = ephemeralPublic.slice(33, 65);
  const ekX = ekPublic.slice(1, 33);

  const z = ecdhX(ephemeralSecret, ekPublic);
  // KDFe's PartyUInfo is the EPHEMERAL point's X, PartyVInfo the STATIC EK's X.
  const seed = kdfe(z, 'IDENTITY', ephemeralX, ekX, SHA256_LEN * 8);
  const symKey = kdfa(seed, 'STORAGE', akName, new Uint8Array(0), 128);
  const hmacKey = kdfa(seed, 'INTEGRITY', new Uint8Array(0), new Uint8Array(0), SHA256_LEN * 8);

  // "All of the encIdentity is encrypted, including the size field" — the
  // plaintext is a complete TPM2B_DIGEST, not a bare buffer.
  const plaintext = concatBytes(u16be(credential.length), credential);
  const encIdentity = cfb(symKey, ZERO_IV).encrypt(plaintext);
  const integrityHmac = hmacSha256(hmacKey, concatBytes(encIdentity, akName));

  return {
    blob: {
      integrityHmac,
      encIdentity,
      secret: marshalEccPoint(ephemeralX, ephemeralY),
    },
    derivation: { z, seed, symKey, hmacKey, akName },
  };
}

export type ActivateOutcome =
  | { ok: true; credential: Uint8Array; derivation: CredentialDerivation }
  | { ok: false; responseName: string; responseCode: number; reason: string };

/**
 * TPM2_ActivateCredential(activateHandle = the AK, keyHandle = the EK).
 *
 * The TPM recomputes the Name from the AK object ACTUALLY LOADED. That is the
 * residency proof: the credential is unreadable unless the same TPM holds both
 * the EK that recovers the seed and the AK whose Name keys the derivation.
 *
 * `TPM_RC_INTEGRITY` is what a real TPM returns when the HMAC does not match —
 * i.e. when the loaded AK is not the one the credential was made for.
 */
export function activateCredential(
  ak: TpmObject,
  ek: TpmObject,
  blob: CredentialBlob
): ActivateOutcome {
  if (!ek.pub.attributes.decrypt || !ek.pub.attributes.restricted) {
    return {
      ok: false,
      responseName: 'TPM_RC_TYPE',
      responseCode: 0x0000008a,
      reason: `${ek.label} is not a restricted decryption key`,
    };
  }
  let ephemeral: { x: Uint8Array; y: Uint8Array };
  try {
    ephemeral = unmarshalEccPoint(blob.secret);
  } catch {
    return {
      ok: false,
      responseName: 'TPM_RC_ECC_POINT',
      responseCode: 0x000000a7,
      reason: 'the encrypted secret is not a well-formed TPMS_ECC_POINT',
    };
  }
  const ephemeralPublic = concatBytes(new Uint8Array([0x04]), ephemeral.x, ephemeral.y);
  const ekX = ek.publicKey.slice(1, 33);

  const z = ecdhX(ek.secretKey, ephemeralPublic);
  const seed = kdfe(z, 'IDENTITY', ephemeral.x, ekX, SHA256_LEN * 8);
  const hmacKey = kdfa(seed, 'INTEGRITY', new Uint8Array(0), new Uint8Array(0), SHA256_LEN * 8);
  // The Name comes from the LOADED object, never from the blob.
  const akName = ak.name;
  const expected = hmacSha256(hmacKey, concatBytes(blob.encIdentity, akName));
  if (!bytesEqual(expected, blob.integrityHmac)) {
    return {
      ok: false,
      responseName: 'TPM_RC_INTEGRITY',
      responseCode: 0x0000009f,
      reason:
        'the identity HMAC does not match. The credential was made for a different object Name, ' +
        'so this TPM will not release it.',
    };
  }
  const symKey = kdfa(seed, 'STORAGE', akName, new Uint8Array(0), 128);
  const plaintext = cfb(symKey, ZERO_IV).decrypt(blob.encIdentity);
  const size = (plaintext[0] << 8) | plaintext[1];
  if (size + 2 !== plaintext.length) {
    return {
      ok: false,
      responseName: 'TPM_RC_SIZE',
      responseCode: 0x00000095,
      reason: 'the decrypted credential is not a well-formed TPM2B_DIGEST',
    };
  }
  return {
    ok: true,
    credential: plaintext.slice(2),
    derivation: { z, seed, symKey, hmacKey, akName },
  };
}

/**
 * The attacker's path: complete the challenge in SOFTWARE using a stolen EK
 * private key, for an AK that is not resident on any TPM.
 *
 * This is deliberately a separate function with an unmistakable name, and it
 * takes the EK's private key as an explicit argument, because the whole point
 * is that no TPM is involved. It performs exactly the same arithmetic as
 * `activateCredential` — which is the finding, not an implementation
 * shortcut.
 */
export function activateCredentialInSoftware(
  stolenEkSecretKey: Uint8Array,
  ekPublicKey: Uint8Array,
  akName: Uint8Array,
  blob: CredentialBlob
): { credential: Uint8Array; derivation: CredentialDerivation } {
  const ephemeral = unmarshalEccPoint(blob.secret);
  const ephemeralPublic = concatBytes(new Uint8Array([0x04]), ephemeral.x, ephemeral.y);
  const z = ecdhX(stolenEkSecretKey, ephemeralPublic);
  const seed = kdfe(z, 'IDENTITY', ephemeral.x, ekPublicKey.slice(1, 33), SHA256_LEN * 8);
  const symKey = kdfa(seed, 'STORAGE', akName, new Uint8Array(0), 128);
  const hmacKey = kdfa(seed, 'INTEGRITY', new Uint8Array(0), new Uint8Array(0), SHA256_LEN * 8);
  const plaintext = cfb(symKey, ZERO_IV).decrypt(blob.encIdentity);
  return {
    credential: plaintext.slice(2),
    derivation: { z, seed, symKey, hmacKey, akName },
  };
}
