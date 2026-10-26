import { describe, expect, it } from 'vitest';
import { sha256 as nobleSha256 } from '@noble/hashes/sha2.js';
import { hmac as nobleHmac } from '@noble/hashes/hmac.js';
import { cfb as nobleCfb } from '@noble/ciphers/aes.js';
import { concatBytes, toHex, u16be, utf8 } from '../core/bytes';
import { sha256, SHA256_LEN } from '../core/sha256';
import { TPM_ALG } from './constants';
import { attributesToUint32, setAttributes } from './key';
import { computeName } from './marshal';
import { startPolicySession, TPM_CC, policyCommandCode } from './policy';
import {
  integrityKey,
  keyedHashUnique,
  marshalSealedPublic,
  marshalSensitive,
  outerHmac,
  sealObject,
  sealedAttributes,
  storageKey,
  tpm2Load,
  tpm2Unseal,
  SRK_SYM_BITS,
  type LoadedObject,
  type StorageParent,
} from './seal';

/**
 * The sealed-object format, checked against an independent re-implementation.
 *
 * `refKdfa` below is SP 800-108 counter mode written from TPM 2.0 Part 1's
 * own description using `@noble/hashes`, so the STORAGE and INTEGRITY
 * derivations are compared against a second implementation rather than
 * against themselves. The same applies to the outer HMAC and to CFB
 * decryption: the sensitive area is recovered here with `@noble/ciphers`
 * directly, so a bug in this module's wrapping would show up as a failure to
 * recover the plaintext rather than as two agreeing errors.
 */

const cat = (...parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
};
const be32 = (v: number): Uint8Array =>
  new Uint8Array([(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff]);

/** KDFa, re-derived: K(i) = HMAC(key, [i]32 || Label || 00 || Context || [L]32). */
function refKdfa(key: Uint8Array, label: string, contextU: Uint8Array, contextV: Uint8Array, bits: number): Uint8Array {
  const tail = cat(utf8(label), new Uint8Array([0]), contextU, contextV, be32(bits));
  const blocks: Uint8Array[] = [];
  const needed = Math.ceil(bits / 8);
  for (let i = 1; blocks.length * 32 < needed; i++) blocks.push(nobleHmac(nobleSha256, key, cat(be32(i), tail)));
  return cat(...blocks).slice(0, needed);
}

const PARENT: StorageParent = {
  label: 'test SRK',
  nameAlg: TPM_ALG.SHA256,
  seedValue: nobleSha256(utf8('a storage parent seed')),
};
const OBFUSCATE = nobleSha256(utf8('an obfuscation value'));
const IV = nobleSha256(utf8('an iv')).slice(0, 16);
const SECRET = utf8('a sealed fixture value');
const POLICY = nobleSha256(utf8('an authPolicy'));

const seal = () =>
  sealObject({ parent: PARENT, secret: SECRET, authPolicy: POLICY, obfuscate: OBFUSCATE, iv: IV });

describe('the TPMT_PUBLIC of a sealed data object', () => {
  const { pub, publicArea, publicFields, name } = seal();

  it('marshals the fields of Table 211 in order, with no gaps and no overlaps', () => {
    expect(publicFields.map((f) => f.path)).toEqual([
      'type',
      'nameAlg',
      'objectAttributes',
      'authPolicy.size',
      'authPolicy.buffer',
      'parameters.scheme.scheme',
      'unique.size',
      'unique.buffer',
    ]);
    let at = 0;
    for (const field of publicFields) {
      expect(field.offset, field.path).toBe(at);
      expect(field.hex, field.path).toBe(toHex(publicArea.slice(at, at + field.length)));
      at += field.length;
    }
    expect(at).toBe(publicArea.length);
  });

  it('is 2 + 2 + 4 + (2 + 32) + 2 + (2 + 32) = 78 bytes', () => {
    expect(publicArea.length).toBe(78);
  });

  it('declares TPM_ALG_KEYEDHASH and a NULL scheme', () => {
    expect(toHex(publicArea.slice(0, 2))).toBe('0008');
    expect(toHex(publicArea.slice(2, 4))).toBe('000b');
    // type(2) + nameAlg(2) + objectAttributes(4) = 8, then the 34-byte
    // authPolicy TPM2B, so parameters.scheme starts at offset 42 and
    // unique.size at 44.
    expect(toHex(publicArea.slice(42, 44))).toBe('0010');
    expect(toHex(publicArea.slice(44, 46))).toBe('0020');
  });

  it('has userWithAuth CLEAR, which is what forces a policy session', () => {
    expect(pub.attributes.userWithAuth).toBe(false);
    expect(pub.attributes.adminWithPolicy).toBe(false);
    expect(pub.attributes.sign).toBe(false);
    expect(pub.attributes.decrypt).toBe(false);
    expect(pub.attributes.restricted).toBe(false);
    expect(pub.attributes.sensitiveDataOrigin).toBe(false);
    expect(pub.attributes.fixedTPM).toBe(true);
    expect(pub.attributes.fixedParent).toBe(true);
    // fixedTPM | fixedParent | noDA = 0x02 | 0x10 | 0x400.
    expect(attributesToUint32(sealedAttributes())).toBe(0x00000412);
    expect(toHex(publicArea.slice(4, 8))).toBe('00000412');
  });

  it('computes the Name as nameAlg || H(publicArea)', () => {
    expect(toHex(name)).toBe(`000b${toHex(nobleSha256(publicArea))}`);
    expect(name.length).toBe(34);
    expect(toHex(name)).toBe(toHex(computeName(publicArea)));
  });

  it('carries unique = H(obfuscate || secret), not H(secret)', () => {
    expect(toHex(pub.unique)).toBe(toHex(nobleSha256(cat(OBFUSCATE, SECRET))));
    expect(toHex(pub.unique)).not.toBe(toHex(nobleSha256(SECRET)));
    expect(toHex(pub.unique)).toBe(toHex(keyedHashUnique(OBFUSCATE, SECRET)));
  });

  it('marshals an Empty Policy as a zero-length TPM2B and nothing else', () => {
    // Part 2 §12.2.4: "This is the Empty Policy if no authorization policy is
    // present." Such an object could be authorized without any policy at all,
    // which is exactly what this lesson's object must not be.
    const empty = marshalSealedPublic({
      nameAlg: TPM_ALG.SHA256,
      attributes: sealedAttributes(),
      authPolicy: new Uint8Array(0),
      unique: keyedHashUnique(OBFUSCATE, SECRET),
    });
    expect(empty.bytes.length).toBe(78 - 32);
    expect(toHex(empty.bytes.slice(8, 10))).toBe('0000');
    expect(toHex(empty.bytes.slice(10, 12))).toBe('0010');
  });

  it('moves the Name when any public byte moves', () => {
    const other = sealObject({
      parent: PARENT,
      secret: SECRET,
      authPolicy: nobleSha256(utf8('a different authPolicy')),
      obfuscate: OBFUSCATE,
      iv: IV,
    });
    expect(toHex(other.name)).not.toBe(toHex(name));
  });
});

describe('the protected private blob', () => {
  const object = seal();

  it('derives symKey from the parent seed AND the object Name', () => {
    expect(toHex(storageKey(PARENT, object.name))).toBe(
      toHex(refKdfa(PARENT.seedValue, 'STORAGE', object.name, new Uint8Array(0), SRK_SYM_BITS))
    );
    expect(storageKey(PARENT, object.name).length).toBe(16);
    // A different Name is a different key, which is the whole reason the
    // public area cannot be edited independently of the private blob.
    expect(toHex(storageKey(PARENT, object.name))).not.toBe(
      toHex(storageKey(PARENT, nobleSha256(utf8('a different name'))))
    );
  });

  it('derives HMACkey from the parent seed alone, with no context', () => {
    expect(toHex(integrityKey(PARENT))).toBe(
      toHex(refKdfa(PARENT.seedValue, 'INTEGRITY', new Uint8Array(0), new Uint8Array(0), 256))
    );
    expect(integrityKey(PARENT).length).toBe(32);
  });

  it('is TPM2B_DIGEST(outerHMAC) || TPM2B_IV(symIv) || encSensitive', () => {
    const { priv, parts } = object;
    expect(toHex(priv.slice(0, 2))).toBe('0020');
    expect(toHex(priv.slice(2, 34))).toBe(toHex(parts.integrityOuter));
    expect(toHex(priv.slice(34, 36))).toBe('0010');
    expect(toHex(priv.slice(36, 52))).toBe(toHex(IV));
    expect(toHex(priv.slice(52))).toBe(toHex(parts.encSensitive));
  });

  it('HMACs the marshalled IV, the ciphertext and the Name with no size field', () => {
    const expected = nobleHmac(
      nobleSha256,
      refKdfa(PARENT.seedValue, 'INTEGRITY', new Uint8Array(0), new Uint8Array(0), 256),
      cat(u16be(IV.length), IV, object.parts.encSensitive, object.name)
    );
    expect(toHex(object.parts.integrityOuter)).toBe(toHex(expected));
    expect(toHex(object.parts.integrityOuter)).toBe(
      toHex(outerHmac(PARENT, IV, object.parts.encSensitive, object.name))
    );
  });

  it('encrypts the whole TPM2B_SENSITIVE, size field included, and nothing else', () => {
    const sensitive = marshalSensitive({
      sensitiveType: TPM_ALG.KEYEDHASH,
      authValue: new Uint8Array(0),
      seedValue: OBFUSCATE,
      data: SECRET,
    });
    expect(object.parts.encSensitive.length).toBe(sensitive.length);
    // Recovered with an independent CFB implementation.
    const recovered = nobleCfb(
      refKdfa(PARENT.seedValue, 'STORAGE', object.name, new Uint8Array(0), SRK_SYM_BITS),
      IV
    ).decrypt(object.parts.encSensitive);
    expect(toHex(recovered)).toBe(toHex(sensitive));
  });

  it('marshals TPMT_SENSITIVE in Table 216 order', () => {
    const sensitive = marshalSensitive({
      sensitiveType: TPM_ALG.KEYEDHASH,
      authValue: new Uint8Array(0),
      seedValue: OBFUSCATE,
      data: SECRET,
    });
    // outer size | sensitiveType | authValue (empty) | seedValue | data
    expect(toHex(sensitive.slice(0, 2))).toBe(toHex(u16be(sensitive.length - 2)));
    expect(toHex(sensitive.slice(2, 4))).toBe('0008');
    expect(toHex(sensitive.slice(4, 6))).toBe('0000');
    expect(toHex(sensitive.slice(6, 8))).toBe('0020');
    expect(toHex(sensitive.slice(8, 40))).toBe(toHex(OBFUSCATE));
    expect(toHex(sensitive.slice(40, 42))).toBe(toHex(u16be(SECRET.length)));
    expect(toHex(sensitive.slice(42))).toBe(toHex(SECRET));
  });

  it('never puts the plaintext in the public area or the ciphertext', () => {
    expect(toHex(object.publicArea)).not.toContain(toHex(SECRET));
    expect(toHex(object.priv)).not.toContain(toHex(SECRET));
  });

  it('is byte-identical on a second seal of the same inputs', () => {
    expect(toHex(seal().priv)).toBe(toHex(object.priv));
    expect(toHex(seal().publicArea)).toBe(toHex(object.publicArea));
  });

  it('refuses to seal an empty secret', () => {
    expect(() =>
      sealObject({ parent: PARENT, secret: new Uint8Array(0), authPolicy: POLICY, obfuscate: OBFUSCATE, iv: IV })
    ).toThrow(/non-empty/);
  });

  it('refuses an obfuscation value or an IV of the wrong size', () => {
    // `seedValue shall be the size of the digest produced by the nameAlg of
    // the object` (Part 2 §12.3.2.4), and symIv is one cipher block.
    expect(() =>
      sealObject({
        parent: PARENT,
        secret: SECRET,
        authPolicy: POLICY,
        obfuscate: OBFUSCATE.slice(0, 16),
        iv: IV,
      })
    ).toThrow(/obfuscation value/);
    expect(() =>
      sealObject({
        parent: PARENT,
        secret: SECRET,
        authPolicy: POLICY,
        obfuscate: OBFUSCATE,
        iv: IV.slice(0, 8),
      })
    ).toThrow(/one AES block/);
  });
});

describe('TPM2_Load', () => {
  const object = seal();

  it('accepts an intact object and recovers the sensitive area', () => {
    const loaded = tpm2Load(PARENT, object.publicArea, object.priv);
    expect(loaded.ok).toBe(true);
    if (!loaded.ok) return;
    expect(toHex(loaded.object.sensitive.data)).toBe(toHex(SECRET));
    expect(toHex(loaded.object.sensitive.seedValue)).toBe(toHex(OBFUSCATE));
    expect(toHex(loaded.object.name)).toBe(toHex(object.name));
  });

  it('refuses one changed bit of the public area with TPM_RC_INTEGRITY', () => {
    const tampered = object.publicArea.slice();
    tampered[10] ^= 0x01;
    const loaded = tpm2Load(PARENT, tampered, object.priv);
    expect(loaded.ok).toBe(false);
    if (loaded.ok) return;
    expect(loaded.rcName).toBe('TPM_RC_INTEGRITY');
    expect(loaded.rcNote).toContain('TPM_RC_P');
  });

  it('refuses one changed bit of the ciphertext with TPM_RC_INTEGRITY, before decrypting', () => {
    const tampered = object.priv.slice();
    tampered[60] ^= 0x01;
    const loaded = tpm2Load(PARENT, object.publicArea, tampered);
    expect(loaded.ok).toBe(false);
    if (!loaded.ok) expect(loaded.rcName).toBe('TPM_RC_INTEGRITY');
  });

  it('refuses a re-wrapped substitute secret with TPM_RC_BINDING, not TPM_RC_INTEGRITY', () => {
    // Only possible for a holder of the parent seed. The HMAC is correct and
    // the object still fails, on `unique`.
    const substitute = marshalSensitive({
      sensitiveType: TPM_ALG.KEYEDHASH,
      authValue: new Uint8Array(0),
      seedValue: OBFUSCATE,
      data: utf8('an attacker-chosen value'),
    });
    const enc = nobleCfb(storageKey(PARENT, object.name), IV).encrypt(substitute);
    const priv = concatBytes(
      u16be(SHA256_LEN),
      outerHmac(PARENT, IV, enc, object.name),
      u16be(IV.length),
      IV,
      enc
    );
    const loaded = tpm2Load(PARENT, object.publicArea, priv);
    expect(loaded.ok).toBe(false);
    if (!loaded.ok) expect(loaded.rcName).toBe('TPM_RC_BINDING');
  });

  it('refuses an empty private area', () => {
    const loaded = tpm2Load(PARENT, object.publicArea, new Uint8Array(0));
    expect(loaded.ok).toBe(false);
    if (!loaded.ok) expect(loaded.rcName).toBe('TPM_RC_SIZE');
  });

  it('refuses a public area with sign or decrypt SET', () => {
    const signing = sealObject({
      parent: PARENT,
      secret: SECRET,
      authPolicy: POLICY,
      obfuscate: OBFUSCATE,
      iv: IV,
      attributes: setAttributes('fixedTPM', 'fixedParent', 'noDA', 'sign'),
    });
    const loaded = tpm2Load(PARENT, signing.publicArea, signing.priv);
    expect(loaded.ok).toBe(false);
    if (!loaded.ok) expect(loaded.rcName).toBe('TPM_RC_ATTRIBUTES');
  });

  it('refuses a public area that does not unmarshal as a KEYEDHASH TPMT_PUBLIC', () => {
    const loaded = tpm2Load(PARENT, object.publicArea.slice(0, 12), object.priv);
    expect(loaded.ok).toBe(false);
    if (!loaded.ok) {
      expect(loaded.rcName).toBe('TPM_RC_SIZE');
      expect(loaded.rcNote).toContain('parameter 2');
    }
  });

  it('refuses a sensitive area that declares a different type from the public one', () => {
    // Reachable only by someone holding the parent seed, which is the same
    // assumption as the binding case: the blob's HMAC is valid and the two
    // halves still disagree.
    const wrongType = marshalSensitive({
      sensitiveType: TPM_ALG.ECC,
      authValue: new Uint8Array(0),
      seedValue: OBFUSCATE,
      data: SECRET,
    });
    const enc = nobleCfb(storageKey(PARENT, object.name), IV).encrypt(wrongType);
    const priv = concatBytes(
      u16be(SHA256_LEN),
      outerHmac(PARENT, IV, enc, object.name),
      u16be(IV.length),
      IV,
      enc
    );
    const loaded = tpm2Load(PARENT, object.publicArea, priv);
    expect(loaded.ok).toBe(false);
    if (!loaded.ok) expect(loaded.rcName).toBe('TPM_RC_TYPE');
  });

  it('refuses a sensitive area that does not unmarshal at all', () => {
    const rubbish = new Uint8Array(48).fill(0xa5);
    const enc = nobleCfb(storageKey(PARENT, object.name), IV).encrypt(rubbish);
    const priv = concatBytes(
      u16be(SHA256_LEN),
      outerHmac(PARENT, IV, enc, object.name),
      u16be(IV.length),
      IV,
      enc
    );
    const loaded = tpm2Load(PARENT, object.publicArea, priv);
    expect(loaded.ok).toBe(false);
    if (!loaded.ok) expect(loaded.rcName).toBe('TPM_RC_SIZE');
  });

  it('refuses the same blob under a different storage parent', () => {
    const other: StorageParent = { ...PARENT, seedValue: nobleSha256(utf8('a different seed')) };
    const loaded = tpm2Load(other, object.publicArea, object.priv);
    expect(loaded.ok).toBe(false);
    if (!loaded.ok) expect(loaded.rcName).toBe('TPM_RC_INTEGRITY');
  });
});

describe('TPM2_Unseal', () => {
  const object = seal();
  const loaded = tpm2Load(PARENT, object.publicArea, object.priv);
  if (!loaded.ok) throw new Error('fixture failed to load');

  /** A satisfied policy session for this object. */
  const satisfied = () => {
    const session = startPolicySession();
    session.policyDigest = POLICY.slice();
    session.commandCode = TPM_CC.Unseal;
    return session;
  };

  it('returns outData when the policy session reached the authPolicy', () => {
    const out = tpm2Unseal(loaded.object, { session: satisfied(), pcrUpdateCounter: 3 });
    expect(out.ok).toBe(true);
    if (out.ok) expect(toHex(out.outData)).toBe(toHex(SECRET));
  });

  it('returns a copy, so a caller cannot mutate the loaded object', () => {
    const out = tpm2Unseal(loaded.object, { session: satisfied(), pcrUpdateCounter: 3 });
    if (!out.ok) throw new Error('unexpected refusal');
    out.outData[0] ^= 0xff;
    expect(toHex(loaded.object.sensitive.data)).toBe(toHex(SECRET));
  });

  it('refuses when the session digest differs from the authPolicy', () => {
    const session = startPolicySession();
    session.policyDigest = nobleSha256(utf8('a different policy'));
    session.commandCode = TPM_CC.Unseal;
    const out = tpm2Unseal(loaded.object, { session, pcrUpdateCounter: 3 });
    expect(out.ok).toBe(false);
    if (!out.ok) {
      expect(out.rcName).toBe('TPM_RC_POLICY_FAIL');
      expect(out.rcNote).toContain('session 1');
    }
  });

  it('refuses a session restricted to a different command', () => {
    const session = startPolicySession();
    session.policyDigest = POLICY.slice();
    const restricted = policyCommandCode(session, TPM_CC.Quote);
    expect(restricted.ok).toBe(true);
    // The command-code assertion also moved the digest, so set it back: the
    // point under test is the commandCode pin, not the digest.
    session.policyDigest = POLICY.slice();
    const out = tpm2Unseal(loaded.object, { session, pcrUpdateCounter: 3 });
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.rcName).toBe('TPM_RC_POLICY_CC');
  });

  it('refuses a password where the object requires a policy', () => {
    const out = tpm2Unseal(loaded.object, {
      session: satisfied(),
      pcrUpdateCounter: 3,
      sessionKind: 'hmac-or-password',
    });
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.rcName).toBe('TPM_RC_POLICY_FAIL');
  });

  it('returns TPM_RC_TYPE for an object whose sensitive area is not KEYEDHASH', () => {
    const wrongType: LoadedObject = {
      ...loaded.object,
      sensitive: { ...loaded.object.sensitive, sensitiveType: TPM_ALG.ECC },
    };
    const out = tpm2Unseal(wrongType, { session: satisfied(), pcrUpdateCounter: 3 });
    expect(out.ok).toBe(false);
    if (!out.ok) {
      expect(out.rcName).toBe('TPM_RC_TYPE');
      expect(out.rcNote).toContain('handle 1');
    }
  });

  it('returns TPM_RC_ATTRIBUTES for an itemHandle with restricted, decrypt or sign SET', () => {
    for (const attribute of ['restricted', 'decrypt', 'sign'] as const) {
      const object2: LoadedObject = {
        ...loaded.object,
        pub: {
          ...loaded.object.pub,
          attributes: { ...loaded.object.pub.attributes, [attribute]: true },
        },
      };
      const out = tpm2Unseal(object2, { session: satisfied(), pcrUpdateCounter: 3 });
      expect(out.ok, attribute).toBe(false);
      if (!out.ok) expect(out.rcName, attribute).toBe('TPM_RC_ATTRIBUTES');
    }
  });
});

describe('the sha256 these tests check against', () => {
  it('agrees with this repo’s hand-rolled implementation', () => {
    expect(toHex(sha256(utf8('abc')))).toBe(toHex(nobleSha256(utf8('abc'))));
  });
});
