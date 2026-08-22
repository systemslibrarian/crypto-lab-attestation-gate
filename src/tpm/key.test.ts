import { describe, expect, it } from 'vitest';
import { p256 } from '@noble/curves/nist.js';
import {
  attributesFromUint32,
  attributesToUint32,
  deterministicSecretKey,
  EK_AUTH_POLICY,
  hierarchyQualifiedName,
  makeAttestationKey,
  makeEndorsementKey,
  makeStorageRootKey,
  marshalPublic,
  setAttributes,
  signExternalData,
  ticketIsSafe,
  tpm2Hash,
  tpm2Sign,
  TPM_RC_TICKET_ON_SIGN,
  verifyOverDigest,
} from './key';
import { TPM_GENERATED_VALUE, TPM_RH } from './constants';
import { concatBytes, fromHex, toHex, u32be, utf8 } from '../core/bytes';
import { sha256 } from '../core/sha256';
import { computeName } from './marshal';

describe('ECDSA P-256 (RFC 6979 §A.2.5)', () => {
  // The deterministic-signature vectors from RFC 6979. They pin the exact
  // curve, hash and nonce derivation this lab signs with, which is what makes
  // every quote on the page reproducible rather than merely plausible.
  const SECRET = fromHex('c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721');
  const PUBLIC_X = '60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6';
  const PUBLIC_Y = '7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299';

  it('derives the published public key', () => {
    expect(toHex(p256.getPublicKey(SECRET, false))).toBe(`04${PUBLIC_X}${PUBLIC_Y}`);
  });

  it('reproduces the (r, s) published for the message "sample"', () => {
    const sig = p256.sign(sha256(utf8('sample')), SECRET, { lowS: false, prehash: false });
    expect(toHex(sig)).toBe(
      'efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716' +
        'f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8'
    );
  });

  it('reproduces the (r, s) published for the message "test"', () => {
    const sig = p256.sign(sha256(utf8('test')), SECRET, { lowS: false, prehash: false });
    expect(toHex(sig)).toBe(
      'f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367' +
        '019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083'
    );
  });

  it('the lab’s verifier accepts those published signatures', () => {
    const sig = p256.sign(sha256(utf8('sample')), SECRET, { lowS: false, prehash: false });
    expect(verifyOverDigest(p256.getPublicKey(SECRET, false), sha256(utf8('sample')), sig)).toBe(true);
  });
});

describe('TPMA_OBJECT', () => {
  it('marshals an attestation key to the well-known 0x00050072', () => {
    const ak = setAttributes(
      'fixedTPM',
      'fixedParent',
      'sensitiveDataOrigin',
      'userWithAuth',
      'restricted',
      'sign'
    );
    expect(attributesToUint32(ak).toString(16).padStart(8, '0')).toBe('00050072');
  });

  it('marshals the standard EK template to the well-known 0x000300b2', () => {
    const ek = setAttributes(
      'fixedTPM',
      'fixedParent',
      'sensitiveDataOrigin',
      'adminWithPolicy',
      'restricted',
      'decrypt'
    );
    expect(attributesToUint32(ek).toString(16).padStart(8, '0')).toBe('000300b2');
  });

  it('drops only the restricted bit to reach the unrestricted signer 0x00040072', () => {
    const unrestricted = setAttributes(
      'fixedTPM',
      'fixedParent',
      'sensitiveDataOrigin',
      'userWithAuth',
      'sign'
    );
    expect(attributesToUint32(unrestricted).toString(16).padStart(8, '0')).toBe('00040072');
  });

  it('round-trips every attribute through the UINT32', () => {
    for (const name of ['fixedTPM', 'stClear', 'noDA', 'restricted', 'decrypt', 'sign'] as const) {
      const a = setAttributes(name);
      expect(attributesFromUint32(attributesToUint32(a))[name]).toBe(true);
    }
  });
});

describe('The EK template’s well-known authPolicy', () => {
  it('is the TPM2_PolicySecret(TPM_RH_ENDORSEMENT) digest, derived here rather than trusted', () => {
    // Two PolicyUpdate steps with policyAlg = SHA-256:
    //   step1 = H(0x00*32 || TPM_CC_PolicySecret || Name(TPM_RH_ENDORSEMENT))
    //   step2 = H(step1 || policyRef)   with policyRef empty
    // Name(TPM_RH_ENDORSEMENT) is the bare handle: permanent handles have
    // Name := handle, with no hash.
    const TPM_CC_PolicySecret = 0x00000151;
    const step1 = sha256(
      concatBytes(new Uint8Array(32), u32be(TPM_CC_PolicySecret), u32be(TPM_RH.ENDORSEMENT))
    );
    const step2 = sha256(step1);
    expect(toHex(step2)).toBe(toHex(EK_AUTH_POLICY));
  });
});

describe('TPMT_PUBLIC and Names', () => {
  const ak = makeAttestationKey('test-ak', hierarchyQualifiedName(TPM_RH.OWNER));

  it('computes the Name as nameAlg || H(marshalled public area)', () => {
    expect(toHex(ak.name)).toBe(`000b${toHex(sha256(ak.publicArea))}`);
    expect(ak.name.length).toBe(34);
  });

  it('maps every marshalled byte of the public area to exactly one field', () => {
    const { bytes, fields } = marshalPublic(ak.pub);
    let at = 0;
    for (const f of fields) {
      expect(f.offset).toBe(at);
      expect(toHex(bytes.slice(f.offset, f.offset + f.length))).toBe(f.hex);
      at += f.length;
    }
    expect(at).toBe(bytes.length);
    expect(toHex(bytes)).toBe(toHex(ak.publicArea));
  });

  it('gives an EK a different Name from an AK even with the same key material', () => {
    const ek = makeEndorsementKey('same-label');
    const other = makeAttestationKey('same-label', hierarchyQualifiedName(TPM_RH.ENDORSEMENT));
    expect(toHex(ek.secretKey)).toBe(toHex(other.secretKey));
    // Same scalar, different public AREA -- so a different Name. The Name is
    // over the whole template, attributes included, not over the key.
    expect(toHex(ek.name)).not.toBe(toHex(other.name));
  });

  it('folds the parent and the hierarchy into the Qualified Name', () => {
    const srk = makeStorageRootKey('test-srk');
    const underSrk = makeAttestationKey('test-ak', srk.qualifiedName);
    const underOwner = makeAttestationKey('test-ak', hierarchyQualifiedName(TPM_RH.OWNER));
    expect(toHex(underSrk.name)).toBe(toHex(underOwner.name));
    expect(toHex(underSrk.qualifiedName)).not.toBe(toHex(underOwner.qualifiedName));
  });

  it('gives a permanent handle a four-byte Name with no hash', () => {
    expect(toHex(hierarchyQualifiedName(TPM_RH.ENDORSEMENT))).toBe('4000000b');
    expect(hierarchyQualifiedName(TPM_RH.OWNER).length).toBe(4);
  });

  it('derives deterministic keys, in range, that do not collide across labels', () => {
    const n = p256.Point.Fn.ORDER;
    const seen = new Set<string>();
    for (const label of ['a', 'b', 'ak/A7', 'ek/A7', 'srk/A7']) {
      const k = deterministicSecretKey(label);
      const v = BigInt(`0x${toHex(k)}`);
      expect(v).toBeGreaterThanOrEqual(1n);
      expect(v).toBeLessThan(n);
      expect(seen.has(toHex(k))).toBe(false);
      seen.add(toHex(k));
      expect(toHex(deterministicSecretKey(label))).toBe(toHex(k));
    }
  });

  it('recomputes the same Name from the public area alone, as a verifier must', () => {
    expect(toHex(computeName(ak.publicArea))).toBe(toHex(ak.name));
  });
});

describe('The restricted signing rule (Act 2a)', () => {
  const parent = hierarchyQualifiedName(TPM_RH.OWNER);
  const restricted = makeAttestationKey('restricted-ak', parent, true);
  const unrestricted = makeAttestationKey('restricted-ak', parent, false);
  const magic = u32be(TPM_GENERATED_VALUE);

  it('TicketIsSafe refuses exactly the four magic octets at offset 0', () => {
    expect(ticketIsSafe(concatBytes(magic, utf8('anything')))).toBe(false);
    expect(ticketIsSafe(magic)).toBe(false);
    // One bit different anywhere in those four octets and it is ordinary data.
    const nearly = concatBytes(magic, utf8('x'));
    nearly[3] ^= 0x01;
    expect(ticketIsSafe(nearly)).toBe(true);
    // The magic later in the buffer is not the magic at offset 0.
    expect(ticketIsSafe(concatBytes(utf8('x'), magic))).toBe(true);
  });

  it('treats a buffer shorter than the magic as unsafe', () => {
    expect(ticketIsSafe(new Uint8Array([0xff, 0x54, 0x43]))).toBe(false);
    expect(ticketIsSafe(new Uint8Array(0))).toBe(false);
  });

  it('TPM2_Hash returns a NULL ticket — not an error — for magic-prefixed data', () => {
    const r = tpm2Hash(concatBytes(magic, utf8('a forged quote')));
    expect(toHex(r.digest)).toBe(toHex(sha256(concatBytes(magic, utf8('a forged quote')))));
    expect(r.ticket.hierarchy).toBe(TPM_RH.NULL);
    expect(r.ticket.digest.length).toBe(0);
    expect(r.refusal).toMatch(/TPM_GENERATED_VALUE/);
  });

  it('TPM2_Hash vouches for ordinary external data', () => {
    const r = tpm2Hash(utf8('an ordinary message'));
    expect(r.ticket.hierarchy).not.toBe(TPM_RH.NULL);
    expect(r.refusal).toBeUndefined();
  });

  it('a RESTRICTED key refuses to sign a forged attestation, with TPM_RC_TICKET', () => {
    const forged = concatBytes(magic, utf8('...a structure shaped exactly like a quote'));
    const outcome = signExternalData(restricted, forged);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) throw new Error('unreachable');
    expect(outcome.responseName).toBe('TPM_RC_TICKET');
    expect(outcome.responseCode).toBe(TPM_RC_TICKET_ON_SIGN);
  });

  it('the same RESTRICTED key signs the same bytes once the magic is gone', () => {
    const notAnAttestation = utf8('please sign this certificate request');
    const outcome = signExternalData(restricted, notAnAttestation);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) throw new Error('unreachable');
    expect(verifyOverDigest(restricted.publicKey, sha256(notAnAttestation), outcome.signature)).toBe(
      true
    );
  });

  it('an UNRESTRICTED key signs the forgery, and the forgery verifies', () => {
    const forged = concatBytes(magic, utf8('...a structure shaped exactly like a quote'));
    const outcome = signExternalData(unrestricted, forged);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) throw new Error('unreachable');
    expect(verifyOverDigest(unrestricted.publicKey, sha256(forged), outcome.signature)).toBe(true);
  });

  it('refuses on the ticket, not on the key — a NULL ticket blocks a restricted key directly', () => {
    const digest = sha256(utf8('anything'));
    expect(tpm2Sign(restricted, digest, { hierarchy: TPM_RH.NULL, digest: new Uint8Array(0) }).ok).toBe(
      false
    );
    expect(tpm2Sign(restricted, digest, { hierarchy: TPM_RH.OWNER, digest }).ok).toBe(true);
    // An unrestricted key needs no ticket at all.
    expect(
      tpm2Sign(unrestricted, digest, { hierarchy: TPM_RH.NULL, digest: new Uint8Array(0) }).ok
    ).toBe(true);
  });

  it('an endorsement key cannot sign anything — TPM_RC_KEY, not a ticket problem', () => {
    const ek = makeEndorsementKey('test-ek');
    const outcome = tpm2Sign(ek, sha256(utf8('x')), { hierarchy: TPM_RH.OWNER, digest: sha256(utf8('x')) });
    expect(outcome.ok).toBe(false);
    if (outcome.ok) throw new Error('unreachable');
    expect(outcome.responseName).toBe('TPM_RC_KEY');
    expect(ek.pub.attributes.sign).toBe(false);
    expect(ek.pub.attributes.decrypt).toBe(true);
    expect(ek.pub.attributes.restricted).toBe(true);
  });
});
