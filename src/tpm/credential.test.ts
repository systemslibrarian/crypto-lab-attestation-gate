import { describe, expect, it } from 'vitest';
import { cfb } from '@noble/ciphers/aes.js';
import {
  activateCredential,
  activateCredentialInSoftware,
  makeCredential,
} from './credential';
import { hierarchyQualifiedName, makeAttestationKey, makeEndorsementKey } from './key';
import { TPM_RH } from './constants';
import { fromHex, toHex, utf8 } from '../core/bytes';
import { sha256 } from '../core/sha256';
import { hmacSha256 } from '../core/hmac';
import { kdfa, kdfe, kdfLabel } from './kdf';

describe('AES-128-CFB (NIST SP 800-38A F.3.13)', () => {
  // The credential wrapper is CFB128. These are the published vectors for the
  // mode, so the encryption inside credential activation is pinned to the
  // standard rather than to itself.
  it('reproduces the published CFB128-AES128 encryption', () => {
    const key = fromHex('2b7e151628aed2a6abf7158809cf4f3c');
    const iv = fromHex('000102030405060708090a0b0c0d0e0f');
    const plaintext = fromHex(
      '6bc1bee22e409f96e93d7e117393172a' +
        'ae2d8a571e03ac9c9eb76fac45af8e51' +
        '30c81c46a35ce411e5fbc1191a0a52ef' +
        'f69f2445df4f9b17ad2b417be66c3710'
    );
    expect(toHex(cfb(key, iv).encrypt(plaintext))).toBe(
      '3b3fd92eb72dad20333449f8e83cfb4a' +
        'c8a64537a0b3a93fcde3cdad9f1ce58b' +
        '26751f67a3cbb140b1808cf187a4f4df' +
        'c04b05357c5d1c0eeac4c66f9ff7f2e6'
    );
  });

  it('round-trips a partial final block, which the TPM2B plaintext always is', () => {
    const key = fromHex('2b7e151628aed2a6abf7158809cf4f3c');
    const iv = new Uint8Array(16);
    const pt = fromHex('0020' + '11'.repeat(32));
    expect(toHex(cfb(key, iv).decrypt(cfb(key, iv).encrypt(pt)))).toBe(toHex(pt));
  });
});

describe('TPM KDFs', () => {
  it('null-terminates labels — "IDENTITY" is nine octets, not eight', () => {
    expect(toHex(kdfLabel('IDENTITY'))).toBe('4944454e5449545900');
    expect(toHex(kdfLabel('STORAGE'))).toBe('53544f5241474500');
    expect(toHex(kdfLabel('INTEGRITY'))).toBe('494e54454752495459' + '00');
  });

  it('KDFa is SP 800-108 counter mode: the counter, label, context and bit length', () => {
    // Re-derived here by a different route than the implementation takes,
    // spelling out the concatenation the spec gives rather than reusing the
    // helper's own assembly.
    const key = sha256(utf8('seed'));
    const contextU = utf8('ctxU');
    const contextV = utf8('ctxV');
    const out = kdfa(key, 'STORAGE', contextU, contextV, 128);
    const manual = new Uint8Array([
      0, 0, 0, 1,
      ...kdfLabel('STORAGE'),
      ...contextU,
      ...contextV,
      0, 0, 0, 128,
    ]);
    // HMAC-SHA-256 of that block, truncated to 16 bytes.
    expect(toHex(out)).toBe(toHex(hmacSha256(key, manual).slice(0, 16)));
  });

  it('KDFa masks, rather than shifts, when bits is not a byte multiple', () => {
    // The spec masks the unused HIGH-ORDER bits of the first octet off. Note
    // the derived bytes are NOT a prefix of the 16-bit derivation: the bit
    // count L is itself an input to the HMAC, so asking for fewer bits gives a
    // different stream. What is observable, and what the spec fixes, is the
    // width and the cleared bits.
    const key = sha256(utf8('seed'));
    for (const [bits, keptBits] of [
      [12, 4],
      [17, 1],
      [1, 1],
      [255, 7],
    ] as const) {
      const out = kdfa(key, 'X', new Uint8Array(0), new Uint8Array(0), bits);
      expect(out.length, `${bits} bits`).toBe(Math.ceil(bits / 8));
      expect(out[0] >> keptBits, `${bits} bits: high-order bits cleared`).toBe(0);
    }
  });

  it('KDFe is the SP 800-56A concatenation KDF with a big-endian counter', () => {
    const z = sha256(utf8('z'));
    const u = utf8('U');
    const v = utf8('V');
    const out = kdfe(z, 'IDENTITY', u, v, 256);
    const manual = sha256(
      new Uint8Array([0, 0, 0, 1, ...z, ...kdfLabel('IDENTITY'), ...u, ...v])
    );
    expect(toHex(out)).toBe(toHex(manual));
  });

  it('produces more than one block when asked for more than a digest', () => {
    const key = sha256(utf8('seed'));
    expect(kdfa(key, 'X', new Uint8Array(0), new Uint8Array(0), 512).length).toBe(64);
    expect(kdfe(key, 'X', new Uint8Array(0), new Uint8Array(0), 512).length).toBe(64);
  });
});

describe('Credential activation (TPM2_MakeCredential / TPM2_ActivateCredential)', () => {
  const parent = hierarchyQualifiedName(TPM_RH.OWNER);
  const ek = makeEndorsementKey('ek/device-1');
  const ak = makeAttestationKey('ak/device-1', parent);
  const secret = sha256(utf8('the CA’s challenge'));

  it('releases the credential to the TPM holding both the EK and that AK', () => {
    const { blob } = makeCredential(ek.publicKey, ak.name, secret, 'eph/1');
    const out = activateCredential(ak, ek, blob);
    expect(out.ok).toBe(true);
    if (!out.ok) throw new Error('unreachable');
    expect(toHex(out.credential)).toBe(toHex(secret));
  });

  it('refuses when a DIFFERENT attestation key is loaded — TPM_RC_INTEGRITY', () => {
    const other = makeAttestationKey('ak/device-1-sibling', parent);
    const { blob } = makeCredential(ek.publicKey, ak.name, secret, 'eph/1');
    const out = activateCredential(other, ek, blob);
    expect(out.ok).toBe(false);
    if (out.ok) throw new Error('unreachable');
    expect(out.responseName).toBe('TPM_RC_INTEGRITY');
  });

  it('refuses when a different EK is loaded — the seed never comes back', () => {
    const otherEk = makeEndorsementKey('ek/device-2');
    const { blob } = makeCredential(ek.publicKey, ak.name, secret, 'eph/1');
    const out = activateCredential(ak, otherEk, blob);
    expect(out.ok).toBe(false);
  });

  it('binds the AK Name TWICE — one flipped bit in encIdentity is caught', () => {
    const { blob } = makeCredential(ek.publicKey, ak.name, secret, 'eph/1');
    const tampered = { ...blob, encIdentity: blob.encIdentity.slice() };
    tampered.encIdentity[0] ^= 0x01;
    const out = activateCredential(ak, ek, tampered);
    expect(out.ok).toBe(false);
    if (out.ok) throw new Error('unreachable');
    expect(out.responseName).toBe('TPM_RC_INTEGRITY');
  });

  it('refuses a key that is not a restricted decryption key — TPM_RC_TYPE', () => {
    const { blob } = makeCredential(ek.publicKey, ak.name, secret, 'eph/1');
    // An AK in the EK's slot: sign SET, decrypt CLEAR.
    const out = activateCredential(ak, ak, blob);
    expect(out.ok).toBe(false);
    if (out.ok) throw new Error('unreachable');
    expect(out.responseName).toBe('TPM_RC_TYPE');
  });

  it('encrypts the credential as a whole TPM2B_DIGEST, size field included', () => {
    const { blob } = makeCredential(ek.publicKey, ak.name, secret, 'eph/1');
    // 32-byte secret + its 2-byte size prefix.
    expect(blob.encIdentity.length).toBe(secret.length + 2);
  });

  it('rejects a credential larger than the EK nameAlg digest — TPM_RC_SIZE', () => {
    expect(() => makeCredential(ek.publicKey, ak.name, new Uint8Array(33), 'eph/1')).toThrow(
      /TPM_RC_SIZE/
    );
  });

  it('THE FINDING: the EK private key alone completes the challenge, no TPM involved', () => {
    // A key the attacker generated in ordinary memory. Its public area has
    // every attribute bit an AK should have -- they are just bits.
    const hostile = makeAttestationKey('ak/hostile-software', parent);
    expect(hostile.pub.attributes.restricted).toBe(true);
    expect(hostile.pub.attributes.fixedTPM).toBe(true);

    const { blob } = makeCredential(ek.publicKey, hostile.name, secret, 'ca-eph/1');
    const recovered = activateCredentialInSoftware(
      ek.secretKey,
      ek.publicKey,
      hostile.name,
      blob
    );
    expect(toHex(recovered.credential)).toBe(toHex(secret));
  });

  it('and the software path derives byte-identical values to the TPM path', () => {
    const { blob, derivation: caSide } = makeCredential(ek.publicKey, ak.name, secret, 'eph/1');
    const tpmSide = activateCredential(ak, ek, blob);
    const softwareSide = activateCredentialInSoftware(ek.secretKey, ek.publicKey, ak.name, blob);
    if (!tpmSide.ok) throw new Error('unreachable');
    for (const field of ['seed', 'symKey', 'hmacKey'] as const) {
      expect(toHex(tpmSide.derivation[field]), field).toBe(toHex(caSide[field]));
      expect(toHex(softwareSide.derivation[field]), field).toBe(toHex(caSide[field]));
    }
  });
});
