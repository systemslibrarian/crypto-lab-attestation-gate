import { describe, expect, it } from 'vitest';
import { sha256 as nobleSha256 } from '@noble/hashes/sha2.js';
import { sha256 } from './sha256';
import { fromHex, toHex, utf8 } from './bytes';

/**
 * Two oracles, deliberately.
 *
 * The published vectors pin the function to FIPS 180-4. The cross-check
 * against `@noble/hashes` — a separately written, separately audited
 * implementation — is what catches a compression function that is
 * self-consistent and wrong on inputs no published vector happens to cover
 * (the multi-block boundary, the length field crossing 2^32 bits, a message
 * whose length lands exactly on 55/56/64 bytes).
 */
describe('SHA-256 (FIPS 180-4)', () => {
  const VECTORS: Array<[string, string]> = [
    ['', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
    ['abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'],
    [
      'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
      '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
    ],
    [
      'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu',
      'cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1',
    ],
  ];

  for (const [msg, want] of VECTORS) {
    it(`matches the published digest for a ${msg.length}-byte message`, () => {
      expect(toHex(sha256(utf8(msg)))).toBe(want);
    });
  }

  it('agrees with @noble/hashes on every length across four block boundaries', () => {
    for (let n = 0; n <= 260; n++) {
      const msg = new Uint8Array(n);
      for (let i = 0; i < n; i++) msg[i] = (i * 7 + 13) & 0xff;
      expect(toHex(sha256(msg)), `length ${n}`).toBe(toHex(nobleSha256(msg)));
    }
  });

  it('agrees with @noble/hashes on the padding-critical lengths', () => {
    for (const n of [55, 56, 57, 63, 64, 65, 119, 120, 127, 128]) {
      const msg = new Uint8Array(n).fill(0xa5);
      expect(toHex(sha256(msg)), `length ${n}`).toBe(toHex(nobleSha256(msg)));
    }
  });

  it('hashes a 1 MiB message identically to @noble/hashes', () => {
    const big = new Uint8Array(1024 * 1024);
    for (let i = 0; i < big.length; i++) big[i] = i & 0xff;
    expect(toHex(sha256(big))).toBe(toHex(nobleSha256(big)));
  });

  it('does not mutate its input', () => {
    const msg = fromHex('deadbeef');
    const copy = msg.slice();
    sha256(msg);
    expect(toHex(msg)).toBe(toHex(copy));
  });
});
