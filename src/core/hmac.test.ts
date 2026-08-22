import { describe, expect, it } from 'vitest';
import { hmacSha256 } from './hmac';
import { fromHex, toHex, utf8 } from './bytes';

/** RFC 4231 §4 — the published HMAC-SHA-256 test cases. */
describe('HMAC-SHA-256 (RFC 4231)', () => {
  const rep = (byte: number, n: number): Uint8Array => new Uint8Array(n).fill(byte);

  const CASES: Array<[string, Uint8Array, Uint8Array, string]> = [
    ['TC1', rep(0x0b, 20), utf8('Hi There'), 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'],
    ['TC2', utf8('Jefe'), utf8('what do ya want for nothing?'), '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843'],
    ['TC3', rep(0xaa, 20), rep(0xdd, 50), '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe'],
    ['TC4', fromHex('0102030405060708090a0b0c0d0e0f10111213141516171819'), rep(0xcd, 50), '82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b'],
    ['TC6', rep(0xaa, 131), utf8('Test Using Larger Than Block-Size Key - Hash Key First'), '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54'],
    [
      'TC7',
      rep(0xaa, 131),
      utf8(
        'This is a test using a larger than block-size key and a larger than block-size data. ' +
          'The key needs to be hashed before being used by the HMAC algorithm.'
      ),
      '9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2',
    ],
  ];

  for (const [name, key, data, want] of CASES) {
    it(`matches ${name}`, () => {
      expect(toHex(hmacSha256(key, data))).toBe(want);
    });
  }

  it('matches TC5 in its truncated-to-128-bit form', () => {
    const full = hmacSha256(rep(0x0c, 20), utf8('Test With Truncation'));
    expect(toHex(full.slice(0, 16))).toBe('a3b6167473100ee06e0c796c2955552b');
  });
});
