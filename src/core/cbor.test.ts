import { describe, expect, it } from 'vitest';
import { CborMap, encodeCbor } from './cbor';
import { fromHex, toHex } from './bytes';

/**
 * RFC 8949 Appendix A, "Examples of Encoded CBOR Data Items" — the
 * specification's own table, which is what makes these known-answer tests
 * rather than a restatement of the encoder.
 *
 * The determinism rules (RFC 8949 §4.2.1) get their own block: shortest head,
 * bytewise-sorted map keys, and a refusal to emit a duplicate key. A signed
 * claims set whose encoder is not deterministic is a signature over bytes the
 * verifier may never reproduce, which is the same failure mode the rest of
 * this lab is about.
 */
describe('CBOR encoder (RFC 8949)', () => {
  const APPENDIX_A: Array<[unknown, string]> = [
    [0, '00'],
    [1, '01'],
    [10, '0a'],
    [23, '17'],
    [24, '1818'],
    [25, '1819'],
    [100, '1864'],
    [1000, '1903e8'],
    [1000000, '1a000f4240'],
    [1000000000000n, '1b000000e8d4a51000'],
    [18446744073709551615n, '1bffffffffffffffff'],
    [-1, '20'],
    [-10, '29'],
    [-100, '3863'],
    [-1000, '3903e7'],
    [false, 'f4'],
    [true, 'f5'],
    [null, 'f6'],
    [new Uint8Array(0), '40'],
    [fromHex('01020304'), '4401020304'],
    ['', '60'],
    ['a', '6161'],
    ['IETF', '6449455446'],
    ['"\\', '62225c'],
    ['ü', '62c3bc'],
    ['水', '63e6b0b4'],
    [[], '80'],
    [[1, 2, 3], '83010203'],
    [[1, [2, 3], [4, 5]], '8301820203820405'],
    [new CborMap([]), 'a0'],
    [
      new CborMap([
        [1, 2],
        [3, 4],
      ]),
      'a201020304',
    ],
    [
      new CborMap([
        ['a', 1],
        ['b', [2, 3]],
      ]),
      'a26161016162820203',
    ],
    [['a', new CborMap([['b', 'c']])], '826161a161626163'],
    [
      new CborMap([
        ['a', 'A'],
        ['b', 'B'],
        ['c', 'C'],
        ['d', 'D'],
        ['e', 'E'],
      ]),
      'a56161614161626142616361436164614461656145',
    ],
    [
      [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25],
      '98190102030405060708090a0b0c0d0e0f101112131415161718181819',
    ],
  ];

  for (const [value, want] of APPENDIX_A) {
    it(`encodes ${JSON.stringify(want)} for the Appendix A entry`, () => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      expect(toHex(encodeCbor(value as never))).toBe(want);
    });
  }

  it('sorts map keys by the bytewise order of their encodings, not insertion order', () => {
    const shuffled = new CborMap([
      [3, 4],
      [1, 2],
    ]);
    expect(toHex(encodeCbor(shuffled))).toBe('a201020304');
  });

  it('sorts a mixed integer/text key map the way RFC 8949 4.2.1 requires', () => {
    // Encoded keys: 10 -> 0x0a, 256 -> 0x190100, "a" -> 0x6161.
    // Bytewise: 0a < 1901 00 < 6161.
    const m = new CborMap([
      ['a', 1],
      [256, 2],
      [10, 3],
    ]);
    expect(toHex(encodeCbor(m))).toBe('a30a03190100026161' + '01');
  });

  it('rejects a duplicate map key rather than emitting an ambiguous map', () => {
    expect(() =>
      encodeCbor(
        new CborMap([
          [1, 'a'],
          [1, 'b'],
        ])
      )
    ).toThrow(/duplicate/);
  });

  it('rejects a non-integer number rather than guessing a float encoding', () => {
    expect(() => encodeCbor(1.5)).toThrow(/non-integer/);
  });

  it('uses the shortest head at every boundary', () => {
    expect(toHex(encodeCbor(23))).toBe('17');
    expect(toHex(encodeCbor(24))).toBe('1818');
    expect(toHex(encodeCbor(255))).toBe('18ff');
    expect(toHex(encodeCbor(256))).toBe('190100');
    expect(toHex(encodeCbor(65535))).toBe('19ffff');
    expect(toHex(encodeCbor(65536))).toBe('1a00010000');
    expect(toHex(encodeCbor(4294967295))).toBe('1affffffff');
    expect(toHex(encodeCbor(4294967296n))).toBe('1b0000000100000000');
  });
});
