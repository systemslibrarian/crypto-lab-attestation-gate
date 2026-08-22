/**
 * A deterministic CBOR encoder (RFC 8949), hand-rolled.
 *
 * EAT's normative serialization is CBOR, and the whole point of showing an
 * EAT beside a TPMS_ATTEST is that both are byte structures a verifier parses
 * — so a lab that encoded its EAT with a library and printed the hex would be
 * asking the reader to take the encoding on trust, which is the failure this
 * exhibit is about.
 *
 * "Deterministic" here is RFC 8949 §4.2.1 Core Deterministic Encoding:
 *   - every integer, string length, array length and map length uses the
 *     SHORTEST head that can hold it;
 *   - map keys are sorted by the bytewise lexicographic order of their own
 *     encoded bytes;
 *   - no indefinite-length items.
 * Note this is §4.2.1's ordering, not the length-first ordering of RFC 7049's
 * canonical form (kept in §4.2.3 as "Deterministic Encoding, Length-First
 * Map Key Ordering") — with the small unsigned claim keys EAT uses the two
 * orders happen to agree, and the sort is written against §4.2.1 anyway
 * because that is the one RFC 8949 makes the default.
 *
 * Determinism is not decoration: an attester and a verifier that encode the
 * same claim set differently produce different signed bytes, which is the
 * same class of bug the magic value in `TPMS_ATTEST` exists to prevent — a
 * signature covers bytes, never the meaning a parser assigns them.
 */

import { concatBytes, u8 } from './bytes';

/** A CBOR map with explicit, orderable entries (a JS object cannot hold integer keys). */
export class CborMap {
  constructor(public readonly entries: Array<[CborValue, CborValue]>) {}
}

export type CborValue =
  | number
  | bigint
  | string
  | Uint8Array
  | boolean
  | null
  | CborValue[]
  | CborMap;

const MT_UINT = 0;
const MT_NINT = 1;
const MT_BSTR = 2;
const MT_TSTR = 3;
const MT_ARRAY = 4;
const MT_MAP = 5;
const MT_SIMPLE = 7;

/** The shortest head (major type + argument) that can carry `arg`. */
function head(major: number, arg: bigint): Uint8Array {
  const base = major << 5;
  if (arg < 24n) return u8(base | Number(arg));
  if (arg < 0x100n) return new Uint8Array([base | 24, Number(arg)]);
  if (arg < 0x10000n) {
    return new Uint8Array([base | 25, Number(arg >> 8n) & 0xff, Number(arg & 0xffn)]);
  }
  if (arg < 0x100000000n) {
    return new Uint8Array([
      base | 26,
      Number((arg >> 24n) & 0xffn),
      Number((arg >> 16n) & 0xffn),
      Number((arg >> 8n) & 0xffn),
      Number(arg & 0xffn),
    ]);
  }
  if (arg < 0x10000000000000000n) {
    const out = new Uint8Array(9);
    out[0] = base | 27;
    let v = arg;
    for (let i = 8; i >= 1; i--) {
      out[i] = Number(v & 0xffn);
      v >>= 8n;
    }
    return out;
  }
  throw new Error('CBOR argument exceeds 64 bits');
}

/** Bytewise lexicographic comparison — RFC 8949 §4.2.1 map key ordering. */
function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

export function encodeCbor(value: CborValue): Uint8Array {
  if (value === null) return u8(0xf6);
  if (value === true) return u8(0xf5);
  if (value === false) return u8(0xf4);

  if (typeof value === 'number' || typeof value === 'bigint') {
    if (typeof value === 'number' && !Number.isInteger(value)) {
      // Floats are legal CBOR and deliberately unsupported: a deterministic
      // float encoding needs the shortest-of-{16,32,64} rule, and nothing in
      // this lab has a non-integer claim. Throwing beats encoding it wrong.
      throw new Error(`CBOR: non-integer number ${value} (floats are not supported here)`);
    }
    const v = typeof value === 'bigint' ? value : BigInt(value);
    return v >= 0n
      ? concatBytes(head(MT_UINT, v), new Uint8Array(0))
      : concatBytes(head(MT_NINT, -1n - v), new Uint8Array(0));
  }

  if (value instanceof Uint8Array) {
    return concatBytes(head(MT_BSTR, BigInt(value.length)), value);
  }

  if (typeof value === 'string') {
    const bytes = new TextEncoder().encode(value);
    return concatBytes(head(MT_TSTR, BigInt(bytes.length)), bytes);
  }

  if (Array.isArray(value)) {
    return concatBytes(head(MT_ARRAY, BigInt(value.length)), ...value.map(encodeCbor));
  }

  if (value instanceof CborMap) {
    const encoded = value.entries.map(
      ([k, v]) => [encodeCbor(k), encodeCbor(v)] as [Uint8Array, Uint8Array]
    );
    encoded.sort((a, b) => compareBytes(a[0], b[0]));
    for (let i = 1; i < encoded.length; i++) {
      if (compareBytes(encoded[i - 1][0], encoded[i][0]) === 0) {
        throw new Error('CBOR: duplicate map key');
      }
    }
    return concatBytes(
      head(MT_MAP, BigInt(encoded.length)),
      ...encoded.flatMap(([k, v]) => [k, v])
    );
  }

  throw new Error(`CBOR: unsupported value ${String(value)}`);
}

/** Convenience for the simple-value head, exported so tests can pin it. */
export const CBOR_SIMPLE_MAJOR = MT_SIMPLE;
