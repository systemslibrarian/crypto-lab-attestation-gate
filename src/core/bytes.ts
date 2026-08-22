/**
 * Byte plumbing shared by every layer of this lab.
 *
 * The TPM marshals every integer BIG-ENDIAN (TPM 2.0 Part 1, "Table 1 — Byte
 * Order"), so the writers here are big-endian only and there is deliberately
 * no little-endian escape hatch: a stray `setUint32(…, true)` is exactly the
 * kind of edit that produces a structure which still parses and no longer
 * matches a real TPM.
 */

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

export function toHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

/** Strict hex parse. Odd length or a non-hex character throws, never truncates. */
export function fromHex(hex: string): Uint8Array {
  const clean = hex.trim().replace(/\s+/g, '');
  if (clean.length % 2 !== 0) throw new Error(`hex string has odd length (${clean.length})`);
  if (!/^[0-9a-fA-F]*$/.test(clean)) throw new Error('hex string contains a non-hex character');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/** UINT8 on the wire. */
export function u8(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xff) {
    throw new Error(`u8 out of range: ${value}`);
  }
  return new Uint8Array([value]);
}

/** UINT16, big-endian. */
export function u16be(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
    throw new Error(`u16 out of range: ${value}`);
  }
  return new Uint8Array([(value >>> 8) & 0xff, value & 0xff]);
}

/** UINT32, big-endian. */
export function u32be(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new Error(`u32 out of range: ${value}`);
  }
  return new Uint8Array([
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ]);
}

/**
 * UINT64, big-endian. Taken as a bigint rather than a number because
 * `clock` is a millisecond counter and `firmwareVersion` packs two 32-bit
 * halves — both routinely exceed 2^53 on real hardware, where a number would
 * silently lose the low bits.
 */
export function u64be(value: bigint): Uint8Array {
  if (value < 0n || value > 0xffff_ffff_ffff_ffffn) {
    throw new Error(`u64 out of range: ${value}`);
  }
  const out = new Uint8Array(8);
  let v = value;
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** Byte equality. Used for verdicts, so it is length-checked before content. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Index of the first differing byte, or -1 when the two are equal. */
export function firstDifference(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return i;
  return a.length === b.length ? -1 : n;
}

/** base64url without padding — the JSON/JWT serialization of a byte string. */
export function toBase64Url(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
