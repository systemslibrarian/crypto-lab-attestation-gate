/**
 * The two key derivation functions TPM 2.0 defines, hand-rolled from Part 1.
 *
 * They are here because credential activation (Act 7b) is only a real proof of
 * TPM residency if the derivation genuinely binds the Attestation Key's Name.
 * A version that hand-waved the KDF would show the shape of the protocol and
 * none of its security.
 *
 * KDFa — Part 1, "Key Derivation Function": SP 800-108 counter mode with HMAC
 * as the PRF.
 *
 *     K(i) := HMAC(key, [i]_32 || Label || 0x00 || Context || [L]_32)
 *
 * with a 32-bit big-endian counter starting at 1, a 32-bit big-endian bit
 * count L, and `Context := contextU.buffer || contextV.buffer` — the TPM2B
 * SIZE FIELDS ARE NOT INCLUDED, which is the detail that most often makes two
 * implementations derive different keys from the same inputs.
 *
 * KDFe — Part 1, the SP 800-56A concatenation KDF used for ECDH:
 *
 *     digest(i) := H([i]_32 || Z || Use || 0x00 || PartyUInfo || PartyVInfo)
 *
 * Labels are null-terminated octet strings ("IDENTITY" is nine octets, not
 * eight). The rule is: a zero octet is appended only if the label is absent or
 * its last octet is not already zero — so passing a string here and appending
 * one 0x00 is the same thing, done once.
 */

import { concatBytes, u32be, utf8 } from '../core/bytes';
import { hmacSha256 } from '../core/hmac';
import { sha256, SHA256_LEN } from '../core/sha256';

/** A TPM KDF label: the ASCII bytes plus the terminating zero octet. */
export function kdfLabel(label: string): Uint8Array {
  return concatBytes(utf8(label), new Uint8Array([0]));
}

/**
 * Truncate to `bits`, masking (not shifting) the unused high-order bits of the
 * first octet. Part 1 is explicit that the excess bits are masked off, which
 * differs from every "just take the first n bytes" implementation the moment
 * `bits` is not a multiple of 8.
 */
function trimToBits(bytes: Uint8Array, bits: number): Uint8Array {
  const out = bytes.slice(0, Math.ceil(bits / 8));
  const excess = out.length * 8 - bits;
  if (excess > 0) out[0] &= 0xff >> excess;
  return out;
}

export function kdfa(
  key: Uint8Array,
  label: string,
  contextU: Uint8Array,
  contextV: Uint8Array,
  bits: number
): Uint8Array {
  const context = concatBytes(contextU, contextV);
  const tail = concatBytes(kdfLabel(label), context, u32be(bits));
  const blocks: Uint8Array[] = [];
  const needed = Math.ceil(bits / 8);
  for (let i = 1; blocks.length * SHA256_LEN < needed; i++) {
    blocks.push(hmacSha256(key, concatBytes(u32be(i), tail)));
  }
  return trimToBits(concatBytes(...blocks), bits);
}

export function kdfe(
  z: Uint8Array,
  use: string,
  partyUInfo: Uint8Array,
  partyVInfo: Uint8Array,
  bits: number
): Uint8Array {
  const otherInfo = concatBytes(kdfLabel(use), partyUInfo, partyVInfo);
  const blocks: Uint8Array[] = [];
  const needed = Math.ceil(bits / 8);
  for (let i = 1; blocks.length * SHA256_LEN < needed; i++) {
    blocks.push(sha256(concatBytes(u32be(i), z, otherInfo)));
  }
  return trimToBits(concatBytes(...blocks), bits);
}
