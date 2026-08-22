/**
 * HMAC-SHA-256 (FIPS 198-1 / RFC 2104), over this repo's own SHA-256.
 *
 * Needed because KDFa — the key derivation inside TPM2_MakeCredential — is
 * SP 800-108 counter mode with HMAC as its PRF. Writing it here rather than
 * importing one keeps the whole credential-activation path readable in one
 * repository, and `hmac.test.ts` pins it to the RFC 4231 vectors.
 */

import { concatBytes } from './bytes';
import { sha256 } from './sha256';

const BLOCK = 64;

export function hmacSha256(key: Uint8Array, message: Uint8Array): Uint8Array {
  // RFC 2104: a key longer than the block size is hashed first; a shorter one
  // is zero-padded up to it.
  const k = new Uint8Array(BLOCK);
  k.set(key.length > BLOCK ? sha256(key) : key);

  const inner = new Uint8Array(BLOCK);
  const outer = new Uint8Array(BLOCK);
  for (let i = 0; i < BLOCK; i++) {
    inner[i] = k[i] ^ 0x36;
    outer[i] = k[i] ^ 0x5c;
  }
  return sha256(concatBytes(outer, sha256(concatBytes(inner, message))));
}
