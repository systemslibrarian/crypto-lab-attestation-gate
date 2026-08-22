/**
 * TPM2_Quote, and the forgery Act 2a needs in order to be refused.
 *
 * A quote is a signature over a marshalled TPMS_ATTEST. Not over the PCR
 * digest, and not over "PCR digest || nonce" — over the whole structure,
 * magic value first. Everything a verifier is entitled to conclude comes from
 * fields inside those signed bytes, which is why the byte inspector in Act 2
 * is the exhibit and not decoration.
 *
 * One detail worth stating because it is easy to double-count: TPM2_Quote
 * returns `quoted` as a TPM2B_ATTEST, and "the size parameter is not signed"
 * (Part 2, TPM2B_ATTEST). The signed message is exactly the marshalled
 * TPMS_ATTEST beginning FF 54 43 47, with no length prefix.
 */

import { concatBytes } from '../core/bytes';
import { sha256 } from '../core/sha256';
import { TPM_ALG, TPM_GENERATED_VALUE, TPM_ST } from './constants';
import {
  marshalAttest,
  type AttestInput,
  type ClockInfo,
  type FieldSpan,
} from './marshal';
import { signInternalStructure, type TpmObject } from './key';
import type { PcrBank } from './pcr';

export interface Quote {
  attest: AttestInput;
  /** The exact bytes that were signed. */
  attestBytes: Uint8Array;
  fields: FieldSpan[];
  /** SHA-256 of `attestBytes` — the digest the signing scheme covers. */
  digest: Uint8Array;
  signature: Uint8Array;
  /** The AK's marshalled TPMT_PUBLIC, which a verifier needs to recompute its Name. */
  akPublicArea: Uint8Array;
  akPublicKey: Uint8Array;
  akQualifiedSigner: Uint8Array;
  /** How this quote came to exist. Displayed; never trusted by the verifier. */
  provenance: 'TPM2_Quote' | 'externally crafted';
}

export interface QuoteOptions {
  ak: TpmObject;
  bank: PcrBank;
  selection: readonly number[];
  /** The relying party's qualifying data. */
  nonce: Uint8Array;
  clockInfo: ClockInfo;
  firmwareVersion: bigint;
  /** Which PCR bank is being quoted. The OUTER hash is always the scheme's. */
  bankHashAlg?: number;
}

export function tpm2Quote(opts: QuoteOptions): Quote {
  const selection = [...new Set(opts.selection)].sort((a, b) => a - b);
  const attest: AttestInput = {
    magic: TPM_GENERATED_VALUE,
    type: TPM_ST.ATTEST_QUOTE,
    qualifiedSigner: opts.ak.qualifiedSigner,
    extraData: opts.nonce,
    clockInfo: opts.clockInfo,
    firmwareVersion: opts.firmwareVersion,
    attested: {
      pcrSelect: selection,
      hashAlg: opts.bankHashAlg ?? TPM_ALG.SHA256,
      pcrDigest: opts.bank.digest(selection),
    },
  };
  const { bytes, fields } = marshalAttest(attest);
  // The internal path: the TPM built this structure, so no validation ticket
  // is involved and the magic value is legitimately present. There is no way
  // to reach this from caller-supplied bytes -- see `craftAttest`.
  const { signature, digest } = signInternalStructure(opts.ak, bytes);
  return {
    attest,
    attestBytes: bytes,
    fields,
    digest,
    signature,
    akPublicArea: opts.ak.publicArea,
    akPublicKey: opts.ak.publicKey,
    akQualifiedSigner: opts.ak.qualifiedSigner,
    provenance: 'TPM2_Quote',
  };
}

/**
 * Build a TPMS_ATTEST outside the TPM, with whatever contents the caller
 * wants — the attacker's move in Act 2a.
 *
 * This produces BYTES, not a quote: it deliberately cannot sign. Getting a
 * signature over these bytes means going through `signExternalData`, which
 * runs TPM2_Hash first and therefore hits the restricted-key rule.
 */
export function craftAttest(input: {
  magic?: number;
  qualifiedSigner: Uint8Array;
  nonce: Uint8Array;
  clockInfo: ClockInfo;
  firmwareVersion: bigint;
  selection: readonly number[];
  /** The PCR values the forger WISHES the machine had. */
  claimedPcrValues: Uint8Array[];
  bankHashAlg?: number;
}): { attest: AttestInput; bytes: Uint8Array; fields: FieldSpan[] } {
  const selection = [...new Set(input.selection)].sort((a, b) => a - b);
  const attest: AttestInput = {
    magic: input.magic ?? TPM_GENERATED_VALUE,
    type: TPM_ST.ATTEST_QUOTE,
    qualifiedSigner: input.qualifiedSigner,
    extraData: input.nonce,
    clockInfo: input.clockInfo,
    firmwareVersion: input.firmwareVersion,
    attested: {
      pcrSelect: selection,
      hashAlg: input.bankHashAlg ?? TPM_ALG.SHA256,
      // The forger computes the composite digest exactly the way the TPM
      // would -- there is nothing secret about it.
      pcrDigest: sha256(concatBytes(...input.claimedPcrValues)),
    },
  };
  const { bytes, fields } = marshalAttest(attest);
  return { attest, bytes, fields };
}
