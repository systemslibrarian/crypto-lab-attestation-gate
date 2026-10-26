/**
 * The evidence bytes used by the DAA lesson.
 *
 * The existing lab's stable-AK path remains a genuine software model of
 * TPM2_Quote. This second path marshals a DAA-shaped TPMS_ATTEST with an empty
 * qualifiedSigner, as anonymous signing requires, then signs those complete
 * bytes with the bounded CDL construction. It does not execute TPM2_Commit,
 * TPM2_Sign, or TPM2_Quote and is not a hardware/command-level implementation.
 */

import { sha256 } from '../core/sha256';
import { TPM_ALG, TPM_GENERATED_VALUE, TPM_ST } from '../tpm/constants';
import { marshalAttest, type AttestInput, type ClockInfo, type FieldSpan } from '../tpm/marshal';
import type { PcrBank } from '../tpm/pcr';

export interface DaaAttestationStatement {
  attest: AttestInput;
  /** Exact bytes covered by the DAA signature. */
  bytes: Uint8Array;
  fields: FieldSpan[];
  digest: Uint8Array;
  provenance: 'software CDL Pi_DAA+ teaching adaptation';
}

export interface DaaAttestationOptions {
  bank: PcrBank;
  selection: readonly number[];
  nonce: Uint8Array;
  clockInfo: ClockInfo;
  firmwareVersion: bigint;
}

export function createDaaAttestation(options: DaaAttestationOptions): DaaAttestationStatement {
  const selection = [...new Set(options.selection)].sort((a, b) => a - b);
  const attest: AttestInput = {
    magic: TPM_GENERATED_VALUE,
    type: TPM_ST.ATTEST_QUOTE,
    // AsiaCCS 2020 Appendix A.2: this is an Empty Buffer for a DAA key.
    // Keeping the stable AK Name here would make an anonymous proof linkable.
    qualifiedSigner: new Uint8Array(),
    extraData: options.nonce.slice(),
    clockInfo: { ...options.clockInfo },
    firmwareVersion: options.firmwareVersion,
    attested: {
      pcrSelect: selection,
      hashAlg: TPM_ALG.SHA256,
      pcrDigest: options.bank.digest(selection),
    },
  };
  const marshalled = marshalAttest(attest);
  return {
    attest,
    bytes: marshalled.bytes,
    fields: marshalled.fields,
    digest: sha256(marshalled.bytes),
    provenance: 'software CDL Pi_DAA+ teaching adaptation',
  };
}
