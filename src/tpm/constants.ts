/**
 * TPM 2.0 constants, from the Trusted Computing Group's
 * "Trusted Platform Module Library — Part 2: Structures".
 *
 * Every value here is a wire constant. They are collected in one file so the
 * byte inspector can name a field's value rather than printing a bare number,
 * and so a reader can check them against the spec's tables without reading
 * any marshalling code.
 */

/**
 * TPM_GENERATED_VALUE — the four bytes 0xFF 'T' 'C' 'G'.
 *
 * This is the whole of Act 2a. It sits at offset 0 of every structure the TPM
 * itself generates and signs, and it exists so that a signature over a
 * TPM-generated structure can never be confused with a signature over bytes
 * somebody handed the TPM. The enforcement is on the SIGNING side: a
 * restricted signing key will not sign externally-supplied data whose first
 * four bytes are this value, because the TPM refuses to issue the validation
 * ticket such a key requires. See `restrictedSigningRule` in `key.ts`.
 *
 * Part 2, "TPM_GENERATED Constants".
 */
export const TPM_GENERATED_VALUE = 0xff544347;

/** TPM_ST (structure tags) for the attestation structures. Part 2, "TPM_ST Constants". */
export const TPM_ST = {
  ATTEST_NV: 0x8014,
  ATTEST_COMMAND_AUDIT: 0x8015,
  ATTEST_SESSION_AUDIT: 0x8016,
  ATTEST_CERTIFY: 0x8017,
  ATTEST_QUOTE: 0x8018,
  ATTEST_TIME: 0x8019,
  ATTEST_CREATION: 0x801a,
  ATTEST_NV_DIGEST: 0x801c,
} as const;

/** Human names for the attestation tags, so the inspector can decode `type`. */
export const TPM_ST_NAMES: Record<number, string> = {
  [TPM_ST.ATTEST_NV]: 'TPM_ST_ATTEST_NV',
  [TPM_ST.ATTEST_COMMAND_AUDIT]: 'TPM_ST_ATTEST_COMMAND_AUDIT',
  [TPM_ST.ATTEST_SESSION_AUDIT]: 'TPM_ST_ATTEST_SESSION_AUDIT',
  [TPM_ST.ATTEST_CERTIFY]: 'TPM_ST_ATTEST_CERTIFY',
  [TPM_ST.ATTEST_QUOTE]: 'TPM_ST_ATTEST_QUOTE',
  [TPM_ST.ATTEST_TIME]: 'TPM_ST_ATTEST_TIME',
  [TPM_ST.ATTEST_CREATION]: 'TPM_ST_ATTEST_CREATION',
  [TPM_ST.ATTEST_NV_DIGEST]: 'TPM_ST_ATTEST_NV_DIGEST',
};

/** TPM_ALG_ID. Part 2, "TPM_ALG_ID Constants" (and the TCG Algorithm Registry). */
export const TPM_ALG = {
  RSA: 0x0001,
  SHA1: 0x0004,
  HMAC: 0x0005,
  AES: 0x0006,
  NULL: 0x0010,
  RSASSA: 0x0014,
  SHA256: 0x000b,
  SHA384: 0x000c,
  SHA512: 0x000d,
  ECDSA: 0x0018,
  ECC: 0x0023,
} as const;

export const TPM_ALG_NAMES: Record<number, string> = {
  [TPM_ALG.RSA]: 'TPM_ALG_RSA',
  [TPM_ALG.SHA1]: 'TPM_ALG_SHA1',
  [TPM_ALG.HMAC]: 'TPM_ALG_HMAC',
  [TPM_ALG.AES]: 'TPM_ALG_AES',
  [TPM_ALG.NULL]: 'TPM_ALG_NULL',
  [TPM_ALG.RSASSA]: 'TPM_ALG_RSASSA',
  [TPM_ALG.SHA256]: 'TPM_ALG_SHA256',
  [TPM_ALG.SHA384]: 'TPM_ALG_SHA384',
  [TPM_ALG.SHA512]: 'TPM_ALG_SHA512',
  [TPM_ALG.ECDSA]: 'TPM_ALG_ECDSA',
  [TPM_ALG.ECC]: 'TPM_ALG_ECC',
};

/** Permanent handles. Part 2, "TPM_RH Constants". Used as the root of a Qualified Name. */
export const TPM_RH = {
  OWNER: 0x40000001,
  NULL: 0x40000007,
  ENDORSEMENT: 0x4000000b,
  PLATFORM: 0x4000000c,
} as const;

/**
 * The number of PCRs this lab models, and therefore the width of the
 * TPMS_PCR_SELECTION bitmap. Real PC Client TPMs implement 24, which is
 * exactly three bytes of `pcrSelect` — the `sizeofSelect: 3` seen in every
 * captured quote.
 */
export const PCR_COUNT = 24;
export const PCR_SELECT_BYTES = 3;
