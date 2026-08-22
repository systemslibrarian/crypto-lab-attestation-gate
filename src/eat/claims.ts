/**
 * RFC 9711 — "The Entity Attestation Token (EAT)" (Standards Track,
 * April 2025) — the claims-set this lab's Evidence travels in.
 *
 * RATS (RFC 9334) is an architecture and defines no wire format at all; EAT
 * is one of the formats that fills that hole. A CBOR-encoded EAT keys its
 * claims by INTEGER; the JSON encoding of the same token keys them by the
 * lowercase JWT names. RFC 9711 writes that as `JC<J, C>` — JSON gets J,
 * CBOR gets C — and both halves are below so the two renderings of the same
 * Evidence can be shown side by side.
 *
 * Three names in this area are commonly written wrong, and each is a claim a
 * verifier would simply not find:
 *   - the boot seed claim is `bootseed`, one word, not `boot_seed`;
 *   - claim 274 is `measres`, not `measurement-results`;
 *   - the nonce is `eat_nonce`, because a `nonce` claim was already
 *     registered for JWT by OpenID Connect and does not support the array
 *     form EAT needs.
 * The IANA registry's "Claim Name" column ("Nonce", "UEID", "Software
 * Measurement Results") is a human-readable label, NOT a wire name.
 *
 * WHAT THIS LAB'S EAT IS AND IS NOT. It is a real RFC 9711 claims-set with
 * real RFC 10013 measured components, encoded to real CBOR and real JSON. It
 * is NOT wrapped in a COSE_Sign1, so the claims-set itself carries no
 * signature. That is deliberate and it is the teaching point: the signature
 * that matters here is the TPM's, over the TPMS_ATTEST, and the EAT is bound
 * to that signature by two equalities a verifier RECOMPUTES —
 *   1. `eat_nonce` equals the quote's `extraData`, byte for byte;
 *   2. replaying the measured components through PCR extension reproduces the
 *      quote's `pcrDigest`, byte for byte.
 * Unbound claims are just claims. A production profile would additionally
 * sign the token; see the README's scoping section.
 */

import { toBase64Url } from '../core/bytes';
import { CborMap, encodeCbor, type CborValue } from '../core/cbor';
import {
  CONTENT_FORMAT,
  encodeMeasuredComponentCbor,
  encodeMeasuredComponentJson,
  type MeasuredComponent,
} from './measured-component';

/** CBOR claim keys. Standard CWT claims are RFC 8392; the rest are RFC 9711 §7.3.1. */
export const CLAIM = {
  ISS: 1,
  SUB: 2,
  AUD: 3,
  EXP: 4,
  NBF: 5,
  IAT: 6,
  CTI: 7,
  EAT_NONCE: 10,
  UEID: 256,
  SUEIDS: 257,
  OEMID: 258,
  HWMODEL: 259,
  HWVERSION: 260,
  UPTIME: 261,
  OEMBOOT: 262,
  DBGSTAT: 263,
  LOCATION: 264,
  EAT_PROFILE: 265,
  SUBMODS: 266,
  BOOTCOUNT: 267,
  BOOTSEED: 268,
  DLOAS: 269,
  SWNAME: 270,
  SWVERSION: 271,
  MANIFESTS: 272,
  MEASUREMENTS: 273,
  MEASRES: 274,
  INTUSE: 275,
} as const;

/** The JSON/JWT wire names — the `J` half of each `JC<J, C>`. */
export const CLAIM_JSON_NAME: Record<number, string> = {
  [CLAIM.ISS]: 'iss',
  [CLAIM.SUB]: 'sub',
  [CLAIM.AUD]: 'aud',
  [CLAIM.EXP]: 'exp',
  [CLAIM.NBF]: 'nbf',
  [CLAIM.IAT]: 'iat',
  // CWT key 7 is `cti` and holds a byte string; the JWT counterpart is `jti`
  // and holds text. Different name AND different type — one of the few places
  // the two serializations genuinely diverge rather than translate.
  [CLAIM.CTI]: 'jti',
  [CLAIM.EAT_NONCE]: 'eat_nonce',
  [CLAIM.UEID]: 'ueid',
  [CLAIM.SUEIDS]: 'sueids',
  [CLAIM.OEMID]: 'oemid',
  [CLAIM.HWMODEL]: 'hwmodel',
  [CLAIM.HWVERSION]: 'hwversion',
  [CLAIM.UPTIME]: 'uptime',
  [CLAIM.OEMBOOT]: 'oemboot',
  [CLAIM.DBGSTAT]: 'dbgstat',
  [CLAIM.LOCATION]: 'location',
  [CLAIM.EAT_PROFILE]: 'eat_profile',
  [CLAIM.SUBMODS]: 'submods',
  [CLAIM.BOOTCOUNT]: 'bootcount',
  [CLAIM.BOOTSEED]: 'bootseed',
  [CLAIM.DLOAS]: 'dloas',
  [CLAIM.SWNAME]: 'swname',
  [CLAIM.SWVERSION]: 'swversion',
  [CLAIM.MANIFESTS]: 'manifests',
  [CLAIM.MEASUREMENTS]: 'measurements',
  [CLAIM.MEASRES]: 'measres',
  [CLAIM.INTUSE]: 'intuse',
};

/**
 * `dbgstat` (claim 263). An integer in CBOR, the matching string in JSON.
 * The levels are cumulative — each implies every lower one — and the claim is
 * explicitly NOT extensible. Reporting level 3 or above requires `oemid` to
 * be present, which is why this lab's claims-set carries one.
 */
export const DBGSTAT = {
  ENABLED: 0,
  DISABLED: 1,
  DISABLED_SINCE_BOOT: 2,
  DISABLED_PERMANENTLY: 3,
  DISABLED_FULLY_AND_PERMANENTLY: 4,
} as const;

export const DBGSTAT_JSON: Record<number, string> = {
  [DBGSTAT.ENABLED]: 'enabled',
  [DBGSTAT.DISABLED]: 'disabled',
  [DBGSTAT.DISABLED_SINCE_BOOT]: 'disabled-since-boot',
  [DBGSTAT.DISABLED_PERMANENTLY]: 'disabled-permanently',
  [DBGSTAT.DISABLED_FULLY_AND_PERMANENTLY]: 'disabled-fully-and-permanently',
};

/**
 * UEID type bytes (RFC 9711 Table 1). Type 0x01 RAND must carry at least 128
 * bits, so the shortest legal RAND UEID is 17 bytes.
 *
 * Note the consumer rule the RFC states and this lab obeys: a VERIFIER must
 * treat a UEID as completely opaque and must not parse even the type byte.
 * Only the producer builds it.
 */
export const UEID_TYPE = { RAND: 0x01, IEEE_EUI: 0x02, IMEI: 0x03 } as const;

export interface EatEvidenceInput {
  /** The relying party's nonce. 8..64 bytes in CBOR; must have >= 64 bits of entropy. */
  nonce: Uint8Array;
  /** RAND-type UEID including its 0x01 type byte. */
  ueid: Uint8Array;
  /** 16-byte random-form OEM ID. `hwmodel`, `oemboot` and `dbgstat` all require it. */
  oemid: Uint8Array;
  /** 1..32 opaque bytes, unique within the OEM. Requires `oemid`. */
  hwmodel: Uint8Array;
  /** [version, scheme]. Requires `hwmodel`. */
  hwversion: { value: string; scheme: number };
  bootcount: number;
  dbgstat: number;
  /** Seconds since the epoch. EAT forbids a floating-point `iat`. */
  iat: number;
  /** The profile URI this claims-set is written against. */
  profile: string;
  /** One measured component per boot stage, in boot order. */
  components: MeasuredComponent[];
}

/**
 * Assert the inter-claim dependencies RFC 9711 states as MUSTs, rather than
 * emitting a claims-set that is structurally valid CBOR and semantically
 * illegal. A verifier is entitled to reject either way; failing here means
 * this lab never SHOWS an invalid token as if it were fine.
 */
function assertClaimDependencies(input: EatEvidenceInput): void {
  if (input.nonce.length < 8 || input.nonce.length > 64) {
    throw new Error(`eat_nonce must be 8..64 bytes in CBOR; got ${input.nonce.length}`);
  }
  if (input.ueid.length < 7 || input.ueid.length > 33) {
    throw new Error(`ueid must be 7..33 bytes; got ${input.ueid.length}`);
  }
  if (input.ueid[0] === UEID_TYPE.RAND && input.ueid.length < 17) {
    throw new Error('a RAND-type UEID must carry at least 128 bits');
  }
  if (input.oemid.length !== 16) {
    throw new Error('this lab uses the 16-byte random form of oemid');
  }
  if (input.hwmodel.length < 1 || input.hwmodel.length > 32) {
    throw new Error(`hwmodel must be 1..32 bytes; got ${input.hwmodel.length}`);
  }
  if (!Number.isInteger(input.iat)) {
    throw new Error('EAT forbids a floating-point iat');
  }
  if (!(input.dbgstat in DBGSTAT_JSON)) {
    throw new Error(`dbgstat is not extensible; ${input.dbgstat} is not a defined level`);
  }
}

/**
 * The CBOR-encoded EAT claims-set.
 *
 * Each measured component is carried as an entry in the `measurements` claim
 * (273): a two-element array of [CoAP Content-Format, body]. In a CBOR EAT
 * the "homogeneous" carriage is content-format 295 with the body as a CBOR
 * byte string wrapping the encoded component — RFC 10013's `<<...>>`
 * notation. The component is never nested as a bare map: it is always an
 * opaque string the consumer decodes separately.
 */
export function encodeEatCbor(input: EatEvidenceInput): Uint8Array {
  assertClaimDependencies(input);
  const measurements: CborValue = input.components.map((c) => [
    CONTENT_FORMAT.MEASURED_COMPONENT_CBOR,
    encodeMeasuredComponentCbor(c),
  ]);
  return encodeCbor(
    new CborMap([
      [CLAIM.IAT, input.iat],
      [CLAIM.EAT_NONCE, input.nonce],
      [CLAIM.UEID, input.ueid],
      [CLAIM.OEMID, input.oemid],
      [CLAIM.HWMODEL, input.hwmodel],
      [CLAIM.HWVERSION, [input.hwversion.value, input.hwversion.scheme]],
      [CLAIM.DBGSTAT, input.dbgstat],
      [CLAIM.EAT_PROFILE, input.profile],
      [CLAIM.BOOTCOUNT, input.bootcount],
      [CLAIM.MEASUREMENTS, measurements],
    ])
  );
}

/**
 * The JSON-encoded EAT claims-set — the same Evidence, the other
 * serialization. Byte strings become unpadded base64url (RFC 9711 §7.2.2);
 * enumerated values become their strings; and a JSON measured component is
 * carried under content-format 296 as a JSON STRING, not as a nested object.
 */
export function encodeEatJson(input: EatEvidenceInput): Record<string, unknown> {
  assertClaimDependencies(input);
  return {
    [CLAIM_JSON_NAME[CLAIM.IAT]]: input.iat,
    [CLAIM_JSON_NAME[CLAIM.EAT_NONCE]]: toBase64Url(input.nonce),
    [CLAIM_JSON_NAME[CLAIM.UEID]]: toBase64Url(input.ueid),
    [CLAIM_JSON_NAME[CLAIM.OEMID]]: toBase64Url(input.oemid),
    [CLAIM_JSON_NAME[CLAIM.HWMODEL]]: toBase64Url(input.hwmodel),
    [CLAIM_JSON_NAME[CLAIM.HWVERSION]]: [input.hwversion.value, input.hwversion.scheme],
    [CLAIM_JSON_NAME[CLAIM.DBGSTAT]]: DBGSTAT_JSON[input.dbgstat],
    [CLAIM_JSON_NAME[CLAIM.EAT_PROFILE]]: input.profile,
    [CLAIM_JSON_NAME[CLAIM.BOOTCOUNT]]: input.bootcount,
    [CLAIM_JSON_NAME[CLAIM.MEASUREMENTS]]: input.components.map((c) => [
      CONTENT_FORMAT.MEASURED_COMPONENT_JSON,
      JSON.stringify(encodeMeasuredComponentJson(c)),
    ]),
  };
}
