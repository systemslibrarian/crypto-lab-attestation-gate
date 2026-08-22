/**
 * RFC 10013 — "Entity Attestation Token (EAT) Measured Component"
 * (Standards Track, July 2026).
 *
 * This is the encoding a boot measurement gets when it travels as RATS
 * Evidence rather than as a raw PCR value. RFC 10013 exists precisely because
 * CoSWID — the only measurement format RFC 9711 originally named — assumes a
 * file system, and early boot does not have one.
 *
 * The data model (§4.3), verbatim from the RFC's CDDL:
 *
 *     measured-component = {
 *       component-id-label => component-id
 *       measurement
 *       ? authorities-label => [ + authority-id-type ]
 *       ? flags-label => flags-type
 *     }
 *     measurement //= ( digested-measurement-label => digest )
 *     measurement //= ( raw-measurement-label => bytes )
 *
 *     component-id-label         = eat.JC<"id", 1>
 *     digested-measurement-label = eat.JC<"digested-measurement", 2>
 *     authorities-label          = eat.JC<"authorities", 3>
 *     flags-label                = eat.JC<"flags", 4>
 *     raw-measurement-label      = eat.JC<"raw-measurement", 5>
 *
 * `eat.JC<J, C>` means the JSON name is J and the CBOR key is C, so the same
 * component has an integer-keyed map in CBOR and a string-keyed object in
 * JSON. Note the two traps:
 *   - `raw-measurement` is key 5, not 3 — it was appended after `authorities`
 *     and `flags`, so the keys are not contiguous with the prose order;
 *   - §4.3's prose bullet calls the group "measurements", but that is the
 *     name of a CDDL group choice and NOT a wire member. A JSON encoder that
 *     emits "measurement" or "measurements" inside a measured component is
 *     non-conformant. (The veraison/eat Go implementation still does, because
 *     it tracks a pre-09 draft — the RFC is normative.)
 *
 * This lab emits only the digested form and deliberately omits `authorities`
 * and `flags`. That is not laziness: RFC 10013 §4.5 says a consumer that does
 * not know the EAT's profile MUST REJECT an EAT whose measured components
 * carry either field, because both are profile-defined and meaningless
 * without one. Omitting them keeps this Evidence readable by any consumer.
 */

import { toBase64Url } from '../core/bytes';
import { CborMap, encodeCbor, type CborValue } from '../core/cbor';

/** CBOR map keys — RFC 10013 §4.3. */
export const MC_KEY = {
  ID: 1,
  DIGESTED_MEASUREMENT: 2,
  AUTHORITIES: 3,
  FLAGS: 4,
  RAW_MEASUREMENT: 5,
} as const;

/** JSON member names — the other half of each `eat.JC<>`. */
export const MC_JSON_NAME = {
  [MC_KEY.ID]: 'id',
  [MC_KEY.DIGESTED_MEASUREMENT]: 'digested-measurement',
  [MC_KEY.AUTHORITIES]: 'authorities',
  [MC_KEY.FLAGS]: 'flags',
  [MC_KEY.RAW_MEASUREMENT]: 'raw-measurement',
} as const;

/**
 * Digest algorithm identifiers come from the IANA "Named Information Hash
 * Algorithm Registry" (RFC 10013 §4.2), NOT from the COSE algorithms
 * registry and not from TPM_ALG_ID. In that registry sha-256 is 1. The RFC
 * recommends the integer form "whenever possible", which is what this uses.
 */
export const NAMED_INFO_SHA256 = 1;
export const NAMED_INFO_SHA256_NAME = 'sha-256';

/** CoAP Content-Format numbers registered by RFC 10013 §7.2. */
export const CONTENT_FORMAT = {
  MEASURED_COMPONENT_CBOR: 295,
  MEASURED_COMPONENT_JSON: 296,
} as const;

/** CoSWID version schemes, imported by RFC 10013 §4.3.1 from RFC 9393 §2.2. */
export const VERSION_SCHEME = {
  MULTIPARTNUMERIC: 1,
  MULTIPARTNUMERIC_SUFFIX: 2,
  ALPHANUMERIC: 3,
  DECIMAL: 4,
  SEMVER: 16384,
} as const;

export interface ComponentVersion {
  value: string;
  scheme?: number;
}

export interface MeasuredComponent {
  name: string;
  version?: ComponentVersion;
  /** The digested form. `raw` is the alternative; exactly one must be present. */
  digest?: { alg: number | string; value: Uint8Array };
  raw?: Uint8Array;
}

function componentId(mc: MeasuredComponent): CborValue[] {
  const id: CborValue[] = [mc.name];
  if (mc.version) {
    const v: CborValue[] = [mc.version.value];
    if (mc.version.scheme !== undefined) v.push(mc.version.scheme);
    id.push(v);
  }
  return id;
}

/** The CBOR serialization of one measured component (RFC 10013 §4.3). */
export function encodeMeasuredComponentCbor(mc: MeasuredComponent): Uint8Array {
  assertExactlyOneMeasurement(mc);
  const entries: Array<[CborValue, CborValue]> = [[MC_KEY.ID, componentId(mc)]];
  if (mc.digest) {
    entries.push([MC_KEY.DIGESTED_MEASUREMENT, [mc.digest.alg, mc.digest.value]]);
  } else {
    entries.push([MC_KEY.RAW_MEASUREMENT, mc.raw!]);
  }
  return encodeCbor(new CborMap(entries));
}

/**
 * The JSON serialization. Byte-valued fields become UNPADDED base64url
 * (RFC 10013 §4.1's `.b64u`, which is RFC 9741 §2.1) — the `=` padding
 * characters are excluded by the type's own regexp, so a padded encoder
 * produces a document that fails validation.
 */
export function encodeMeasuredComponentJson(mc: MeasuredComponent): Record<string, unknown> {
  assertExactlyOneMeasurement(mc);
  const out: Record<string, unknown> = { [MC_JSON_NAME[MC_KEY.ID]]: componentId(mc) };
  if (mc.digest) {
    out[MC_JSON_NAME[MC_KEY.DIGESTED_MEASUREMENT]] = [mc.digest.alg, toBase64Url(mc.digest.value)];
  } else {
    out[MC_JSON_NAME[MC_KEY.RAW_MEASUREMENT]] = toBase64Url(mc.raw!);
  }
  return out;
}

function assertExactlyOneMeasurement(mc: MeasuredComponent): void {
  const has = (mc.digest ? 1 : 0) + (mc.raw ? 1 : 0);
  if (has !== 1) {
    throw new Error(
      'RFC 10013 measurement is an unconditioned group choice: exactly one of ' +
        'digested-measurement (2) or raw-measurement (5) must be present'
    );
  }
}
