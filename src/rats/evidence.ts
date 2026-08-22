/**
 * Evidence, in the RATS sense (RFC 9334): what the Attester conveys to the
 * Verifier.
 *
 * RFC 9334 is an architecture and defines no wire format whatsoever — §12 says
 * so in as many words: "No specific wire protocol is documented here." The
 * byte formats come from elsewhere, and this bundle carries the three pieces a
 * real measured-boot attestation actually ships:
 *
 *   1. THE QUOTE — a signed TPMS_ATTEST. It carries one composite digest and
 *      nothing else about the machine. On its own it can tell a verifier that
 *      something differs from expectations; it cannot tell it what.
 *
 *   2. THE EVENT LOG — the sequence of measurements, unsigned. This is the
 *      part people are surprised by: the log is NOT signed and does not need
 *      to be, because replaying it has to reproduce the quote's composite
 *      digest exactly. A tampered log fails to replay. The signature over the
 *      quote is what makes an unsigned log trustworthy.
 *
 *   3. THE EAT — the same measurements as an RFC 9711 claims-set with RFC
 *      10013 measured components, in both CBOR and JSON. This is the modern
 *      claims-format rendering, and it is bound to the quote by two equalities
 *      the verifier recomputes rather than by a signature of its own.
 *
 * Scoping, stated plainly: the association between a measured component and a
 * PCR is not something RFC 10013 encodes — it has no PCR field, and the one
 * extension point it offers (`flags`) is profile-defined, with §4.5 requiring
 * a consumer that does not know the profile to REJECT any EAT that uses it.
 * So the PCR mapping lives in the event log, exactly as it does in a real TCG
 * attestation, and this lab's EAT deliberately carries no `flags` at all.
 */

import { toHex } from '../core/bytes';
import { sha256 } from '../core/sha256';
import { encodeEatCbor, encodeEatJson, type EatEvidenceInput } from '../eat/claims';
import {
  NAMED_INFO_SHA256,
  type MeasuredComponent,
} from '../eat/measured-component';
import type { Quote } from '../tpm/quote';
import type { AkCertificate } from './verify';
import type { BootStage } from '../boot/stages';
import { EV_SEPARATOR_BYTES } from '../boot/stages';
import { utf8 } from '../core/bytes';

/** One entry of the TCG event log. */
export interface EventLogEntry {
  pcr: number;
  eventType: { name: string; value: number };
  /** The digest that was extended. */
  digest: Uint8Array;
  /** Human description of what was measured. */
  eventName: string;
  /** The measured bytes, as text, so the page can show the preimage. */
  content: string;
}

export interface Evidence {
  quote: Quote;
  /**
   * The AK certificate the attester presents. Optional, because an attester
   * that has none is a real case — and one of the two Act 7b branches.
   * Deliberately typed loosely here (the shape lives in `verify.ts`) so that
   * Evidence stays a description of what was SENT, not of what was believed.
   */
  akCertificate?: AkCertificate;
  eventLog: EventLogEntry[];
  eat: {
    input: EatEvidenceInput;
    cbor: Uint8Array;
    json: Record<string, unknown>;
  };
  components: MeasuredComponent[];
  /** The AK's marshalled public area, so the verifier can recompute its Name. */
  akPublicArea: Uint8Array;
}

export function eventLogFrom(stages: readonly BootStage[]): EventLogEntry[] {
  return stages.map((stage) => {
    const bytes = stage.id === 'separator' ? EV_SEPARATOR_BYTES : utf8(stage.content);
    return {
      pcr: stage.pcr,
      eventType: { ...stage.eventType },
      digest: sha256(bytes),
      eventName: stage.name,
      content: stage.content,
    };
  });
}

/** One RFC 10013 measured component per event-log entry. */
export function componentsFrom(log: readonly EventLogEntry[]): MeasuredComponent[] {
  return log.map((entry) => ({
    name: entry.eventName,
    digest: { alg: NAMED_INFO_SHA256, value: entry.digest },
  }));
}

export interface EvidenceIdentity {
  ueid: Uint8Array;
  oemid: Uint8Array;
  hwmodel: Uint8Array;
  hwversion: { value: string; scheme: number };
  bootcount: number;
  dbgstat: number;
  iat: number;
  profile: string;
}

export function buildEvidence(
  quote: Quote,
  stages: readonly BootStage[],
  identity: EvidenceIdentity,
  akPublicArea: Uint8Array,
  akCertificate?: AkCertificate
): Evidence {
  const eventLog = eventLogFrom(stages);
  const components = componentsFrom(eventLog);
  const input: EatEvidenceInput = {
    nonce: quote.attest.extraData,
    ueid: identity.ueid,
    oemid: identity.oemid,
    hwmodel: identity.hwmodel,
    hwversion: identity.hwversion,
    bootcount: identity.bootcount,
    dbgstat: identity.dbgstat,
    iat: identity.iat,
    profile: identity.profile,
    components,
  };
  return {
    quote,
    akCertificate,
    eventLog,
    components,
    akPublicArea,
    eat: { input, cbor: encodeEatCbor(input), json: encodeEatJson(input) },
  };
}

/**
 * Replay an event log into PCR values, from the reset state.
 *
 * This is the whole reason an unsigned log is safe to send: the replay has to
 * land on the composite digest inside the signed quote. It is also an
 * INDEPENDENT re-derivation of the attester's PCRs — the verifier never takes
 * a PCR value on the attester's word, because a quote does not contain any.
 */
export function replayEventLog(
  log: readonly EventLogEntry[],
  resetValueFor: (pcr: number) => Uint8Array
): Map<number, Uint8Array> {
  const values = new Map<number, Uint8Array>();
  for (const entry of log) {
    const before = values.get(entry.pcr) ?? resetValueFor(entry.pcr);
    const preimage = new Uint8Array(before.length + entry.digest.length);
    preimage.set(before);
    preimage.set(entry.digest, before.length);
    values.set(entry.pcr, sha256(preimage));
  }
  return values;
}

/** Hex snapshot of a replay, for display and diffing. */
export function replayToHex(values: Map<number, Uint8Array>): Map<number, string> {
  return new Map([...values].map(([pcr, v]) => [pcr, toHex(v)]));
}
