/**
 * TPM 2.0 structure marshalling, hand-rolled, with a byte map.
 *
 * This is the file the whole exhibit turns on. Revision 2 of the brief for
 * this lab said "the quote is a signature over (PCR digest || nonce)". That
 * is adjacent to the spec and wrong, and it is wrong in a way that would have
 * been invisible: such a structure verifies against itself perfectly, teaches
 * a plausible-looking lesson, and shares no bytes with anything a TPM has
 * ever produced. A real TPM2_Quote signs a marshalled TPMS_ATTEST.
 *
 * Every writer records a `FieldSpan`, so the UI can show the produced bytes
 * with each field named, sized and decoded rather than as an undifferentiated
 * hex run. "Show the mechanism, do not assert it" applies to a byte layout
 * exactly as much as to a curve.
 *
 * All TPM integers are BIG-ENDIAN on the wire (Part 1, "Byte Order").
 */

import { concatBytes, toHex, u8, u16be, u32be, u64be } from '../core/bytes';
import { sha256 } from '../core/sha256';
import {
  PCR_SELECT_BYTES,
  TPM_ALG,
  TPM_ALG_NAMES,
  TPM_GENERATED_VALUE,
  TPM_ST,
  TPM_ST_NAMES,
} from './constants';

/** One named region of the marshalled structure. */
export interface FieldSpan {
  /** Dotted path, e.g. `clockInfo.resetCount`. Unique within a structure. */
  path: string;
  /** Short display label. */
  label: string;
  /** The spec type, e.g. `UINT32`, `TPM2B_NAME`. */
  type: string;
  offset: number;
  length: number;
  hex: string;
  /** The decoded value, in whatever form reads best for that field. */
  value: string;
  /** One sentence of teaching, shown when the field is selected. */
  note: string;
  /** Nesting depth, for indentation in the inspector. */
  depth: number;
}

export interface Marshalled {
  bytes: Uint8Array;
  fields: FieldSpan[];
}

/** Append-only writer that records a span for every field it emits. */
class Writer {
  private chunks: Uint8Array[] = [];
  private at = 0;
  readonly fields: FieldSpan[] = [];

  push(
    bytes: Uint8Array,
    span: Omit<FieldSpan, 'offset' | 'length' | 'hex'> & { depth?: number }
  ): void {
    this.fields.push({
      ...span,
      depth: span.depth ?? 0,
      offset: this.at,
      length: bytes.length,
      hex: toHex(bytes),
    });
    this.chunks.push(bytes);
    this.at += bytes.length;
  }

  done(): Marshalled {
    return { bytes: concatBytes(...this.chunks), fields: this.fields };
  }
}

// ── The pieces ──────────────────────────────────────────────────────────────

/**
 * TPM2B_NAME for an ordinary (non-NV) object: the hash algorithm id followed
 * by the digest of the object's public area, wrapped in a UINT16 size prefix.
 *
 * Part 1, "Names": `Name ≔ nameAlg || H_nameAlg(publicArea)`. For SHA-256
 * that is 2 + 32 = 34 bytes of content, so the TPM2B is 36 bytes on the wire.
 */
export function computeName(publicArea: Uint8Array, nameAlg: number = TPM_ALG.SHA256): Uint8Array {
  if (nameAlg !== TPM_ALG.SHA256) throw new Error('this lab implements the SHA-256 bank only');
  return concatBytes(u16be(nameAlg), sha256(publicArea));
}

/**
 * Qualified Name. Part 1, "Qualified Names":
 * `QN(B) ≔ H_B(QN(A) || NAME(B))`, where the recursion bottoms out at the
 * hierarchy's permanent handle. The result is a bare digest; it takes the
 * `nameAlg` prefix when it is marshalled into a TPM2B_NAME.
 *
 * It matters here because `qualifiedSigner` is what pins a quote to a key at
 * a particular place in a particular hierarchy on a particular TPM — the
 * field Act 5 (wrong machine) and Act 7 (whose key) both turn on.
 */
export function qualifiedName(parentQn: Uint8Array, name: Uint8Array): Uint8Array {
  return sha256(concatBytes(parentQn, name));
}

/** The bitmap byte the TPM puts on the wire for a set of PCR indices. */
export function pcrSelectionBitmap(indices: readonly number[]): Uint8Array {
  const bitmap = new Uint8Array(PCR_SELECT_BYTES);
  for (const i of indices) {
    if (!Number.isInteger(i) || i < 0 || i >= PCR_SELECT_BYTES * 8) {
      throw new Error(`PCR index out of range: ${i}`);
    }
    // Part 2, TPMS_PCR_SELECTION: PCR n is bit (n mod 8) of octet (n / 8),
    // counting bit 0 as the LEAST significant bit of the octet. So PCR 0 is
    // 0x01 of byte 0 and PCR 8 is 0x01 of byte 1 — NOT a big-endian bit run,
    // which is the mistake that produces a selection a real TPM reads as a
    // different PCR set.
    bitmap[Math.floor(i / 8)] |= 1 << i % 8;
  }
  return bitmap;
}

/** Decode a selection bitmap back to indices — used to prove the round trip. */
export function pcrIndicesFromBitmap(bitmap: Uint8Array): number[] {
  const out: number[] = [];
  for (let byte = 0; byte < bitmap.length; byte++) {
    for (let bit = 0; bit < 8; bit++) {
      if (bitmap[byte] & (1 << bit)) out.push(byte * 8 + bit);
    }
  }
  return out;
}

export interface ClockInfo {
  /** Milliseconds the TPM has been powered since the clock was last set. */
  clock: bigint;
  /** Increments on every TPM Reset (power cycle). */
  resetCount: number;
  /** Increments on every TPM Restart or Resume. */
  restartCount: number;
  /** FALSE means `clock` may have gone backwards relative to a previous report. */
  safe: boolean;
}

export interface QuoteInfo {
  /** PCR indices covered by this quote, in ascending order. */
  pcrSelect: readonly number[];
  /** Hash algorithm of the selected PCR bank. */
  hashAlg: number;
  /** H(concatenation of the selected PCR values, in ascending index order). */
  pcrDigest: Uint8Array;
}

export interface AttestInput {
  /** Almost always TPM_GENERATED_VALUE. Act 2a is the reason it is a parameter. */
  magic: number;
  type: number;
  /** The Qualified Name of the signing key, already TPM2B content (alg || digest). */
  qualifiedSigner: Uint8Array;
  /** Caller-supplied qualifying data — the relying party's nonce. */
  extraData: Uint8Array;
  clockInfo: ClockInfo;
  firmwareVersion: bigint;
  attested: QuoteInfo;
}

const T = {
  magic:
    'The four bytes 0xFF 54 43 47 — 0xFF followed by "TCG". Present only on structures the TPM ' +
    'itself generated. A restricted signing key refuses to sign externally-supplied data that ' +
    'starts with these bytes, which is what stops an attestation key being used as a general ' +
    'signing oracle.',
  type:
    'Which kind of attestation this is. TPM_ST_ATTEST_QUOTE (0x8018) says the union at the end ' +
    'is a TPMS_QUOTE_INFO. Change this and a parser reads the same trailing bytes as a different ' +
    'structure entirely.',
  qualifiedSigner:
    'The signing key’s Qualified Name: nameAlg followed by H(QN(parent) || Name(key)). It ' +
    'identifies not just the key but its position in a hierarchy on one specific TPM, which is ' +
    'what a relying party matches against its trust anchors.',
  extraDataSize: 'UINT16 size prefix of the TPM2B_DATA that follows.',
  extraData:
    'Caller-supplied qualifying data. In a challenge/response attestation this is the relying ' +
    'party’s nonce, and it is the only thing in the whole structure that makes this quote ' +
    'fresh rather than replayable.',
  clock:
    'Milliseconds of powered-on time. Monotonic within a reset epoch, and a coarse freshness ' +
    'signal — but a value the attester supplies, so it is evidence, not proof.',
  resetCount:
    'Number of TPM Resets. A change here means the PCRs went back to their reset values, so two ' +
    'quotes from different reset counts are not comparable measurements.',
  restartCount: 'Number of TPM Restarts or Resumes since the last Reset.',
  safe:
    'TPMI_YES_NO. YES (0x01) asserts the clock value has not gone backwards. A NO here quietly ' +
    'invalidates every time-based inference a verifier wanted to draw.',
  firmwareVersion:
    'Vendor-specific TPM firmware version, as one 64-bit value. It is inside the signed bytes so ' +
    'a verifier can refuse quotes from firmware it knows to be vulnerable.',
  pcrSelectCount: 'UINT32 count of TPMS_PCR_SELECTION entries — one per PCR bank being quoted.',
  pcrHashAlg:
    'Which PCR bank. A TPM keeps parallel banks (SHA-1, SHA-256, ...), and quoting the wrong ' +
    'one is how a verifier ends up comparing a SHA-1 measurement against a SHA-256 reference.',
  sizeofSelect: 'Number of bitmap octets that follow. 3 octets covers the 24 PCRs of a PC Client TPM.',
  pcrBitmap:
    'Which PCRs are covered, one bit each: PCR n is bit (n mod 8) of octet (n / 8), least ' +
    'significant bit first. A quote says nothing whatever about a PCR whose bit is clear.',
  pcrDigestSize: 'UINT16 size prefix of the TPM2B_DIGEST that follows.',
  pcrDigest:
    'H(all selected PCR values concatenated in ascending index order). One digest for the whole ' +
    'selection — which is why a mismatch tells a verifier that something changed, but not what.',
};

/**
 * Marshal a TPMS_ATTEST exactly as TPM2_Quote returns it.
 *
 * Field order, from Part 2 "TPMS_ATTEST":
 *   magic | type | qualifiedSigner | extraData | clockInfo | firmwareVersion | attested
 */
export function marshalAttest(input: AttestInput): Marshalled {
  const w = new Writer();

  w.push(u32be(input.magic), {
    path: 'magic',
    label: 'magic',
    type: 'TPM_GENERATED',
    value:
      input.magic === TPM_GENERATED_VALUE
        ? 'TPM_GENERATED_VALUE (0xFF544347)'
        : `NOT TPM_GENERATED_VALUE (0x${input.magic.toString(16).padStart(8, '0')})`,
    note: T.magic,
    depth: 0,
  });

  w.push(u16be(input.type), {
    path: 'type',
    label: 'type',
    type: 'TPMI_ST_ATTEST',
    value: TPM_ST_NAMES[input.type] ?? `unknown (0x${input.type.toString(16)})`,
    note: T.type,
    depth: 0,
  });

  w.push(u16be(input.qualifiedSigner.length), {
    path: 'qualifiedSigner.size',
    label: 'qualifiedSigner.size',
    type: 'UINT16',
    value: `${input.qualifiedSigner.length} bytes`,
    note: 'UINT16 size prefix of the TPM2B_NAME that follows.',
    depth: 1,
  });
  w.push(input.qualifiedSigner, {
    path: 'qualifiedSigner.name',
    label: 'qualifiedSigner.name',
    type: 'TPM2B_NAME',
    value: `${TPM_ALG_NAMES[(input.qualifiedSigner[0] << 8) | input.qualifiedSigner[1]] ?? 'alg?'} + ${input.qualifiedSigner.length - 2}-byte digest`,
    note: T.qualifiedSigner,
    depth: 1,
  });

  w.push(u16be(input.extraData.length), {
    path: 'extraData.size',
    label: 'extraData.size',
    type: 'UINT16',
    value: `${input.extraData.length} bytes`,
    note: T.extraDataSize,
    depth: 1,
  });
  w.push(input.extraData, {
    path: 'extraData.buffer',
    label: 'extraData.buffer',
    type: 'TPM2B_DATA',
    value: 'the relying party’s nonce',
    note: T.extraData,
    depth: 1,
  });

  w.push(u64be(input.clockInfo.clock), {
    path: 'clockInfo.clock',
    label: 'clockInfo.clock',
    type: 'UINT64',
    value: `${input.clockInfo.clock} ms`,
    note: T.clock,
    depth: 1,
  });
  w.push(u32be(input.clockInfo.resetCount), {
    path: 'clockInfo.resetCount',
    label: 'clockInfo.resetCount',
    type: 'UINT32',
    value: String(input.clockInfo.resetCount),
    note: T.resetCount,
    depth: 1,
  });
  w.push(u32be(input.clockInfo.restartCount), {
    path: 'clockInfo.restartCount',
    label: 'clockInfo.restartCount',
    type: 'UINT32',
    value: String(input.clockInfo.restartCount),
    note: T.restartCount,
    depth: 1,
  });
  w.push(u8(input.clockInfo.safe ? 1 : 0), {
    path: 'clockInfo.safe',
    label: 'clockInfo.safe',
    type: 'TPMI_YES_NO',
    value: input.clockInfo.safe ? 'YES' : 'NO',
    note: T.safe,
    depth: 1,
  });

  w.push(u64be(input.firmwareVersion), {
    path: 'firmwareVersion',
    label: 'firmwareVersion',
    type: 'UINT64',
    value: `0x${input.firmwareVersion.toString(16).padStart(16, '0')}`,
    note: T.firmwareVersion,
    depth: 0,
  });

  // TPMU_ATTEST -> TPMS_QUOTE_INFO
  w.push(u32be(1), {
    path: 'attested.pcrSelect.count',
    label: 'attested.pcrSelect.count',
    type: 'UINT32',
    value: '1 bank',
    note: T.pcrSelectCount,
    depth: 1,
  });
  w.push(u16be(input.attested.hashAlg), {
    path: 'attested.pcrSelect.hash',
    label: 'attested.pcrSelect[0].hash',
    type: 'TPMI_ALG_HASH',
    value: TPM_ALG_NAMES[input.attested.hashAlg] ?? `0x${input.attested.hashAlg.toString(16)}`,
    note: T.pcrHashAlg,
    depth: 2,
  });
  w.push(u8(PCR_SELECT_BYTES), {
    path: 'attested.pcrSelect.sizeofSelect',
    label: 'attested.pcrSelect[0].sizeofSelect',
    type: 'UINT8',
    value: `${PCR_SELECT_BYTES} octets`,
    note: T.sizeofSelect,
    depth: 2,
  });
  const bitmap = pcrSelectionBitmap(input.attested.pcrSelect);
  w.push(bitmap, {
    path: 'attested.pcrSelect.bitmap',
    label: 'attested.pcrSelect[0].pcrSelect',
    type: 'BYTE[3]',
    value: `PCRs ${pcrIndicesFromBitmap(bitmap).join(', ')}`,
    note: T.pcrBitmap,
    depth: 2,
  });
  w.push(u16be(input.attested.pcrDigest.length), {
    path: 'attested.pcrDigest.size',
    label: 'attested.pcrDigest.size',
    type: 'UINT16',
    value: `${input.attested.pcrDigest.length} bytes`,
    note: T.pcrDigestSize,
    depth: 2,
  });
  w.push(input.attested.pcrDigest, {
    path: 'attested.pcrDigest.buffer',
    label: 'attested.pcrDigest.buffer',
    type: 'TPM2B_DIGEST',
    value: 'digest over the selected PCRs',
    note: T.pcrDigest,
    depth: 2,
  });

  return w.done();
}

/** The fields every TPMS_ATTEST carries, whatever its `type` selects at the end. */
export interface AttestHeader {
  magic: number;
  type: number;
  qualifiedSigner: Uint8Array;
  extraData: Uint8Array;
  clockInfo: ClockInfo;
  firmwareVersion: bigint;
  /** Offset at which the TPMU_ATTEST union begins. */
  attestedOffset: number;
}

/** A cursor that fails closed on every short read rather than reading past the end. */
class Reader {
  at = 0;
  private readonly view: DataView;
  constructor(private readonly bytes: Uint8Array) {
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }
  private need(n: number, what: string): void {
    if (this.at + n > this.bytes.length) {
      throw new Error(`truncated TPMS_ATTEST: ${what} needs ${n} more byte(s)`);
    }
  }
  u8(what: string): number {
    this.need(1, what);
    return this.bytes[this.at++];
  }
  u16(what: string): number {
    this.need(2, what);
    const v = this.view.getUint16(this.at, false);
    this.at += 2;
    return v;
  }
  u32(what: string): number {
    this.need(4, what);
    const v = this.view.getUint32(this.at, false);
    this.at += 4;
    return v;
  }
  u64(what: string): bigint {
    this.need(8, what);
    const v = this.view.getBigUint64(this.at, false);
    this.at += 8;
    return v;
  }
  take(n: number, what: string): Uint8Array {
    this.need(n, what);
    const out = this.bytes.slice(this.at, this.at + n);
    this.at += n;
    return out;
  }
  /** A TPM2B: UINT16 size prefix then that many bytes. */
  sized(what: string): Uint8Array {
    return this.take(this.u16(`${what}.size`), what);
  }
  get remaining(): number {
    return this.bytes.length - this.at;
  }
}

/**
 * Parse the part of a TPMS_ATTEST that does not depend on `type`.
 *
 * Split out because every attestation structure a TPM produces — quote,
 * certify, time, creation, NV — shares this prefix byte for byte. The lab
 * uses that to run a REAL captured `TPM_ST_ATTEST_CERTIFY` blob through the
 * same reader as its quotes: a header parser that only ever sees structures
 * this repo generated is a parser that has only ever agreed with itself.
 */
export function unmarshalAttestHeader(bytes: Uint8Array): AttestHeader {
  const r = new Reader(bytes);
  const magic = r.u32('magic');
  const type = r.u16('type');
  const qualifiedSigner = r.sized('qualifiedSigner');
  const extraData = r.sized('extraData');
  const clock = r.u64('clockInfo.clock');
  const resetCount = r.u32('clockInfo.resetCount');
  const restartCount = r.u32('clockInfo.restartCount');
  const safeByte = r.u8('clockInfo.safe');
  if (safeByte !== 0 && safeByte !== 1) {
    // TPMI_YES_NO is a BYTE with exactly two legal values; a TPM unmarshalling
    // anything else answers TPM_RC_VALUE, so this parser does the same.
    throw new Error(`TPMI_YES_NO must be 0 or 1, got ${safeByte}`);
  }
  const firmwareVersion = r.u64('firmwareVersion');
  return {
    magic,
    type,
    qualifiedSigner,
    extraData,
    clockInfo: { clock, resetCount, restartCount, safe: safeByte === 1 },
    firmwareVersion,
    attestedOffset: r.at,
  };
}

/**
 * Parse a marshalled TPMS_ATTEST whose `type` is TPM_ST_ATTEST_QUOTE.
 *
 * The verifier uses this rather than being handed the attester's in-memory
 * object, which is the point: a relying party receives BYTES. Every strictness
 * check here — a size prefix that overruns the buffer, trailing bytes after
 * the structure, a `type` that does not select TPMS_QUOTE_INFO — is a real
 * failure a verifier must fail closed on, and each has a test.
 *
 * Note what is NOT checked here: `magic`. Parsing is not judging, and Act 2a
 * turns on keeping the two apart — a structure whose magic is wrong parses
 * perfectly and must be REJECTED by the verifier, not by the reader. Real
 * tooling has had exactly this bug (the tpm2-tools `tpm2_checkquote` /
 * FAPI VerifyQuote advisories).
 */
export function unmarshalAttest(bytes: Uint8Array): AttestInput {
  const header = unmarshalAttestHeader(bytes);
  if (header.type !== TPM_ST.ATTEST_QUOTE) {
    throw new Error(
      `type ${TPM_ST_NAMES[header.type] ?? `0x${header.type.toString(16)}`} does not select ` +
        'TPMS_QUOTE_INFO; the union after firmwareVersion is a different structure'
    );
  }

  const r = new Reader(bytes);
  r.take(header.attestedOffset, 'header');

  const bankCount = r.u32('attested.pcrSelect.count');
  if (bankCount !== 1) {
    throw new Error(`this lab quotes exactly one PCR bank; the structure declares ${bankCount}`);
  }
  const hashAlg = r.u16('attested.pcrSelect[0].hash');
  const sizeofSelect = r.u8('attested.pcrSelect[0].sizeofSelect');
  const bitmap = r.take(sizeofSelect, 'attested.pcrSelect[0].pcrSelect');
  const pcrDigest = r.sized('attested.pcrDigest');

  if (r.remaining !== 0) {
    throw new Error(`trailing bytes after TPMS_ATTEST (${r.remaining} extra)`);
  }

  return {
    magic: header.magic,
    type: header.type,
    qualifiedSigner: header.qualifiedSigner,
    extraData: header.extraData,
    clockInfo: header.clockInfo,
    firmwareVersion: header.firmwareVersion,
    attested: { pcrSelect: pcrIndicesFromBitmap(bitmap), hashAlg, pcrDigest },
  };
}
