import { describe, expect, it } from 'vitest';
import {
  computeName,
  marshalAttest,
  pcrIndicesFromBitmap,
  pcrSelectionBitmap,
  qualifiedName,
  unmarshalAttest,
  unmarshalAttestHeader,
} from './marshal';
import { TPM_ALG, TPM_GENERATED_VALUE, TPM_ST } from './constants';
import { fromHex, toHex, utf8 } from '../core/bytes';
import { sha256 } from '../core/sha256';

/**
 * The two vectors below are REAL TPM output, not structures this repo made.
 * That distinction is the whole value of them: a marshaller tested only
 * against its own unmarshaller agrees with itself no matter how wrong it is,
 * which is exactly how the "signature over (PCR digest || nonce)" shape this
 * lab was nearly built on would have passed its tests.
 *
 * KAT 1 — a TPM2_Quote captured with tpm2-tools:
 *   tpm2_quote -c 0x81010003 -l sha1:0,1,2,3,4,5,6,7,8,9 \
 *              -m quote.msg -s quote.sig -g sha256 -q 123456
 *   (nokia/TPMCourse, docs/quoting.md — the blob and its `tpm2_print` decode.)
 *
 * KAT 2 — a Windows Hello WebAuthn TPM attestation `certInfo`, which is a
 *   TPM_ST_ATTEST_CERTIFY rather than a quote. It exercises the shared header
 *   and proves the `Name = nameAlg || H(TPMT_PUBLIC)` rule against a real
 *   public area. (Yubico/python-fido2, tests/test_attestation.py.)
 */

const QUOTE_KAT = fromHex(
  'ff54434780180022000b36ec8291b370f278c241fe44260da8b24f7bc472879d13c48' +
    '88017643de294080003123456000000000007b15e00000001000000000120170619' +
    '0016363600000001000403ff0300' +
    '0020900e54b2767b470bf08fb69a1270723a6e2b0f44c661bce7b4a89244a077f9cb'
);

/** The ten SHA-1 PCR values the same capture lists for PCRs 0..9. */
const QUOTE_KAT_PCRS = [
  '7EBA0CFB74F41FEBCCDD1251F02BC208052B6023',
  'B8720B5234E2F08CFA87069F172CBB43F0F08225',
  '86FA03B9C721AF57DE8FB1C43CC3FE7B0A42239A',
  'B2A83B0EBF2F8374299A5B2BDFC31EA955AD7236',
  'AB705AAE41789E02A1909B2CBB8BFC0806115004',
  '7B25D2EABBA18DC910E724A0C75020F1FEC80BE2',
  'B2A83B0EBF2F8374299A5B2BDFC31EA955AD7236',
  '518BD167271FBB64589C61E43D8C0165861431D8',
  'C3DF1A5D37AC51163C63320F28B9C1C1FD933BD2',
  '944C3EFEB668CB217B260F7D4B594DA4341E6FF2',
].map((h) => fromHex(h));

const CERTIFY_KAT = fromHex(
  'ff54434780170022000b68cec627cc6411099a1f809fde4379f649aa170c7072d1adf' +
    '230de439efc80810014f7c8b0cdeb31328648130a19733d6fff16e76e1300000003' +
    'ef605603446ed8c56aa7608d01a6ea5651ee67a8a20022000bdf681917e18529c61' +
    'e1b85a1e7952f3201eb59c609ed5d8e217e5de76b228bbd0022000b0a10d216b0c3' +
    'ab82bfdc1f0a016ab9493384c7aee1937ee8800f76b30c9b71a7'
);

describe('TPMS_ATTEST — real captured TPM output', () => {
  it('parses a real tpm2_quote blob field for field, consuming every byte', () => {
    expect(QUOTE_KAT.length).toBe(116);
    const a = unmarshalAttest(QUOTE_KAT);
    expect(a.magic).toBe(TPM_GENERATED_VALUE);
    expect(a.type).toBe(TPM_ST.ATTEST_QUOTE);
    expect(a.qualifiedSigner.length).toBe(34);
    expect(toHex(a.qualifiedSigner.slice(0, 2))).toBe('000b');
    expect(toHex(a.extraData)).toBe('123456');
    expect(a.clockInfo.clock).toBe(504158n);
    expect(a.clockInfo.resetCount).toBe(1);
    expect(a.clockInfo.restartCount).toBe(0);
    expect(a.clockInfo.safe).toBe(true);
    expect(a.firmwareVersion).toBe(0x2017061900163636n);
    expect(a.attested.hashAlg).toBe(TPM_ALG.SHA1);
    expect(a.attested.pcrSelect).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    expect(toHex(a.attested.pcrDigest)).toBe(
      '900e54b2767b470bf08fb69a1270723a6e2b0f44c661bce7b4a89244a077f9cb'
    );
  });

  it('recomputes that quote’s pcrDigest from the published PCR values', () => {
    // Three normative rules are proven at once here: the concatenation order
    // (ascending PCR index), the absence of separators or length prefixes,
    // and — the subtle one — that the OUTER hash is the signing scheme's hash
    // (SHA-256, from `-g sha256`) and not the quoted bank's (SHA-1).
    const concatenated = new Uint8Array(QUOTE_KAT_PCRS.length * 20);
    QUOTE_KAT_PCRS.forEach((v, i) => concatenated.set(v, i * 20));
    expect(concatenated.length).toBe(200);
    expect(toHex(sha256(concatenated))).toBe(
      '900e54b2767b470bf08fb69a1270723a6e2b0f44c661bce7b4a89244a077f9cb'
    );
  });

  it('re-marshals the parsed quote back to the identical 116 bytes', () => {
    const a = unmarshalAttest(QUOTE_KAT);
    expect(toHex(marshalAttest(a).bytes)).toBe(toHex(QUOTE_KAT));
  });

  it('parses the shared header of a real TPM_ST_ATTEST_CERTIFY blob', () => {
    const h = unmarshalAttestHeader(CERTIFY_KAT);
    expect(h.magic).toBe(TPM_GENERATED_VALUE);
    expect(h.type).toBe(TPM_ST.ATTEST_CERTIFY);
    expect(h.extraData.length).toBe(20);
    expect(toHex(h.extraData)).toBe('f7c8b0cdeb31328648130a19733d6fff16e76e13');
    expect(h.clockInfo.clock).toBe(0x00000003ef605603n);
    expect(h.clockInfo.safe).toBe(true);
    expect(h.attestedOffset).toBe(89);
  });

  it('refuses to read a certify blob as a quote instead of misparsing it', () => {
    expect(() => unmarshalAttest(CERTIFY_KAT)).toThrow(/TPM_ST_ATTEST_CERTIFY/);
  });
});

describe('TPM2B_NAME', () => {
  it('is nameAlg || H(TPMT_PUBLIC), 34 bytes for SHA-256', () => {
    const publicArea = utf8('a marshalled TPMT_PUBLIC stands here');
    const name = computeName(publicArea);
    expect(name.length).toBe(34);
    expect(toHex(name.slice(0, 2))).toBe('000b');
    expect(toHex(name.slice(2))).toBe(toHex(sha256(publicArea)));
  });

  it('composes a Qualified Name by hashing the parent QN with the child Name', () => {
    const parentQn = sha256(utf8('parent'));
    const name = computeName(utf8('child public area'));
    expect(toHex(qualifiedName(parentQn, name))).toBe(
      toHex(sha256(new Uint8Array([...parentQn, ...name])))
    );
  });
});

describe('TPMS_PCR_SELECTION bitmap', () => {
  // The spec's own worked examples. The bit order inside each octet is
  // LITTLE-endian, the opposite of every integer in the rest of the structure,
  // which is why this is the classic byte-exactness bug.
  it('matches Part 2 §10.6.1 EXAMPLE 2: PCR 19 alone is 00 00 08', () => {
    expect(toHex(pcrSelectionBitmap([19]))).toBe('000008');
  });

  it('matches Part 1 §17.5: PCR 0 and PCR 13 are 01 20 (in the first two octets)', () => {
    expect(toHex(pcrSelectionBitmap([0, 13])).slice(0, 4)).toBe('0120');
  });

  it('places PCR 0, 8 and 17 in the documented octets and bits', () => {
    expect(toHex(pcrSelectionBitmap([0]))).toBe('010000');
    expect(toHex(pcrSelectionBitmap([8]))).toBe('000100');
    expect(toHex(pcrSelectionBitmap([17]))).toBe('000002');
    expect(toHex(pcrSelectionBitmap([7]))).toBe('800000');
    expect(toHex(pcrSelectionBitmap([23]))).toBe('000080');
  });

  it('round-trips every subset of a representative PCR set', () => {
    const universe = [0, 1, 4, 7, 8, 13, 17, 23];
    for (let mask = 0; mask < 1 << universe.length; mask++) {
      const chosen = universe.filter((_, i) => mask & (1 << i));
      expect(pcrIndicesFromBitmap(pcrSelectionBitmap(chosen))).toEqual(chosen);
    }
  });

  it('rejects a PCR index outside the implemented bank', () => {
    expect(() => pcrSelectionBitmap([24])).toThrow(/out of range/);
    expect(() => pcrSelectionBitmap([-1])).toThrow(/out of range/);
  });
});

describe('TPMS_ATTEST — fail-closed parsing', () => {
  const good = QUOTE_KAT;

  it('rejects a truncated structure rather than returning a partial parse', () => {
    for (const cut of [3, 7, 40, 80, 115]) {
      expect(() => unmarshalAttest(good.slice(0, cut)), `cut at ${cut}`).toThrow(/truncated/);
    }
  });

  it('rejects trailing bytes after the structure', () => {
    expect(() => unmarshalAttest(new Uint8Array([...good, 0x00]))).toThrow(/trailing bytes/);
  });

  it('rejects a size prefix that overruns the buffer', () => {
    const overrun = good.slice();
    overrun[6] = 0xff; // qualifiedSigner.size high byte
    expect(() => unmarshalAttest(overrun)).toThrow(/truncated/);
  });

  it('rejects a TPMI_YES_NO that is neither 0 nor 1', () => {
    const bad = good.slice();
    bad[63] = 0x02; // clockInfo.safe
    expect(() => unmarshalAttest(bad)).toThrow(/TPMI_YES_NO/);
  });

  it('parses a structure whose magic is wrong — judging it is the verifier’s job', () => {
    const forged = good.slice();
    forged.set([0x00, 0x00, 0x00, 0x00], 0);
    const a = unmarshalAttest(forged);
    expect(a.magic).not.toBe(TPM_GENERATED_VALUE);
    expect(a.attested.pcrSelect).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
  });
});

describe('TPMS_ATTEST — the field map the inspector renders', () => {
  const a = unmarshalAttest(QUOTE_KAT);
  const { bytes, fields } = marshalAttest(a);

  it('covers every byte exactly once, in order', () => {
    let at = 0;
    for (const f of fields) {
      expect(f.offset, `${f.path} starts where the previous field ended`).toBe(at);
      at += f.length;
    }
    expect(at).toBe(bytes.length);
  });

  it('reports each field’s own bytes', () => {
    for (const f of fields) {
      expect(toHex(bytes.slice(f.offset, f.offset + f.length)), f.path).toBe(f.hex);
    }
  });

  it('gives every field a unique path and a non-empty teaching note', () => {
    expect(new Set(fields.map((f) => f.path)).size).toBe(fields.length);
    for (const f of fields) {
      expect(f.note.length, f.path).toBeGreaterThan(20);
      expect(f.label.length, f.path).toBeGreaterThan(0);
    }
  });

  it('decodes the magic field by name when it is right and flags it when it is not', () => {
    expect(fields[0].value).toContain('TPM_GENERATED_VALUE');
    const forged = marshalAttest({ ...a, magic: 0x00000000 });
    expect(forged.fields[0].value).toContain('NOT TPM_GENERATED_VALUE');
  });
});
