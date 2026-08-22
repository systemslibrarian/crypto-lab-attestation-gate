import { describe, expect, it } from 'vitest';
import { CLAIM, CLAIM_JSON_NAME, DBGSTAT, encodeEatCbor, encodeEatJson, UEID_TYPE } from './claims';
import { CONTENT_FORMAT, NAMED_INFO_SHA256 } from './measured-component';
import { fromHex, toBase64Url, toHex, utf8 } from '../core/bytes';
import { sha256 } from '../core/sha256';
import type { EatEvidenceInput } from './claims';

function baseInput(): EatEvidenceInput {
  return {
    nonce: sha256(utf8('nonce')),
    ueid: new Uint8Array([UEID_TYPE.RAND, ...sha256(utf8('ueid')).slice(0, 16)]),
    oemid: sha256(utf8('oem')).slice(0, 16),
    hwmodel: sha256(utf8('model')).slice(0, 8),
    hwversion: { value: '1.4.0', scheme: 1 },
    bootcount: 41,
    dbgstat: DBGSTAT.DISABLED_SINCE_BOOT,
    iat: 1_776_000_000,
    profile: 'https://example.test/profile/v1',
    components: [{ name: 'firmware', digest: { alg: NAMED_INFO_SHA256, value: sha256(utf8('fw')) } }],
  };
}

describe('RFC 9711 claim keys', () => {
  it('uses the registered CBOR claim keys', () => {
    expect(CLAIM.EAT_NONCE).toBe(10);
    expect(CLAIM.UEID).toBe(256);
    expect(CLAIM.OEMID).toBe(258);
    expect(CLAIM.HWMODEL).toBe(259);
    expect(CLAIM.HWVERSION).toBe(260);
    expect(CLAIM.DBGSTAT).toBe(263);
    expect(CLAIM.EAT_PROFILE).toBe(265);
    expect(CLAIM.BOOTCOUNT).toBe(267);
    expect(CLAIM.BOOTSEED).toBe(268);
    expect(CLAIM.MEASUREMENTS).toBe(273);
    expect(CLAIM.MEASRES).toBe(274);
    expect(CLAIM.IAT).toBe(6);
  });

  it('uses the JWT names, which are not the registry’s "Claim Name" column', () => {
    // The registry labels these "Nonce", "UEID", "Boot Seed" and "Software
    // Measurement Results". Those are human-readable labels, not wire names.
    expect(CLAIM_JSON_NAME[CLAIM.EAT_NONCE]).toBe('eat_nonce');
    expect(CLAIM_JSON_NAME[CLAIM.BOOTSEED]).toBe('bootseed');
    expect(CLAIM_JSON_NAME[CLAIM.MEASRES]).toBe('measres');
    // CWT key 7 is `cti`; the JWT counterpart is `jti` — a different name AND
    // a different type.
    expect(CLAIM_JSON_NAME[CLAIM.CTI]).toBe('jti');
  });

  it('spells the boot seed and measurement-results claims the way the RFC does', () => {
    expect(Object.values(CLAIM_JSON_NAME)).not.toContain('boot_seed');
    expect(Object.values(CLAIM_JSON_NAME)).not.toContain('measurement-results');
  });

  it('encodes each claim key with the shortest CBOR head', () => {
    const cbor = toHex(encodeEatCbor(baseInput()));
    expect(cbor).toContain('0a'); // eat_nonce -> 0x0a
    expect(cbor).toContain('190100'); // ueid -> 0x19 0x01 0x00
    expect(cbor).toContain('190111'); // measurements -> 0x19 0x01 0x11
  });
});

describe('The EAT claims-set this lab emits', () => {
  it('carries measurements as [content-format, wrapped body] pairs', () => {
    const json = encodeEatJson(baseInput()) as Record<string, unknown>;
    const measurements = json.measurements as unknown[][];
    expect(measurements).toHaveLength(1);
    expect(measurements[0][0]).toBe(CONTENT_FORMAT.MEASURED_COMPONENT_JSON);
    // In BOTH serializations the component is an opaque string, never a
    // directly nested object — RFC 10013 §4.4.
    expect(typeof measurements[0][1]).toBe('string');
    const inner = JSON.parse(measurements[0][1] as string);
    expect(Object.keys(inner)).toEqual(['id', 'digested-measurement']);
  });

  it('uses content-format 295 in CBOR and 296 in JSON', () => {
    const cbor = toHex(encodeEatCbor(baseInput()));
    expect(cbor).toContain('190127'); // 295
    const json = encodeEatJson(baseInput()) as Record<string, unknown>;
    expect((json.measurements as unknown[][])[0][0]).toBe(296);
  });

  it('base64url-encodes byte strings in JSON, unpadded', () => {
    const input = baseInput();
    const json = encodeEatJson(input) as Record<string, string>;
    expect(json.eat_nonce).toBe(toBase64Url(input.nonce));
    expect(json.eat_nonce).not.toContain('=');
    expect(json.ueid).not.toContain('=');
  });

  it('renders dbgstat as an integer in CBOR and its string in JSON', () => {
    const json = encodeEatJson(baseInput()) as Record<string, string>;
    expect(json.dbgstat).toBe('disabled-since-boot');
    expect(DBGSTAT.DISABLED_SINCE_BOOT).toBe(2);
  });

  it('enforces the inter-claim MUSTs rather than emitting an illegal token', () => {
    expect(() => encodeEatCbor({ ...baseInput(), nonce: new Uint8Array(7) })).toThrow(/8\.\.64/);
    expect(() => encodeEatCbor({ ...baseInput(), nonce: new Uint8Array(65) })).toThrow(/8\.\.64/);
    expect(() => encodeEatCbor({ ...baseInput(), ueid: new Uint8Array(6) })).toThrow(/7\.\.33/);
    // A RAND-type UEID must carry at least 128 bits.
    expect(() =>
      encodeEatCbor({ ...baseInput(), ueid: new Uint8Array([UEID_TYPE.RAND, ...new Uint8Array(10)]) })
    ).toThrow(/128 bits/);
    expect(() => encodeEatCbor({ ...baseInput(), oemid: new Uint8Array(8) })).toThrow(/16-byte/);
    expect(() => encodeEatCbor({ ...baseInput(), hwmodel: new Uint8Array(33) })).toThrow(/1\.\.32/);
    expect(() => encodeEatCbor({ ...baseInput(), iat: 1.5 })).toThrow(/floating-point/);
    expect(() => encodeEatCbor({ ...baseInput(), dbgstat: 9 })).toThrow(/not extensible/);
  });

  it('is deterministic: the same claims produce the same bytes', () => {
    expect(toHex(encodeEatCbor(baseInput()))).toBe(toHex(encodeEatCbor(baseInput())));
  });

  it('sorts claim keys ascending in the CBOR map regardless of authoring order', () => {
    const cbor = toHex(encodeEatCbor(baseInput()));
    // iat (6) comes before eat_nonce (10), which comes before ueid (256).
    const iatAt = cbor.indexOf('06');
    const nonceAt = cbor.indexOf('0a');
    const ueidAt = cbor.indexOf('190100');
    expect(iatAt).toBeLessThan(nonceAt);
    expect(nonceAt).toBeLessThan(ueidAt);
  });

  it('omits authorities and flags, which a profile-blind consumer MUST reject', () => {
    // RFC 10013 §4.5: "If the profile of the EAT is not known to the consumer
    // and one or more measured components within that EAT include authorities
    // and/or profile flags, the consumer MUST reject the EAT."
    const json = encodeEatJson(baseInput()) as Record<string, unknown>;
    const inner = JSON.parse((json.measurements as unknown[][])[0][1] as string);
    expect(inner.authorities).toBeUndefined();
    expect(inner.flags).toBeUndefined();
    expect(toHex(encodeEatCbor(baseInput()))).not.toContain(
      toHex(fromHex('48')) + '0000000000000101'
    );
  });
});
