import { describe, expect, it } from 'vitest';
import {
  encodeMeasuredComponentCbor,
  encodeMeasuredComponentJson,
  NAMED_INFO_SHA256_NAME,
  VERSION_SCHEME,
} from './measured-component';
import { fromHex, toHex } from '../core/bytes';

/**
 * RFC 10013's own worked examples.
 *
 * The RFC prints them in CBOR diagnostic notation rather than as hex, so the
 * hex asserted below is this encoder's output — pinned so a change to the
 * encoding is loud. What makes these KATs rather than a restatement is
 * Figure 4: the RFC PUBLISHES the base64url text of the same three byte
 * strings that Figure 2 gives in hex, so the JSON assertions below compare
 * this encoder's output against strings printed in the specification.
 * Anything that would corrupt the byte strings — a wrong digest field, a
 * padded base64, a swapped authority — breaks that comparison.
 *
 * The structural assertions are read straight off the CDDL: the map keys, the
 * array shapes, and the fact that `id` is an array rather than a map are all
 * things an implementation gets wrong in a way that still round-trips against
 * itself.
 */
describe('RFC 10013 measured component', () => {
  // The digest from RFC 10013 Figure 2.
  const FIG2_DIGEST = fromHex(
    '3996003d486fb91ffb056f7d03f2b2992b215b31dbe7af4b373431fc7d319da3'
  );

  it('encodes Figure 2’s component identifier and digest', () => {
    const bytes = encodeMeasuredComponentCbor({
      name: 'boot loader X',
      version: { value: '1.2.3rc2', scheme: VERSION_SCHEME.SEMVER },
      digest: { alg: NAMED_INFO_SHA256_NAME, value: FIG2_DIGEST },
    });
    expect(toHex(bytes)).toBe(
      'a2' + // map(2)
        '01' + // key 1 (id)
        '82' + // array(2)
        '6d' +
        '626f6f74206c6f6164657220' +
        '58' + // "boot loader X"
        '82' + // array(2)
        '68' +
        '312e322e337263' +
        '32' + // "1.2.3rc2"
        '194000' + // 16384 (semver)
        '02' + // key 2 (digested-measurement)
        '82' + // array(2)
        '67' +
        '7368612d323536' + // "sha-256"
        '5820' +
        toHex(FIG2_DIGEST)
    );
  });

  it('encodes Figure 6’s raw measured component', () => {
    // { 1: ["hardware-config"], 5: h'4f6d616861' }  ("Omaha")
    const bytes = encodeMeasuredComponentCbor({
      name: 'hardware-config',
      raw: fromHex('4f6d616861'),
    });
    expect(toHex(bytes)).toBe('a201816f68617264776172652d636f6e66696705454f6d616861');
  });

  it('reproduces the base64url strings the RFC prints in Figure 4', () => {
    // Figure 4 is the JSON rendering of Figure 3's component. These three
    // strings are copied out of the RFC; the byte strings are copied out of
    // Figure 2. If the base64url is padded, or the wrong bytes are encoded,
    // the comparison fails.
    const json = encodeMeasuredComponentJson({
      name: 'boot loader X',
      version: { value: '1.2.3rc2', scheme: VERSION_SCHEME.SEMVER },
      digest: { alg: NAMED_INFO_SHA256_NAME, value: FIG2_DIGEST },
    });
    expect(json).toEqual({
      id: ['boot loader X', ['1.2.3rc2', 16384]],
      'digested-measurement': [
        'sha-256',
        'OZYAPUhvuR_7BW99A_KymSshWzHb569LNzQx_H0xnaM',
      ],
    });
  });

  it('uses the RFC’s member names, not the veraison Go implementation’s', () => {
    const json = encodeMeasuredComponentJson({
      name: 'x',
      digest: { alg: 1, value: new Uint8Array(32) },
    });
    expect(Object.keys(json)).toEqual(['id', 'digested-measurement']);
    expect(Object.keys(json)).not.toContain('measurement');
    expect(Object.keys(json)).not.toContain('measurements');
    expect(Object.keys(json)).not.toContain('signers');
  });

  it('puts raw-measurement at key 5, not key 3', () => {
    const bytes = encodeMeasuredComponentCbor({ name: 'a', raw: new Uint8Array([1]) });
    // a2 01 81 6161 05 4101
    expect(toHex(bytes)).toBe('a20181616105' + '4101');
  });

  it('refuses a component with both a digest and a raw value', () => {
    expect(() =>
      encodeMeasuredComponentCbor({
        name: 'a',
        raw: new Uint8Array([1]),
        digest: { alg: 1, value: new Uint8Array(32) },
      })
    ).toThrow(/exactly one/);
  });

  it('refuses a component with neither measurement form', () => {
    expect(() => encodeMeasuredComponentCbor({ name: 'a' })).toThrow(/exactly one/);
  });

  it('omits the version array entirely when there is no version', () => {
    const bytes = encodeMeasuredComponentCbor({
      name: 'a',
      digest: { alg: 1, value: new Uint8Array(1) },
    });
    // id is a ONE-element array here: 81, not 82.
    expect(toHex(bytes).startsWith('a2018161')).toBe(true);
  });
});
