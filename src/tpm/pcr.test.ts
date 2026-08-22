import { describe, expect, it } from 'vitest';
import { isResettableGuard, PcrBank, resetRule, resetValue } from './pcr';
import { concatBytes, toHex, utf8 } from '../core/bytes';
import { sha256 } from '../core/sha256';

describe('PCR extend', () => {
  it('is exactly H(old || measurement), with the old value FIRST', () => {
    const bank = new PcrBank();
    const m = sha256(utf8('a measurement'));
    const record = bank.extend(4, m, 'test');
    expect(toHex(record.preimage)).toBe(toHex(concatBytes(new Uint8Array(32), m)));
    expect(toHex(record.after)).toBe(toHex(sha256(record.preimage)));
    expect(toHex(bank.read(4))).toBe(toHex(record.after));
  });

  it('hashes exactly 64 bytes in the SHA-256 bank — no tag, no length, no separator', () => {
    const bank = new PcrBank();
    const record = bank.extend(4, sha256(utf8('x')), 'test');
    expect(record.preimage.length).toBe(64);
  });

  it('is order-dependent: the same two measurements in the other order differ', () => {
    const a = sha256(utf8('kernel'));
    const b = sha256(utf8('initrd'));
    const one = new PcrBank();
    one.extend(9, a, '');
    one.extend(9, b, '');
    const two = new PcrBank();
    two.extend(9, b, '');
    two.extend(9, a, '');
    expect(toHex(one.read(9))).not.toBe(toHex(two.read(9)));
  });

  it('refuses anything that is not a bank-sized digest', () => {
    const bank = new PcrBank();
    expect(() => bank.extend(0, new Uint8Array(20), '')).toThrow(/32-byte digest/);
    expect(() => bank.extend(0, new Uint8Array(0), '')).toThrow(/32-byte digest/);
  });

  it('rejects a PCR index outside the implemented bank', () => {
    const bank = new PcrBank();
    expect(() => bank.read(24)).toThrow(/out of range/);
    expect(() => bank.extend(-1, new Uint8Array(32), '')).toThrow(/out of range/);
  });
});

describe('PCR initial values (PC Client PTP Table 7)', () => {
  it('brings PCR 0–16 and 23 up all-zero', () => {
    for (const pcr of [0, 1, 4, 8, 9, 10, 15, 16, 23]) {
      expect(toHex(resetValue(pcr)), `PCR ${pcr}`).toBe('00'.repeat(32));
    }
  });

  it('brings the D-RTM set 17–22 up all-ONES', () => {
    for (const pcr of [17, 18, 19, 20, 21, 22]) {
      expect(toHex(resetValue(pcr)), `PCR ${pcr}`).toBe('ff'.repeat(32));
    }
  });

  it('puts the startup locality in the last octet of PCR 0', () => {
    // "In a TPMA_LOCALITY, a locality of four would be represented by the octet
    // 0001 0000b. When encoded for a PCR initial value, locality 4 would be
    // represented by the octet 0000 0100b."
    expect(toHex(resetValue(0, 4))).toBe('00'.repeat(31) + '04');
    expect(toHex(resetValue(0, 3))).toBe('00'.repeat(31) + '03');
  });
});

describe('PCR reset authority (PC Client PTP Table 6)', () => {
  it('gives the static set 0–15 no reset authorisation at any locality', () => {
    for (let pcr = 0; pcr <= 15; pcr++) {
      expect(resetRule(pcr).resettable, `PCR ${pcr}`).toBe(false);
      expect(resetRule(pcr).drtmReset, `PCR ${pcr}`).toBe(false);
    }
  });

  it('lets ordinary software reset PCR 16 and 23 at localities 0–3, but not 4', () => {
    for (const pcr of [16, 23]) {
      expect(resetRule(pcr).localities).toEqual([0, 1, 2, 3]);
      const bank = new PcrBank();
      bank.extend(pcr, sha256(utf8('x')), '');
      expect(toHex(bank.read(pcr))).not.toBe('00'.repeat(32));
      bank.reset(pcr, 0);
      expect(toHex(bank.read(pcr))).toBe('00'.repeat(32));
      expect(() => bank.reset(pcr, 4)).toThrow(/locality 4/);
    }
  });

  it('never lets TPM2_PCR_Reset touch PCR 17, 18 or 19', () => {
    const bank = new PcrBank();
    for (const pcr of [17, 18, 19]) {
      expect(resetRule(pcr).resettable).toBe(false);
      expect(resetRule(pcr).drtmReset).toBe(true);
      expect(() => bank.reset(pcr, 4)).toThrow(/no reset authorisation/);
      expect(() => bank.reset(pcr, 0)).toThrow(/no reset authorisation/);
    }
  });

  it('lets PCR 20–22 be reset at localities 2 and 3 only', () => {
    for (const pcr of [20, 21, 22]) {
      expect(resetRule(pcr).localities).toEqual([2, 3]);
      const bank = new PcrBank();
      expect(() => bank.reset(pcr, 0)).toThrow(/locality 0/);
      bank.reset(pcr, 2);
      // The sharp corner: PCR 20-22 power on to all-ONES, and TPM2_PCR_Reset
      // sets them to ZERO. "Reset" and "initial" are different values.
      expect(toHex(bank.read(pcr))).toBe('00'.repeat(32));
      expect(toHex(resetValue(pcr))).toBe('ff'.repeat(32));
    }
  });

  it('agrees with itself: every PCR the guard calls one-way refuses every reset', () => {
    const bank = new PcrBank();
    for (let pcr = 0; pcr < 24; pcr++) {
      if (isResettableGuard(pcr)) continue;
      for (const locality of [0, 1, 2, 3, 4]) {
        expect(() => bank.reset(pcr, locality), `PCR ${pcr} @ ${locality}`).toThrow();
      }
    }
  });
});

describe('PCR composite digest', () => {
  it('concatenates in ASCENDING index order regardless of the selection order', () => {
    const bank = new PcrBank();
    bank.extend(0, sha256(utf8('a')), '');
    bank.extend(4, sha256(utf8('b')), '');
    bank.extend(9, sha256(utf8('c')), '');
    const expected = sha256(concatBytes(bank.read(0), bank.read(4), bank.read(9)));
    expect(toHex(bank.digest([9, 0, 4]))).toBe(toHex(expected));
    expect(toHex(bank.digest([0, 4, 9]))).toBe(toHex(expected));
  });

  it('deduplicates a repeated index rather than hashing it twice', () => {
    const bank = new PcrBank();
    bank.extend(0, sha256(utf8('a')), '');
    expect(toHex(bank.digest([0, 0, 0]))).toBe(toHex(bank.digest([0])));
  });

  it('includes an untouched PCR at its reset value, not as nothing', () => {
    const bank = new PcrBank();
    bank.extend(0, sha256(utf8('a')), '');
    expect(toHex(bank.digest([0, 4]))).toBe(
      toHex(sha256(concatBytes(bank.read(0), new Uint8Array(32))))
    );
  });
});
