import { describe, expect, it } from 'vitest';
import {
  cloneStages,
  DEFAULT_STAGES,
  EV_SEPARATOR_BYTES,
  EV_SEPARATOR_SHA256,
  QUOTED_PCRS,
  referenceValues,
  RUNTIME_MEASUREMENT_PCR,
  runMeasuredBoot,
} from './stages';
import { concatBytes, toHex, utf8 } from '../core/bytes';
import { sha256 } from '../core/sha256';
import { resetValue } from '../tpm/pcr';

describe('EV_SEPARATOR', () => {
  it('digests the four octets the PFP allows, to the published constant', () => {
    // The PFP fixes the event data at 4 bytes, 00000000h or FFFFFFFFh. Both
    // are byte-order palindromes, so this vector also settles that the raw
    // octets are hashed rather than any re-encoded integer.
    expect(toHex(sha256(EV_SEPARATOR_BYTES))).toBe(EV_SEPARATOR_SHA256);
    expect(toHex(sha256(new Uint8Array([0xff, 0xff, 0xff, 0xff])))).toBe(
      'ad95131bc0b799c0b1af477fb14fcf26a6a9f76079e48bf090acb7e8367bfd0e'
    );
  });

  it('is not editable — its bytes are fixed by the specification', () => {
    expect(DEFAULT_STAGES.find((s) => s.id === 'separator')!.editable).toBe(false);
  });
});

describe('The measured boot chain', () => {
  it('measures each stage into the PCR its source assigns', () => {
    const byId = Object.fromEntries(DEFAULT_STAGES.map((s) => [s.id, s]));
    expect(byId.firmware.pcr).toBe(0);
    expect(byId.separator.pcr).toBe(0);
    expect(byId.bootloader.pcr).toBe(4);
    expect(byId.cmdline.pcr).toBe(8);
    expect(byId.kernel.pcr).toBe(9);
    expect(byId.initrd.pcr).toBe(9);
  });

  it('labels TCG assignments and bootloader conventions differently', () => {
    const byId = Object.fromEntries(DEFAULT_STAGES.map((s) => [s.id, s]));
    // PCR 0-7 are normative; PCR 8/9 are GRUB's own choice inside the range
    // the PFP hands to the "Static OS" without saying what goes there.
    expect(byId.firmware.pcrSource).toBe('TCG PC Client Platform Firmware Profile');
    expect(byId.bootloader.pcrSource).toBe('TCG PC Client Platform Firmware Profile');
    expect(byId.cmdline.pcrSource).toBe('GRUB2 convention');
    expect(byId.kernel.pcrSource).toBe('GRUB2 convention');
  });

  it('does not quote the PCR a runtime measurement architecture would use', () => {
    expect(RUNTIME_MEASUREMENT_PCR).toBe(10);
    expect(QUOTED_PCRS).not.toContain(RUNTIME_MEASUREMENT_PCR);
  });

  it('quotes only PCRs the "one-way" claim is actually true for', () => {
    // Every quoted register is in the 0-15 static set, which is the only range
    // TPM2_PCR_Reset can never touch at any locality.
    for (const pcr of QUOTED_PCRS) expect(pcr).toBeLessThanOrEqual(15);
  });

  it('accumulates two measurements into PCR 9, in order', () => {
    const { bank } = runMeasuredBoot(DEFAULT_STAGES);
    const kernel = sha256(utf8(DEFAULT_STAGES.find((s) => s.id === 'kernel')!.content));
    const initrd = sha256(utf8(DEFAULT_STAGES.find((s) => s.id === 'initrd')!.content));
    // Re-derived by hand from the definition, not by calling the bank again.
    const afterKernel = sha256(concatBytes(resetValue(9), kernel));
    const afterInitrd = sha256(concatBytes(afterKernel, initrd));
    expect(toHex(bank.read(9))).toBe(toHex(afterInitrd));
  });

  it('changes exactly one register when exactly one stage changes', () => {
    const before = referenceValues(DEFAULT_STAGES);
    const stages = cloneStages(DEFAULT_STAGES);
    stages.find((s) => s.id === 'bootloader')!.content += ' ';
    const after = referenceValues(stages);
    const changed = [...before.keys()].filter((pcr) => before.get(pcr) !== after.get(pcr));
    expect(changed).toEqual([4]);
  });

  it('changes the kernel register but not the loader’s when the kernel changes', () => {
    const before = referenceValues(DEFAULT_STAGES);
    const stages = cloneStages(DEFAULT_STAGES);
    stages.find((s) => s.id === 'kernel')!.content = 'vmlinuz-6.12.10 / 000000 / signed';
    const after = referenceValues(stages);
    const changed = [...before.keys()].filter((pcr) => before.get(pcr) !== after.get(pcr));
    expect(changed).toEqual([9]);
  });

  it('is one-way in the sense that matters: no reordering reproduces the value', () => {
    const stages = cloneStages(DEFAULT_STAGES);
    const k = stages.findIndex((s) => s.id === 'kernel');
    const i = stages.findIndex((s) => s.id === 'initrd');
    [stages[k], stages[i]] = [stages[i], stages[k]];
    expect(referenceValues(stages).get(9)).not.toBe(referenceValues(DEFAULT_STAGES).get(9));
  });

  it('cloneStages produces an independent copy', () => {
    const copy = cloneStages(DEFAULT_STAGES);
    copy[0].content = 'mutated';
    expect(DEFAULT_STAGES[0].content).not.toBe('mutated');
  });

  it('produces a reference value for every quoted PCR', () => {
    const refs = referenceValues(DEFAULT_STAGES);
    for (const pcr of QUOTED_PCRS) {
      expect(refs.get(pcr), `PCR ${pcr}`).toMatch(/^[0-9a-f]{64}$/);
      expect(refs.get(pcr)).not.toBe('00'.repeat(32));
    }
  });
});
