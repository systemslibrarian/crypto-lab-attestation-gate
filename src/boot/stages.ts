/**
 * Measured boot: the transitive-trust chain, as a list of stages.
 *
 * The rule that makes this a chain rather than a list: each stage measures the
 * NEXT one into a PCR *before* transferring control to it. Nothing measures
 * itself after the fact, and nothing gets to run before its measurement has
 * landed. The TCG PC Client Platform Firmware Profile states the order
 * normatively (§7.2.4); the interesting consequence is that a stage cannot
 * un-say what an earlier stage recorded, because Extend folds the old register
 * value into the new one.
 *
 * PCR allocation, and where each number actually comes from — because half of
 * these are TCG assignments and half are bootloader conventions, and a lab
 * that blurs the two teaches a spec that does not exist:
 *
 *   PCR 0  TCG PFP Table 1 — "SRTM, BIOS, Host Platform Extensions, Embedded
 *          Option ROMs and PI Drivers". Normative.
 *   PCR 4  TCG PFP Table 1 — "UEFI Boot Manager Code (usually the MBR) and
 *          Boot Attempts". The shim/GRUB PE image lands here. Normative.
 *   PCR 8  GRUB2's `GRUB_STRING_PCR` (include/grub/tpm.h). NOT a TCG
 *          assignment: the PFP says only that PCR 8-15 are "defined for use by
 *          the Static OS".
 *   PCR 9  GRUB2's `GRUB_BINARY_PCR`. Also a convention, not a TCG assignment.
 *
 * And the one this exhibit is really about:
 *
 *   PCR 10 Linux IMA's default (`CONFIG_IMA_MEASURE_PCR_IDX`, range 8-14,
 *          default 10). Runtime measurement. It is NOT in this lab's quote,
 *          and Act 6 is precisely about what that omission costs.
 */

import { toHex, utf8 } from '../core/bytes';
import { sha256 } from '../core/sha256';
import { PcrBank, type ExtendRecord } from '../tpm/pcr';

export interface BootStage {
  id: string;
  /** What is being measured. */
  name: string;
  /** Which component performs the measurement — the previous link in the chain. */
  measuredBy: string;
  pcr: number;
  /** The TCG event type, by name and value. */
  eventType: { name: string; value: number };
  /** Where the PCR number comes from: the spec, or a bootloader convention. */
  pcrSource: 'TCG PC Client Platform Firmware Profile' | 'GRUB2 convention';
  /** The bytes measured. Editable in Act 3; the digest is recomputed from them. */
  content: string;
  /** Whether the learner may edit this stage's content. */
  editable: boolean;
  /** One line explaining what this beat of the chain is for. */
  note: string;
}

/**
 * EV_SEPARATOR's event data is four octets, and the PFP allows exactly two
 * normal values: 00000000h or FFFFFFFFh. Its digest is therefore a published
 * constant; `stages.test.ts` checks this repo's SHA-256 reproduces it.
 */
export const EV_SEPARATOR_BYTES = new Uint8Array([0, 0, 0, 0]);
export const EV_SEPARATOR_SHA256 =
  'df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119';

export const DEFAULT_STAGES: BootStage[] = [
  {
    id: 'firmware',
    name: 'Platform firmware (POST BIOS)',
    measuredBy: 'S-CRTM (the immutable root of trust for measurement)',
    pcr: 0,
    eventType: { name: 'EV_POST_CODE', value: 0x00000001 },
    pcrSource: 'TCG PC Client Platform Firmware Profile',
    content: 'OpenFW 3.4.2 / POST / build 20260114',
    editable: true,
    note:
      'The chain has to start somewhere unmeasurable. The S-CRTM is a small piece of firmware ' +
      'the platform cannot rewrite, and it measures the rest of the firmware before running it. ' +
      'Everything after this is measured by something already measured.',
  },
  {
    id: 'separator',
    name: 'EV_SEPARATOR (firmware hands over)',
    measuredBy: 'Platform firmware',
    pcr: 0,
    eventType: { name: 'EV_SEPARATOR', value: 0x00000004 },
    pcrSource: 'TCG PC Client Platform Firmware Profile',
    content: '00000000',
    editable: false,
    note:
      'A one-way epoch marker built out of nothing but Extend. After it, PCR 0 can never again ' +
      'hold the value it had while firmware was in control — which is how a secret sealed to ' +
      'the pre-handover value becomes unsealable by anything the OS runs.',
  },
  {
    id: 'bootloader',
    name: 'Boot loader (shim → GRUB, PE/COFF image)',
    measuredBy: 'UEFI Boot Manager',
    pcr: 4,
    eventType: { name: 'EV_EFI_BOOT_SERVICES_APPLICATION', value: 0x80000003 },
    pcrSource: 'TCG PC Client Platform Firmware Profile',
    content: 'grubx64.efi 2.12-9 / a4f1c2 / signed',
    editable: true,
    note:
      'The boot manager measures the image it is about to launch — before launching it. Change ' +
      'one byte of the loader and this digest changes, and every PCR value downstream of it ' +
      'changes with it.',
  },
  {
    id: 'cmdline',
    name: 'Kernel command line',
    measuredBy: 'GRUB',
    pcr: 8,
    eventType: { name: 'EV_IPL', value: 0x0000000d },
    pcrSource: 'GRUB2 convention',
    content: 'root=UUID=6f2a ro quiet lsm=lockdown,integrity',
    editable: true,
    note:
      'Configuration is as load-bearing as code. A kernel booted with `init=/bin/sh` is the same ' +
      'kernel image with a completely different trust story, which is why GRUB measures the ' +
      'command line separately.',
  },
  {
    id: 'kernel',
    name: 'Kernel image',
    measuredBy: 'GRUB',
    pcr: 9,
    eventType: { name: 'EV_IPL', value: 0x0000000d },
    pcrSource: 'GRUB2 convention',
    content: 'vmlinuz-6.12.9 / 5e0b71 / signed',
    editable: true,
    note: 'GRUB measures each file it reads before handing control to it.',
  },
  {
    id: 'initrd',
    name: 'Initial ramdisk',
    measuredBy: 'GRUB',
    pcr: 9,
    eventType: { name: 'EV_IPL', value: 0x0000000d },
    pcrSource: 'GRUB2 convention',
    content: 'initramfs-6.12.9.img / 91cd04',
    editable: true,
    note:
      'The second measurement into PCR 9. Watch the register: the kernel’s digest is an input to ' +
      'this extension, so the two are welded in order. Swap them and the final value differs.',
  },
];

/** The PCRs a quote in this lab selects — the static boot set, ascending. */
export const QUOTED_PCRS = [0, 4, 8, 9] as const;

/**
 * The PCR Linux IMA extends at runtime by default. Deliberately NOT quoted
 * here, and named so Act 6's scope statement is a property of the code rather
 * than a sentence in the copy.
 */
export const RUNTIME_MEASUREMENT_PCR = 10;

export interface BootResult {
  bank: PcrBank;
  log: ExtendRecord[];
  /** The digest each stage contributed, for display. */
  measurements: Array<{ stage: BootStage; digest: Uint8Array }>;
}

/** Run the chain: hash each stage's bytes, extend, hand off, repeat. */
export function runMeasuredBoot(stages: readonly BootStage[]): BootResult {
  const bank = new PcrBank();
  const measurements: Array<{ stage: BootStage; digest: Uint8Array }> = [];
  for (const stage of stages) {
    const bytes = stage.id === 'separator' ? EV_SEPARATOR_BYTES : utf8(stage.content);
    const digest = sha256(bytes);
    bank.extend(stage.pcr, digest, `${stage.eventType.name}: ${stage.name}`);
    measurements.push({ stage, digest });
  }
  return { bank, log: bank.log, measurements };
}

/**
 * Reference values ("golden" PCRs) for a known-good boot — in RATS terms, what
 * a Reference Value Provider supplies to the Verifier. They are computed by
 * replaying the chain, which is exactly how a real fleet builds them: from the
 * software the fleet is supposed to be running.
 */
export function referenceValues(
  stages: readonly BootStage[],
  selection: readonly number[] = QUOTED_PCRS
): Map<number, string> {
  const { bank } = runMeasuredBoot(stages);
  return new Map(selection.map((pcr) => [pcr, toHex(bank.read(pcr))]));
}

/** A deep copy, so an act that edits a stage cannot mutate the defaults. */
export function cloneStages(stages: readonly BootStage[] = DEFAULT_STAGES): BootStage[] {
  return stages.map((s) => ({ ...s, eventType: { ...s.eventType } }));
}
