/**
 * Act 1 — Measured boot.
 *
 * This panel is where the headline mechanism is SHOWN rather than asserted.
 * The one idea the exhibit exists to teach is that a PCR has no write
 * operation, only
 *
 *     PCR_new = H( PCR_old || measurement )
 *
 * and that the old value being an INPUT is what makes the accumulation
 * one-way. So the stepper puts the exact 64-byte preimage on screen with its
 * two halves coloured differently, and the register above it moves. Nobody is
 * told the chain is one-way; they watch the previous value get eaten.
 *
 * The break-it-yourself interaction is the stage editor: change any measured
 * byte and every register downstream of it moves, live, against the real hash.
 */

import { concatBytes, toHex, utf8 } from '../../core/bytes';
import { sha256 } from '../../core/sha256';
import {
  cloneStages,
  DEFAULT_STAGES,
  EV_SEPARATOR_BYTES,
  QUOTED_PCRS,
  referenceValues,
  RUNTIME_MEASUREMENT_PCR,
  runMeasuredBoot,
  type BootStage,
} from '../../boot/stages';
import { resetRule, resetValue } from '../../tpm/pcr';
import { button, card, clear, disclosure, el } from '../dom';
import { callout, pcrStrip } from '../parts';

const GOLDEN = referenceValues(DEFAULT_STAGES);

export function renderBootPanel(root: HTMLElement): void {
  const stages = cloneStages(DEFAULT_STAGES);
  let step = 0;

  const stepOut = el('div', { class: 'step-out' });
  const registerOut = el('div', { class: 'register-out' });
  const stageOut = el('div', { class: 'stage-out' });
  const progress = el('span', { class: 'step-progress' }, ['Step 0 / 6']);

  const backBtn = button('‹ Back', () => {
    step = Math.max(0, step - 1);
    draw();
  });
  const nextBtn = button('Next ›', () => {
    step = Math.min(stages.length, step + 1);
    draw();
  });
  const resetBtn = button('Back to step 0', () => {
    step = 0;
    draw();
  });

  function draw(): void {
    const { measurements } = runMeasuredBoot(stages);
    progress.textContent = `Step ${step} / ${stages.length}`;
    (backBtn as HTMLButtonElement).disabled = step === 0;
    (nextBtn as HTMLButtonElement).disabled = step === stages.length;

    // ── The register strip, as it stands after `step` extensions ──────────
    const partial = runMeasuredBoot(stages.slice(0, step));
    const changedPcr = step > 0 ? stages[step - 1].pcr : -1;
    clear(registerOut).appendChild(
      pcrStrip(
        [...QUOTED_PCRS].map((pcr) => ({
          pcr,
          value: toHex(step === 0 ? resetValue(pcr) : partial.bank.read(pcr)),
          changed: pcr === changedPcr,
        }))
      )
    );

    // ── The extension itself ──────────────────────────────────────────────
    clear(stepOut);
    if (step === 0) {
      stepOut.appendChild(
        el('p', { class: 'card-lede' }, [
          'Every register starts at its reset value. For the static boot PCRs this exhibit uses, ' +
            'that is thirty-two zero bytes. Press Next and watch the first measurement land.',
        ])
      );
    } else {
      const stage = stages[step - 1];
      const before = step === 1 ? resetValue(stage.pcr) : previousValue(stages, step, stage.pcr);
      const digest = measurements[step - 1].digest;
      const preimage = concatBytes(before, digest);
      const after = sha256(preimage);

      stepOut.appendChild(
        el('div', { role: 'status', 'aria-live': 'polite' }, [
          el('p', {}, [
            el('strong', {}, [`${stage.measuredBy}`]),
            ` measures `,
            el('strong', {}, [stage.name]),
            ` into PCR ${stage.pcr}, then hands control to it.`,
          ]),
          el('span', { class: 'field-label' }, [`PCR ${stage.pcr} before`]),
          el('div', { class: 'hexblock' }, [el('span', { class: 'hex-old' }, [toHex(before)])]),
          el('span', { class: 'field-label' }, ['measurement = SHA-256 of the measured bytes']),
          el('div', { class: 'hexblock' }, [el('span', { class: 'hex-new' }, [toHex(digest)])]),
          el('span', { class: 'field-label' }, [
            'the 64 bytes actually hashed — old register first, then the measurement',
          ]),
          el('div', { class: 'hexblock' }, [
            el('span', { class: 'hex-old' }, [toHex(before)]),
            el('span', { class: 'hex-new' }, [toHex(digest)]),
          ]),
          el('span', { class: 'field-label' }, [`PCR ${stage.pcr} after = SHA-256 of those 64 bytes`]),
          el('div', { class: 'hexblock' }, [toHex(after)]),
          el('p', { class: 'card-lede' }, [stage.note]),
        ])
      );
      if (step === stages.length) {
        stepOut.appendChild(
          callout('The chain is closed', [
            el('p', {}, [
              'Six measurements, four registers. Nothing here can be un-said: to land PCR 4 back ' +
                'on the value it held before the boot loader was measured, you would have to find ' +
                'bytes whose digest sends the current register to a value you chose. That is a ' +
                'second-preimage problem on SHA-256.',
            ]),
          ])
        );
      }
    }

    // ── The stage editor ──────────────────────────────────────────────────
    const current = referenceValues(stages);
    const moved = [...QUOTED_PCRS].filter((pcr) => current.get(pcr) !== GOLDEN.get(pcr));
    clear(stageOut).append(
      el(
        'ul',
        { class: 'stages', role: 'list', 'aria-label': 'Boot stages' },
        stages.map((stage, i) => stageRow(stage, i, () => draw()))
      ),
      moved.length === 0
        ? el('p', { class: 'card-lede', role: 'status', 'aria-live': 'polite' }, [
            'Every register matches the fleet’s reference values. Edit any measured field above ' +
              'and watch which ones stop matching.',
          ])
        : callout(
            `${moved.length} register${moved.length === 1 ? '' : 's'} no longer match the reference values`,
            [
              el('p', { role: 'status', 'aria-live': 'polite' }, [
                `PCR ${moved.join(', ')} moved. Note what did NOT move: a change to one stage ` +
                  'touches only the register that stage was measured into, which is exactly why ' +
                  'the split across PCR 0, 4, 8 and 9 is worth having.',
              ]),
            ],
            'alarm'
          )
    );
  }

  clear(root).append(
    card('What a measured boot actually is', [
      el('p', { class: 'card-lede' }, [
        'A computer cannot check its own firmware, because the firmware is what would be doing ' +
          'the checking. Measured boot answers a smaller question instead: each stage of boot ' +
          'records a fingerprint of the next stage into a special register inside the TPM, and ' +
          'only then hands control over. Nobody decides whether the fingerprint is good. The ' +
          'record just accumulates.',
      ]),
      el('p', { class: 'card-lede' }, [
        'The registers are called PCRs, and they have no write operation. The only thing you can ' +
          'do to one is extend it, which replaces its contents with a hash of its old contents ' +
          'followed by the new measurement. Step through it below.',
      ]),
    ]),
    card('Step the chain', [
      el('div', { class: 'btn-row' }, [backBtn, nextBtn, resetBtn, progress]),
      registerOut,
      stepOut,
    ]),
    card('Break it yourself', [
      el('p', { class: 'card-lede' }, [
        'Change any measured value. Every digest and every register below is recomputed with the ' +
          'real hash function — nothing here is a lookup table.',
      ]),
      stageOut,
    ]),
    card('The parts of this that are conventions, not specifications', [
      disclosure('Where each PCR number comes from', [
        el('div', { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': 'PCR allocation sources' }, [
          el('table', {}, [
            el('thead', {}, [
              el('tr', {}, [
                el('th', { scope: 'col' }, ['PCR']),
                el('th', { scope: 'col' }, ['Used here for']),
                el('th', { scope: 'col' }, ['Where the assignment comes from']),
              ]),
            ]),
            el(
              'tbody',
              {},
              [
                ['0', 'Platform firmware', 'TCG PC Client Platform Firmware Profile, Table 1 — normative'],
                ['4', 'Boot loader image', 'TCG PC Client Platform Firmware Profile, Table 1 — normative'],
                ['8', 'Kernel command line', 'GRUB2’s GRUB_STRING_PCR — a bootloader convention'],
                ['9', 'Kernel and initrd', 'GRUB2’s GRUB_BINARY_PCR — a bootloader convention'],
                [
                  String(RUNTIME_MEASUREMENT_PCR),
                  'NOT QUOTED HERE — runtime measurement',
                  'Linux IMA’s default (CONFIG_IMA_MEASURE_PCR_IDX, range 8–14). Act 6 is about this omission.',
                ],
              ].map(([a, b, c]) =>
                el('tr', {}, [el('td', {}, [el('code', {}, [a])]), el('td', {}, [b]), el('td', {}, [c])])
              )
            ),
          ]),
        ]),
        el('p', { class: 'card-lede' }, [
          'The TCG profile assigns PCR 0–7, 16 and 23 and says of the rest only that PCR 8–15 are ' +
            '“defined for use by the Static OS”. Any statement about what is in PCR 8, 9, 10 or 14 ' +
            'is a statement about a particular bootloader and OS, not about the specification.',
        ]),
      ]),
      disclosure('Can a PCR be rewound? (the short answer is: some of them, yes)', [
        el('p', {}, [
          '“You can never rewind a PCR” is a useful shorthand and false as a general claim about ' +
            'TPMs. TPM2_PCR_Reset exists. A dynamic root-of-trust launch zeroes registers ' +
            'mid-run. A TPM Reset returns PCR 17–22 to all-ones, a value no amount of extending ' +
            'could ever reach. And TPM Resume restores PCR 0–15 to saved values, which is ' +
            'literally loading an earlier state back in.',
        ]),
        el('p', {}, [
          'What is one-way is the extend OPERATION. And on a PC Client platform the no-rewind ' +
            'claim holds for PCR 0 through 15 and only for those — which is where every register ' +
            'this exhibit quotes lives.',
        ]),
        el('div', { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': 'PCR reset authority' }, [
          el('table', {}, [
            el('thead', {}, [
              el('tr', {}, [
                el('th', { scope: 'col' }, ['PCR']),
                el('th', { scope: 'col' }, ['Value at TPM2_Startup(CLEAR)']),
                el('th', { scope: 'col' }, ['Who can rewind it']),
              ]),
            ]),
            el(
              'tbody',
              {},
              [0, 4, 8, 9, 16, 17, 20, 23].map((pcr) =>
                el('tr', {}, [
                  el('td', {}, [el('code', {}, [String(pcr)])]),
                  el('td', {}, [toHex(resetValue(pcr)).slice(0, 8) + '…' + (pcr >= 17 && pcr <= 22 ? ' (all ones)' : ' (all zeros)')]),
                  el('td', {}, [resetRule(pcr).summary]),
                ])
              )
            ),
          ]),
        ]),
        el('p', { class: 'card-lede' }, [
          'One sharp corner worth keeping: PCR 20–22 power on to all-ones and TPM2_PCR_Reset sets ' +
            'them to zero. “Reset” and “initial” are two different values for the same register.',
        ]),
      ]),
      disclosure('EV_SEPARATOR — an epoch marker built from nothing but Extend', [
        el('p', {}, [
          'Step 2 measures four bytes of zeros. That is EV_SEPARATOR, and it marks the moment ' +
            'platform firmware stops controlling the measurement process. Its digest is a fixed ' +
            'published constant, because the event data is fixed:',
        ]),
        el('div', { class: 'hexblock' }, [
          `SHA-256(00 00 00 00) = ${toHex(sha256(EV_SEPARATOR_BYTES))}`,
        ]),
        el('p', {}, [
          'The consequence is the interesting part. A secret sealed to PCR 0’s value before the ' +
            'separator becomes unsealable by anything the operating system runs, because the ' +
            'register can never hold that value again. No new mechanism was needed for that — ' +
            'just one more extension.',
        ]),
      ]),
    ])
  );

  draw();
}

/** The value a register held immediately before the `step`-th extension. */
function previousValue(stages: readonly BootStage[], step: number, pcr: number): Uint8Array {
  return runMeasuredBoot(stages.slice(0, step - 1)).bank.read(pcr);
}

function stageRow(stage: BootStage, index: number, onChange: () => void): HTMLElement {
  const bytes = stage.id === 'separator' ? EV_SEPARATOR_BYTES : utf8(stage.content);
  const digest = sha256(bytes);
  const inputId = `stage-${stage.id}`;
  const body: Array<HTMLElement | null> = [
    el('span', { class: 'stage-head' }, [
      el('span', { class: 'stage-name' }, [`${index + 1}. ${stage.name}`]),
      el('span', { class: 'stage-pcr' }, [`PCR ${stage.pcr}`]),
      el('span', { class: 'stage-pcr' }, [stage.eventType.name]),
    ]),
    el('span', { class: 'stage-meta' }, [`measured by ${stage.measuredBy}`]),
  ];
  if (stage.editable) {
    const input = el('input', {
      type: 'text',
      id: inputId,
      value: stage.content,
      spellcheck: 'false',
      autocomplete: 'off',
    }) as HTMLInputElement;
    input.addEventListener('input', () => {
      stage.content = input.value;
      onChange();
    });
    body.push(
      el('label', { class: 'field', for: inputId }, [
        el('span', { class: 'field-label' }, ['measured bytes']),
        input,
      ])
    );
  } else {
    body.push(
      el('span', { class: 'stage-meta' }, [
        'measured bytes: 00 00 00 00 — fixed by the specification, not editable',
      ])
    );
  }
  body.push(el('div', { class: 'hexblock' }, [`SHA-256 = ${toHex(digest)}`]));
  return el('li', { class: 'stage', role: 'listitem', 'data-stage': stage.id }, body);
}
