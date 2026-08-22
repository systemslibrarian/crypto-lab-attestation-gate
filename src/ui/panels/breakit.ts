/**
 * Acts 3, 4 and 5 — the three rejections.
 *
 * Each one is a complete, real exchange that the real verifier rejects, and
 * each fails in exactly one way. The point of putting them side by side is
 * that the checks which PASS are as informative as the one that fails: a
 * replayed quote has a perfect signature, and a quote from the wrong machine
 * has perfect PCRs.
 */

import { toHex } from '../../core/bytes';
import {
  scenarioReplay,
  scenarioTamperedBootloader,
  scenarioWrongMachine,
  type ScenarioRun,
} from '../../acts/scenarios';
import { DEFAULT_STAGES } from '../../boot/stages';
import { button, card, clear, disclosure, el } from '../dom';
import { callout, checkList, failureCodeList, headline, pcrComparison } from '../parts';

type Which = 'tamper' | 'replay' | 'wrong-machine';

const DEFAULT_BOOTLOADER = DEFAULT_STAGES.find((s) => s.id === 'bootloader')!.content;

export function renderBreakPanel(root: HTMLElement): void {
  let which: Which = 'tamper';
  let bootloader = 'grubx64.efi 2.12-9 / a4f1c3 / signed';

  const out = el('div', { class: 'break-out' });
  const editorWrap = el('div', {});

  const input = el('input', {
    type: 'text',
    id: 'bootloader-input',
    value: bootloader,
    spellcheck: 'false',
    autocomplete: 'off',
  }) as HTMLInputElement;
  input.addEventListener('input', () => {
    bootloader = input.value;
    draw();
  });

  const buttons: Array<[Which, string]> = [
    ['tamper', 'Act 3 · Change one byte'],
    ['replay', 'Act 4 · Replay yesterday’s quote'],
    ['wrong-machine', 'Act 5 · A different machine answers'],
  ];
  const btnEls = buttons.map(([id, label]) =>
    button(
      label,
      () => {
        which = id;
        draw();
      },
      { class: 'btn', 'data-which': id }
    )
  );

  function currentRun(): ScenarioRun {
    if (which === 'tamper') return scenarioTamperedBootloader(bootloader);
    if (which === 'replay') return scenarioReplay();
    return scenarioWrongMachine();
  }

  function draw(): void {
    for (const [i, [id]] of buttons.entries()) {
      btnEls[i].setAttribute('aria-pressed', String(id === which));
    }
    const run = currentRun();

    clear(editorWrap);
    if (which === 'tamper') {
      editorWrap.append(
        el('label', { class: 'field', for: 'bootloader-input' }, [
          el('span', { class: 'field-label' }, [
            'the boot loader’s measured bytes — edit them and watch the verdict',
          ]),
          input,
        ]),
        el('p', { class: 'card-lede appraisal-status', role: 'status', 'aria-live': 'polite' }, [
          bootloader === DEFAULT_BOOTLOADER
            ? 'Re-appraised: any earlier verdict on this panel has been discarded. These bytes are ' +
              'identical to the fleet’s reference image, so this run appraises clean. Change one ' +
              'character.'
            : 'Re-appraised: any earlier verdict on this panel has been discarded. These bytes ' +
              'differ from the reference image, and the verifier is about to notice without being ' +
              'told what changed.',
        ])
      );
    }

    clear(out).append(
      el('span', { class: 'eyebrow' }, [`${run.act} · ${run.title}`]),
      el('p', { class: 'card-lede' }, [run.premise]),
      editorWrap,
      headline(run.result, run.groundTruth),
      failureCodeList(run.result.codes) ?? el('div', {}),
      el('h4', { class: 'card-title' }, ['Every check the verifier ran']),
      el('p', { class: 'card-lede' }, [
        'The passing rows matter here. A quote can be perfectly signed and still wrong; it can ' +
          'have perfect registers and still be from the wrong device.',
      ]),
      checkList(run.result.checks),
      el('h4', { class: 'card-title' }, ['Replayed registers against the reference values']),
      pcrComparison(run.result.pcrs),
      ...(run.result.divergence
        ? [callout(
            'Which stage broke the chain',
            [
              el('p', {}, [
                `Entry ${run.result.divergence.index + 1} of the event log is the first one that ` +
                  `differs from the reference log: `,
                el('strong', {}, [run.result.divergence.entry.eventName]),
                `, measured into PCR ${run.result.divergence.entry.pcr}.`,
              ]),
              el('div', { class: 'hexblock' }, [
                `reference digest  ${toHex(run.result.divergence.expected?.digest ?? new Uint8Array(0))}\n` +
                  `presented digest  ${toHex(run.result.divergence.entry.digest)}`,
              ]),
              el('p', {}, [
                'Note what supplied that answer: the event log, not the quote. A quote carries one ' +
                  'composite digest and can only ever say “the set changed”. The log says which ' +
                  'stage — and the log is trustworthy only because replaying it has to reproduce ' +
                  'the number inside the signature.',
              ]),
            ],
            'alarm'
          )]
        : [])
    );
  }

  clear(root).append(
    card('Three ways a quote fails, and what each one proves', [
      el('p', { class: 'card-lede' }, [
        'A verifier is not one yes-or-no question. It is a list of independent questions, and ' +
          'each of these three runs answers all of them — failing exactly one. Watch which checks ' +
          'stay green.',
      ]),
      el('div', { class: 'btn-row' }, btnEls),
    ]),
    out,
    card('The failure codes this exhibit uses', [
      disclosure('Why these names are ours, and what the field actually calls them', [
        el('p', {}, [
          'There is no standard registry of attestation failure codes. The seven names this ' +
            'exhibit reports are its own vocabulary, chosen so each failure has a name you can ' +
            'point at. Real implementations express the same conditions as raw TPM response codes ' +
            'or as free-text validation errors, and every code in this lab carries its real-world ' +
            'analogue alongside it.',
        ]),
        el('p', {}, [
          'The clearest case is AK_NOT_CERTIFIED, which appears in no implementation anywhere. ' +
            'TCG expresses the requirement as a normative MUST on the relying party — check for ' +
            'the tcg-cap-verifiedTPMRestricted policy OID 2.23.133.11.1.3 — precisely because the ' +
            'protocol produces no error of its own when nobody looks.',
        ]),
      ]),
    ])
  );

  draw();
}
