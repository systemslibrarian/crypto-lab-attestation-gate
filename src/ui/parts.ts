/**
 * The shared display pieces: verdicts, check rows, PCR strips, the byte map.
 *
 * Two rules govern all of them.
 *
 * COLOUR NEVER CARRIES STATE ALONE (WCAG 1.4.1). Every verdict and every check
 * row pairs its tone with a glyph AND a word — "PASS", "FAIL", "NOT RUN",
 * "ATTESTED — AND COMPROMISED" — so the page reads identically in grayscale
 * and under deuteranopia. The glyphs are `aria-hidden` because the word beside
 * them already says it; a screen reader hearing "check mark PASS" twice is
 * worse, not better.
 *
 * COLOUR TRACKS SYSTEM INTEGRITY, NOT RETURN VALUE. A verifier that returns
 * ATTESTED over a compromised machine paints ALARM. That is the exhibit.
 */

import { toHex } from '../core/bytes';
import { FAILURE_TABLE, type FailureCode } from '../rats/failures';
import type { AttestationResult, Check, PcrComparison } from '../rats/verify';
import type { FieldSpan } from '../tpm/marshal';
import { el, type Child } from './dom';

export type Tone = 'ok' | 'bad' | 'alarm';

const TONE_ICON: Record<Tone, string> = { ok: '✓', bad: '✕', alarm: '!' };

export function verdictBlock(
  tone: Tone,
  label: string,
  note?: string,
  live = true
): HTMLElement {
  return el(
    'div',
    {
      class: 'verdict',
      'data-tone': tone,
      // Every verdict is produced by a user action and replaces earlier output,
      // so it is announced politely rather than silently swapped in.
      role: live ? 'status' : undefined,
      'aria-live': live ? 'polite' : undefined,
    },
    [
      el('span', { class: 'verdict-icon', 'aria-hidden': 'true' }, [TONE_ICON[tone]]),
      el('span', {}, [
        el('span', { class: 'verdict-label' }, [label]),
        note ? el('span', { class: 'verdict-note' }, [note]) : null,
      ]),
    ]
  );
}

const CHECK_ICON = { pass: '✓', fail: '✕', 'not-run': '—' } as const;
const CHECK_WORD = { pass: 'PASS', fail: 'FAIL', 'not-run': 'NOT RUN' } as const;

export function checkList(checks: readonly Check[]): HTMLElement {
  // `list-style: none` drops the implicit list role in Safari/VoiceOver, so
  // the roles are declared explicitly. The <ul> always has children here —
  // an empty role="list" would fail aria-required-children.
  return el(
    'ul',
    { class: 'checks', role: 'list', 'aria-label': 'Verifier checks' },
    checks.map((c) =>
      el('li', { class: 'check', 'data-state': c.state, role: 'listitem' }, [
        el('span', { class: 'check-icon', 'aria-hidden': 'true' }, [CHECK_ICON[c.state]]),
        el('span', {}, [
          el('span', { class: 'check-name' }, [`${CHECK_WORD[c.state]} — ${c.name}`]),
          el('span', { class: 'check-detail' }, [c.detail]),
          c.computed !== undefined || c.presented !== undefined
            ? el('span', { class: 'check-detail' }, [
                `expected ${c.computed ?? '—'} · presented ${c.presented ?? '—'}`,
              ])
            : null,
          c.code ? el('span', { class: 'check-code' }, [c.code]) : null,
        ]),
      ])
    )
  );
}

export function pcrStrip(
  rows: Array<{ pcr: number; value: string; changed?: boolean; label?: string }>
): HTMLElement {
  return el(
    'ul',
    { class: 'pcr-strip', role: 'list', 'aria-label': 'Platform Configuration Registers' },
    rows.map((r) =>
      el(
        'li',
        {
          class: 'pcr-row',
          role: 'listitem',
          'data-changed': r.changed ? 'true' : 'false',
        },
        [
          el('span', { class: 'pcr-name' }, [r.label ?? `PCR ${r.pcr}`]),
          el('span', { class: 'pcr-value' }, [r.value]),
        ]
      )
    )
  );
}

export function pcrComparison(rows: readonly PcrComparison[]): HTMLElement {
  return el(
    'ul',
    { class: 'pcr-strip', role: 'list', 'aria-label': 'Replayed registers against reference values' },
    rows.map((r) =>
      el(
        'li',
        { class: 'pcr-row', role: 'listitem', 'data-match': String(r.match) },
        [
          el('span', { class: 'pcr-name' }, [
            `${r.match ? '✓' : '✕'} PCR ${r.pcr}`,
          ]),
          el('span', { class: 'pcr-value' }, [
            r.match
              ? `matches reference · ${r.actual ?? ''}`
              : `DIFFERS\nreplayed  ${r.actual ?? '(none)'}\nreference ${r.expected ?? '(none held)'}`,
          ]),
        ]
      )
    )
  );
}

/**
 * The TPMS_ATTEST byte map — the exhibit for Act 2.
 *
 * Printing 116 bytes of hex asserts that a quote is a structure. Naming every
 * field, sizing it, decoding it and saying what it is for SHOWS it, which is
 * the difference the pedagogy standard is about. It lives behind a disclosure
 * because a newcomer does not need it to follow the act and an expert will
 * open it immediately.
 */
export function byteMap(fields: readonly FieldSpan[], highlight?: (path: string) => boolean): HTMLElement {
  return el(
    'ul',
    { class: 'bytemap', role: 'list', 'aria-label': 'TPMS_ATTEST fields, in wire order' },
    fields.map((f) =>
      el(
        'li',
        {
          class: 'byte-field',
          role: 'listitem',
          'data-depth': String(f.depth),
          'data-highlight': highlight?.(f.path) ? 'true' : 'false',
        },
        [
          el('span', { class: 'byte-head' }, [
            el('span', { class: 'byte-path' }, [f.label]),
            el('span', { class: 'byte-type' }, [f.type]),
            el('span', { class: 'byte-offset' }, [
              `offset ${f.offset} · ${f.length} byte${f.length === 1 ? '' : 's'}`,
            ]),
          ]),
          el('span', { class: 'byte-hex' }, [f.hex]),
          el('span', { class: 'byte-value' }, [f.value]),
          el('span', { class: 'byte-note' }, [f.note]),
        ]
      )
    )
  );
}

export function callout(label: string, body: Child[], tone: 'alarm' | 'scope' = 'scope'): HTMLElement {
  return el('div', { class: 'callout', 'data-tone': tone }, [
    el('span', { class: 'callout-label' }, [label]),
    ...body,
  ]);
}

/** The failure codes a run produced, each with what it means. */
export function failureCodeList(codes: readonly FailureCode[]): HTMLElement | null {
  if (codes.length === 0) return null;
  return el(
    'ul',
    { class: 'checks', role: 'list', 'aria-label': 'Failure codes' },
    codes.map((code) =>
      el('li', { class: 'check', 'data-state': 'fail', role: 'listitem' }, [
        el('span', { class: 'check-icon', 'aria-hidden': 'true' }, ['✕']),
        el('span', {}, [
          el('span', { class: 'check-name' }, [code]),
          el('span', { class: 'check-detail' }, [FAILURE_TABLE[code].meaning]),
          el('span', { class: 'check-detail' }, [`In the field: ${FAILURE_TABLE[code].realWorld}`]),
        ]),
      ])
    )
  );
}

/**
 * The exhibit's headline verdict.
 *
 * The verifier's own answer and the exhibit's headline are rendered as two
 * separate lines with two separate attributions, because they are two
 * different claims and collapsing them is the misunderstanding this whole lab
 * is about.
 */
export function headline(
  result: AttestationResult,
  ground: { compromised: boolean; headline: string; explanation: string }
): HTMLElement {
  const rejected = result.verdict === 'REJECTED';
  const tone: Tone = rejected ? 'bad' : ground.compromised ? 'alarm' : 'ok';
  const label = rejected
    ? 'REJECTED'
    : ground.compromised
      ? 'ATTESTED — AND COMPROMISED'
      : 'ATTESTED';
  return el('div', {}, [
    verdictBlock(tone, label, undefined),
    el('div', { class: 'callout', 'data-tone': ground.compromised ? 'alarm' : 'scope' }, [
      el('span', { class: 'callout-label' }, [
        rejected ? 'What the verifier concluded' : 'What the verifier concluded, and what it could not see',
      ]),
      el('p', {}, [
        `The verifier returned ${result.verdict}. ` +
          (rejected
            ? `It named ${result.codes.length} failure code${result.codes.length === 1 ? '' : 's'} ` +
              `across ${result.checks.filter((c) => c.state === 'fail').length} failed check` +
              `${result.checks.filter((c) => c.state === 'fail').length === 1 ? '' : 's'}.`
            : `All ${result.checks.filter((c) => c.state === 'pass').length} checks it ran passed, ` +
              'and every one of them was telling the truth.'),
      ]),
      el('p', {}, [`Ground truth, which the verifier has no way to observe: ${ground.headline}`]),
      el('p', {}, [ground.explanation]),
    ]),
  ]);
}

export function hexRow(label: string, bytes: Uint8Array | string): HTMLElement {
  return el('div', {}, [
    el('span', { class: 'field-label' }, [label]),
    el('div', { class: 'hexblock' }, [typeof bytes === 'string' ? bytes : toHex(bytes)]),
  ]);
}
