/**
 * The page: hero, the plain-language on-ramp, the honest-scoping card, six
 * tabbed acts, the failure-code reference, and the footer.
 *
 * Panels render lazily on first activation and are `hidden` until then, which
 * is what a reader actually gets. The tablist uses roving `tabindex` with
 * Home/End/Arrow support, and every panel is labelled by its own tab.
 */

import { FAILURE_CODES, FAILURE_TABLE } from '../rats/failures';
import { QUOTED_PCRS, RUNTIME_MEASUREMENT_PCR } from '../boot/stages';
import { card, clear, disclosure, el } from './dom';
import { callout } from './parts';
import { renderBootPanel } from './panels/boot';
import { renderQuotePanel } from './panels/quote';
import { renderMagicPanel } from './panels/magic';
import { renderBreakPanel } from './panels/breakit';
import { renderTimeOfUsePanel } from './panels/timeofuse';
import { renderSignaturePanel } from './panels/signature';

interface Tab {
  id: string;
  label: string;
  render: (root: HTMLElement) => void;
}

const TABS: Tab[] = [
  { id: 'boot', label: 'Measured Boot', render: renderBootPanel },
  { id: 'quote', label: 'Quote & Verify', render: renderQuotePanel },
  { id: 'magic', label: 'The Magic Value', render: renderMagicPanel },
  { id: 'break', label: 'Break It', render: renderBreakPanel },
  { id: 'time', label: 'Time of Use', render: renderTimeOfUsePanel },
  { id: 'signature', label: 'Whose Signature', render: renderSignaturePanel },
];

export function mount(root: HTMLElement): void {
  clear(root);
  root.append(hero(), intro(), scoping(), tabs(), failureReference(), footer());
}

function hero(): HTMLElement {
  return el('header', { class: 'cl-hero' }, [
    el('div', { class: 'cl-hero-main' }, [
      el('h1', { class: 'cl-hero-title' }, ['Attestation Gate']),
      el('p', { class: 'cl-hero-sub' }, ['Remote attestation · RFC 9334 · TPM 2.0 Quote']),
      el('p', { class: 'cl-hero-desc' }, [
        'Extends a real measured boot into PCRs, signs a byte-exact TPMS_ATTEST over them, and ' +
          'appraises that quote against reference values — including the run where every check ' +
          'passes honestly and the machine is owned anyway.',
      ]),
    ]),
    el('aside', { class: 'cl-hero-why', 'aria-label': 'Why it matters' }, [
      el('span', { class: 'cl-hero-why-label' }, ['WHY IT MATTERS']),
      el('p', { class: 'cl-hero-why-text' }, [
        'Cloud providers, enterprise networks and confidential-computing platforms all gate access ' +
          'on remote attestation: prove your machine booted what it was supposed to, or stay off. ' +
          'A boot quote is strong evidence about the past and weak evidence about the present, and ' +
          'the distance between those two sentences is where real compromises live.',
      ]),
    ]),
  ]);
}

function intro(): HTMLElement {
  return card('What is remote attestation?', [
    el('p', { class: 'card-lede' }, [
      'Suppose you want to let a machine onto your network only if it booted software you trust. ' +
        'You cannot just ask it — a compromised machine will say whatever you want to hear. So ' +
        'instead you ask a small, separate chip on its motherboard, which recorded what got ' +
        'loaded while the machine was starting up and will sign a statement about that record ' +
        'with a key it never releases.',
    ]),
    el('p', { class: 'card-lede' }, [
      'That signed statement is a quote, the chip is a TPM, and the whole arrangement — who ' +
        'produces evidence, who appraises it, who acts on the result — is standardised by the ' +
        'IETF as RATS, RFC 9334. This exhibit builds all of it: real hashes, real signatures, ' +
        'real byte layouts, and a verifier you can watch reject things.',
    ]),
    el('p', { class: 'card-lede' }, [
      'Start at Measured Boot to see how the record accumulates. The last two tabs are the ones ' +
        'worth staying for.',
    ]),
  ]);
}

function scoping(): HTMLElement {
  return card(
    'What is real here, and what this does not prove',
    [
      el('p', { class: 'card-lede' }, [
        'Not production cryptography. This is a teaching demo that runs entirely in your browser ' +
          'with no backend, no network calls and no persistence. There is no TPM anywhere near ' +
          'it — a TPM is a piece of hardware, and this page models one in software.',
      ]),
      disclosure('What is real', [
        el(
          'ul',
          { role: 'list' },
          [
            'SHA-256 and HMAC-SHA-256, hand-rolled here and checked against the FIPS 180-4 and ' +
              'RFC 4231 vectors.',
            'The TPMS_ATTEST byte layout, hand-rolled from TPM 2.0 Part 2. It round-trips a real ' +
              'captured tpm2_quote blob byte for byte, and recomputes that quote’s composite ' +
              'digest from its published PCR values.',
            'ECDSA on NIST P-256, via @noble/curves, pinned to the RFC 6979 test vectors.',
            'The restricted-signing rule, transcribed from the TPM reference implementation, ' +
              'including the NULL validation ticket and the TPM_RC_TICKET response code.',
            'Credential activation: real ECDH, real KDFa and KDFe, real AES-128-CFB (checked ' +
              'against NIST SP 800-38A), real HMAC.',
            'Deterministic CBOR per RFC 8949, EAT claims per RFC 9711, measured components per ' +
              'RFC 10013 — checked against the base64url strings the RFC itself prints.',
          ].map((t) => el('li', { role: 'listitem' }, [t]))
        ),
      ]),
      disclosure('What is modelled rather than real', [
        el(
          'ul',
          { role: 'list' },
          [
            'The TPM itself. There is no hardware boundary here, so the protections that come ' +
              'from a key physically never leaving a chip are described, not enforced.',
            'Signatures are RFC 6979 deterministic so that every hex string on this page is ' +
              'reproducible. A real TPM draws its per-signature nonce from its own RNG. ' +
              'Verification is identical either way.',
            'Keys are derived from labels by rejection sampling rather than from a TPM seed.',
            'The validation ticket is modelled as the fact of its issuance. A real ticket is an ' +
              'HMAC under a hierarchy proof value that never leaves the TPM, which is what makes ' +
              'it unforgeable off-chip.',
            'The EAT is not wrapped in a COSE_Sign1. It is bound to the TPM’s signature by two ' +
              'equalities the verifier recomputes, and the page says so where it shows the token.',
            'X.509 certificates are modelled as their assertions — issuer, subject key, subject ' +
              'Name, and the two TCG policy assertions — rather than encoded and chain-verified.',
            'The failure code names are this lab’s own vocabulary. There is no standard registry, ' +
              'and every code below carries what real implementations actually call it.',
          ].map((t) => el('li', { role: 'listitem' }, [t]))
        ),
      ]),
      callout('What this exhibit does NOT prove', [
        el('p', {}, [
          el('strong', {}, ['NEG-1. ']),
          'A static measured-boot quote proves the measurements those PCRs represent at the time ' +
            'they were taken. It does not continuously prove current runtime state. That is a ' +
            `statement about a static quote over PCRs ${QUOTED_PCRS.join(', ')} — not about ` +
            'attestation in general. Runtime measurement architectures exist; Linux IMA extends ' +
            `PCR ${RUNTIME_MEASUREMENT_PCR} for the lifetime of the system, and this exhibit does ` +
            'not quote it. Act 6 is the evidence fixture.',
        ]),
        el('p', {}, [
          el('strong', {}, ['THREAT-1. ']),
          'The verifier’s trust anchors are an assumption, not a result. Evidence itself never ' +
            'establishes them, and no amount of appraisal can check them. The fixture in the last ' +
            'tab verifies completely clean under a hostile anchor.',
        ]),
      ]),
    ],
    'card-scope'
  );
}

function tabs(): HTMLElement {
  const tablist = el('div', { class: 'tabs', role: 'tablist', 'aria-label': 'Exhibits' });
  const panels: HTMLElement[] = [];
  const buttons: HTMLButtonElement[] = [];
  const rendered = new Set<string>();

  TABS.forEach((tab, i) => {
    const btn = el(
      'button',
      {
        type: 'button',
        class: 'tab-btn',
        role: 'tab',
        id: `tab-${tab.id}`,
        'aria-controls': `panel-${tab.id}`,
        'aria-selected': String(i === 0),
        tabindex: i === 0 ? '0' : '-1',
      },
      [el('span', { class: 'tab-num', 'aria-hidden': 'true' }, [String(i + 1)]), tab.label]
    ) as HTMLButtonElement;
    const panel = el('div', {
      class: 'panel',
      role: 'tabpanel',
      id: `panel-${tab.id}`,
      'aria-labelledby': `tab-${tab.id}`,
      tabindex: '0',
    });
    if (i !== 0) panel.hidden = true;
    btn.addEventListener('click', () => select(i));
    buttons.push(btn);
    panels.push(panel);
    tablist.appendChild(btn);
  });

  function select(index: number): void {
    TABS.forEach((tab, i) => {
      const active = i === index;
      buttons[i].setAttribute('aria-selected', String(active));
      buttons[i].setAttribute('tabindex', active ? '0' : '-1');
      buttons[i].classList.toggle('active', active);
      panels[i].hidden = !active;
      if (active && !rendered.has(tab.id)) {
        rendered.add(tab.id);
        tab.render(panels[i]);
      }
    });
    buttons[index].focus();
  }

  tablist.addEventListener('keydown', (event) => {
    const key = (event as KeyboardEvent).key;
    const current = buttons.findIndex((b) => b.getAttribute('aria-selected') === 'true');
    let next = current;
    if (key === 'ArrowRight') next = (current + 1) % buttons.length;
    else if (key === 'ArrowLeft') next = (current - 1 + buttons.length) % buttons.length;
    else if (key === 'Home') next = 0;
    else if (key === 'End') next = buttons.length - 1;
    else return;
    event.preventDefault();
    select(next);
  });

  buttons[0].classList.add('active');
  TABS[0].render(panels[0]);
  rendered.add(TABS[0].id);

  return el('main', {}, [tablist, ...panels]);
}

function failureReference(): HTMLElement {
  return card('Every failure code this verifier can report', [
    el('p', { class: 'card-lede' }, [
      'These names are this lab’s own. There is no standard registry of attestation failure ' +
        'codes; real implementations return raw TPM response codes or free-text validation ' +
        'errors. The right-hand column is what the field actually says.',
    ]),
    el(
      'div',
      { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': 'Failure codes' },
      [
        el('table', {}, [
          el('thead', {}, [
            el('tr', {}, [
              el('th', { scope: 'col' }, ['Code']),
              el('th', { scope: 'col' }, ['What the verifier found']),
              el('th', { scope: 'col' }, ['In the field']),
            ]),
          ]),
          el(
            'tbody',
            {},
            FAILURE_CODES.map((code) =>
              el('tr', {}, [
                el('td', {}, [el('code', {}, [code])]),
                el('td', {}, [FAILURE_TABLE[code].meaning]),
                el('td', {}, [FAILURE_TABLE[code].realWorld]),
              ])
            )
          ),
        ]),
      ]
    ),
  ]);
}

function footer(): HTMLElement {
  return el('footer', { class: 'scripture-footer' }, [
    el('p', {}, [
      'So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31',
    ]),
  ]);
}
