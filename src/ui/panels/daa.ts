/** Act 8 — stable attestation identity versus anonymous issuer membership. */

import { toHex } from '../../core/bytes';
import { CURVE_NAME, point1Bytes, point2Bytes } from '../../daa/groups';
import { runDaaLesson, type DaaLessonRun } from '../../daa/lesson';
import type { DaaVerification } from '../../daa/protocol';
import { button, card, clear, disclosure, el } from '../dom';
import { callout, verdictBlock } from '../parts';

type VerifierState = 'baseline' | 'rotated' | 'rejoined' | 'revoked';

export function renderDaaPanel(root: HTMLElement): void {
  const run = runDaaLesson();
  let selected: VerifierState = 'baseline';
  const stateOutput = el('div', { class: 'daa-state-output', 'data-daa-output': 'baseline' });

  const states: Array<{
    id: VerifierState;
    label: string;
    title: string;
    result: DaaVerification;
    note: string;
  }> = [
    {
      id: 'baseline',
      label: 'Trusted issuer, empty list',
      title: 'Original issuer key remains trusted',
      result: run.revocation.before,
      note: 'The credential, proof, signed evidence, epoch, and empty rogue list all verify.',
    },
    {
      id: 'rotated',
      label: 'Switch to issuer epoch 2',
      title: 'Old credential presented to the new issuer epoch',
      result: run.rotation.oldAgainstNewIssuer,
      note:
        'The old signature is rejected under epoch 2. It still verifies wherever the old epoch-1 key remains trusted; rotation is policy, not retroactive erasure.',
    },
    {
      id: 'rejoined',
      label: 'Re-Join under epoch 2',
      title: 'Fresh credential under the new issuer epoch',
      result: run.rotation.rejoinedUnderNewIssuer,
      note: 'The same platform secret completed a new Join and the resulting epoch-2 proof verifies.',
    },
    {
      id: 'revoked',
      label: 'Publish this platform secret',
      title: 'Exact gsk added to the private-key rogue list',
      result: run.revocation.exact,
      note:
        'The already-created signature now fails because H1(basename)^listed-secret equals its nym. No resigning or scenario label is involved.',
    },
  ];

  const stateButtons = states.map((state) =>
    button(
      state.label,
      () => {
        selected = state.id;
        drawState();
      },
      { class: 'btn', 'data-daa-state': state.id }
    )
  );

  function drawState(): void {
    const state = states.find((candidate) => candidate.id === selected)!;
    for (const [index, candidate] of states.entries()) {
      stateButtons[index].setAttribute('aria-pressed', String(candidate.id === selected));
    }
    stateOutput.setAttribute('data-daa-output', state.id);
    clear(stateOutput).append(
      el('h4', { class: 'subhead' }, [state.title]),
      verdictBlock(
        state.result.valid ? 'ok' : 'bad',
        state.result.valid ? 'MEMBERSHIP ACCEPTED' : state.result.revoked ? 'REVOKED' : 'MEMBERSHIP REJECTED',
        state.note
      ),
      verificationChecks(state.result)
    );
  }

  clear(root).append(
    card('Act 8 · Prove membership without sending a universal device identifier', [
      el('p', { class: 'card-lede' }, [
        'The ordinary quote path identifies one attestation key. This path instead runs the ' +
          'issuer Setup, Join proof, credential issuance, randomized Sign, Verify, Link, ' +
          'and private-key rogue-list check from one named construction: Camenisch–Drijvers–Lehmann ' +
          'Pi_DAA+, section 5.1, specialized to zero application attributes.',
      ]),
      callout('The model boundary', [
        el('p', {}, [
          `Every protocol result below is computed from current inputs; credential and membership ` +
            `checks use the real ${CURVE_NAME} pairing algebra. ` +
            'The platform secret is software-held. This browser does not execute TPM2_Commit, ' +
            'TPM2_Sign, or TPM2_Quote, does not implement a TPM/ISO ECDAA wire profile, and does ' +
            'not provide hardware key confinement. Its deterministic JavaScript bigint arithmetic ' +
            'is variable-time and is not side-channel-hardened secret handling. All fixture seeds ' +
            'ship in the page source; “secret” names a protocol role, not browser-enforced secrecy.',
        ]),
        el('p', {}, [
          'CDL assumes an authenticated Join channel and issuer admission policy. This panel ' +
            'checks the nonce-bound proof of gsk, but it does not implement unique-TPM admission. ' +
            'The existing endorsement-key/credential-activation lesson models the prerequisite; ' +
            'it is an enrollment adapter around CDL, not part of CDL’s pairing algebra.',
        ]),
      ]),
    ]),
    identityComparison(run),
    joinAndProof(run),
    linkability(run),
    card('Change verifier state, then explicitly re-Join', [
      el('p', { class: 'card-lede' }, [
        'Each control below evaluates a real policy state. The old issuer-key result and the ' +
          'rogue-list result use the same epoch-1 signature; the re-Join case alone creates new ' +
          'credential and proof material.',
      ]),
      el('div', { class: 'btn-row', role: 'group', 'aria-label': 'DAA verifier state' }, stateButtons),
      stateOutput,
      el('div', { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': 'Credential control results' }, [
        el('table', { 'data-daa-table': 'credential-control' }, [
          el('thead', {}, [
            el('tr', {}, [
              el('th', { scope: 'col' }, ['Credential state']),
              el('th', { scope: 'col' }, ['Pairing check']),
              el('th', { scope: 'col' }, ['Meaning']),
            ]),
          ]),
          el('tbody', {}, [
            resultRow(
              'Issued (A, e, s)',
              run.credentialControl.originalAccepted,
              'Host independently accepts e(A, w + e·g2) = e(g1 + s·h0 + Q, g2).'
            ),
            resultRow(
              'Change s by one',
              !run.credentialControl.changedRejected,
              'The same credential equation rejects; a client-side input check is not standing in for it.'
            ),
          ]),
        ]),
      ]),
    ]),
    limitsAndSources(run)
  );

  drawState();
}

function identityComparison(run: DaaLessonRun): HTMLElement {
  const stable = toHex(run.stableAk.firstQualifiedSigner);
  return card('A stable AK answers “which key?”; DAA answers “a member of which issuer set?”', [
    el('div', { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': 'Stable quote and DAA comparison' }, [
      el('table', { 'data-daa-table': 'identity-comparison' }, [
        el('thead', {}, [
          el('tr', {}, [
            el('th', { scope: 'col' }, ['Path']),
            el('th', { scope: 'col' }, ['qualifiedSigner']),
            el('th', { scope: 'col' }, ['What repeats']),
            el('th', { scope: 'col' }, ['Verifier learns']),
          ]),
        ]),
        el('tbody', {}, [
          el('tr', { 'data-daa-row': 'stable-ak' }, [
            el('th', { scope: 'row' }, ['Existing P-256 TPM2_Quote model']),
            el('td', {}, [
              el('code', { 'data-daa-value': 'stable-ak-one' }, [stable]),
              el('br'),
              el('code', { 'data-daa-value': 'stable-ak-two' }, [
                toHex(run.stableAk.secondQualifiedSigner),
              ]),
            ]),
            el('td', { 'data-result': run.stableAk.linked ? 'same' : 'different' }, [
              run.stableAk.linked ? 'SAME across fresh nonces' : 'different',
            ]),
            el('td', {}, ['A stable AK Qualified Name that links the two quotes.']),
          ]),
          el('tr', { 'data-daa-row': 'anonymous' }, [
            el('th', { scope: 'row' }, ['CDL Pi_DAA+ adaptation']),
            el('td', {}, [el('code', {}, ['0000 · Empty Buffer'])]),
            el('td', { 'data-result': run.statement1.attest.qualifiedSigner.length === 0 ? 'empty' : 'present' }, [
              'No AK Name in either signed statement',
            ]),
            el('td', {}, [
              'From signer authentication: issuer membership plus a basename pseudonym. The signed evidence fields remain visible and may correlate.',
            ]),
          ]),
        ]),
      ]),
    ]),
    el('p', { class: 'card-lede' }, [
      'The DAA statement still signs the verifier nonce, PCR selection and composite digest, ' +
        'clock/reset state, and firmware version. Removing qualifiedSigner does not remove those ' +
        'measurements. It removes the universal key name that would defeat the anonymity lesson.',
    ]),
  ]);
}
function joinAndProof(run: DaaLessonRun): HTMLElement {
  return card('The credential and proof are computed, not asserted', [
    el('div', { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': 'DAA protocol stages' }, [
      el('table', { 'data-daa-table': 'protocol-stages' }, [
        el('thead', {}, [
          el('tr', {}, [
            el('th', { scope: 'col' }, ['Stage']),
            el('th', { scope: 'col' }, ['Current-run equation']),
            el('th', { scope: 'col' }, ['Result']),
          ]),
        ]),
        el('tbody', {}, [
          resultRow(
            'Issuer Setup',
            run.baseline.checks.find((check) => check.name === 'issuer key proof')?.ok ?? false,
            'One Schnorr/Chaum–Pedersen response binds w = x·g2 and the issuer G1 proof point to the same x.'
          ),
          resultRow(
            'Join proof (authenticated channel assumed)',
            run.join.proofAccepted,
            'The platform proves knowledge of gsk for Q = gsk·h1, bound to the issuer nonce.'
          ),
          resultRow(
            'Credential',
            run.join.credentialAccepted,
            'The host checks the BBS+ pairing equation before retaining (A, e, s).'
          ),
          resultRow(
            'Anonymous Sign/Verify',
            run.baseline.valid,
            'The randomized credential proof binds the complete statement, basename, issuer epoch, and policy.'
          ),
        ]),
      ]),
    ]),
    disclosure('Inspect the issuer and proof outputs', [
      el('div', { class: 'hexblock', 'data-daa-value': 'issuer-w' }, [
        `issuer w (G2 compressed)\n${toHex(point2Bytes(run.issuer.w))}`,
      ]),
      el('div', { class: 'hexblock', 'data-daa-value': 'a-prime' }, [
        `randomized A' (G1 compressed)\n${toHex(point1Bytes(run.signature1.APrime))}`,
      ]),
      el('div', { class: 'hexblock', 'data-daa-value': 'a-bar' }, [
        `A-bar = x·A' (G1 compressed)\n${toHex(point1Bytes(run.signature1.ABar))}`,
      ]),
      el('div', { class: 'hexblock', 'data-daa-value': 'statement-bytes' }, [
        `complete DAA-shaped TPMS_ATTEST\n${toHex(run.statement1.bytes)}`,
      ]),
      el('div', { class: 'hexblock', 'data-daa-value': 'statement-digest' }, [
        `SHA-256(complete DAA-shaped TPMS_ATTEST)\n${toHex(run.statement1.digest)}`,
      ]),
      el('p', {}, [
        'The digest is shown as an inspector aid. Pi_DAA+ binds the complete statement bytes in ' +
          'its Fiat–Shamir transcript; the page does not replace the statement with a scenario label.',
      ]),
    ]),
  ]);
}

function linkability(run: DaaLessonRun): HTMLElement {
  const first = run.nymHex(run.signature1.nym);
  return card('A basename is a deliberate linkability scope', [
    el('p', { class: 'card-lede' }, [
      'The pseudonym is nym = gsk·H1(basename). Link first verifies both signatures and is defined ' +
        'only when their basenames match. Different-basename pseudonym inequality is an observed ' +
        'result, not a proof that all other metadata is unlinkable.',
    ]),
    el('div', { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': 'DAA basename link results' }, [
      el('table', { 'data-daa-table': 'linkability' }, [
        el('thead', {}, [
          el('tr', {}, [
            el('th', { scope: 'col' }, ['Pair']),
            el('th', { scope: 'col' }, ['Basename rule']),
            el('th', { scope: 'col' }, ['Pseudonyms']),
            el('th', { scope: 'col' }, ['Computed Link result']),
          ]),
        ]),
        el('tbody', {}, [
          el('tr', { 'data-daa-link': 'same-basename' }, [
            el('th', { scope: 'row' }, ['Same platform, two fresh statements']),
            el('td', {}, ['same service basename']),
            el('td', {}, ['equal']),
            el('td', { 'data-result': run.sameBasename.linked ? 'linked' : 'not-linked' }, [
              run.sameBasename.linked ? 'LINKED' : 'NOT LINKED',
            ]),
          ]),
          el('tr', { 'data-daa-link': 'different-basename' }, [
            el('th', { scope: 'row' }, ['Same platform, two services']),
            el('td', {}, ['different basenames']),
            el('td', {}, ['different in this run']),
            el('td', { 'data-result': run.differentBasename.applicable ? 'applied' : 'inapplicable' }, [
              'INAPPLICABLE — Link refuses cross-basename comparison',
            ]),
          ]),
          el('tr', { 'data-daa-link': 'different-platform' }, [
            el('th', { scope: 'row' }, ['Two issuer members']),
            el('td', {}, ['same service basename']),
            el('td', {}, ['different']),
            el('td', { 'data-result': run.otherPlatform.linked ? 'linked' : 'not-linked' }, [
              run.otherPlatform.linked ? 'LINKED' : 'NOT LINKED',
            ]),
          ]),
        ]),
      ]),
    ]),
    disclosure('Inspect the three current-run pseudonyms', [
      el('div', { class: 'hexblock', 'data-daa-nym': 'service-a-first' }, [
        `platform A · service basename · statement 1\n${first}`,
      ]),
      el('div', { class: 'hexblock', 'data-daa-nym': 'service-a-second' }, [
        `platform A · service basename · statement 2\n${run.nymHex(run.signature2.nym)}`,
      ]),
      el('div', { class: 'hexblock', 'data-daa-nym': 'research-a' }, [
        `platform A · research basename\n${run.nymHex(run.differentBasenameSignature.nym)}`,
      ]),
      el('div', { class: 'hexblock', 'data-daa-nym': 'service-b' }, [
        `platform B · service basename\n${run.nymHex(run.otherPlatformSignature.nym)}`,
      ]),
    ]),
  ]);
}

function limitsAndSources(run: DaaLessonRun): HTMLElement {
  return card('What the construction establishes — and what it does not', [
    callout('Revocation has a sharp privacy cost', [
      el('p', {}, [
        'This is CDL’s private-key rogue-list check, not credential-serial or administrator ' +
          'revocation. It can revoke a platform only after gsk becomes known. Publishing that ' +
          'secret lets every verifier compute the revoked platform’s pseudonym for every known ' +
          'basename, sacrificing that platform’s privacy.',
      ]),
      disclosure('Teaching view: the exact secret added in the revoked case', [
        el('div', { class: 'hexblock', 'data-daa-value': 'revoked-secret' }, [run.revocation.publishedSecret]),
        el('p', {}, [
          'The ordinary verifier view does not contain this value. It appears here only because ' +
            'the selected policy case models a compromised secret being published to the list.',
        ]),
      ]),
    ], 'alarm'),
    callout('Anonymous provenance is not runtime integrity', [
      el('p', {}, [
        'DAA proves that an issuer-approved member signed these evidence bytes without disclosing ' +
          'a universal AK Name. Appraisal of the PCR digest still proves only the measured state ' +
          'represented by those bytes. It does not prove that unmeasured runtime code is safe, ' +
          'and it does not repair NEG-1 from Act 6.',
      ]),
    ]),
    disclosure('Sources, assumptions, and deliberately omitted features', [
      el('p', {}, [
        el('a', {
          href: 'https://eprint.iacr.org/2016/663.pdf',
          target: '_blank',
          rel: 'noreferrer',
        }, ['CDL full version, ePrint 2016/663']),
        ': section 5.1 supplies Setup, Join, credential issuance, Sign, Verify, Link, and the ' +
          'private-key rogue-list check used here. The construction assumes DDH, JOC qSDH, random ' +
          'oracles, static corruptions, online-extractable proofs, and idealized hybrid functionalities.',
      ]),
      el('p', {}, [
        el('a', {
          href: 'https://www.rfc-editor.org/rfc/rfc9380.html',
          target: '_blank',
          rel: 'noreferrer',
        }, ['RFC 9380']),
        ' supplies hash-to-curve and domain-separation requirements. This implementation uses ' +
          'distinct DAA-specific BLS12-381 G1 domain tags and canonical compressed points.',
      ]),
      el('p', {}, [
        'Omitted: bsn = bottom, application attributes, signature-based revocation, TPM/ISO ' +
          'interoperability, hardware confinement, UC security, and post-quantum security. ' +
          'Deterministic seeds make the lesson reproducible; they are not production randomness.',
      ]),
      el('p', {}, [
        `The unrelated-secret control also ran: ${run.revocation.unrelated.valid ? 'ACCEPTED as expected' : 'unexpectedly rejected'}. ` +
          'A rogue list is not allowed to reject every member merely because it is nonempty.',
      ]),
    ]),
  ]);
}

function verificationChecks(result: DaaVerification): HTMLElement {
  return el(
    'ul',
    { class: 'checks', role: 'list', 'aria-label': 'DAA verifier checks' },
    result.checks.map((check) =>
      el('li', { class: 'check', role: 'listitem', 'data-state': check.ok ? 'pass' : 'fail' }, [
        el('span', { class: 'check-icon', 'aria-hidden': 'true' }, [check.ok ? '✓' : '✕']),
        el('span', {}, [
          el('span', { class: 'check-name' }, [`${check.ok ? 'PASS' : 'FAIL'} — ${check.name}`]),
          el('span', { class: 'check-detail' }, [check.detail]),
        ]),
      ])
    )
  );
}

function resultRow(label: string, passed: boolean, meaning: string): HTMLTableRowElement {
  return el('tr', { 'data-state': passed ? 'pass' : 'fail' }, [
    el('th', { scope: 'row' }, [label]),
    el('td', { 'data-result': passed ? 'pass' : 'fail' }, [passed ? 'PASS' : 'FAIL']),
    el('td', {}, [meaning]),
  ]);
}
