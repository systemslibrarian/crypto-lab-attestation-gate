/**
 * Act 8 — Sealed Storage. The other half of the PCR story.
 *
 * Act 2 asks a machine to PROVE what it measured to someone else. This act
 * asks the TPM to RELEASE something only while the machine is in a measured
 * state. The same registers, the same extend operation, and a different
 * question: not "do you believe this report?" but "will the chip hand the
 * bytes over?".
 *
 * The three things this panel is built to keep apart, because collapsing any
 * two of them is how sealing gets taught wrongly:
 *
 *   - A POLICY DIGEST IS NOT THE STATE. `authPolicy` is one 32-byte commitment
 *     to a condition. The PCR values are not in it and cannot be read out of
 *     it; the comparison happens by RE-COMPUTING the digest from the registers
 *     the machine actually has.
 *   - PUBLIC METADATA IS NOT THE SECRET, AND IS NOT UNPROTECTED EITHER. The
 *     sealed object's `TPM2B_PUBLIC` is readable by anyone and still cannot be
 *     edited, because the object's Name is a digest of it and the Name is
 *     inside the private blob's HMAC.
 *   - A SATISFIED POLICY IS NOT A GUARANTEE ABOUT WHAT HAPPENS NEXT. Once the
 *     bytes are released they are in the platform's memory and the TPM has no
 *     further say. The last scenario shows that, and says in as many words that
 *     the policy was satisfied rather than defeated.
 *
 * Every verdict on this page is computed by `runSealing`, from the measured
 * state the boot chain actually produces. Nothing is a stored expected answer,
 * and changing any input retires the previous verdict rather than leaving it
 * on screen beside inputs that no longer produced it.
 */

import { toHex } from '../../core/bytes';
import { cloneStages, DEFAULT_STAGES } from '../../boot/stages';
import {
  describeResponseCode,
  OEM_AUTHORITY,
  RECOVERY_PURPOSE,
  referenceSealedObject,
  runSealing,
  SCENARIOS,
  SEALED_PCRS,
  SEALED_SECRET,
  SEAL_PARENT,
  SEAL_FIXTURES,
  SEAL_RESPONSE_CODES,
  withStage,
  type SealingRun,
  type Scenario,
} from '../../acts/sealing';
import { button, card, clear, disclosure, el } from '../dom';
import { byteMap, callout, checkList, hexRow, pcrStrip, verdictBlock } from '../parts';
import type { PolicyStep } from '../../tpm/policy';

const FIRMWARE_DEFAULT =
  DEFAULT_STAGES.find((s) => s.id === 'firmware')?.content ?? 'OpenFW 3.4.2 / POST / build 20260114';

/** The firmware value a scenario arrives with, so the field and the case agree. */
function firmwareOf(scenario: Scenario): string {
  const stages = scenario.config.runStages ?? DEFAULT_STAGES;
  return stages.find((s) => s.id === 'firmware')?.content ?? FIRMWARE_DEFAULT;
}

function stepRow(step: PolicyStep, index: number): HTMLElement {
  const hashRows: HTMLElement[] = [];
  step.hashes.forEach((hash, i) => {
    const label =
      step.hashes.length === 1
        ? 'the exact bytes hashed'
        : `the exact bytes hashed — hash ${i + 1} of ${step.hashes.length}`;
    hashRows.push(
      el('span', { class: 'field-label' }, [label]),
      el('div', { class: 'hexblock', 'data-seal-hash': 'preimage' }, [toHex(hash.preimage)]),
      el('span', { class: 'field-label' }, [
        i === step.hashes.length - 1 ? 'policyDigest after' : 'intermediate digest',
      ]),
      el('div', { class: 'hexblock hex-new', 'data-seal-hash': 'digest' }, [toHex(hash.digest)])
    );
  });
  return el('li', { class: 'stage', role: 'listitem', 'data-seal-resets': String(step.resets) }, [
    el('span', { class: 'stage-head' }, [
      el('span', { class: 'stage-name' }, [`${index + 1}. ${step.command}`]),
      el('span', { class: 'stage-pcr' }, [`0x${step.commandCode.toString(16).padStart(8, '0')}`]),
    ]),
    el('span', { class: 'stage-note' }, [step.detail]),
    el('span', { class: 'field-label' }, ['policyDigest before']),
    el('div', { class: 'hexblock hex-old', 'data-seal-hash': 'before' }, [toHex(step.before)]),
    step.resets
      ? el('span', { class: 'stage-meta' }, [
          'This command DISCARDS the digest above and restarts from a Zero Digest, so the bytes ' +
            'hashed below begin with 0…0 rather than with it. That is the specified behaviour, ' +
            'not a slip.',
        ])
      : null,
    ...hashRows,
  ]);
}

function stepList(steps: readonly PolicyStep[], label: string, key: string): HTMLElement {
  return el(
    'ul',
    { class: 'stages', role: 'list', 'aria-label': label, 'data-seal-policy': key },
    steps.map((step, i) => stepRow(step, i))
  );
}

function viewList(label: string, items: readonly string[]): HTMLElement {
  return el('div', {}, [
    el('span', { class: 'field-label' }, [label]),
    el(
      'ul',
      { role: 'list' },
      items.map((text) => el('li', { role: 'listitem' }, [text]))
    ),
  ]);
}

export function renderSealedPanel(root: HTMLElement): void {
  let selected: Scenario = SCENARIOS[0];
  let firmware = FIRMWARE_DEFAULT;
  let result: SealingRun | null = null;
  let retiredBecause: string | null = null;

  const reference = referenceSealedObject();
  const out = el('div', { class: 'seal-out' });
  const resultHost = el('div', { class: 'seal-result-host' });
  const intent = el('p', { class: 'card-lede', role: 'status', 'aria-live': 'polite' });
  const scenarioButtons: HTMLButtonElement[] = [];

  const firmwareInput = el('input', {
    type: 'text',
    id: 'seal-firmware',
    value: FIRMWARE_DEFAULT,
    spellcheck: 'false',
    autocomplete: 'off',
  }) as HTMLInputElement;
  firmwareInput.addEventListener('input', () => {
    firmware = firmwareInput.value;
    retire('the measured firmware value was edited');
  });

  const runButton = button(
    'Run this case',
    () => {
      const base = selected.config;
      const stages = base.runStages ?? cloneStages(DEFAULT_STAGES);
      result = runSealing({ ...base, runStages: withStage(stages, 'firmware', firmware) });
      retiredBecause = null;
      draw();
    },
    { class: 'btn btn-primary' }
  );

  function retire(reason: string): void {
    // Any change to an input, the policy, or the measured state invalidates the
    // previous answer. It is removed rather than greyed out: a stale verdict
    // beside inputs that did not produce it is the one thing this panel must
    // never show.
    result = null;
    retiredBecause = reason;
    draw();
  }

  function selectScenario(scenario: Scenario): void {
    selected = scenario;
    firmware = firmwareOf(scenario);
    firmwareInput.value = firmware;
    retire(`a different case was selected: ${scenario.label}`);
  }

  function drawScenarioButtons(): void {
    scenarioButtons.forEach((btn, i) => {
      const active = SCENARIOS[i].id === selected.id;
      btn.setAttribute('aria-pressed', String(active));
      btn.classList.toggle('active', active);
    });
  }

  function resultRegion(): HTMLElement {
    if (!result) {
      return el('div', { class: 'seal-result' }, [
        verdictBlock(
          'bad',
          'NOT RUN',
          retiredBecause
            ? `The previous result was retired because ${retiredBecause}. Press “Run this case”.`
            : 'Choose a case and press “Run this case”.',
          true
        ),
      ]);
    }
    const run = result;
    const tone = run.verdict === 'RELEASED' ? 'ok' : run.verdict === 'REFUSED' ? 'bad' : 'alarm';
    return el('div', { class: 'seal-result' }, [
      verdictBlock(tone, run.verdict, undefined, true),
      el('span', { class: 'eyebrow' }, ['What the TPM model did, step by step']),
      checkList(run.checks),
      run.codes.length > 0
        ? el('div', {}, [
            el('span', { class: 'field-label' }, ['Response codes, in order']),
            el(
              'ul',
              { class: 'codes', role: 'list', 'aria-label': 'TPM response codes this run returned' },
              run.codes.map((code) =>
                el('li', { class: 'code-row', 'data-state': 'fail', role: 'listitem' }, [
                  el('span', { class: 'code-icon', 'aria-hidden': 'true' }, ['✕']),
                  el('span', {}, [
                    el('span', { class: 'code-name' }, [code.name]),
                    el('span', { class: 'code-detail' }, [code.note]),
                  ]),
                ])
              )
            ),
          ])
        : el('div', {}),
      el('span', { class: 'eyebrow' }, ['The registers this run actually produced']),
      pcrStrip(
        run.current.pcrs.map((p, i) => ({
          pcr: p.pcr,
          value: p.value,
          changed: run.sealed.pcrs[i]?.value !== p.value,
        }))
      ),
      el('div', { 'data-seal-run': 'current-digest' }, [
        hexRow(
          `composite digest over PCRs {${run.plan.selection.join(', ')}} at unseal time`,
          toHex(run.current.digestTPM)
        ),
      ]),
      el('div', { 'data-seal-run': 'sealed-digest' }, [
        hexRow('the digest the object was sealed to', toHex(run.sealed.digestTPM)),
      ]),
      el('div', { 'data-seal-run': 'session-digest' }, [
        hexRow('policyDigest the session reached', toHex(run.sessionDigest)),
      ]),
      el('div', { 'data-seal-run': 'auth-policy' }, [
        hexRow('authPolicy the object requires', toHex(run.plan.authPolicy)),
      ]),
      run.released !== undefined
        ? callout(
            run.exposed ? 'Released, and then read by something else' : 'Released',
            [
              el('p', {}, ['TPM2_Unseal returned outData:']),
              el('div', { class: 'hexblock' }, [run.released]),
              el('p', {}, [run.views.ground.explanation]),
            ],
            run.exposed ? 'alarm' : 'scope'
          )
        : callout('Nothing was released', [el('p', {}, [run.views.ground.explanation])]),
      el('span', { class: 'eyebrow' }, ['Four views of the same run']),
      el('p', { class: 'card-lede' }, [
        'These are four different sets of knowledge, not four descriptions of one. The attacker ' +
          'view holds only what is actually public; the TPM-model view holds the session state no ' +
          'caller can read; the teaching view holds the plaintext, which nothing else here does.',
      ]),
      disclosure('Attacker view — what a holder of the blob can do with it', [
        viewList('Holds', run.views.attacker.holds),
        viewList('Learns from this run', run.views.attacker.learns),
        viewList('Cannot do', run.views.attacker.cannot),
      ]),
      disclosure('Platform view — what the machine itself sees', [
        viewList('Observed', run.views.platform),
      ]),
      disclosure('TPM-model view — the session state and the response code', [
        viewList('Session', run.views.tpm),
        run.steps.length > 0
          ? stepList(run.steps, 'The policy assertions this session executed', 'session')
          : el('p', {}, ['No assertion was accepted, so the session never left the Zero Digest.']),
      ]),
      disclosure('Teaching view — the ground truth nothing else here can observe', [
        el('p', {}, [run.views.ground.headline]),
        el('p', {}, [run.views.ground.explanation]),
        el('span', { class: 'field-label' }, ['The sealed plaintext, which only this view knows']),
        el('div', { class: 'hexblock', 'data-seal-truth': 'plaintext' }, [SEALED_SECRET]),
        el('span', { class: 'field-label' }, [
          'The TPM-generated obfuscation value in front of it — unique = H(obfuscate ‖ secret)',
        ]),
        el('div', { class: 'hexblock', 'data-seal-truth': 'obfuscate' }, [
          toHex(SEAL_FIXTURES.obfuscate),
        ]),
        el('span', { class: 'field-label' }, ['The storage parent’s seedValue — never readable on real hardware']),
        el('div', { class: 'hexblock' }, [toHex(SEAL_PARENT.seedValue)]),
      ]),
    ]);
  }

  // ONLY the result region is redrawn. The controls above it are built once and
  // never removed, because `clear()`-ing a subtree that contains the focused
  // element blurs it — so redrawing the whole panel on every keystroke made
  // the measured-value field lose focus after one character and the act
  // unusable without a pointer. The claims suite drives this act by keyboard
  // alone, which is what found it.
  function draw(): void {
    drawScenarioButtons();
    intent.textContent = selected.intent;
    clear(resultHost).append(resultRegion());
  }

  SCENARIOS.forEach((scenario) => {
    scenarioButtons.push(
      button(scenario.label, () => selectScenario(scenario), {
        'aria-pressed': 'false',
        'data-scenario': scenario.id,
      })
    );
  });

  out.append(
    el('span', { class: 'eyebrow' }, ['1 · What the secret is sealed to']),
    el('p', { class: 'card-lede' }, [
      `A synthetic value is sealed to PCRs {${SEALED_PCRS.join(', ')}} — the same static boot ` +
        'set the quote in Act 2 selects, so the chain you stepped through in Act 1 is the chain ' +
        'this policy checks.',
    ]),
    pcrStrip(reference.sealed.pcrs.map((p) => ({ pcr: p.pcr, value: p.value }))),
    hexRow('composite digest of the sealed state', toHex(reference.sealed.digestTPM)),
    el('div', { 'data-seal-ref': 'authPolicy' }, [
      hexRow('authPolicy stored in the sealed object', toHex(reference.plan.authPolicy)),
    ]),
    el('span', { class: 'eyebrow' }, ['2 · Choose a case']),
    el('div', { class: 'btn-row' }, scenarioButtons),
    intent,
    el('label', { class: 'field', for: 'seal-firmware' }, [
      el('span', { class: 'field-label' }, [
        'The measured firmware value at unseal time — edit it and the registers move',
      ]),
      firmwareInput,
    ]),
    el('div', { class: 'btn-row' }, [runButton]),
    el('span', { class: 'eyebrow' }, ['3 · What happened']),
    resultHost
  );

  clear(root).append(
    card('Sealing asks the chip a different question', [
      el('p', { class: 'card-lede' }, [
        'A quote is a report. It travels to someone else, who decides what to do about it, and ' +
          'every act before this one is about what that report can and cannot establish.',
      ]),
      el('p', { class: 'card-lede' }, [
        'Sealing does not report anything. A secret is wrapped so that the TPM itself will only ' +
          'unwrap it while the machine is in a measured state the owner chose in advance. There ' +
          'is no verifier, no nonce and no network: the enforcement is local, and the thing being ' +
          'enforced is a 32-byte digest called a policy.',
      ]),
      el('p', { class: 'card-lede' }, [
        'That is stronger than attestation in one specific way and exactly as narrow in another. ' +
          'Stronger, because nobody has to be trusted to act on a report. Exactly as narrow, ' +
          'because a policy over PCRs is a statement about what was measured — and the last case ' +
          'below is the one worth staying for.',
      ]),
    ]),
    card('The object, and the four things it keeps apart', [
      el('p', { class: 'card-lede' }, [
        'A sealed secret is an ordinary TPM object with no key in it: a ' +
          'TPM_ALG_KEYEDHASH public area with sign and decrypt CLEAR, which is the ' +
          'specification’s definition of a Sealed Data Object. Four distinct things travel with ' +
          'it, and only one of them is confidential.',
      ]),
      el(
        'ul',
        { role: 'list' },
        [
          'The PCR VALUES. Public, unsigned, and readable by anything running on the machine. ' +
            'They are not stored in the object at all.',
          'The POLICY DIGEST. Public. A commitment to a condition, not a record of a state — ' +
            'you cannot read the expected PCR values out of it, and the TPM does not store them ' +
            'either. It recomputes.',
          'The SEALED OBJECT’S PUBLIC METADATA. Public: type, attributes, authPolicy, and ' +
            '`unique`. Not confidential, and not editable without the parent seed, because the ' +
            'object’s Name is a digest of this structure and the Name is inside the private ' +
            'blob’s HMAC.',
          'The PROTECTED SECRET MATERIAL. Only ever inside `encSensitive`, recoverable only with ' +
            'the storage parent’s seedValue.',
        ].map((t) => el('li', { role: 'listitem' }, [t]))
      ),
      disclosure('The sealed object’s public area, field by field', [
        el('p', {}, [
          'This is the exact byte string whose digest becomes the Name. One changed byte anywhere ' +
            'in it makes the object unloadable rather than merely different, which is why the ' +
            '“tamper with the public metadata” case below reports an integrity failure.',
        ]),
        byteMap(
          reference.object.publicFields,
          undefined,
          'Sealed object TPMT_PUBLIC fields, in wire order'
        ),
        el('div', { 'data-seal-ref': 'name' }, [
          hexRow('Name = nameAlg || H(publicArea)', toHex(reference.object.name)),
        ]),
      ]),
      disclosure('The private blob’s three parts', [
        el('p', {}, [
          'TPM2B_DIGEST(outerHMAC) followed by the marshalled TPM2B_IV and the encrypted ' +
            'TPM2B_SENSITIVE. The HMAC covers the IV, the ciphertext AND the Name, so the public ' +
            'and private halves cannot be mixed and matched without the parent seed.',
        ]),
        hexRow('outerHMAC = HMAC(HMACkey, symIv || encSensitive || Name)', toHex(reference.object.parts.integrityOuter)),
        hexRow('symIv', toHex(reference.object.parts.iv)),
        hexRow('encSensitive — AES-128-CFB over the whole TPM2B_SENSITIVE', toHex(reference.object.parts.encSensitive)),
        el('p', {}, [
          'Neither key is in the blob. symKey comes from KDFa over the parent’s seedValue AND ' +
            'this object’s Name; HMACkey comes from the same seed with the INTEGRITY label and no ' +
            'context at all.',
        ]),
      ]),
      disclosure('How the policy digest was built', [
        el('p', {}, [
          'Computed with TRIAL policy sessions, which is how a policy for a state the TPM is not ' +
            'currently in can be calculated at all. A trial session authorizes nothing — the ' +
            'authorization check refuses one outright.',
        ]),
        el('span', { class: 'field-label' }, ['Branch A — the sealed state']),
        stepList(reference.plan.steps.branchA, 'Branch A assertions', 'branchA'),
        hexRow('branch A digest', toHex(reference.plan.branchA)),
        el('span', { class: 'field-label' }, ['Branch B — the authorized recovery route']),
        stepList(reference.plan.steps.branchB, 'Branch B assertions', 'branchB'),
        hexRow('branch B digest', toHex(reference.plan.branchB)),
        el('span', { class: 'field-label' }, ['Both branches converge, then the command is pinned']),
        stepList(reference.plan.steps.common, 'The shared tail of the policy', 'common'),
        el('div', { 'data-seal-ref': 'authPolicy-derived' }, [
        hexRow('authPolicy', toHex(reference.plan.authPolicy)),
      ]),
        callout('The honest cost of the recovery branch', [
          el('p', {}, [
            'TPM2_PolicyAuthorize resets the digest to zero and replaces it with a digest over ' +
              'the AUTHORITY’S NAME and a purpose string. So branch B’s value does not depend on ' +
              'which state preceded it: it says “a state this authority approved”, not “this ' +
              'state”. The authority’s signature is the entire security of that branch.',
          ]),
          el('p', {}, [
            'What it is not is “accept any mismatch”. Reaching branch B needs a verification ' +
              'ticket over H(approvedPolicy || policyRef) under ' +
              `${OEM_AUTHORITY.label}, for the purpose “${RECOVERY_PURPOSE}”. A different key, a ` +
              'different purpose, a different state, or no signature at all each fail, and four ' +
              'of the cases above execute exactly those.',
          ]),
          el('p', {}, [
            'And the pin is still there: authPolicy is a function of branch A, so the object ' +
              'really is bound to one explicit PCR selection and one expected composite digest.',
          ]),
        ]),
      ]),
    ]),
    out,
    card('Every response code this model can return', [
      el('p', { class: 'card-lede' }, [
        'Unlike the failure codes in the appraisal acts, these are not this lab’s vocabulary. ' +
          'They are TPM_RC values from the specification’s own response-code tables, composed ' +
          'the way the reference implementation composes them: a format-one code carries the ' +
          'parameter, handle or session it is about in its own bits.',
      ]),
      el(
        'div',
        { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': 'TPM response codes' },
        [
          el('table', {}, [
            el('thead', {}, [
              el('tr', {}, [
                el('th', { scope: 'col' }, ['Code']),
                el('th', { scope: 'col' }, ['Value']),
                el('th', { scope: 'col' }, ['Returned by']),
                el('th', { scope: 'col' }, ['When']),
              ]),
            ]),
            el(
              'tbody',
              {},
              SEAL_RESPONSE_CODES.map((row) =>
                el('tr', {}, [
                  el('td', {}, [el('code', {}, [row.name])]),
                  el('td', {}, [describeResponseCode(row.code, row.name).note]),
                  el('td', {}, [row.from]),
                  el('td', {}, [row.when]),
                ])
              )
            ),
          ]),
        ]
      ),
    ]),
    card('What this act does not claim', [
      callout('No hardware, and no substitute for it', [
        el('p', {}, [
          'No TPM is executed and nothing is transmitted. The policy arithmetic and the object ' +
            'format are byte-exact for the structures implemented, but there is no command ' +
            'buffer, no session HMAC, no parameter encryption and no transport, so none of this ' +
            'is wire interoperable and a real TPM would accept none of it.',
        ]),
        el('p', {}, [
          'The storage parent’s seedValue is a value in this page’s memory. In hardware it is ' +
            'generated inside the chip and never leaves, and THAT — not any JavaScript equality ' +
            'check — is what makes an integrity failure mean something. One case above hands that ' +
            'seed to an attacker on purpose. Part 4 ObjectLoad skips CryptValidateKeys beneath a ' +
            'fixedTPM parent because it trusts that the TPM created or import-validated the blob; ' +
            'after seed extraction, that assumption fails and an authenticated substitute loads.',
        ]),
      ]),
      callout('Four things a PCR policy is not', [
        el(
          'ul',
          { role: 'list' },
          [
            'NOT secure boot. Nothing here verifies a signature on firmware. Measurement records ' +
              'what ran; secure boot refuses to run it. They are different mechanisms and a ' +
              'machine can have either without the other.',
            'NOT rollback prevention. This model has no NV counter, no TPM2_PolicyNV and no ' +
              'TPM2_PolicyCounterTimer, so an old sealed blob paired with an old measured state ' +
              'is accepted. That is also true of a bare PCR policy on real hardware, and is why ' +
              'real designs add an NV index as a second assertion.',
            'NOT anti-hammering. The object has noDA SET and there is no dictionary-attack ' +
              'lockout, no failed-attempt counter and no lockoutAuth. Nothing here slows an ' +
              'attacker down.',
            'NOT a production authorization system. There is no authValue, no HMAC or bound ' +
              'session, no audit, no locality and no physical presence. The object’s whole ' +
              'authorization is the one policy digest, which is the point of the lesson and not a ' +
              'deployment recommendation.',
          ].map((t) => el('li', { role: 'listitem' }, [t]))
        ),
      ]),
      disclosure('What the policy digests are and are not pinned to', [
        el('p', {}, [
          'The two-hash PolicyUpdate function is pinned to a published constant: the TCG EK ' +
            'Credential Profile’s authPolicy is the digest of a one-assertion policy, and the ' +
            'unit tests re-derive it from scratch. The composite PCR digest is pinned to a real ' +
            'captured tpm2_quote blob elsewhere in this lab.',
        ]),
        el('p', {}, [
          'The TPM2_PolicyPCR, TPM2_PolicyOR and TPM2_PolicyCommandCode digests are NOT pinned to ' +
            'a published test vector, because none was located. They are transcribed from the ' +
            'reference implementation published with Revision 01.83 and re-derived in the tests ' +
            'by a second implementation written from the equations. That is weaker than a ' +
            'published vector and is recorded as such rather than described as one.',
        ]),
      ]),
      disclosure('Where the specification text comes from', [
        el(
          'ul',
          { role: 'list' },
          [
            'Trusted Platform Module 2.0 Library, Version 185, March 12, 2026 — Part 1 ' +
              'Architecture §14.5, §16.7.3, §16.7.11, §19.4, §19.5, §24.5.2, §24.5.3.2; Part 2 ' +
              'Structures §8.3, §10.5.2, §10.8.7, §12.2.3.3, §12.2.4, §12.2.5, §12.3.2.4, ' +
              '§12.3.6, §12.3.7; Part 3 Commands §5.6, §12.1, §12.2, §12.7, §20.2, §22.2, ' +
              '§23.2.3, §23.6, §23.7, §23.11, §23.16.',
            'Trusted Platform Module Library, Family “2.0”, Level 00 Revision 01.83, January 25, ' +
              '2024 — the same clauses under the older numbering (Part 1 §17.5, §19.7.3, ' +
              '§19.7.11, §22.4, §22.5, §27.5.3.2), and the reference C code published only in ' +
              'that revision’s Part 3 “Commands with Code” and Part 4 “Supporting Routines”. ' +
              'The policy hashing order comes from Part 3; PrivateToSensitive, UnwrapOuter, ' +
              'ObjectLoad and CryptValidateKeys come from Part 4.',
            'TPM2_VerifySignature (Part 3 §20.2) was DEPRECATED in Version 185, in favour of ' +
              'TPM2_VerifySequenceComplete (§20.3) and TPM2_VerifyDigestSignature (§20.4), whose ' +
              'ticket carries the different tag TPM_ST_DIGEST_VERIFIED. This act mints the ' +
              'TPM_ST_VERIFIED ticket of the deprecated command, because that is the one the 01.83 ' +
              'equation specifies byte for byte. Version 185 §23.16 accepts a ticket from any of ' +
              'the three.',
          ].map((t) => el('li', { role: 'listitem' }, [t]))
        ),
      ]),
    ]),
    card('What this act adds to the one before it', [
      el('p', { class: 'card-lede' }, [
        'Act 6 showed a quote that verifies perfectly over a compromised machine, and said the ' +
          'gap is in the measured set rather than in attestation. Sealing has exactly the same ' +
          'scope limit, arriving from the other direction: the TPM will release a secret to a ' +
          'machine whose registers match, and the registers only know what was measured into ' +
          'them. The last case above is that sentence, executed.',
      ]),
      el('p', { class: 'card-lede' }, [
        'It is worth being precise about what that case does and does not show. The policy was ' +
          'not bypassed, the digest was not forged, and no check was skipped. The secret was ' +
          'released to an authorized state — and then read by something running in it. What a ' +
          'post-release compromise reaches is the material already handed over; the sealed object ' +
          'is unchanged and still requires the policy.',
      ]),
    ])
  );

  draw();
}
