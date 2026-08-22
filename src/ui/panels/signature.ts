/**
 * Act 7 — Whose signature, and who says so.
 *
 * Two sub-acts, and the distinction between them is the teaching.
 *
 * 7a is the direct path: the attestation key, or the environment holding it,
 * is compromised. Signatures are valid and the Evidence is false. Note what
 * this removes — the restricted-key rule of Act 2a is enforced BY THE TPM, and
 * once the private scalar is outside there is no signing side left to enforce
 * anything.
 *
 * 7b is the one people get wrong. The endorsement key does not sign quotes; it
 * cannot, because the standard EK templates have `sign` CLEAR. Its role is at
 * enrolment, in protocols whose TPM-residency proof rests on EK-backed
 * credential activation. An attacker holding the EK private key does not forge
 * a quote — they get a hostile attestation key CERTIFIED as TPM-resident, and
 * then sign whatever they like with it. Same end state, different mechanism,
 * and the mechanism is what you have to defend.
 *
 * THREAT-1 closes the panel: the verifier's trust anchors are an assumption,
 * not a result, and the fixture for that claim verifies completely clean.
 */

import { toHex } from '../../core/bytes';
import {
  runHostileEnrollment,
  scenarioCompromisedAk,
  scenarioEkBackedEnrollment,
  scenarioHostileAnchor,
  scenarioUncertifiedAk,
  type ScenarioRun,
} from '../../acts/scenarios';
import { attributesToUint32, makeEndorsementKey, tpm2Sign } from '../../tpm/key';
import { sha256 } from '../../core/sha256';
import { utf8 } from '../../core/bytes';
import { TPM_RH } from '../../tpm/constants';
import { button, card, clear, disclosure, el } from '../dom';
import { callout, checkList, failureCodeList, headline } from '../parts';

type Which = '7a' | '7b-checked' | '7b-unchecked' | '7b-ek' | 'threat-1';

const CHOICES: Array<[Which, string]> = [
  ['7a', '7a · The attestation key is stolen'],
  ['7b-checked', '7b-i · A software key, and the relying party checks'],
  ['7b-unchecked', '7b-i · …and the relying party does not check'],
  ['7b-ek', '7b-ii · The endorsement key gets it certified'],
  ['threat-1', 'THREAT-1 · A hostile trust anchor'],
];

export function renderSignaturePanel(root: HTMLElement): void {
  let which: Which = '7a';
  const out = el('div', { class: 'sig-out' });

  const btnEls = CHOICES.map(([id, label]) =>
    button(
      label,
      () => {
        which = id;
        draw();
      },
      { class: 'btn' }
    )
  );

  function currentRun(): ScenarioRun {
    switch (which) {
      case '7a':
        return scenarioCompromisedAk();
      case '7b-checked':
        return scenarioUncertifiedAk(true);
      case '7b-unchecked':
        return scenarioUncertifiedAk(false);
      case '7b-ek':
        return scenarioEkBackedEnrollment();
      default:
        return scenarioHostileAnchor();
    }
  }

  function draw(): void {
    for (const [i, [id]] of CHOICES.entries()) {
      btnEls[i].setAttribute('aria-pressed', String(id === which));
    }
    const run = currentRun();

    clear(out).append(
      el('span', { class: 'eyebrow' }, [`${run.act} · ${run.title}`]),
      el('p', { class: 'card-lede' }, [run.premise]),
      headline(run.result, run.groundTruth),
      failureCodeList(run.result.codes) ?? el('div', {}),
      checkList(run.result.checks),
      ...(which === '7a' ? [act7aDetail(run)] : []),
      ...(which === '7b-ek' || which === '7b-checked' || which === '7b-unchecked'
        ? [act7bDetail()]
        : []),
      ...(which === 'threat-1' ? [threatDetail(run)] : [])
    );
  }

  clear(root).append(
    card('A valid signature says a key was used. It has never said the statement is true.', [
      el('p', { class: 'card-lede' }, [
        'Everything so far assumed the attestation key is a real key inside a real TPM, and that ' +
          'the relying party knows which keys to trust. Both are assumptions, and neither is ' +
          'established by anything in the Evidence.',
      ]),
      el('div', { class: 'btn-row' }, btnEls),
    ]),
    out
  );

  draw();
}

function act7aDetail(run: ScenarioRun): HTMLElement {
  return card('What stealing the key removes', [
    el('p', { class: 'card-lede' }, [
      'Act 2a showed a restricted attestation key refusing to sign a hand-built TPMS_ATTEST. ' +
        'That refusal is enforced by the TPM. The structure below was built the same way and ' +
        'signed with the same key — because the private scalar is in the attacker’s hands, and ' +
        'plain ECDSA has no opinion about what it is signing.',
    ]),
    el('div', { class: 'hexblock' }, [
      `provenance: ${run.evidence.quote.provenance}\n` +
        `magic:      ${toHex(run.evidence.quote.attestBytes.slice(0, 4))} (the attacker typed it)\n` +
        `pcrDigest:  ${toHex(run.evidence.quote.attest.attested.pcrDigest)}`,
    ]),
    el('p', { class: 'card-lede' }, [
      'The event log sent alongside is the fleet’s own published reference log, so it replays to ' +
        'the composite digest the attacker claimed. Everything is internally consistent. It is ' +
        'also entirely false.',
    ]),
    callout(
      'This is why fixedTPM exists',
      [
        el('p', {}, [
          'A real attestation key is created with fixedTPM SET, which means the TPM will never ' +
            'produce a duplicable copy of it. That attribute is not paperwork — it is the only ' +
            'thing standing between "an attacker can use your key" and "an attacker has your ' +
            'key", and the second is categorically worse because every protection in Act 2a ' +
            'lives on the TPM’s side of that boundary.',
        ]),
      ],
      'alarm'
    ),
  ]);
}

function act7bDetail(): HTMLElement {
  const trace = runHostileEnrollment();
  const ek = makeEndorsementKey('demo/ek');
  const signAttempt = tpm2Sign(ek, sha256(utf8('a quote')), {
    hierarchy: TPM_RH.OWNER,
    digest: sha256(utf8('a quote')),
  });

  return card('The endorsement key, and what it is actually for', [
    el('p', { class: 'card-lede' }, [
      'A TPM ships with an endorsement key whose certificate is issued by the manufacturer. It ' +
        'is the closest thing a TPM has to a birth certificate, which is why people reach for ' +
        'it — and then assume it signs attestations. It does not.',
    ]),
    el('div', { class: 'hexblock' }, [
      `EK TPMA_OBJECT = 0x${attributesToUint32(ek.pub.attributes).toString(16).padStart(8, '0')}  ` +
        `(restricted, decrypt, sign CLEAR)\n` +
        `TPM2_Sign with the EK → ${signAttempt.ok ? 'signed' : signAttempt.responseName}` +
        `${signAttempt.ok ? '' : ` — ${signAttempt.reason}`}`,
    ]),
    el('p', { class: 'card-lede' }, [
      'The EK is a restricted DECRYPTION key. Its role is at enrolment: a CA wraps a challenge to ' +
        'it, bound to the Name of the attestation key being certified, and only a TPM holding ' +
        'both can return the challenge. That is the residency proof.',
    ]),
    disclosure('The enrolment, run for real — with no TPM anywhere in it', [
      el('p', {}, [
        'Below is a genuine TPM2_MakeCredential / TPM2_ActivateCredential exchange: real ECDH on ' +
          'P-256, real KDFe and KDFa, real AES-128-CFB, real HMAC-SHA-256. The attestation key ' +
          'was generated in ordinary memory and its public area carries every attribute bit an ' +
          'attestation key should have — they are just bits in a structure the attacker marshals, ' +
          'so a CA’s attribute check passes.',
      ]),
      el('div', { class: 'hexblock' }, [
        `AK Name (nameAlg || H(TPMT_PUBLIC))   ${toHex(trace.akName)}\n` +
          `CA’s challenge                        ${toHex(trace.credential)}\n` +
          `Z  = ECDH(stolen EK key, ephemeral)   ${trace.derivation.z}\n` +
          `seed = KDFe(Z, "IDENTITY", …)         ${trace.derivation.seed}\n` +
          `symKey = KDFa(seed, "STORAGE", Name)  ${trace.derivation.symKey}\n` +
          `hmacKey = KDFa(seed, "INTEGRITY")     ${trace.derivation.hmacKey}\n` +
          `recovered challenge                   ${toHex(trace.recovered)}\n` +
          `matches?                              ${trace.matched ? 'YES' : 'no'}`,
      ]),
      el('p', {}, [
        'Notice where the Name appears: as the KDF context for the symmetric key, and again as ' +
          'trailing input to the HMAC. It is bound twice. That binding is real and it works — a ' +
          'TPM loading a different attestation key gets TPM_RC_INTEGRITY and nothing is released.',
      ]),
      el('p', {}, [
        'And notice what the binding does not do. The specification says it plainly: “The ' +
          'credential provider could have produced the credential with no information from the ' +
          'TPM as the TPM did not need to provide a proof-of-possession of any private key in ' +
          'order for the credential provider to create the credential.” The challenge is public ' +
          'math. Whoever can decrypt it gets certified.',
      ]),
    ]),
    disclosure('What a relying party is supposed to check, and what happens when it does not', [
      el('p', {}, [
        'TCG states it as a normative MUST: a relying party evaluating signed data purporting to ' +
          'be TPM internal data must check for tcg-cap-verifiedTPMRestricted (OID ' +
          '2.23.133.11.1.3) in the attestation key’s certificate — the assertion that the issuing ' +
          'CA verified both fixedTPM and restricted.',
      ]),
      el('p', {}, [
        'When that check is missing there is no error, no TPM response code, and no protocol ' +
          'signal. The quote is well-formed, the signature verifies, the nonce is fresh and the ' +
          'registers match. The verifier returns a clean pass. That absence is the finding, and ' +
          'it is the shape of CVE-2021-3406, where a registrar’s missing checks invalidated the ' +
          'chain of trust from the endorsement certificate to every agent attestation.',
      ]),
    ]),
  ]);
}

function threatDetail(run: ScenarioRun): HTMLElement {
  return card('THREAT-1 — the trust anchors are an input', [
    callout(
      'The negative claim, and its evidence',
      [
        el('p', {}, [
          'The verifier’s trust anchors are an assumption, not a result. Evidence itself never ' +
            'establishes them.',
        ]),
        el('p', {}, [
          `This run is the fixture. The only thing different about it is one line of the relying ` +
            `party’s configuration: its trusted-issuer list contains ` +
            `${run.policy.trustedIssuers.join(', ')}. Everything else — the quote, the signature, ` +
            'the registers, the certificate — is genuine. The appraisal is not "clean with a ' +
            'warning". It is clean.',
        ]),
      ],
      'alarm'
    ),
    el('p', { class: 'card-lede' }, [
      'There is nothing in the Evidence a verifier could inspect to catch this, because appraisal ' +
        'is what happens after trust has been assumed. RFC 9334 puts the decision with the ' +
        'Verifier Owner, supplied out of band, for exactly this reason.',
    ]),
    disclosure('What this means in practice', [
      el('p', {}, [
        'Every attestation deployment has an answer to "which CA do we trust, and how did that ' +
          'list get onto this verifier?". If the answer is a configuration file that ships with ' +
          'the product, or an environment variable, or a list somebody pasted in during setup, ' +
          'then the strength of the whole system is the strength of that step — not the strength ' +
          'of the TPM, the signature, or the hash.',
      ]),
      el('p', {}, [
        'The same applies one layer down: the CA had to chain the endorsement certificate to a ' +
          'TPM manufacturer’s root, and that root list is another anchor supplied out of band.',
      ]),
    ]),
  ]);
}
