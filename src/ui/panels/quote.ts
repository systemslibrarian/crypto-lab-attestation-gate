/**
 * Act 2 — Quote and verify.
 *
 * The relying party issues a nonce, the attester returns a signed quote, and
 * the verifier appraises it against reference values. Every check is shown,
 * passing ones included, because which questions a verifier chose to ask is
 * the security-relevant decision and a verdict alone hides it.
 *
 * The full TPMS_ATTEST goes behind a disclosure, field by field. That is where
 * the depth lives — a newcomer follows the act without opening it and an
 * expert opens it first.
 */

import { toBase64Url, toHex } from '../../core/bytes';
import { Machine, labelledNonce } from '../../acts/machine';
import { DEFAULT_STAGES, QUOTED_PCRS, referenceValues } from '../../boot/stages';
import { TPM_ALG } from '../../tpm/constants';
import { verifyEvidence, type AppraisalPolicy } from '../../rats/verify';
import { FLEET_CA, SELF_SERVICE_CA } from '../../acts/scenarios';
import { REFERENCE_LOG } from '../../acts/scenarios';
import { button, card, clear, disclosure, el } from '../dom';
import { byteMap, callout, checkList, headline, hexRow, pcrComparison } from '../parts';

const CERT = {
  issuer: FLEET_CA,
  verifiedTpmRestricted: true,
  residency: 'credential-activation' as const,
};

export function renderQuotePanel(root: HTMLElement): void {
  let exchange = 0;
  const out = el('div', { class: 'quote-out' });

  function draw(): void {
    const nonce = labelledNonce(exchange === 0 ? 'today' : `exchange-${exchange}`);
    const machine = new Machine({ serial: 'A7-3391', certificate: CERT });
    const evidence = machine.attest(nonce);
    const policy: AppraisalPolicy = {
      expectedNonce: nonce,
      referenceValues: referenceValues(DEFAULT_STAGES),
      referenceBankAlg: TPM_ALG.SHA256,
      trustedIssuers: [FLEET_CA, SELF_SERVICE_CA],
      requiredPcrs: [...QUOTED_PCRS],
      checkAkCertification: true,
      checkMagic: true,
    };
    const result = verifyEvidence(evidence, policy, REFERENCE_LOG);
    const q = evidence.quote;

    clear(out).append(
      el('div', { class: 'two-col' }, [
        el('div', {}, [
          el('span', { class: 'eyebrow' }, ['1 · Relying party → attester']),
          hexRow('nonce (32 random bytes, fresh for this exchange)', nonce),
          el('p', { class: 'card-lede' }, [
            'The nonce is the only thing making this exchange different from the last one. It goes ' +
              'into the signed structure as extraData, untouched — the TPM does not interpret it.',
          ]),
        ]),
        el('div', {}, [
          el('span', { class: 'eyebrow' }, ['2 · Attester → relying party']),
          hexRow(`TPMS_ATTEST (${q.attestBytes.length} bytes, the exact signed message)`, q.attestBytes),
          hexRow('ECDSA P-256 signature over SHA-256 of those bytes', q.signature),
        ]),
      ]),
      el('span', { class: 'eyebrow' }, ['3 · Verifier appraises']),
      headline(result, {
        compromised: false,
        headline: 'The machine is running exactly what it measured.',
        explanation:
          'Nothing outside the measured set has executed, the attestation key is inside the TPM, ' +
          'and the relying party’s trust anchors are the ones it meant to configure. The other ' +
          'tabs are the runs where one of those stops being true.',
      }),
      checkList(result.checks),
      el('h4', { class: 'card-title' }, ['Replayed registers against the reference values']),
      el('p', { class: 'card-lede' }, [
        'A quote contains no PCR values at all — only one composite digest over the selected set. ' +
          'The verifier gets the individual registers by replaying the event log, and knows the ' +
          'log is honest because the replay has to reproduce the digest inside the signature.',
      ]),
      pcrComparison(result.pcrs),
      disclosure('The whole TPMS_ATTEST, field by field', [
        el('p', {}, [
          'This is the structure a real TPM2_Quote returns. Not a signature over the PCR digest, ' +
            'and not a signature over “PCR digest and nonce” — over all of this, magic value ' +
            'first. Everything a relying party is entitled to conclude comes from a field in here.',
        ]),
        el('p', { class: 'card-lede' }, [
          'One detail that is easy to double-count: TPM2_Quote returns this wrapped in a ' +
            'TPM2B_ATTEST, and the specification says “the size parameter is not signed”. The ' +
            'signed message starts at the FF below.',
        ]),
        byteMap(q.fields, (path) => path === 'magic' || path === 'extraData.buffer'),
      ]),
      disclosure('The same Evidence as an Entity Attestation Token (RFC 9711 / RFC 10013)', [
        el('p', {}, [
          'RATS (RFC 9334) is an architecture and defines no wire format at all — §12 says so in ' +
            'as many words. EAT is one of the formats that fills the gap. The claims below are ' +
            'the same measurements, keyed by integer in CBOR and by name in JSON.',
        ]),
        callout('What this EAT is, and is not', [
          el('p', {}, [
            'It is a real RFC 9711 claims-set carrying real RFC 10013 measured components. It is ' +
              'NOT wrapped in a COSE_Sign1, so the claims-set carries no signature of its own. ' +
              'That is deliberate: the signature that matters is the TPM’s, over the TPMS_ATTEST, ' +
              'and this token is bound to it by two equalities the verifier recomputes — ' +
              'eat_nonce equals extraData byte for byte, and every measured component’s digest ' +
              'equals the event-log entry it corresponds to. Unbound claims are just claims.',
          ]),
        ]),
        el('span', { class: 'field-label' }, [
          `CBOR (${evidence.eat.cbor.length} bytes, deterministically encoded per RFC 8949 §4.2.1)`,
        ]),
        el('div', { class: 'hexblock' }, [toHex(evidence.eat.cbor)]),
        el('span', { class: 'field-label' }, ['JSON serialization of the same claims']),
        el('div', { class: 'hexblock' }, [JSON.stringify(evidence.eat.json, null, 2)]),
        el('p', { class: 'card-lede' }, [
          `eat_nonce is claim key 10 in CBOR and "eat_nonce" in JSON — base64url, unpadded: ` +
            `${toBase64Url(nonce)}. The measurements claim is key 273, and each entry is a ` +
            '[CoAP Content-Format, body] pair: 295 for a CBOR measured component, 296 for a JSON ' +
            'one. In both serializations the component is an opaque string, never a nested object.',
        ]),
      ]),
      disclosure('The RATS roles, and which one each piece of this is', [
        el(
          'div',
          { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': 'RATS roles' },
          [
            el('table', {}, [
              el('thead', {}, [
                el('tr', {}, [
                  el('th', { scope: 'col' }, ['RFC 9334 role or artifact']),
                  el('th', { scope: 'col' }, ['In this exhibit']),
                ]),
              ]),
              el(
                'tbody',
                {},
                [
                  ['Attester', 'The modelled machine and its TPM'],
                  ['Evidence', 'The signed quote, the event log, and the EAT'],
                  ['Verifier', 'The appraisal above, running against a policy'],
                  ['Attestation Result', 'ATTESTED or REJECTED, plus the failure codes'],
                  ['Relying Party', 'Whoever acts on that result — the network gate'],
                  ['Reference Values', 'The golden PCR values, from a Reference Value Provider'],
                  ['Endorser', 'The CA that issued the attestation key’s certificate'],
                  [
                    'Appraisal Policy for Evidence',
                    'Which checks run, which issuers are trusted, which PCRs are required',
                  ],
                ].map(([a, b]) => el('tr', {}, [el('td', {}, [a]), el('td', {}, [b])]))
              ),
            ]),
          ]
        ),
      ])
    );
  }

  clear(root).append(
    card('Asking a machine what it booted', [
      el('p', { class: 'card-lede' }, [
        'The registers from Act 1 never leave the TPM. To convey them somewhere, the TPM signs a ' +
          'statement about them with a key it will not release — an attestation key — and that ' +
          'signed statement is a quote.',
      ]),
      el('p', { class: 'card-lede' }, [
        'The relying party goes first: it sends a nonce, so a quote made yesterday cannot answer ' +
          'today’s question. Then it appraises what comes back against reference values for the ' +
          'software the machine is supposed to be running.',
      ]),
      el('div', { class: 'btn-row' }, [
        button(
          'New challenge',
          () => {
            exchange += 1;
            draw();
          },
          { class: 'btn btn-primary' }
        ),
      ]),
    ]),
    out
  );

  draw();
}
