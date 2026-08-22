/**
 * Act 2a — Domain separation, enforced at the signer.
 *
 * The four bytes FF 54 43 47 at the head of every TPM-generated structure are
 * a domain-separation tag, and the domain is enforced by the SIGNING oracle.
 * A restricted signing key refuses to sign externally-supplied bytes that
 * begin with them, because the TPM will not issue the validation ticket such a
 * key requires.
 *
 * The interaction is the argument. Hand a real attestation key a real,
 * byte-perfect TPMS_ATTEST built outside the TPM and watch TPM2_Sign answer
 * TPM_RC_TICKET. Then clear one bit of TPMA_OBJECT — the same key, the same
 * scalar, the same bytes — and watch the forgery become both signable and
 * verifiable.
 */

import { concatBytes, toHex, u32be } from '../../core/bytes';
import { sha256 } from '../../core/sha256';
import { DEFAULT_STAGES, QUOTED_PCRS, runMeasuredBoot } from '../../boot/stages';
import { TPM_GENERATED_VALUE, TPM_RH } from '../../tpm/constants';
import {
  attributesToUint32,
  hierarchyQualifiedName,
  makeAttestationKey,
  signExternalData,
  ticketIsSafe,
  tpm2Hash,
  verifyOverDigest,
} from '../../tpm/key';
import { craftAttest } from '../../tpm/quote';
import { labelledNonce } from '../../acts/machine';
import { button, card, clear, disclosure, el } from '../dom';
import { callout, hexRow, verdictBlock } from '../parts';

const PARENT = hierarchyQualifiedName(TPM_RH.OWNER);

export function renderMagicPanel(root: HTMLElement): void {
  let restricted = true;
  let includeMagic = true;
  const out = el('div', { class: 'magic-out' });

  const restrictedBtn = button('', () => {
    restricted = !restricted;
    draw();
  });
  const magicBtn = button('', () => {
    includeMagic = !includeMagic;
    draw();
  });

  function draw(): void {
    const ak = makeAttestationKey('magic-demo-ak', PARENT, restricted);
    const golden = runMeasuredBoot(DEFAULT_STAGES).bank;
    const nonce = labelledNonce('today');
    const crafted = craftAttest({
      magic: includeMagic ? TPM_GENERATED_VALUE : 0x00000000,
      qualifiedSigner: ak.qualifiedSigner,
      nonce,
      clockInfo: { clock: 3_600_000n, resetCount: 4, restartCount: 0, safe: true },
      firmwareVersion: 0x2026041500110203n,
      selection: QUOTED_PCRS,
      claimedPcrValues: [...QUOTED_PCRS].map((pcr) => golden.read(pcr)),
    });

    const hashed = tpm2Hash(crafted.bytes);
    const outcome = signExternalData(ak, crafted.bytes);
    const attrs = attributesToUint32(ak.pub.attributes);

    restrictedBtn.textContent = restricted
      ? 'restricted = SET  (a real attestation key)'
      : 'restricted = CLEAR  (an ordinary signing key)';
    restrictedBtn.setAttribute('aria-pressed', String(restricted));
    magicBtn.textContent = includeMagic
      ? 'magic = FF 54 43 47  (shaped like a real quote)'
      : 'magic = 00 00 00 00  (a careless forgery)';
    magicBtn.setAttribute('aria-pressed', String(includeMagic));

    const forgeryVerifies =
      outcome.ok && verifyOverDigest(ak.publicKey, sha256(crafted.bytes), outcome.signature);

    clear(out).append(
      el('div', { class: 'two-col' }, [
        el('div', {}, [
          el('span', { class: 'eyebrow' }, ['The key']),
          el('div', { class: 'hexblock' }, [
            `TPMA_OBJECT = 0x${attrs.toString(16).padStart(8, '0')}`,
          ]),
          el('p', { class: 'card-lede' }, [
            restricted
              ? '0x00050072 — fixedTPM, fixedParent, sensitiveDataOrigin, userWithAuth, restricted, sign. ' +
                'This is the well-known attribute value for an attestation key.'
              : '0x00040072 — the same key with bit 16 cleared. Same curve, same private scalar, ' +
                'same public key. One bit of a structure.',
          ]),
        ]),
        el('div', {}, [
          el('span', { class: 'eyebrow' }, ['The bytes handed to the TPM']),
          el('div', { class: 'hexblock' }, [
            el('span', { class: includeMagic ? 'hex-old' : '' }, [toHex(crafted.bytes.slice(0, 4))]),
            toHex(crafted.bytes.slice(4)),
          ]),
          el('p', { class: 'card-lede' }, [
            `${crafted.bytes.length} bytes. This is a complete, valid TPMS_ATTEST claiming the ` +
              'fleet’s golden PCR values and carrying the live nonce. It was assembled in ' +
              'ordinary memory; no TPM produced it.',
          ]),
        ]),
      ]),
      el('span', { class: 'eyebrow' }, ['Step 1 · TPM2_Hash over externally-supplied data']),
      el('div', { role: 'status', 'aria-live': 'polite' }, [
        el('p', {}, [
          `TicketIsSafe(buffer) → ${ticketIsSafe(crafted.bytes) ? 'TRUE' : 'FALSE'}. `,
          hashed.ticket.hierarchy === TPM_RH.NULL
            ? 'The TPM hashed the data — it always does — and returned a NULL ticket: hierarchy ' +
              'TPM_RH_NULL, empty digest. It will not certify that this digest is safe for a ' +
              'restricted key.'
            : 'The TPM returned a real validation ticket, vouching that these bytes did not begin ' +
              'with TPM_GENERATED_VALUE.',
        ]),
        hashed.refusal ? callout('Why the ticket is NULL', [el('p', {}, [hashed.refusal])]) : null,
      ]),
      el('span', { class: 'eyebrow' }, ['Step 2 · TPM2_Sign']),
      outcome.ok
        ? el('div', {}, [
            verdictBlock(
              includeMagic ? 'alarm' : 'ok',
              'SIGNED',
              includeMagic
                ? 'An unrestricted key signs anything. This forgery is now indistinguishable from ' +
                  'a genuine quote by any test a verifier can run on the bytes.'
                : 'A restricted key signed these bytes precisely BECAUSE they are not shaped like ' +
                  'an attestation. That is the rule working, not failing.'
            ),
            hexRow('signature', outcome.signature),
            el('p', { role: 'status', 'aria-live': 'polite' }, [
              `A verifier checking the signature against this key’s public half: ` +
                `${forgeryVerifies ? 'ACCEPTS' : 'rejects'}.`,
            ]),
            includeMagic
              ? callout(
                  'This is what the rule exists to prevent',
                  [
                    el('p', {}, [
                      'The magic value is not a secret and not an authenticator. An attacker can ' +
                        'type it. The only thing that ever stopped this forgery was the TPM ' +
                        'declining to sign, and that protection disappears the moment the key is ' +
                        'not restricted — or is not inside a TPM at all.',
                    ]),
                  ],
                  'alarm'
                )
              : callout('Now the verifier-side backstop earns its keep', [
                  el('p', {}, [
                    'This blob does not begin with FF 54 43 47, so a verifier that checks the ' +
                      'magic rejects it with NOT_TPM_GENERATED. That check is worth having — but ' +
                      'notice it only catches the careless case. Set the magic back and the same ' +
                      'check passes on a forgery.',
                  ]),
                ]),
          ])
        : el('div', {}, [
            // The `ok` tone on a refusal is deliberate, and it is the rule
            // this stylesheet is built on: colour tracks system integrity,
            // not the return value. The TPM declining to sign is the
            // protection working.
            verdictBlock(
              'ok',
              `REFUSED — ${outcome.responseName}`,
              `The protection held. ${outcome.reason}`
            ),
            el('div', { class: 'hexblock' }, [
              `responseCode = 0x${outcome.responseCode.toString(16).padStart(8, '0')} ` +
                `(TPM_RC_TICKET on parameter 3)`,
            ]),
            el('p', {}, [
              'No signature was produced. Not a bad signature, not a warning — the operation did ' +
                'not happen. Every subsequent check a verifier might run is moot.',
            ]),
          ])
    );
  }

  clear(root).append(
    card('Four bytes that are not a signature, and not a checksum', [
      el('p', { class: 'card-lede' }, [
        'Every structure a TPM generates and signs begins with the same four bytes: 0xFF followed ' +
          'by the ASCII letters T, C, G. It is tempting to read that as a marker a verifier ' +
          'authenticates. It is not — it is public, and anyone can type it.',
      ]),
      el('p', { class: 'card-lede' }, [
        'It is a domain separator, and the domain is enforced on the signing side. When a TPM ' +
          'hashes data you gave it, it checks whether the first four octets are that value. If ' +
          'they are, it returns a NULL validation ticket — and a restricted signing key will not ' +
          'sign without a real one. So an attestation key cannot be talked into signing something ' +
          'a verifier would read as attestation data. That is the whole mechanism.',
      ]),
      el('p', { class: 'card-lede' }, [
        'Below: a real attestation key, and a real TPMS_ATTEST built outside the TPM claiming a ' +
          'clean boot. Try to get it signed.',
      ]),
      el('div', { class: 'btn-row' }, [restrictedBtn, magicBtn]),
    ]),
    out,
    card('Reading the rule precisely', [
      disclosure('Where the specification says this, in its own words', [
        el('p', {}, [
          el('em', {}, ['TPM 2.0 Library Part 1 §11.4.6.1: ']),
          '“When a key has this restriction, the TPM will not use the key to sign message digests ' +
            'that the TPM did not compute… To allow a restricted key to sign an externally ' +
            'generated message, the TPM is used to produce the message digest. When the TPM ' +
            'computes the digest, it will validate that the message does not begin with ' +
            'TPM_GENERATED_VALUE. If it does, then the TPM will not produce the special ' +
            'certification (a ticket) that indicates that the digest was produced by the TPM and ' +
            'is safe to sign with a restricted key.”',
        ]),
        el('p', {}, [
          el('em', {}, ['And Part 1 §9.5.3.2, on the verifier’s duty: ']),
          '“Similarly, an entity checking an attestation made by an AK must verify that the ' +
            'message signed begins with TPM_GENERATED_VALUE.” Note the word the specification ' +
            'chose. The mechanism is stated first and the verifier’s check is introduced as an ' +
            'additional, similar duty — a backstop against misparsing, not the anti-forgery ' +
            'measure.',
        ]),
      ]),
      disclosure('Why a restricted key is allowed to sign external data at all', [
        el('p', {}, [
          'Because it is genuinely useful. An attestation key signing a certificate request is a ' +
            'normal operation, and that request is external data. The rule is not “refuse ' +
            'everything external” — it is “refuse external data in the attestation domain”. The ' +
            'ticket is how a stateless TPM remembers, across two commands, that a particular ' +
            'digest came from data outside that domain.',
        ]),
        el('p', {}, [
          'That is also exactly why the verifier-side magic check is still required: a restricted ' +
            'key’s signature could legitimately be over a CSR, so the verifier has to confirm the ' +
            'blob it is parsing really is an attestation.',
        ]),
      ]),
      disclosure('When the backstop was the only thing left — CVE-2024-29038', [
        el('p', {}, [
          'tpm2-tools’ `tpm2_checkquote` stopped comparing the magic field in 4.1-rc0, when ' +
            '`tpm2_util_get_digest_from_quote()` was replaced with a helper that dropped the ' +
            'check. It was not fixed until 5.5.1 / 5.6.1 / 5.7. The advisory’s own words: “A ' +
            'malicious attacker can generate arbitrary quote data which is not detected by tpm2 ' +
            'checkquote.”',
        ]),
        el('p', {}, [
          'The sibling issue, CVE-2024-29039, is the other half of the same lesson: the ' +
            'TPML_PCR_SELECTION in the supplied PCR file was never compared against the one ' +
            'inside the signed structure, so digests could be attributed to different PCR slots ' +
            'or banks entirely. Both are checks a verifier must perform because nothing about the ' +
            'bytes performs them for it.',
        ]),
      ]),
      disclosure('The same idea elsewhere in this suite', [
        el('p', {}, [
          'A signature binds an exact byte string and never the meaning a parser assigns to it. ',
          el('a', { href: 'https://systemslibrarian.github.io/crypto-lab-signed-bytes/', target: '_blank', rel: 'noopener' }, [
            'Signed Bytes',
          ]),
          ' is the whole exhibit for that, and this act is the same principle applied at the ' +
            'signing oracle instead of at the parser: prefix the domain, and refuse to sign into ' +
            'a domain you did not generate.',
        ]),
      ]),
    ]),
    card('A quick check', [
      disclosure('If a verifier checks the magic value, is quote forgery prevented?', [
        el('p', {}, [
          'No. The magic is attacker-controllable — it is four constant bytes in a public ' +
            'specification. An attacker who can get a suitable key to sign simply includes it, ' +
            'and the check passes. Toggle the two controls above to see both halves: with ' +
            'restricted CLEAR and the magic present, the forgery is signed and verifies; with ' +
            'restricted SET, the signature never happens no matter what the verifier does.',
        ]),
        el('p', {}, [
          'The check is still required, because a restricted key may legitimately sign non-' +
            'attestation data. It is a backstop against misparsing. Treating it as the mechanism ' +
            'is the mistake.',
        ]),
      ]),
      disclosure('What are the four bytes, and why those four?', [
        el('p', {}, [
          `TPM_GENERATED_VALUE = 0x${TPM_GENERATED_VALUE.toString(16)} — on the wire, ` +
            `${toHex(u32be(TPM_GENERATED_VALUE))}: the octet 0xFF followed by "TCG" in ASCII. ` +
            'The leading 0xFF is not a valid first byte of most structures a TPM might otherwise ' +
            'be asked to sign, and the tag is fixed-width so the TPM can test it after four ' +
            'octets without buffering the message.',
        ]),
        el('div', { class: 'hexblock' }, [
          `SHA-256 of the magic alone = ${toHex(sha256(concatBytes(u32be(TPM_GENERATED_VALUE))))}`,
        ]),
      ]),
    ])
  );

  draw();
}
