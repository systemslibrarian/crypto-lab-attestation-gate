/**
 * Act 6 — Time of check, time of use. The climax.
 *
 * A clean, correctly-measured kernel boots. After the final boot measurement
 * lands, userspace loads something that is not in this exhibit's measured set.
 * Every register still matches. The quote verifies perfectly. Every check
 * passes and every one of them is telling the truth.
 *
 * The verdict borrows Context Ward's convention deliberately — ATTESTED — AND
 * COMPROMISED — because it is the same shape of failure: an honest mechanism
 * answering the question it was asked while a different question goes unasked.
 *
 * SCOPE, and this is the part that has to be exactly right. The gap is in THIS
 * EXHIBIT'S measured set, not in attestation. The extend operation has no
 * notion of "boot": Linux IMA runs the identical operation on PCR 10 for the
 * lifetime of the system. What is being shown is that a STATIC MEASURED-BOOT
 * quote over PCR 0, 4, 8 and 9 proves what those registers accumulated at the
 * time they accumulated it, and says nothing whatever about a register it does
 * not select.
 */

import { toHex } from '../../core/bytes';
import { scenarioTimeOfUse } from '../../acts/scenarios';
import { RUNTIME_MEASUREMENT_PCR } from '../../boot/stages';
import { button, card, clear, disclosure, el } from '../dom';
import { callout, checkList, headline, pcrStrip } from '../parts';

export function renderTimeOfUsePanel(root: HTMLElement): void {
  let loaded = false;
  const out = el('div', { class: 'tou-out' });

  const loadBtn = button('', () => {
    loaded = !loaded;
    draw();
  });

  function draw(): void {
    const run = scenarioTimeOfUse();
    const runtime = run.groundTruth.runtimeEvent!;
    loadBtn.textContent = loaded
      ? 'Undo — unload it and re-quote'
      : `Load ${runtime.name} — after the last boot measurement`;
    loadBtn.setAttribute('aria-pressed', String(loaded));

    const quoted = run.evidence.quote.attest.attested;

    clear(out).append(
      el('span', { class: 'eyebrow' }, ['1 · The machine boots, correctly and honestly']),
      el('p', { class: 'card-lede' }, [
        'Nothing is tampered with. The firmware, the boot loader, the command line, the kernel ' +
          'and the initrd are all exactly what the fleet expects.',
      ]),
      el('span', { class: 'eyebrow' }, ['2 · Something runs that nobody measured']),
      el('div', { class: 'btn-row' }, [loadBtn]),
      loaded
        ? callout(
            'Loaded, and completely unrecorded',
            [
              el('p', {}, [
                `Userspace loaded `,
                el('strong', {}, [runtime.name]),
                `. Its digest is `,
              ]),
              el('div', { class: 'hexblock' }, [runtime.digest]),
              el('p', {}, [
                `Nothing extended PCR 0, 4, 8 or 9, because nothing measured this into them. A ` +
                  `runtime measurement architecture would extend PCR ${runtime.wouldMeasureInto} — ` +
                  `and this quote does not select PCR ${runtime.wouldMeasureInto}.`,
              ]),
            ],
            'alarm'
          )
        : el('p', { class: 'card-lede', role: 'status', 'aria-live': 'polite' }, [
            'Nothing has been loaded yet. Press the button, then look at what changes in the ' +
              'registers below. The answer is nothing.',
          ]),
      el('span', { class: 'eyebrow' }, ['3 · The registers, before and after']),
      pcrStrip(
        run.result.pcrs.map((p) => ({
          pcr: p.pcr,
          value: p.actual ?? '',
          changed: false,
        }))
      ),
      el('p', { class: 'card-lede', role: 'status', 'aria-live': 'polite' }, [
        loaded
          ? 'Identical. Not similar — identical, byte for byte, to the values before the load. ' +
            'The registers are not lying; they were never asked.'
          : 'These are the values a clean boot produces.',
      ]),
      el('div', { class: 'hexblock' }, [
        `composite pcrDigest over PCRs {${quoted.pcrSelect.join(', ')}} = ${toHex(quoted.pcrDigest)}`,
      ]),
      el('span', { class: 'eyebrow' }, ['4 · The relying party asks, and the verifier answers']),
      headline(
        run.result,
        loaded
          ? run.groundTruth
          : {
              compromised: false,
              headline: 'The machine is running exactly what it measured.',
              explanation: 'Load something outside the measured set and run this again.',
            }
      ),
      checkList(run.result.checks),
      loaded
        ? callout(
            'What just happened',
            [
              el('p', {}, [
                'Every check passed. Every check was honest. The signature is genuine, the nonce ' +
                  'is fresh, the attestation key is a real, certified, TPM-resident key, and the ' +
                  'registers match the reference values exactly — because they do match.',
              ]),
              el('p', {}, [
                'A boot quote proves what was measured. It does not prove what is running. Those ' +
                  'are different sentences, and the distance between them is where real ' +
                  'compromises live.',
              ]),
            ],
            'alarm'
          )
        : el('div', {}),
      el('h4', { class: 'card-title' }, ['NEG-1 — stated precisely, because the loose version is false']),
      callout('The negative claim this exhibit makes', [
        el('p', {}, [
          'A static measured-boot quote proves the measurements those PCRs represent at the time ' +
            'they were taken. It does not continuously prove current runtime state.',
        ]),
        el('p', {}, [
          'And the scope: that is a statement about a STATIC measured-boot quote over a chosen ' +
            'set of registers, not about attestation. RATS Evidence is general. Runtime ' +
            'measurement architectures exist and are ordinary — RFC 10013 lists a Run-Time ' +
            'Integrity Check among the things a measured component may be, and Linux IMA extends ' +
            `PCR ${RUNTIME_MEASUREMENT_PCR} on every policy-matched file access for the lifetime ` +
            'of the system. This exhibit implements static measured boot, and says so.',
        ]),
      ]),
    );
  }

  clear(root).append(
    card('The gap between what was measured and what is running', [
      el('p', { class: 'card-lede' }, [
        'Measured boot records what each stage handed to the next. That recording stops when the ' +
          'boot stops. Everything a machine does afterwards — every program it starts, every ' +
          'library it maps, every configuration it reloads — happens after the last measurement.',
      ]),
      el('p', { class: 'card-lede' }, [
        'This act is the one the rest of the exhibit is built to set up. Nothing below is broken, ' +
          'forged, replayed or misconfigured. Every piece works.',
      ]),
    ]),
    out,
    card('What actually closes this gap, and what does not', [
      disclosure('Runtime measurement — what IMA does and does not fix', [
        el('p', {}, [
          'The extend primitive is indifferent to time. PCR_new = H(PCR_old || digest) has no ' +
            'notion of "boot", and Linux IMA runs exactly that operation on PCR 10 per ' +
            'policy-matched file access, for as long as the system is up. The TCG profile itself ' +
            'hands the chain onward rather than ending it: PCR 8–15 are reserved so the OS can ' +
            'keep measuring.',
        ]),
        el('p', {}, [
          'So IMA widens the measured set forward in time. It closes the "loaded after the last ' +
            'boot measurement and never recorded" gap this act demonstrates. It does not close ' +
            '"measured correctly, then modified in memory", and it does not make a quote ' +
            'continuous — a quote is still a point-in-time signature over a point-in-time ' +
            'aggregate, and the aggregate can move between the quote and the relying party acting ' +
            'on it. IMA’s own violation handling, which poisons PCR 10 with 0xFF bytes on a ' +
            'time-of-measure/time-of-use race, is an admission that it detects some of those ' +
            'races rather than preventing them.',
        ]),
      ]),
      disclosure('Sealing, which is a different answer to a different question', [
        el('p', {}, [
          'A TPM can bind a secret to a PCR state so that it is only released while the registers ' +
            'hold particular values. That is stronger than attestation in one specific way — the ' +
            'TPM enforces it locally rather than reporting to someone who decides — and it shares ' +
            'exactly the same scope limit: it is a statement about the registers, and the ' +
            'registers only know what was measured into them.',
        ]),
      ]),
      disclosure('The sibling exhibit this one answers', [
        el('p', {}, [
          el('a', { href: 'https://systemslibrarian.github.io/crypto-lab-context-ward/', target: '_blank', rel: 'noopener' }, [
            'Context Ward',
          ]),
          ' shows an agent whose every integrity check passes honestly while it is compromised ' +
            'anyway, and states that role separation assumes a trusted host. This exhibit is the ' +
            'answer to the question that leaves open — remote attestation is how you check the ' +
            'host — and then shows the answer is narrower than it sounds. The verdict wording ' +
            'here is borrowed from there on purpose.',
        ]),
      ]),
    ])
  );

  draw();
}
