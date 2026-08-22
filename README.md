# Attestation Gate

Browser demo: measured boot into PCRs, a real TPMS_ATTEST quote, and a verifier with reference values — then execute something outside the measured set after the final boot measurement and watch every check pass. A boot quote proves what was measured, not what is running.

**Live demo:** https://systemslibrarian.github.io/crypto-lab-attestation-gate/

---

## What It Is

A working model of remote attestation, built from the actual specifications rather than from an
analogy to them.

**The primitives, exactly.**

| Piece | Standard | What this repo does |
|---|---|---|
| PCR extension | TPM 2.0 Library Part 1, "PCR Operations" | Hand-rolled `PCR_new := H(PCR_old ‖ measurement)` over a hand-rolled SHA-256 (FIPS 180-4), so the exact 64-byte preimage can be shown |
| `TPMS_ATTEST` | TPM 2.0 Library Part 2, `TPMS_ATTEST` / `TPMS_QUOTE_INFO` / `TPML_PCR_SELECTION` | Hand-rolled marshaller with a per-field byte map, plus a strict fail-closed parser |
| Restricted signing | TPM 2.0 Part 1 §11.4.6.1, §25.1.3; Part 3 §15.4, §17.6, §20.2 | `TicketIsSafe()`, the NULL validation ticket, and `TPM_RC_TICKET` on `TPM2_Sign` |
| Quote signature | ECDSA on NIST P-256 (FIPS 186-4) | `@noble/curves`, deterministic per RFC 6979 so every byte on the page is reproducible |
| Credential activation | TPM 2.0 Part 3 §12.6–12.7; TCG EK Credential Profile | Real ECDH on P-256, real `KDFa`/`KDFe`, real AES-128-CFB, real HMAC-SHA-256 |
| Attestation architecture | **RFC 9334** — RATS Architecture (Informational, January 2023) | Attester → Evidence → Verifier → Attestation Result → Relying Party, with Endorsements and Reference Values as separate inputs |
| Evidence format | **RFC 9711** — Entity Attestation Token (Standards Track, April 2025) | A real claims-set, integer-keyed in CBOR and name-keyed in JSON |
| Measurement encoding | **RFC 10013** — EAT Measured Component (Standards Track, July 2026) | The `measured-component` data item, both serializations |
| CBOR | **RFC 8949** | Hand-rolled deterministic encoder (§4.2.1 core deterministic encoding) |

**The maths, in one paragraph.** A PCR is a register whose only write operation is
`PCR ← H(PCR ‖ d)`. The old value is an input, so the sequence of measurements is welded in order:
landing on a chosen final value would mean finding `d` with `H(PCR ‖ d) = target`, a second-preimage
problem. A quote is an ECDSA signature over `H(m)` where `m` is a marshalled `TPMS_ATTEST` beginning
`FF 54 43 47`, and the only thing that structure says about the registers is one composite digest,
`H(PCR_a ‖ PCR_b ‖ …)` over the selected set in ascending index order. Individual register values
reach the verifier separately, in an unsigned event log, and are trustworthy only because replaying
that log has to reproduce the composite digest inside the signature. The page shows every one of
those steps with its inputs.

**The security model.** The attester is untrusted; the TPM inside it is trusted to the extent that
its keys never leave it. The verifier is trusted by the relying party. The verifier's trust anchors
are supplied out of band and are never established by Evidence. Nothing here defends against a
compromised verifier, and nothing here defends against physical attack on a TPM.

**Not production cryptography.** This is a teaching demo. It runs entirely in your browser, with no
backend, no network calls and nothing persisted. There is no TPM anywhere near it — a TPM is
hardware, and this page models one in software, so every protection that comes from a key
physically never leaving a chip is described here rather than enforced.

## Exhibits

1. **Measured Boot** — step the chain firmware → EV_SEPARATOR → boot loader → kernel command line →
   kernel → initrd, one extension at a time, with the exact 64 bytes hashed shown as two tinted
   halves. Edit any measured value and watch which registers move and which do not. Includes the
   reset-authority table, because "you can never rewind a PCR" is false as a general claim about
   TPMs and true only for PCR 0–15.
2. **Quote & Verify** — the relying party issues a nonce, the attester returns a signed
   `TPMS_ATTEST`, and the verifier appraises it. Every check is shown, passing ones included. Behind
   disclosures: the whole structure field by field, and the same Evidence as an EAT in CBOR and
   JSON.
3. **The Magic Value** — hand a restricted attestation key a byte-perfect `TPMS_ATTEST` built
   outside the TPM and watch `TPM2_Sign` answer `TPM_RC_TICKET`. Clear one attribute bit and watch
   the same forgery become both signable and verifiable. The verifier-side magic check is shown as
   the backstop it is.
4. **Break It** — change one byte of the boot loader (`PCR_MISMATCH`, with the diverged register and
   the named stage); replay yesterday's genuine quote (`NONCE_STALE`, with a perfect signature); let
   a different machine with identical PCRs answer (`TRUST_ANCHOR_UNKNOWN`).
5. **Time of Use** — a clean boot, a clean quote, a clean appraisal, and then something outside the
   measured set runs. Every register is byte-identical afterwards. Verdict:
   **ATTESTED — AND COMPROMISED.**
6. **Whose Signature** — a stolen attestation key signing statements it wrote itself; a software key
   at a CA that never proved TPM residency, with the relying party checking and then not checking; a
   real `TPM2_MakeCredential` / `TPM2_ActivateCredential` run completed **in software** with a stolen
   endorsement key; and the hostile-trust-anchor fixture that appraises completely clean.

## When to Use It

Use remote attestation when a relying party must make a decision about a machine it does not
administer, and the machine's own assertions about itself are worthless. Network access control,
confidential computing, fleet compliance, and key release conditional on platform state are all real
and load-bearing uses.

**Do NOT use a static measured-boot quote as evidence that a machine is currently safe to talk to.**
It is evidence about a set of measurements at the time they were taken. Exhibit 5 is a complete,
honest, passing attestation of a compromised machine. If runtime state matters, you need runtime
measurement (Linux IMA extends PCR 10 for the lifetime of the system), and you need to quote the
register it uses.

Two more do-nots, both of which have real CVEs behind them: do not treat the `TPM_GENERATED_VALUE`
prefix as an authenticity marker a verifier can rely on, and do not accept an attestation key
without checking that a CA proved its TPM residency.

## Live Demo

https://systemslibrarian.github.io/crypto-lab-attestation-gate/

Step the boot chain and edit a measured value to see one register move. Open the byte map in
Quote & Verify and read a real `TPMS_ATTEST` field by field. Then go to Time of Use, press the
button, and read the check rows.

## What Can Go Wrong

**The measurement is a scope, not a guarantee.** A quote says nothing whatever about a PCR whose
selection bit is clear, and nothing about anything that was never measured into a PCR at all.
Exhibit 5 is that failure, performed. The correct mitigation is to widen the measured set (runtime
measurement) and to state the scope of what a given quote covers, not to describe attestation as
proving more than it does.

**The trust anchors are an input.** Evidence never establishes who to trust. A quote signed under an
attacker-controlled CA verifies completely clean, and there is nothing in the bytes that could
reveal it. Whatever process puts a CA into a verifier's trusted list is the real strength of the
system. Exhibit 6's last branch is the fixture.

**Key extraction removes the only real defence against quote forgery.** The `TPM_GENERATED_VALUE`
rule is enforced by the TPM refusing to sign, not by anything a verifier inspects. Once the
attestation key's private half is outside the TPM, plain ECDSA has no opinion about what it is
signing. This is what `fixedTPM` is for.

**A verifier-side magic check is a backstop, not the mechanism.** `tpm2_checkquote` stopped comparing
the magic field in 4.1-rc0 and was not fixed until 5.5.1 / 5.6.1 / 5.7 (CVE-2024-29038); its sibling
CVE-2024-29039 is the same shape, with the `TPML_PCR_SELECTION` in a supplied PCR file never compared
against the one inside the signed structure. Both are checks a verifier must perform because nothing
about the bytes performs them for it.

**An uncertified attestation key produces no error at all.** There is no TPM response code and no
protocol signal for "nobody proved this key is in a TPM". TCG has to phrase the countermeasure as a
normative MUST on the relying party — check for the `tcg-cap-verifiedTPMRestricted` policy OID
2.23.133.11.1.3 — precisely because the absence is silent. CVE-2021-3406 is that check missing in
production: a registrar's omissions invalidated the chain of trust from the endorsement certificate
to every agent attestation.

**The endorsement key is not the attestation key.** The EK cannot sign quotes — the standard
templates have `sign` CLEAR, and asking returns `TPM_RC_KEY`. But an attacker holding the EK private
key can complete a CA's credential-activation challenge in software and have a hostile key certified
as TPM-resident. Same end state, different mechanism.

**A replayed quote is a genuine quote.** Signatures do not expire. Freshness comes from the relying
party's nonce inside the signed bytes, and from nowhere else.

## Real-World Usage

TPM-based measured boot and attestation are deployed at scale. Windows uses PCR-bound sealing for
BitLocker and reports measured-boot state through Device Health Attestation. Linux fleets use
[Keylime](https://keylime.dev/) for continuous attestation, and `tpm2-tools` for the underlying
operations. Cloud providers expose vTPM attestation for confidential VMs. The IETF RATS working
group standardised the roles and the evidence formats used here. Every failure code in this demo
carries the name a real implementation would give the same condition.

## How to Run Locally

```
npm install
npm run dev          # vite dev server
npm test             # the unit and known-answer suites
npm run build        # typecheck, then a production build
npm run test:a11y    # the axe WCAG 2.1 A/AA gate against the built site
npm run test:e2e     # the claims suite
```

Playwright needs a browser once: `npx playwright install chromium`.

## Related Demos

- [Context Ward](https://systemslibrarian.github.io/crypto-lab-context-ward/) — the exhibit this one
  answers. It shows every integrity check passing honestly while an agent is compromised anyway, and
  states that role separation assumes a trusted host. This is the answer to that open question, and
  the demonstration that the answer is narrower than it sounds.
- [Signed Bytes](https://systemslibrarian.github.io/crypto-lab-signed-bytes/) — a signature binds an
  exact byte string, never the meaning a parser assigns it. Exhibit 3 is the same principle applied
  at the signing oracle instead of at the parser.
- [Chain of Trust](https://systemslibrarian.github.io/crypto-lab-chain-of-trust/) — what it takes for
  a certificate chain to mean something, which is the layer the trust anchors in Exhibit 6 sit on.
- [Model Breach](https://systemslibrarian.github.io/crypto-lab-model-breach/) — assumptions drifting
  from deployment, which is the general form of NEG-1.
- [Merkle Vault](https://systemslibrarian.github.io/crypto-lab-merkle-vault/) — the other major use
  of hash accumulation, for comparison with a PCR's linear chain.

## Build & Verify

Every cryptographic claim on the page is pinned to a published vector.

| Suite | What it checks |
|---|---|
| `src/core/sha256.test.ts` | FIPS 180-4 vectors, plus agreement with `@noble/hashes` on every length across four block boundaries and on a 1 MiB message |
| `src/core/hmac.test.ts` | RFC 4231 HMAC-SHA-256 test cases |
| `src/core/cbor.test.ts` | RFC 8949 Appendix A, the specification's own encoding table |
| `src/tpm/marshal.test.ts` | A **real captured `tpm2_quote` blob**, parsed field by field and re-marshalled to the identical 116 bytes; its `pcrDigest` recomputed from the ten published PCR values; a **real Windows Hello `TPM_ST_ATTEST_CERTIFY`** header; the spec's own `pcrSelect` bitmap examples |
| `src/tpm/key.test.ts` | RFC 6979 §A.2.5 ECDSA P-256 vectors; the EK template's `authPolicy` derived from scratch and compared to the published constant; the restricted-signing rule in both directions |
| `src/tpm/credential.test.ts` | NIST SP 800-38A CFB128-AES128 vectors; KDFa and KDFe re-derived by hand; the full activation path, including the software one |
| `src/eat/measured-component.test.ts` | RFC 10013's own worked examples, including the base64url strings the RFC prints in Figure 4 |
| `src/boot/stages.test.ts` | The published EV_SEPARATOR digest constants |
| `src/rats/verify.test.ts` | Every failure path, the two negative-claim fixtures, and the failure-code table |
| `e2e/claims.spec.ts` | Does the page tell the truth — every printed extension re-derived with OpenSSL's SHA-256, the byte map tiled against the blob it describes, each failure path naming its actual cause, verdict retirement, and the NEG-1 / THREAT-1 fixtures |
| `e2e/a11y.spec.ts` | Zero axe WCAG 2.1 A/AA violations across every driven state, at desktop and 380px, with arithmetic contrast and non-text contrast oracles axe does not have |

The GitHub Pages deploy runs all of it and is blocked if any of it fails.

## Performance

Everything runs synchronously in the main thread. A full measured boot, quote and appraisal is six
SHA-256 compressions plus one ECDSA signature and one verification — under a millisecond. The byte
inspector renders seventeen fields. There is nothing here that needs a worker.

---

*One of the browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
