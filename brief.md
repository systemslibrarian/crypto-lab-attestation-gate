5. Attestation Gate

crypto-lab-attestation-gate · PROTOCOLS · direct sequel to Context Ward

Thesis. Context Ward states that role separation assumes a trusted host, and Act 6 shows that assumption failing. This is the exhibit that answers the question Context Ward leaves open — and then shows the answer is narrower than it sounds.

Construction. RATS architecture (RFC 9334): Attester → Evidence → Verifier → Attestation Result → Relying Party. PCRs extended as PCR_new = H(PCR_old ‖ measurement).

Implement the real quote structure. Revision 2 said the quote is a signature over (PCR digest ‖ nonce). That is adjacent-to-spec, and the spec-fidelity rule this document added in Revision 2 is exactly what should have caught it — so it catches it now. A real TPM2_Quote signs a structured TPMS_ATTEST containing the magic value, attestation type, qualified signer, caller-supplied extra data (the nonce), clock information (clock, reset count, restart count, safe flag), firmware version, and the attested PCR selection and digest. Build that byte layout with deterministic teaching keys.

The magic value earns its own act: it exists so a signing key cannot be tricked into signing externally-supplied bytes that a verifier would mistake for attestation data. That is a domain-separation lesson in a place nobody looks for one, and it pairs with Signed Bytes.

EAT and RATS sit above the quote, not instead of it. Evidence encoded as EAT — RFC 9711 (Standards Track, April 2025), CBOR or JWT. For measurement encoding, RFC 10013 (EAT Measured Component) defines the information model and its JSON/CBOR serializations. Both numbers verified.

Acts
Measured boot. Step firmware → bootloader → kernel → initrd, each stage extending a PCR before handing off. Extension is one-way accumulation. Scope the claim to the static boot PCRs this lab uses — TPM reset semantics do exist for other PCRs, including locality-gated resets, and "you can never rewind a PCR" is false as a general statement about TPMs.
Quote and verify. Relying party issues a nonce, attester returns a signed quote, verifier compares against reference values. Inspect the full TPMS_ATTEST byte-by-byte in Full lab depth — every field, not just the digest. 2a. Domain separation, enforced at the signer. The magic value at the head of the structure exists so an attestation key cannot be induced to sign externally-supplied bytes that a verifier would read as TPM-generated attestation data. The enforcement lives on the signing side, not the verifying side — a restricted signing key refuses to sign a payload beginning with the generated-value magic, which is why the protection holds even against a verifier that never looks. Model it that way: hand the AK an externally-crafted TPMS_ATTEST, watch the restricted-key rule refuse to sign it, then remove the restriction and watch the forgery become both signable and verifiable. A verifier-side magic check is a secondary backstop and should be shown as such, not as the mechanism. Cross-link Signed Bytes: a signature binds an exact byte string, never the meaning a parser assigns to it.
Change one byte. Modify the bootloader; the final digest diverges. PCR_MISMATCH, with a diff showing which stage broke the chain.
Replay. Present yesterday's valid quote. NONCE_STALE.
Wrong machine. A genuinely signed quote from a different attester. TRUST_ANCHOR_UNKNOWN.
Time of check, time of use — the climax. Boot a clean, correctly-measured kernel. After the final boot measurement, load something outside this lab's measured set. Every PCR still matches. The quote verifies perfectly. Verdict: ATTESTED — AND COMPROMISED, borrowing Context Ward's convention deliberately. Phrase it as outside-the-measured-set rather than "loads a malicious module," because runtime measurement architectures do measure later-loaded components — RFC 10013 explicitly contemplates run-time integrity checks as measured components. The gap this act demonstrates is in this measurement scope, not in attestation.
Whose signature, and who says so. Two sub-acts, and the distinction between them is the teaching:
7a — compromised attesting environment. Compromise the attestation key or the environment that holds it. Signatures are valid and the Evidence is false. This is the direct path and the one to lead with.
7b — endorsement, not signing. The endorsement key and the attestation key are different keys, and Revision 1 conflated them. The EK does not sign quotes. Its role is narrower than Revision 2 implied too: in enrollment protocols whose TPM-residency proof rests on EK-backed credential activation, MakeCredential/ActivateCredential binds an AK object to the TPM through the EK relationship. An attacker holding the EK private key therefore does not forge quotes directly — they get a hostile AK certified as TPM-resident during enrollment, then sign whatever they like with it. Same end state, different mechanism, and the mechanism is the lesson. Scope the act to that enrollment path explicitly. AK_NOT_CERTIFIED when the chain is checked; nothing at all when it isn't.

Negative claim (NEG-1). A static measured-boot quote proves the measurements those PCRs represent at the time they were taken; it does not continuously prove current runtime state. Scope this precisely — RATS Evidence is general, and runtime measurement architectures exist (run-time integrity checks are explicitly among the measured components RFC 10013 contemplates). The exhibit implements static measured boot and must say so, or it teaches a false generalization about attestation as a whole. Act 6 is the evidence fixture.

Negative claim (THREAT-1). The verifier's trust anchors are an assumption, not a result. Evidence itself never establishes them. Act 7's fixture verifies completely clean under a hostile anchor.

Failure codes. PCR_MISMATCH · NONCE_STALE · TRUST_ANCHOR_UNKNOWN · AK_NOT_CERTIFIED · QUOTE_BAD_SIGNATURE · REFERENCE_MISSING · ALG_MISMATCH

Repo description.

Browser demo: measured boot into PCRs, a real TPMS_ATTEST quote, and a verifier with reference values — then execute something outside the measured set after the final boot measurement and watch every check pass. A boot quote proves what was measured, not what is running.