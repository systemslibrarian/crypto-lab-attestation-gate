import { describe, expect, it } from 'vitest';
import { craftAttest, tpm2Quote } from './quote';
import { hierarchyQualifiedName, makeAttestationKey, signExternalData, verifyOverDigest } from './key';
import { TPM_GENERATED_VALUE, TPM_RH, TPM_ST } from './constants';
import { PcrBank } from './pcr';
import { unmarshalAttest } from './marshal';
import { concatBytes, toHex, u32be, utf8 } from '../core/bytes';
import { sha256 } from '../core/sha256';

const ak = makeAttestationKey('quote-test-ak', hierarchyQualifiedName(TPM_RH.OWNER));

function bankWith(values: Record<number, string>): PcrBank {
  const bank = new PcrBank();
  for (const [pcr, text] of Object.entries(values)) {
    bank.extend(Number(pcr), sha256(utf8(text)), text);
  }
  return bank;
}

describe('TPM2_Quote', () => {
  const bank = bankWith({ 0: 'firmware', 4: 'loader', 9: 'kernel' });
  const nonce = sha256(utf8('challenge'));
  const quote = tpm2Quote({
    ak,
    bank,
    selection: [0, 4, 9],
    nonce,
    clockInfo: { clock: 1234n, resetCount: 2, restartCount: 0, safe: true },
    firmwareVersion: 0x2026041500110203n,
  });

  it('signs the marshalled structure, not the composite digest', () => {
    expect(toHex(quote.digest)).toBe(toHex(sha256(quote.attestBytes)));
    expect(toHex(quote.digest)).not.toBe(toHex(quote.attest.attested.pcrDigest));
    expect(verifyOverDigest(quote.akPublicKey, quote.digest, quote.signature)).toBe(true);
  });

  it('begins the signed message with the magic, with no TPM2B size prefix in front', () => {
    expect(toHex(quote.attestBytes.slice(0, 4))).toBe('ff544347');
    expect(quote.attest.magic).toBe(TPM_GENERATED_VALUE);
    expect(quote.attest.type).toBe(TPM_ST.ATTEST_QUOTE);
  });

  it('carries the caller’s nonce verbatim in extraData', () => {
    expect(toHex(unmarshalAttest(quote.attestBytes).extraData)).toBe(toHex(nonce));
  });

  it('carries the AK’s Qualified Name, which folds in the hierarchy', () => {
    expect(toHex(quote.attest.qualifiedSigner)).toBe(toHex(ak.qualifiedSigner));
    expect(quote.attest.qualifiedSigner.length).toBe(34);
  });

  it('returns the selection sorted ascending, whatever order it was asked for', () => {
    const shuffled = tpm2Quote({
      ak,
      bank,
      selection: [9, 0, 4],
      nonce,
      clockInfo: { clock: 1234n, resetCount: 2, restartCount: 0, safe: true },
      firmwareVersion: 0x2026041500110203n,
    });
    expect(shuffled.attest.attested.pcrSelect).toEqual([0, 4, 9]);
    expect(toHex(shuffled.attestBytes)).toBe(toHex(quote.attestBytes));
  });

  it('says nothing about a PCR whose selection bit is clear', () => {
    const narrow = tpm2Quote({
      ak,
      bank,
      selection: [0],
      nonce,
      clockInfo: { clock: 1234n, resetCount: 2, restartCount: 0, safe: true },
      firmwareVersion: 0x2026041500110203n,
    });
    expect(toHex(narrow.attest.attested.pcrDigest)).toBe(toHex(sha256(bank.read(0))));
    // Extending an unselected register changes nothing in this quote.
    const later = bankWith({ 0: 'firmware', 4: 'loader', 9: 'kernel' });
    later.extend(8, sha256(utf8('anything')), '');
    const again = tpm2Quote({
      ak,
      bank: later,
      selection: [0],
      nonce,
      clockInfo: { clock: 1234n, resetCount: 2, restartCount: 0, safe: true },
      firmwareVersion: 0x2026041500110203n,
    });
    expect(toHex(again.attestBytes)).toBe(toHex(narrow.attestBytes));
  });

  it('changes the signed bytes when any single input changes', () => {
    const base = toHex(quote.attestBytes);
    const variants = [
      tpm2Quote({ ak, bank, selection: [0, 4, 9], nonce: sha256(utf8('other')), clockInfo: { clock: 1234n, resetCount: 2, restartCount: 0, safe: true }, firmwareVersion: 0x2026041500110203n }),
      tpm2Quote({ ak, bank, selection: [0, 4, 9], nonce, clockInfo: { clock: 1235n, resetCount: 2, restartCount: 0, safe: true }, firmwareVersion: 0x2026041500110203n }),
      tpm2Quote({ ak, bank, selection: [0, 4, 9], nonce, clockInfo: { clock: 1234n, resetCount: 3, restartCount: 0, safe: true }, firmwareVersion: 0x2026041500110203n }),
      tpm2Quote({ ak, bank, selection: [0, 4, 9], nonce, clockInfo: { clock: 1234n, resetCount: 2, restartCount: 0, safe: false }, firmwareVersion: 0x2026041500110203n }),
      tpm2Quote({ ak, bank, selection: [0, 4, 9], nonce, clockInfo: { clock: 1234n, resetCount: 2, restartCount: 0, safe: true }, firmwareVersion: 1n }),
    ];
    for (const v of variants) expect(toHex(v.attestBytes)).not.toBe(base);
  });

  it('is reproducible: the same inputs give byte-identical signatures', () => {
    const again = tpm2Quote({
      ak,
      bank,
      selection: [0, 4, 9],
      nonce,
      clockInfo: { clock: 1234n, resetCount: 2, restartCount: 0, safe: true },
      firmwareVersion: 0x2026041500110203n,
    });
    expect(toHex(again.signature)).toBe(toHex(quote.signature));
  });
});

describe('Crafting an attestation outside the TPM (Act 2a)', () => {
  const golden = bankWith({ 0: 'firmware', 4: 'loader', 9: 'kernel' });
  const nonce = sha256(utf8('challenge'));
  const crafted = craftAttest({
    qualifiedSigner: ak.qualifiedSigner,
    nonce,
    clockInfo: { clock: 1234n, resetCount: 2, restartCount: 0, safe: true },
    firmwareVersion: 0x2026041500110203n,
    selection: [0, 4, 9],
    claimedPcrValues: [golden.read(0), golden.read(4), golden.read(9)],
  });

  it('is byte-identical to a genuine quote of the same state', () => {
    const genuine = tpm2Quote({
      ak,
      bank: golden,
      selection: [0, 4, 9],
      nonce,
      clockInfo: { clock: 1234n, resetCount: 2, restartCount: 0, safe: true },
      firmwareVersion: 0x2026041500110203n,
    });
    expect(toHex(crafted.bytes)).toBe(toHex(genuine.attestBytes));
  });

  it('cannot be signed by a restricted attestation key', () => {
    const outcome = signExternalData(ak, crafted.bytes);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) throw new Error('unreachable');
    expect(outcome.responseName).toBe('TPM_RC_TICKET');
  });

  it('CAN be signed by the same key with only the restricted bit cleared', () => {
    const unrestricted = makeAttestationKey(
      'quote-test-ak',
      hierarchyQualifiedName(TPM_RH.OWNER),
      false
    );
    expect(toHex(unrestricted.secretKey)).toBe(toHex(ak.secretKey));
    const outcome = signExternalData(unrestricted, crafted.bytes);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) throw new Error('unreachable');
    // ...and the forgery verifies. That is the whole point: the defence is
    // the refusal to sign, not anything a verifier can look at.
    expect(
      verifyOverDigest(unrestricted.publicKey, sha256(crafted.bytes), outcome.signature)
    ).toBe(true);
  });

  it('a forgery WITHOUT the magic is signable by a restricted key — and useless', () => {
    const noMagic = craftAttest({
      magic: 0x00000000,
      qualifiedSigner: ak.qualifiedSigner,
      nonce,
      clockInfo: { clock: 1234n, resetCount: 2, restartCount: 0, safe: true },
      firmwareVersion: 0x2026041500110203n,
      selection: [0, 4, 9],
      claimedPcrValues: [golden.read(0), golden.read(4), golden.read(9)],
    });
    const outcome = signExternalData(ak, noMagic.bytes);
    expect(outcome.ok).toBe(true);
    // The restricted key signed it precisely BECAUSE it is not shaped like an
    // attestation. A verifier's magic check is what catches this one.
    expect(toHex(noMagic.bytes.slice(0, 4))).not.toBe('ff544347');
  });

  it('the magic must be at offset 0 to trigger the refusal', () => {
    const shifted = concatBytes(new Uint8Array([0x00]), u32be(TPM_GENERATED_VALUE), utf8('x'));
    expect(signExternalData(ak, shifted).ok).toBe(true);
  });
});
