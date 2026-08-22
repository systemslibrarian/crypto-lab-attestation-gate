/**
 * A modelled attester: a TPM with an EK, an SRK and an AK, a boot chain, and
 * the ability to answer a challenge with Evidence.
 *
 * Everything is deterministic. Keys come from labelled rejection sampling and
 * signatures are RFC 6979, so every hex string the page prints is reproducible
 * and an act can be re-entered without the numbers moving. A real TPM draws
 * its keys from its own seeds and its signature nonces from its own RNG;
 * nothing the exhibit claims depends on which of those is true.
 */

import { concatBytes, u32be, utf8 } from '../core/bytes';
import { sha256 } from '../core/sha256';
import { TPM_ALG } from '../tpm/constants';
import {
  hierarchyQualifiedName,
  makeAttestationKey,
  makeEndorsementKey,
  makeStorageRootKey,
  type TpmObject,
} from '../tpm/key';
import { TPM_RH } from '../tpm/constants';
import { qualifiedName } from '../tpm/marshal';
import { tpm2Quote, type Quote } from '../tpm/quote';
import type { ClockInfo } from '../tpm/marshal';
import {
  cloneStages,
  DEFAULT_STAGES,
  QUOTED_PCRS,
  runMeasuredBoot,
  type BootStage,
} from '../boot/stages';
import { DBGSTAT, UEID_TYPE } from '../eat/claims';
import { VERSION_SCHEME } from '../eat/measured-component';
import { buildEvidence, type Evidence, type EvidenceIdentity } from '../rats/evidence';
import { computeName } from '../tpm/marshal';
import type { AkCertificate } from '../rats/verify';

/** This lab's own EAT profile identifier. Not a standard profile — see the README. */
export const LAB_EAT_PROFILE = 'https://crypto-lab.systemslibrarian.dev/profiles/attestation-gate/v1';

/** A deterministic nonce, so a replayed quote is reproducibly the wrong one. */
export function labelledNonce(label: string): Uint8Array {
  return sha256(utf8(`crypto-lab-attestation-gate/nonce/${label}`));
}

function labelledBytes(label: string, length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0; out.length > i; i += 32) {
    out.set(sha256(concatBytes(utf8(label), u32be(i))).slice(0, Math.min(32, length - i)), i);
  }
  return out;
}

export interface MachineOptions {
  /** Distinguishes one modelled machine from another — Act 5 needs two. */
  serial: string;
  stages?: BootStage[];
  /** Act 2a flips this to model an ordinary signing key wearing an AK's clothes. */
  akRestricted?: boolean;
  clock?: bigint;
  resetCount?: number;
  restartCount?: number;
  firmwareVersion?: bigint;
  bootcount?: number;
  /** The AK certificate this attester presents, if it has one. */
  certificate?: Omit<AkCertificate, 'subjectPublicKey' | 'subjectName'>;
}

export class Machine {
  readonly ek: TpmObject;
  readonly srk: TpmObject;
  readonly ak: TpmObject;
  readonly stages: BootStage[];
  readonly clockInfo: ClockInfo;
  readonly firmwareVersion: bigint;
  readonly identity: EvidenceIdentity;

  constructor(readonly options: MachineOptions) {
    const s = options.serial;
    this.ek = makeEndorsementKey(`ek/${s}`);
    this.srk = makeStorageRootKey(`srk/${s}`);
    // The AK is a child of the SRK in the owner hierarchy, so its Qualified
    // Name folds in the SRK's Name and the hierarchy handle -- which is what
    // pins a quote to one key at one place on one TPM.
    const srkQn = qualifiedName(hierarchyQualifiedName(TPM_RH.OWNER), this.srk.name);
    this.ak = makeAttestationKey(`ak/${s}`, srkQn, options.akRestricted ?? true);
    this.stages = options.stages ?? cloneStages(DEFAULT_STAGES);
    this.clockInfo = {
      clock: options.clock ?? 3_600_000n,
      resetCount: options.resetCount ?? 4,
      restartCount: options.restartCount ?? 0,
      safe: true,
    };
    this.firmwareVersion = options.firmwareVersion ?? 0x2026041500110203n;
    this.identity = {
      ueid: concatBytes(new Uint8Array([UEID_TYPE.RAND]), labelledBytes(`ueid/${s}`, 16)),
      oemid: labelledBytes(`oemid/${s}`, 16),
      hwmodel: labelledBytes(`hwmodel/${s}`, 8),
      hwversion: { value: '1.4.0', scheme: VERSION_SCHEME.MULTIPARTNUMERIC },
      bootcount: options.bootcount ?? 41,
      dbgstat: DBGSTAT.DISABLED_SINCE_BOOT,
      // Fixed rather than Date.now(): a page whose bytes change every render
      // cannot be compared against anything, including its own earlier output.
      iat: 1_776_000_000,
      profile: LAB_EAT_PROFILE,
    };
  }

  /**
   * The certificate this attester presents, bound to its own AK. Built here
   * rather than supplied whole so a scenario cannot accidentally hand out a
   * certificate for the wrong key -- when a scenario wants that, it says so.
   */
  get certificate(): AkCertificate | undefined {
    if (!this.options.certificate) return undefined;
    return {
      ...this.options.certificate,
      subjectPublicKey: this.ak.publicKey,
      subjectName: computeName(this.ak.publicArea),
    };
  }

  /** Run the measured boot and answer a challenge. */
  attest(nonce: Uint8Array, selection: readonly number[] = QUOTED_PCRS): Evidence {
    const { bank } = runMeasuredBoot(this.stages);
    const quote = tpm2Quote({
      ak: this.ak,
      bank,
      selection,
      nonce,
      clockInfo: this.clockInfo,
      firmwareVersion: this.firmwareVersion,
      bankHashAlg: TPM_ALG.SHA256,
    });
    return buildEvidence(quote, this.stages, this.identity, this.ak.publicArea, this.certificate);
  }

  /** The boot as run, for the UI's Act 1 stepper. */
  boot(): ReturnType<typeof runMeasuredBoot> {
    return runMeasuredBoot(this.stages);
  }
}

export type { Quote };
