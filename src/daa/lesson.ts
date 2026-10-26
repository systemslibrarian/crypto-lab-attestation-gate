/** One deterministic current-run fixture for the learner panel and claim tests. */

import { DEFAULT_STAGES, QUOTED_PCRS, runMeasuredBoot } from '../boot/stages';
import { toHex, utf8 } from '../core/bytes';
import { sha256 } from '../core/sha256';
import { labelledNonce, Machine } from '../acts/machine';
import { createDaaAttestation, type DaaAttestationStatement } from './attestation';
import { h1, point1Bytes, scale1, type G1Point } from './groups';
import {
  completeJoin,
  link,
  setupIssuer,
  sign,
  verify,
  verifyCredential,
  verifyJoinRequest,
  type DaaCredential,
  type DaaIssuerPublicKey,
  type DaaSignature,
  type DaaVerification,
  type LinkResult,
} from './protocol';

export const DAA_ISSUER_ID = 'Example University DAA Issuer';
export const DAA_POLICY_ID = 'attestation-gate/access/v1';
export const SERVICE_BASENAME = utf8('access.example.edu/attestation');
export const RESEARCH_BASENAME = utf8('research.example.edu/attestation');

export interface DaaLessonRun {
  stableAk: {
    firstQualifiedSigner: Uint8Array;
    secondQualifiedSigner: Uint8Array;
    linked: boolean;
  };
  issuer: DaaIssuerPublicKey;
  join: {
    proofAccepted: boolean;
    credentialAccepted: boolean;
  };
  statement1: DaaAttestationStatement;
  statement2: DaaAttestationStatement;
  signature1: DaaSignature;
  signature2: DaaSignature;
  differentBasenameSignature: DaaSignature;
  otherPlatformSignature: DaaSignature;
  baseline: DaaVerification;
  sameBasename: LinkResult;
  differentBasename: LinkResult;
  otherPlatform: LinkResult;
  revocation: {
    before: DaaVerification;
    unrelated: DaaVerification;
    exact: DaaVerification;
    publishedSecret: string;
  };
  rotation: {
    oldStillTrusted: DaaVerification;
    oldAgainstNewIssuer: DaaVerification;
    rejoinedUnderNewIssuer: DaaVerification;
    nextIssuer: DaaIssuerPublicKey;
  };
  credentialControl: {
    originalAccepted: boolean;
    changedRejected: boolean;
  };
  nymHex: (point: G1Point) => string;
}

const CLOCK = {
  clock: 9_876_543n,
  resetCount: 4,
  restartCount: 9,
  safe: true,
};

function changedCredential(credential: DaaCredential): DaaCredential {
  return { ...credential, s: credential.s + 1n };
}

export function runDaaLesson(): DaaLessonRun {
  const stableMachine = new Machine({ serial: 'A7-3391' });
  const stable1 = stableMachine.attest(labelledNonce('daa-stable-one'));
  const stable2 = stableMachine.attest(labelledNonce('daa-stable-two'));

  const issuer = setupIssuer(DAA_ISSUER_ID, 1, utf8('daa lesson issuer epoch 1'));
  const joinNonce = sha256(utf8('daa lesson Join nonce / platform A'));
  const joined = completeJoin(
    issuer,
    joinNonce,
    utf8('daa lesson platform A'),
    utf8('daa lesson platform A credential / epoch 1')
  );

  const bank = runMeasuredBoot(DEFAULT_STAGES).bank;
  const statement1 = createDaaAttestation({
    bank,
    selection: QUOTED_PCRS,
    nonce: labelledNonce('daa-one'),
    clockInfo: CLOCK,
    firmwareVersion: 0x0003_0004_0000_002an,
  });
  const statement2 = createDaaAttestation({
    bank,
    selection: QUOTED_PCRS,
    nonce: labelledNonce('daa-two'),
    clockInfo: CLOCK,
    firmwareVersion: 0x0003_0004_0000_002an,
  });

  const signature1 = sign(
    issuer.publicKey,
    joined.membership,
    statement1.bytes,
    SERVICE_BASENAME,
    DAA_POLICY_ID,
    utf8('daa lesson signature A/1')
  );
  const signature2 = sign(
    issuer.publicKey,
    joined.membership,
    statement2.bytes,
    SERVICE_BASENAME,
    DAA_POLICY_ID,
    utf8('daa lesson signature A/2')
  );
  const differentBasenameSignature = sign(
    issuer.publicKey,
    joined.membership,
    statement1.bytes,
    RESEARCH_BASENAME,
    DAA_POLICY_ID,
    utf8('daa lesson signature A/research')
  );

  const platformB = completeJoin(
    issuer,
    sha256(utf8('daa lesson Join nonce / platform B')),
    utf8('daa lesson platform B'),
    utf8('daa lesson platform B credential / epoch 1')
  ).membership;
  const otherPlatformSignature = sign(
    issuer.publicKey,
    platformB,
    statement1.bytes,
    SERVICE_BASENAME,
    DAA_POLICY_ID,
    utf8('daa lesson signature B/1')
  );

  const baseline = verify(
    issuer.publicKey,
    signature1,
    statement1.bytes,
    SERVICE_BASENAME,
    DAA_POLICY_ID
  );
  const sameBasename = link(
    issuer.publicKey,
    { signature: signature1, message: statement1.bytes, basename: SERVICE_BASENAME },
    { signature: signature2, message: statement2.bytes, basename: SERVICE_BASENAME },
    DAA_POLICY_ID
  );
  const differentBasename = link(
    issuer.publicKey,
    { signature: signature1, message: statement1.bytes, basename: SERVICE_BASENAME },
    {
      signature: differentBasenameSignature,
      message: statement1.bytes,
      basename: RESEARCH_BASENAME,
    },
    DAA_POLICY_ID
  );
  const otherPlatform = link(
    issuer.publicKey,
    { signature: signature1, message: statement1.bytes, basename: SERVICE_BASENAME },
    {
      signature: otherPlatformSignature,
      message: statement1.bytes,
      basename: SERVICE_BASENAME,
    },
    DAA_POLICY_ID
  );

  const unrelatedSecret = platformB.secret.gsk;
  const before = verify(
    issuer.publicKey,
    signature1,
    statement1.bytes,
    SERVICE_BASENAME,
    DAA_POLICY_ID
  );
  const unrelated = verify(
    issuer.publicKey,
    signature1,
    statement1.bytes,
    SERVICE_BASENAME,
    DAA_POLICY_ID,
    [unrelatedSecret]
  );
  const exact = verify(
    issuer.publicKey,
    signature1,
    statement1.bytes,
    SERVICE_BASENAME,
    DAA_POLICY_ID,
    [joined.membership.secret.gsk]
  );

  const nextIssuer = setupIssuer(DAA_ISSUER_ID, 2, utf8('daa lesson issuer epoch 2'));
  const oldStillTrusted = verify(
    issuer.publicKey,
    signature1,
    statement1.bytes,
    SERVICE_BASENAME,
    DAA_POLICY_ID
  );
  const oldAgainstNewIssuer = verify(
    nextIssuer.publicKey,
    signature1,
    statement1.bytes,
    SERVICE_BASENAME,
    DAA_POLICY_ID
  );
  const rejoined = completeJoin(
    nextIssuer,
    sha256(utf8('daa lesson Join nonce / platform A / epoch 2')),
    utf8('daa lesson platform A'),
    utf8('daa lesson platform A credential / epoch 2')
  ).membership;
  const nextSignature = sign(
    nextIssuer.publicKey,
    rejoined,
    statement1.bytes,
    SERVICE_BASENAME,
    DAA_POLICY_ID,
    utf8('daa lesson signature A/epoch 2')
  );
  const rejoinedUnderNewIssuer = verify(
    nextIssuer.publicKey,
    nextSignature,
    statement1.bytes,
    SERVICE_BASENAME,
    DAA_POLICY_ID
  );

  const Q = scale1(h1, joined.membership.secret.gsk);
  return {
    stableAk: {
      firstQualifiedSigner: stable1.quote.akQualifiedSigner,
      secondQualifiedSigner: stable2.quote.akQualifiedSigner,
      linked: toHex(stable1.quote.akQualifiedSigner) === toHex(stable2.quote.akQualifiedSigner),
    },
    issuer: issuer.publicKey,
    join: {
      proofAccepted: verifyJoinRequest(issuer.publicKey, joinNonce, joined.request),
      credentialAccepted: verifyCredential(issuer.publicKey, joined.membership.credential, Q),
    },
    statement1,
    statement2,
    signature1,
    signature2,
    differentBasenameSignature,
    otherPlatformSignature,
    baseline,
    sameBasename,
    differentBasename,
    otherPlatform,
    revocation: {
      before,
      unrelated,
      exact,
      publishedSecret: joined.membership.secret.gsk.toString(16).padStart(64, '0'),
    },
    rotation: { oldStillTrusted, oldAgainstNewIssuer, rejoinedUnderNewIssuer, nextIssuer: nextIssuer.publicKey },
    credentialControl: {
      originalAccepted: verifyCredential(issuer.publicKey, joined.membership.credential, Q),
      changedRejected: !verifyCredential(
        issuer.publicKey,
        changedCredential(joined.membership.credential),
        Q
      ),
    },
    nymHex: (point) => toHex(point1Bytes(point)),
  };
}
