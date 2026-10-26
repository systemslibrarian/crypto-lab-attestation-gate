import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { stripVTControlCharacters } from 'node:util';

const PROTOCOL = 'src/daa/protocol.ts';
const ATTESTATION = 'src/daa/attestation.ts';
const PROTOCOL_TEST = 'src/daa/protocol.test.ts';
const ATTESTATION_TEST = 'src/daa/attestation.test.ts';
const POLICY = 'src/tpm/policy.ts';
const POLICY_TEST = 'src/tpm/policy.test.ts';
const SEAL = 'src/tpm/seal.ts';
const SEAL_TEST = 'src/tpm/seal.test.ts';
const SEALING = 'src/acts/sealing.ts';
const SEALING_TEST = 'src/acts/sealing.test.ts';

const mutations = [
  {
    name: 'issuer G1 equality proof',
    file: PROTOCOL,
    anchor: 'return lhsG1.equals(rhsG1) && lhsG2.equals(rhsG2);',
    replacement:
      'return lhsG1.equals(lhsG1.add(rhsG1.subtract(rhsG1))) && lhsG2.equals(rhsG2);',
    spec: PROTOCOL_TEST,
    test: 'the issuer proves one exponent binds its G1 and G2 public points',
  },
  {
    name: 'issuer G2 equality proof',
    file: PROTOCOL,
    anchor: 'return lhsG1.equals(rhsG1) && lhsG2.equals(rhsG2);',
    replacement:
      'return lhsG1.equals(rhsG1) && lhsG2.equals(lhsG2.add(rhsG2.subtract(rhsG2)));',
    spec: PROTOCOL_TEST,
    test: 'the issuer proves one exponent binds its G1 and G2 public points',
  },
  {
    name: 'issuer proof nonce epoch context',
    file: PROTOCOL,
    anchor: '[seed, utf8(issuerId), u32be(epoch)]',
    replacement: '[seed, utf8(issuerId)]',
    spec: PROTOCOL_TEST,
    test: 'reusing an external issuer seed across epochs does not reuse proof randomness',
  },
  {
    name: 'Join Fiat-Shamir nonce binding',
    file: PROTOCOL,
    anchor:
      "  return scalarFromTranscript('crypto-lab/daa/v1/join-proof', [\n    ...issuerBinding(publicKey),\n    request.nonce,\n    point1Bytes(request.Q),",
    replacement:
      "  return scalarFromTranscript('crypto-lab/daa/v1/join-proof', [\n    ...issuerBinding(publicKey),\n    point1Bytes(request.Q),",
    spec: PROTOCOL_TEST,
    test: 'Join proves possession of gsk and binds the issuer nonce',
  },
  {
    name: 'Join proof-randomness issuer context',
    file: PROTOCOL,
    anchor: '[...issuerBinding(publicKey), platformSeed, nonce, point1Bytes(request.Q)]',
    replacement: '[platformSeed, nonce, point1Bytes(request.Q)]',
    spec: PROTOCOL_TEST,
    test: 'same platform seed and nonce across issuers never repeats the Join commitment',
  },
  {
    name: 'credential e binds platform Q',
    file: PROTOCOL,
    anchor:
      '    issuanceSeed,\n    request.nonce,\n    point1Bytes(request.Q),\n  ];',
    replacement: '    issuanceSeed,\n    request.nonce,\n  ];',
    spec: PROTOCOL_TEST,
    test: 'same external issuance seed on two Q values does not repeat e and s or enable interpolation',
  },
  {
    name: 'credential pairing equation',
    file: PROTOCOL,
    anchor: '    return pairingEqual(\n      credential.A,',
    replacement: '    return true || pairingEqual(\n      credential.A,',
    spec: PROTOCOL_TEST,
    test: 'the host independently checks the issued BBS+ credential',
  },
  {
    name: 'signature proof-randomness message context',
    file: PROTOCOL,
    anchor: '    proofSeed,\n    utf8(policyId),\n    message,\n    basename,',
    replacement: '    proofSeed,\n    utf8(policyId),\n    basename,',
    spec: PROTOCOL_TEST,
    test: 'reusing an external proof seed on two messages does not expose gsk',
  },
  {
    name: 'signature transcript message binding',
    file: PROTOCOL,
    anchor: '    utf8(signature.policyId),\n    message,\n    basename,',
    replacement: '    utf8(signature.policyId),\n    message.slice(0, 0),\n    basename,',
    spec: PROTOCOL_TEST,
    test: 'message, basename, policy, issuer, and every proof response are bound',
  },
  {
    name: 'signature proof-randomness basename context',
    file: PROTOCOL,
    anchor: '    message,\n    basename,\n    point1Bytes(credential.A),',
    replacement: '    message,\n    point1Bytes(credential.A),',
    spec: PROTOCOL_TEST,
    test: 'reusing an external proof seed on two messages does not expose gsk',
  },
  {
    name: 'randomized credential pairing check',
    file: PROTOCOL,
    anchor: '    const pairingOk = pairingEqual(signature.APrime, publicKey.w, signature.ABar, g2);',
    replacement:
      '    const pairingOk = true || pairingEqual(signature.APrime, publicKey.w, signature.ABar, g2);',
    spec: PROTOCOL_TEST,
    test: 'a Sigma-valid witness without the issuer pairing relation is rejected only by pairing',
  },
  {
    name: 'canonical proof scalar guard',
    file: PROTOCOL,
    anchor: '    if (!proofScalars.every((value) => isCanonicalScalar(value))) {',
    replacement: '    if (false && !proofScalars.every((value) => isCanonicalScalar(value))) {',
    spec: PROTOCOL_TEST,
    test: 'noncanonical scalars, identity points, and invalid curve points fail closed',
  },
  {
    name: 'rogue-list equality',
    file: PROTOCOL,
    anchor: '      if (scale1(B, rogue).equals(signature.nym)) revoked = true;',
    replacement: '      if (false) revoked = true;',
    spec: PROTOCOL_TEST,
    test: 'the same existing signature changes verdict when its exact secret enters the rogue list',
  },
  {
    name: 'revocation classification requires valid proof',
    file: PROTOCOL,
    anchor: '    if (!checks.every((check) => check.ok)) {',
    replacement: '    if (false && !checks.every((check) => check.ok)) {',
    spec: PROTOCOL_TEST,
    test: 'an invalid proof with a copied revoked nym is not misclassified as revocation',
  },
  {
    name: 'Link refuses different basenames',
    file: PROTOCOL,
    anchor: '  if (!bytesEqual(left.basename, right.basename)) {',
    replacement: '  if (false && !bytesEqual(left.basename, right.basename)) {',
    spec: PROTOCOL_TEST,
    test: 'different basenames produce different pseudonyms but Link is inapplicable',
  },
  {
    name: 'anonymous statement omits stable signer Name',
    file: ATTESTATION,
    anchor: '    qualifiedSigner: new Uint8Array(),',
    replacement: '    qualifiedSigner: options.nonce.slice(),',
    spec: ATTESTATION_TEST,
    test: 'the complete TPMS_ATTEST is marshalled with an empty qualifiedSigner',
  },

  // ── Sealed storage: the policy arithmetic ────────────────────────────────
  {
    name: 'PolicyPCR omits the marshalled PCR selection',
    file: POLICY,
    anchor: '    [u32be(TPM_CC.PolicyPCR), pcrs, bound],',
    // `pcrs.slice(0, 0)` rather than dropping the argument: `noUnusedLocals`
    // would reject an unused binding, and a mutation that fails to COMPILE is
    // not a mutation the suite caught.
    replacement: '    [u32be(TPM_CC.PolicyPCR), pcrs.slice(0, 0), bound],',
    spec: POLICY_TEST,
    test: 'extends policyDigest_old || TPM_CC_PolicyPCR || pcrs || digestTPM',
  },
  {
    name: 'PolicyPCR accepts a mismatched expected digest',
    file: POLICY,
    anchor: '    if (input.pcrDigest.length !== 0 && !bytesEqual(input.pcrDigest, input.digestTPM)) {',
    replacement: '    if (false && input.pcrDigest.length !== 0) {',
    spec: POLICY_TEST,
    test: 'returns TPM_RC_VALUE and changes nothing when the expected digest is wrong',
  },
  {
    name: 'PolicyPCR ignores a moved pcrUpdateCounter',
    file: POLICY,
    anchor:
      '    if (session.pcrUpdateCounter !== undefined && session.pcrUpdateCounter !== input.pcrUpdateCounter) {',
    replacement: '    if (false && session.pcrUpdateCounter !== undefined) {',
    spec: POLICY_TEST,
    test: 'pins pcrUpdateCounter on first use and refuses when it has moved',
  },
  {
    name: 'PolicyOR does not reset to a Zero Digest',
    file: POLICY,
    anchor: '  session.policyDigest = ZERO_DIGEST.slice();',
    replacement: '  session.policyDigest = session.policyDigest.slice();',
    spec: POLICY_TEST,
    test: 'resets to a Zero Digest and extends over the whole list',
  },
  {
    name: 'PolicyOR accepts a session that matches no branch',
    file: POLICY,
    anchor: '  if (!session.trial && !matched) {',
    replacement: '  if (false && !matched) {',
    spec: POLICY_TEST,
    test: 'returns TPM_RC_VALUE when the session matches no branch',
  },
  {
    name: 'PolicyAuthorize ignores which state the authority approved',
    file: POLICY,
    anchor: '    if (!bytesEqual(session.policyDigest, input.approvedPolicy)) {',
    replacement: '    if (false) {',
    spec: POLICY_TEST,
    test: 'refuses when the approval is for a state this session did not reach',
  },
  {
    name: 'PolicyAuthorize accepts an unverified ticket',
    file: POLICY,
    anchor:
      '    if (input.checkTicket.tag !== TPM_ST_VERIFIED || !bytesEqual(input.checkTicket.digest, expected)) {',
    // Keeps `expected` referenced, so the mutation compiles and the kill is a
    // kill rather than a type error.
    replacement:
      '    if (input.checkTicket.tag !== TPM_ST_VERIFIED || !bytesEqual(expected, expected)) {',
    spec: POLICY_TEST,
    test: 'refuses a ticket minted for a different authority',
  },
  {
    name: 'PolicyAuthorize ignores the verification-ticket hierarchy',
    file: POLICY,
    anchor: '    if (input.checkTicket.hierarchy !== TPM_RH.OWNER) {',
    replacement: '    if (false && input.checkTicket.hierarchy !== TPM_RH.OWNER) {',
    spec: POLICY_TEST,
    test: 'refuses an owner-proof digest relabelled as a NULL-hierarchy ticket',
  },
  {
    name: 'PolicyUpdate collapsed into a single hash',
    file: POLICY,
    anchor: '  const first = sha256(concatBytes(before, u32be(commandCode), arg2));\n  return { first, second: sha256(concatBytes(first, arg3)) };',
    replacement:
      '  const first = sha256(concatBytes(before, u32be(commandCode), arg2));\n  return { first, second: sha256(concatBytes(before, u32be(commandCode), arg2, arg3)) };',
    spec: POLICY_TEST,
    test: 're-derives the TCG EK Credential Profile authPolicy through policyUpdate',
  },
  {
    name: 'the use-time check stops comparing policyDigest with authPolicy',
    file: POLICY,
    anchor: '  if (!bytesEqual(session.policyDigest, entity.authPolicy)) {',
    replacement: '  if (false) {',
    spec: POLICY_TEST,
    test: 'refuses a digest that differs from the authPolicy',
  },

  // ── Sealed storage: the object format ────────────────────────────────────
  {
    name: 'the sealed object gains userWithAuth',
    file: SEAL,
    anchor:
      "export const SEALED_ATTRIBUTES: readonly AttributeName[] = ['fixedTPM', 'fixedParent', 'noDA'];",
    replacement:
      "export const SEALED_ATTRIBUTES: readonly AttributeName[] = [\n  'fixedTPM',\n  'fixedParent',\n  'noDA',\n  'userWithAuth',\n];",
    spec: SEAL_TEST,
    test: 'has userWithAuth CLEAR, which is what forces a policy session',
  },
  {
    name: 'the private blob’s HMAC stops covering the object Name',
    file: SEAL,
    anchor: '  return hmacSha256(integrityKey(parent), concatBytes(marshalIv(iv), encSensitive, name));',
    // `name.slice(0, 0)` keeps the parameter referenced so the mutation
    // compiles under `noUnusedParameters`; the Name contributes nothing.
    replacement:
      '  return hmacSha256(integrityKey(parent), concatBytes(marshalIv(iv), encSensitive, name.slice(0, 0)));',
    spec: SEAL_TEST,
    test: 'HMACs the marshalled IV, the ciphertext and the Name with no size field',
  },
  {
    name: 'unique stops including the obfuscation value',
    file: SEAL,
    anchor: '  return sha256(concatBytes(obfuscate, secret));',
    // Keeps the parameter referenced so the mutation compiles; the
    // obfuscation value contributes no bytes.
    replacement: '  return sha256(concatBytes(obfuscate.slice(0, 0), secret));',
    spec: SEAL_TEST,
    test: 'carries unique = H(obfuscate || secret), not H(secret)',
  },
  {
    name: 'TPM2_Load stops checking that the two halves are one object',
    file: SEAL,
    anchor: '  if (!bytesEqual(keyedHashUnique(sensitive.seedValue, sensitive.data), pub.unique)) {',
    // Compares the sensitive area against ITSELF rather than against the
    // public area's `unique`: always false, and it keeps the control flow and
    // the narrowing `if (false)` would discard, so the mutation compiles.
    replacement:
      '  if (!bytesEqual(keyedHashUnique(sensitive.seedValue, sensitive.data), keyedHashUnique(sensitive.seedValue, sensitive.data))) {',
    spec: SEAL_TEST,
    test: 'refuses a re-wrapped substitute secret with TPM_RC_BINDING, not TPM_RC_INTEGRITY',
  },
  {
    name: 'TPM2_Load accepts bytes after the declared TPM2B_SENSITIVE',
    file: SEAL,
    anchor: '  if (bytes.length !== 2 + outer) return null;',
    replacement: '  if (bytes.length < 2 + outer) return null;',
    spec: SEAL_TEST,
    test: 'refuses authenticated trailing bytes after the declared TPM2B_SENSITIVE',
  },
  {
    name: 'TPM2_Load sends a wrong-size symIv into AES-CFB',
    file: SEAL,
    anchor: '  if (iv.length !== AES_BLOCK) {',
    replacement: '  if (false && iv.length !== AES_BLOCK) {',
    spec: SEAL_TEST,
    test: 'refuses an authenticated wrong-size symIv without throwing',
  },
  {
    name: 'the post-release exposure is suppressed',
    file: SEALING,
    anchor: '  const exposed = unseal.ok && (config.postUnsealCompromise ?? false);',
    replacement: '  const exposed = false;',
    spec: SEALING_TEST,
    test: 'shows a post-release compromise reaching only what was already released',
  },
];

function run(command, args, timeout = 300_000) {
  const child = spawnSync(command, args, {
    encoding: 'utf8',
    env: { ...process.env, CI: '1', NO_COLOR: '1' },
    maxBuffer: 16 * 1024 * 1024,
    timeout,
  });
  return {
    ok: child.status === 0 && !child.error && !child.signal,
    status: child.status,
    output: stripVTControlCharacters(`${child.stdout ?? ''}${child.stderr ?? ''}`),
    error: child.error,
    signal: child.signal,
  };
}

function requirePass(result, label) {
  if (!result.ok) {
    throw new Error(`${label} failed (status ${result.status}, signal ${result.signal ?? 'none'}):\n${result.output}`);
  }
}

function build() {
  const result = run('npm', ['run', 'build'], 120_000);
  requirePass(result, 'build');
}

function bundleHash() {
  const files = readdirSync('dist/assets').filter((file) => file.endsWith('.js')).sort();
  if (files.length === 0) throw new Error('build produced no JavaScript bundle');
  const hash = createHash('sha256');
  for (const file of files) hash.update(file).update(readFileSync(`dist/assets/${file}`));
  return hash.digest('hex');
}

function namedTest(mutation) {
  const pattern = mutation.test.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return run('npx', ['vitest', 'run', mutation.spec, '-t', pattern], 120_000);
}

function requireNamedPass(result, mutation, label) {
  requirePass(result, label);
  if (!/Tests\s+1 passed\b/.test(result.output)) {
    throw new Error(`${label} did not execute exactly one passing test:\n${result.output}`);
  }
}

const requested = process.argv[2];
const selected = requested ? mutations.filter((mutation) => mutation.name === requested) : mutations;
if (selected.length === 0) throw new Error(`unknown mutation: ${requested}`);

build();
// The WHOLE unit suite, not just the directories these mutations touch. A
// baseline scoped to the mutated files would stay green while a mutation broke
// something elsewhere, and the restore control at the end would agree with it.
const baseline = run('npx', ['vitest', 'run'], 300_000);
requirePass(baseline, 'unmutated unit baseline');
console.log('baseline: unmutated copy PASSES');

for (const [index, mutation] of selected.entries()) {
  const original = readFileSync(mutation.file, 'utf8');
  if (original.split(mutation.anchor).length !== 2) {
    throw new Error(`${mutation.name}: mutation anchor must occur exactly once`);
  }
  requireNamedPass(namedTest(mutation), mutation, `${mutation.name} named baseline`);
  const originalHash = bundleHash();
  let caught = false;
  try {
    const changed = original.replace(mutation.anchor, mutation.replacement);
    if (changed === original) throw new Error(`${mutation.name}: mutation made no source change`);
    writeFileSync(mutation.file, changed);
    build();
    const changedHash = bundleHash();
    if (changedHash === originalHash) {
      throw new Error(`${mutation.name}: production JavaScript bundle did not change`);
    }
    const result = namedTest(mutation);
    if (result.ok) throw new Error(`${mutation.name}: mutation survived its owning test`);
    if (!result.output.includes(mutation.test)) {
      throw new Error(`${mutation.name}: failure did not name its owning test:\n${result.output}`);
    }
    if (/No test files found|Cannot find module|Failed to load url|Unhandled Error/.test(result.output)) {
      throw new Error(`${mutation.name}: infrastructure failure is not a mutation kill:\n${result.output}`);
    }
    caught = true;
    console.log(`caught ${index + 1}/${selected.length}: ${mutation.name}`);
  } finally {
    writeFileSync(mutation.file, original);
    build();
    if (readFileSync(mutation.file, 'utf8') !== original) {
      throw new Error(`${mutation.name}: source was not restored byte for byte`);
    }
    if (bundleHash() !== originalHash) {
      throw new Error(`${mutation.name}: restored bundle differs from baseline`);
    }
    const restored = namedTest(mutation);
    requireNamedPass(restored, mutation, `${mutation.name} restored control`);
  }
  if (!caught) throw new Error(`${mutation.name}: mutation was not caught`);
}

const finalBaseline = run('npx', ['vitest', 'run'], 300_000);
requirePass(finalBaseline, 'restored unit baseline');
console.log(`all ${selected.length} mutation(s) caught`);
