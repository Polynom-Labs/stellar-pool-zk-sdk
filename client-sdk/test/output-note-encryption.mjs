import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

globalThis.Worker ??= class Worker {
  postMessage() {}
  terminate() {}
  addEventListener() {}
  removeEventListener() {}
};

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const sdkPath = join(root, 'dist/index.mjs');
const wasmJsPath = join(root, 'pkg/client_sdk_wasm.js');
const wasmBinaryPath = join(root, 'pkg/client_sdk_wasm_bg.wasm');

const {
  decryptOutputNoteEvent,
  encryptOutputNoteForDeposit,
  encryptNoteAuditSlot,
  secretFromDepositEphemeralScalarDecimal,
  scalarHexToFrDecimal,
  coordHexToDecimal,
  TOTAL_PUBLIC_SIGNALS,
} = await import(pathToFileURL(sdkPath).href);

assert.equal(TOTAL_PUBLIC_SIGNALS, 93);

const wasmModule = await import(pathToFileURL(wasmJsPath).href);
wasmModule.initSync({ module: readFileSync(wasmBinaryPath) });

const FR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function frDecimalToHex(value) {
  let v = BigInt(value) % FR_MODULUS;
  const buf = Buffer.alloc(32);
  for (let index = 31; index >= 0; index -= 1) {
    buf[index] = Number(v & 0xffn);
    v >>= 8n;
  }
  return buf.toString('hex');
}

function normalizeCoordHex(hex) {
  return hex.trim().replace(/^0x/i, '').padStart(64, '0');
}

function buildDeposit(depositorScalarHex, recipientScalarHex) {
  const recipientPoint = wasmModule.ecdhEphemeralPublicKeyFromScalarHex(recipientScalarHex);
  return {
    value: '1000',
    nullifier: '501',
    ephemeralKeyScalar: scalarHexToFrDecimal(depositorScalarHex),
    asset: ['11', '12'],
    applicationId: '101',
    recipientPublicKeys: [
      coordHexToDecimal(recipientPoint.x),
      coordHexToDecimal(recipientPoint.y),
    ],
  };
}

const ecdhShared = (priv, pubX, pubY) => wasmModule.ecdhSharedKey(priv, pubX, pubY);
const recipientScalarHex = '0000000000000000000000000000000000000000000000000000000000000003';
const depositorScalarHex = '0000000000000000000000000000000000000000000000000000000000000007';
const alternateDepositorScalarHex =
  '000000000000000000000000000000000000000000000000000000000000000b';

const deposit = buildDeposit(depositorScalarHex, recipientScalarHex);
const alternateDeposit = buildDeposit(alternateDepositorScalarHex, recipientScalarHex);

const encryption = await encryptOutputNoteForDeposit({ deposit, ecdhShared });
const alternateEncryption = await encryptOutputNoteForDeposit({
  deposit: alternateDeposit,
  ecdhShared,
});

assert.equal(encryption.ciphertext.length, 6);
assert.notEqual(encryption.ciphertext[0], '0');
assert.notEqual(
  encryption.ciphertext.join(','),
  alternateEncryption.ciphertext.join(','),
);

const { buildMimc7, buildPoseidon } = await import('circomlibjs');
const recipientPoint = wasmModule.ecdhEphemeralPublicKeyFromScalarHex(recipientScalarHex);
const shared = ecdhShared(
  depositorScalarHex,
  normalizeCoordHex(recipientPoint.x),
  normalizeCoordHex(recipientPoint.y),
);
const sharedX = BigInt(`0x${normalizeCoordHex(shared.x)}`);
const sharedY = BigInt(`0x${normalizeCoordHex(shared.y)}`);
const [mimc7, poseidon] = await Promise.all([buildMimc7(), buildPoseidon()]);
const poseidonHash = (inputs) =>
  BigInt(poseidon.F.toString(poseidon(inputs.map((input) => poseidon.F.e(input)))));
const mimcHash = (message, key) =>
  BigInt(mimc7.F.toString(mimc7.hash(mimc7.F.e(message), mimc7.F.e(key))));
const rawStream = mimcHash(poseidonHash([sharedY, 1n, 0n]), sharedX);
const rawCipher0 = (1000n + rawStream) % FR_MODULUS;
assert.notEqual(
  BigInt(encryption.ciphertext[0]),
  rawCipher0,
  'cipher key must be derived; raw ECDH-x must not key the MiMC stream',
);

const createdEphemeralPoint =
  wasmModule.ecdhEphemeralPublicKeyFromScalarHex(depositorScalarHex);
const createdEphemeralKey = [
  normalizeCoordHex(createdEphemeralPoint.x),
  normalizeCoordHex(createdEphemeralPoint.y),
];
const eventCiphertext = encryption.ciphertext.map((field) => frDecimalToHex(field));
const eventTag = frDecimalToHex(encryption.tag);

const secret = await secretFromDepositEphemeralScalarDecimal(
  deposit.ephemeralKeyScalar,
);
const ownerBoundCommitmentHex = (() => {
  const ownerX = BigInt(`0x${normalizeCoordHex(recipientPoint.x)}`);
  const ownerY = BigInt(`0x${normalizeCoordHex(recipientPoint.y)}`);
  const registeredOwnerMode = 0n;
  const commitment = poseidonHash([
    1000n,
    BigInt(secret),
    501n,
    ownerX,
    ownerY,
    registeredOwnerMode,
    11n,
    12n,
    101n,
  ]);
  return commitment.toString(16).padStart(64, '0');
})();

const decrypted = await decryptOutputNoteEvent({
  recipientScalarHex,
  commitmentHashHex: ownerBoundCommitmentHex,
  createdEphemeralKey,
  ciphertext: eventCiphertext,
  tag: eventTag,
});
assert.equal(decrypted.value, '1000');
assert.equal(decrypted.commitmentMatches, true);
assert.equal(decrypted.commitmentHex, ownerBoundCommitmentHex);

await assert.rejects(
  () =>
    decryptOutputNoteEvent({
      recipientScalarHex,
      commitmentHashHex: '0'.repeat(64),
      createdEphemeralKey,
      ciphertext: eventCiphertext,
      tag: eventTag,
    }),
  /commitment checksum mismatch/,
);

const wrongRecipientScalarHex =
  '0000000000000000000000000000000000000000000000000000000000000005';
await assert.rejects(
  () =>
    decryptOutputNoteEvent({
      recipientScalarHex: wrongRecipientScalarHex,
      commitmentHashHex: '0'.repeat(64),
      createdEphemeralKey,
      ciphertext: eventCiphertext,
      tag: eventTag,
    }),
  /tag verification failed|commitment checksum mismatch/,
);

const auditPlaintext = Array.from({ length: 12 }, (_unused, index) => String(index + 1));
const auditEncrypted = await encryptNoteAuditSlot({
  plaintext: auditPlaintext,
  auditPublicKey: [
    coordHexToDecimal(recipientPoint.x),
    coordHexToDecimal(recipientPoint.y),
  ],
  auditEphemeralScalar: scalarHexToFrDecimal(depositorScalarHex),
  ecdhShared,
});
assert.equal(auditEncrypted.ciphertext.length, 12);
assert.notEqual(auditEncrypted.tag, '0');
assert.notEqual(auditEncrypted.ciphertext[0], '1');

console.log('output-note-encryption: ok');
