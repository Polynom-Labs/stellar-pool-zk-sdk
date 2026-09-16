import { buildBabyjub, buildMimc7, buildPoseidon } from 'circomlibjs';
import type {
  DepositObject,
  TransactionWitnessInput,
} from './withdrawal-transaction-input.js';
import type { EcdhSharedKeyFn } from './shared-secret.js';
import { DOM_ENC, DOM_AUDIT_TAG, DOM_OUTPUT_NOTE_TAG } from './domain-separators.js';
import { encodeTransactionCiphertextBlob } from './ciphertext-blob.js';
import type { ZkLayoutParams } from './zk-layout.js';

export const NOTE_OUTPUT_LEN = 6;
export const NOTE_AUDIT_LEN = 12;
export const STREAM_DOMAIN = 1n;
export const FR_SIZE = 32;

const FR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const ONE = 1n;
const ZERO = 0n;
const BABYJUB_SCALAR_BITS = 253n;
const SCALAR_253_MASK = (ONE << BABYJUB_SCALAR_BITS) - ONE;

type Field = {
  e(value: bigint | number | string): unknown;
  toString(value: unknown): string;
};

type BabyJub = Awaited<ReturnType<typeof buildBabyjub>>;
type Mimc7 = Awaited<ReturnType<typeof buildMimc7>>;
type Poseidon = Awaited<ReturnType<typeof buildPoseidon>>;

type CryptoPrimitives = {
  babyJub: BabyJub;
  mimc7: Mimc7;
  poseidon: Poseidon;
};

export type OutputNotePlaintext = {
  value: string;
  assetHi: string;
  assetLo: string;
  nullifier: string;
  secret: string;
  applicationId: string;
};

export type OutputNoteEncryption = {
  ciphertext: [string, string, string, string, string, string];
  tag: string;
};

export type DecryptedOutputNote = OutputNotePlaintext & {
  commitmentHex: string;
  commitmentMatches: boolean;
};

export type OutputNoteEventInput = {
  recipientScalarHex: string;
  commitmentHashHex: string;
  createdEphemeralKey: readonly [string, string];
  ciphertext: readonly string[];
  tag: string;
  ownerMode?: bigint;
};

let primitivesPromise: Promise<CryptoPrimitives> | undefined;

function primitives(): Promise<CryptoPrimitives> {
  primitivesPromise ??= Promise.all([
    buildBabyjub(),
    buildMimc7(),
    buildPoseidon(),
  ]).then(([babyJub, mimc7, poseidon]) => ({ babyJub, mimc7, poseidon }));
  return primitivesPromise;
}

function normalizeHex(value: string): string {
  return value.trim().replace(/^0x/i, '').padStart(FR_SIZE * 2, '0');
}

function bigintFromHex(value: string): bigint {
  return BigInt(`0x${normalizeHex(value)}`);
}

function bigintFromDecimal(value: string): bigint {
  const parsed = BigInt(value);
  return parsed % FR_MODULUS;
}

function bigintToFrHex(value: bigint): string {
  let v = moduleFr(value);
  const buf = Buffer.alloc(FR_SIZE);
  for (let index = FR_SIZE - 1; index >= 0; index -= 1) {
    buf[index] = Number(v & 0xffn);
    v >>= 8n;
  }
  return buf.toString('hex');
}

function frDecimalToHex(value: string): string {
  return bigintToFrHex(bigintFromDecimal(value));
}

function frDecimalFromBigint(value: bigint): string {
  const reduced = value >= ZERO ? value % FR_MODULUS : (value % FR_MODULUS) + FR_MODULUS;
  return reduced.toString(10);
}

function fieldBigint(field: Field, value: unknown): bigint {
  return BigInt(field.toString(value));
}

function moduleFr(value: bigint): bigint {
  const reduced = value % FR_MODULUS;
  return reduced >= ZERO ? reduced : reduced + FR_MODULUS;
}

function mimcHash(parameters: {
  mimc7: Mimc7;
  message: bigint;
  key: bigint;
}): bigint {
  return fieldBigint(
    parameters.mimc7.F,
    parameters.mimc7.hash(
      parameters.mimc7.F.e(parameters.message),
      parameters.mimc7.F.e(parameters.key),
    ),
  );
}

function poseidonHash(poseidon: Poseidon, inputs: readonly bigint[]): bigint {
  return fieldBigint(
    poseidon.F,
    poseidon(inputs.map((input) => poseidon.F.e(input))),
  );
}

function deriveEncCipherKey(poseidon: Poseidon, sharedX: bigint): bigint {
  return poseidonHash(poseidon, [DOM_ENC, sharedX]);
}

function sharedKeyFromDepositor(parameters: {
  babyJub: BabyJub;
  ecdhShared: EcdhSharedKeyFn;
  ephemeralKeyScalarDecimal: string;
  recipientPublicKey: readonly [string, string];
}): readonly [bigint, bigint] {
  const scalarHex = frDecimalToHex(parameters.ephemeralKeyScalarDecimal);
  const shared = parameters.ecdhShared(
    scalarHex,
    frDecimalToHex(parameters.recipientPublicKey[0]),
    frDecimalToHex(parameters.recipientPublicKey[1]),
  );
  return [bigintFromHex(shared.x), bigintFromHex(shared.y)];
}

function sharedKeyFromRecipient(parameters: {
  babyJub: BabyJub;
  recipientScalarHex: string;
  ephemeralPublicKey: readonly [string, string];
}): readonly [bigint, bigint] {
  const { babyJub, recipientScalarHex, ephemeralPublicKey } = parameters;
  const point: [unknown, unknown] = [
    babyJub.F.e(bigintFromHex(ephemeralPublicKey[0])),
    babyJub.F.e(bigintFromHex(ephemeralPublicKey[1])),
  ];
  if (!babyJub.inCurve(point)) {
    throw new Error('Created ephemeral public key is not on BabyJubJub curve');
  }
  const product = babyJub.mulPointEscalar(
    point,
    bigintFromHex(recipientScalarHex) & SCALAR_253_MASK,
  );
  return [
    fieldBigint(babyJub.F, product[0]),
    fieldBigint(babyJub.F, product[1]),
  ];
}

export function poseidonMacTag(parameters: {
  poseidon: Poseidon;
  domain: bigint;
  key: bigint;
  nonce: bigint;
  message: readonly bigint[];
}): bigint {
  return poseidonHash(parameters.poseidon, [
    parameters.domain,
    parameters.key,
    parameters.nonce,
    ...parameters.message,
  ]);
}

function outputNoteTag(parameters: {
  poseidon: Poseidon;
  key: bigint;
  nonce: bigint;
  plaintext: readonly bigint[];
}): bigint {
  return poseidonMacTag({
    poseidon: parameters.poseidon,
    domain: DOM_OUTPUT_NOTE_TAG,
    key: parameters.key,
    nonce: parameters.nonce,
    message: parameters.plaintext,
  });
}

function encryptFields(parameters: {
  mimc7: Mimc7;
  poseidon: Poseidon;
  key: bigint;
  nonce: bigint;
  plaintext: readonly bigint[];
}): bigint[] {
  return parameters.plaintext.map((field, index) => {
    const seed = poseidonHash(parameters.poseidon, [
      parameters.nonce,
      STREAM_DOMAIN,
      BigInt(index),
    ]);
    const stream = mimcHash({
      mimc7: parameters.mimc7,
      message: seed,
      key: parameters.key,
    });
    return moduleFr(field + stream);
  });
}

function decryptFields(parameters: {
  mimc7: Mimc7;
  poseidon: Poseidon;
  key: bigint;
  nonce: bigint;
  ciphertext: readonly string[];
}): bigint[] {
  return parameters.ciphertext.map((field, index) => {
    const seed = poseidonHash(parameters.poseidon, [
      parameters.nonce,
      STREAM_DOMAIN,
      BigInt(index),
    ]);
    const stream = mimcHash({
      mimc7: parameters.mimc7,
      message: seed,
      key: parameters.key,
    });
    return moduleFr(bigintFromHex(field) - stream);
  });
}

function plaintextBigints(plaintext: OutputNotePlaintext): bigint[] {
  return [
    bigintFromDecimal(plaintext.value),
    bigintFromDecimal(plaintext.assetHi),
    bigintFromDecimal(plaintext.assetLo),
    bigintFromDecimal(plaintext.nullifier),
    bigintFromDecimal(plaintext.secret),
    bigintFromDecimal(plaintext.applicationId),
  ];
}

function plaintextFromBigints(fields: readonly bigint[]): OutputNotePlaintext {
  return {
    value: frDecimalFromBigint(fields[0] ?? ZERO),
    assetHi: frDecimalFromBigint(fields[1] ?? ZERO),
    assetLo: frDecimalFromBigint(fields[2] ?? ZERO),
    nullifier: frDecimalFromBigint(fields[3] ?? ZERO),
    secret: frDecimalFromBigint(fields[4] ?? ZERO),
    applicationId: frDecimalFromBigint(fields[5] ?? ZERO),
  };
}

export async function secretFromDepositEphemeralScalarDecimal(
  ephemeralKeyScalarDecimal: string,
): Promise<string> {
  const { poseidon } = await primitives();
  const secret = poseidonHash(poseidon, [bigintFromDecimal(ephemeralKeyScalarDecimal)]);
  return frDecimalFromBigint(secret);
}

export async function encryptOutputNoteForDeposit(parameters: {
  deposit: DepositObject;
  ecdhShared: EcdhSharedKeyFn;
}): Promise<OutputNoteEncryption> {
  const { babyJub, mimc7, poseidon } = await primitives();
  const secret = await secretFromDepositEphemeralScalarDecimal(
    parameters.deposit.ephemeralKeyScalar,
  );
  const plaintext: OutputNotePlaintext = {
    value: parameters.deposit.value,
    assetHi: parameters.deposit.asset[0],
    assetLo: parameters.deposit.asset[1],
    nullifier: parameters.deposit.nullifier,
    secret,
    applicationId: parameters.deposit.applicationId,
  };
  const [sharedX, sharedY] = sharedKeyFromDepositor({
    babyJub,
    ecdhShared: parameters.ecdhShared,
    ephemeralKeyScalarDecimal: parameters.deposit.ephemeralKeyScalar,
    recipientPublicKey: parameters.deposit.recipientPublicKeys,
  });
  const key = deriveEncCipherKey(poseidon, sharedX);
  const nonce = sharedY;
  const message = plaintextBigints(plaintext);
  const ciphertext = encryptFields({ mimc7, poseidon, key, nonce, plaintext: message });
  const tag = outputNoteTag({ poseidon, key, nonce, plaintext: message });
  return {
    ciphertext: ciphertext.map((field) => frDecimalFromBigint(field)) as OutputNoteEncryption['ciphertext'],
    tag: frDecimalFromBigint(tag),
  };
}

export async function buildOutputNoteEncryptionPublicInputs(parameters: {
  deposits: [DepositObject, DepositObject];
  ecdhShared: EcdhSharedKeyFn;
}): Promise<{
  outputNoteCiphertexts: [OutputNoteEncryption['ciphertext'], OutputNoteEncryption['ciphertext']];
  outputNoteTags: [string, string];
}> {
  const enc0 = await encryptOutputNoteForDeposit({
    deposit: parameters.deposits[0],
    ecdhShared: parameters.ecdhShared,
  });
  const enc1 = await encryptOutputNoteForDeposit({
    deposit: parameters.deposits[1],
    ecdhShared: parameters.ecdhShared,
  });
  return {
    outputNoteCiphertexts: [enc0.ciphertext, enc1.ciphertext],
    outputNoteTags: [enc0.tag, enc1.tag],
  };
}

function ownerPubFromRecipientScalar(
  babyJub: BabyJub,
  recipientScalarHex: string,
): readonly [bigint, bigint] {
  const product = babyJub.mulPointEscalar(
    babyJub.Base8,
    bigintFromHex(recipientScalarHex) & SCALAR_253_MASK,
  );
  return [
    fieldBigint(babyJub.F, product[0]),
    fieldBigint(babyJub.F, product[1]),
  ];
}

function commitmentFromPlaintextAndOwnerPub(parameters: {
  poseidon: Poseidon;
  plaintext: OutputNotePlaintext;
  ownerPub: readonly [bigint, bigint];
  ownerMode: bigint;
}): string {
  const commitment = poseidonHash(parameters.poseidon, [
    bigintFromDecimal(parameters.plaintext.value),
    bigintFromDecimal(parameters.plaintext.secret),
    bigintFromDecimal(parameters.plaintext.nullifier),
    parameters.ownerPub[0],
    parameters.ownerPub[1],
    parameters.ownerMode,
    bigintFromDecimal(parameters.plaintext.assetHi),
    bigintFromDecimal(parameters.plaintext.assetLo),
    bigintFromDecimal(parameters.plaintext.applicationId),
  ]);
  return normalizeHex(commitment.toString(16));
}

export async function decryptOutputNoteEvent(
  input: OutputNoteEventInput,
): Promise<DecryptedOutputNote> {
  const { babyJub, mimc7, poseidon } = await primitives();
  const [sharedX, sharedY] = sharedKeyFromRecipient({
    babyJub,
    recipientScalarHex: input.recipientScalarHex,
    ephemeralPublicKey: input.createdEphemeralKey,
  });
  const key = deriveEncCipherKey(poseidon, sharedX);
  const nonce = sharedY;
  const decrypted = decryptFields({
    mimc7,
    poseidon,
    key,
    nonce,
    ciphertext: input.ciphertext,
  });
  const expectedTag = outputNoteTag({
    poseidon,
    key,
    nonce,
    plaintext: decrypted,
  });
  if (expectedTag !== bigintFromHex(input.tag)) {
    throw new Error('Output note tag verification failed');
  }
  const plaintext = plaintextFromBigints(decrypted);
  const commitmentHex = commitmentFromPlaintextAndOwnerPub({
    poseidon,
    plaintext,
    ownerPub: ownerPubFromRecipientScalar(babyJub, input.recipientScalarHex),
    ownerMode: input.ownerMode ?? 0n,
  });
  const commitmentMatches =
    normalizeHex(input.commitmentHashHex) === commitmentHex;
  if (!commitmentMatches) {
    throw new Error('Output note commitment checksum mismatch');
  }
  return {
    ...plaintext,
    commitmentHex,
    commitmentMatches,
  };
}

function ownerModeFromEscrowNonce(escrowNonce: string): bigint {
  return bigintFromDecimal(escrowNonce) === ZERO ? ZERO : ONE;
}

function emptyFlagFromValue(value: string): bigint {
  return bigintFromDecimal(value) === ZERO ? ONE : ZERO;
}

function precommitmentFromOpening(parameters: {
  poseidon: Poseidon;
  secret: bigint;
  ownerMode: bigint;
  ownerPub: readonly [bigint, bigint];
}): bigint {
  const ownerKeyHash = poseidonHash(parameters.poseidon, [
    parameters.ownerPub[0],
    parameters.ownerPub[1],
  ]);
  return poseidonHash(parameters.poseidon, [
    parameters.secret,
    parameters.ownerMode,
    ownerKeyHash,
  ]);
}

export async function encryptNoteAuditSlot(parameters: {
  auditPublicKey: readonly [string, string];
  auditEphemeralScalar: string;
  plaintext: readonly string[];
  ecdhShared: EcdhSharedKeyFn;
}): Promise<{ ciphertext: string[]; tag: string }> {
  if (parameters.plaintext.length !== NOTE_AUDIT_LEN) {
    throw new Error(
      `encryptNoteAuditSlot: expected ${String(NOTE_AUDIT_LEN)} limbs`,
    );
  }
  const { babyJub, mimc7, poseidon } = await primitives();
  const [sharedX, sharedY] = sharedKeyFromDepositor({
    babyJub,
    ecdhShared: parameters.ecdhShared,
    ephemeralKeyScalarDecimal: parameters.auditEphemeralScalar,
    recipientPublicKey: parameters.auditPublicKey,
  });
  const key = deriveEncCipherKey(poseidon, sharedX);
  const nonce = sharedY;
  const message = parameters.plaintext.map((field) => bigintFromDecimal(field));
  const ciphertext = encryptFields({ mimc7, poseidon, key, nonce, plaintext: message });
  const tag = poseidonMacTag({
    poseidon,
    domain: DOM_AUDIT_TAG,
    key,
    nonce,
    message,
  });
  return {
    ciphertext: ciphertext.map((field) => frDecimalFromBigint(field)),
    tag: frDecimalFromBigint(tag),
  };
}

function auditPlaintextForWithdraw(parameters: {
  poseidon: Poseidon;
  witness: TransactionWitnessInput;
  index: number;
}): string[] {
  const value = parameters.witness.withdrawnValues[parameters.index] ?? '0';
  const ownerPub = parameters.witness.ownerPubs[parameters.index] ?? ['0', '0'];
  const escrowNonce = parameters.witness.withdrawnEscrowNonces[parameters.index] ?? '0';
  const secret = bigintFromDecimal(
    parameters.witness.withdrawnSecrets[parameters.index] ?? '0',
  );
  const ownerMode = ownerModeFromEscrowNonce(escrowNonce);
  const precommitment = precommitmentFromOpening({
    poseidon: parameters.poseidon,
    secret,
    ownerMode,
    ownerPub: [bigintFromDecimal(ownerPub[0]), bigintFromDecimal(ownerPub[1])],
  });
  const asset = parameters.witness.withdrawnAssets[parameters.index] ?? ['0', '0'];
  const stellar = parameters.witness.inputRecipientStellar[parameters.index] ?? ['0', '0'];
  return [
    frDecimalFromBigint(emptyFlagFromValue(value)),
    value,
    asset[0],
    asset[1],
    frDecimalFromBigint(precommitment),
    parameters.witness.withdrawnNullifiers[parameters.index] ?? '0',
    ownerPub[0],
    ownerPub[1],
    parameters.witness.inputApplicationIds[parameters.index] ?? '0',
    stellar[0],
    stellar[1],
    escrowNonce,
  ];
}

async function auditPlaintextForDeposit(parameters: {
  poseidon: Poseidon;
  witness: TransactionWitnessInput;
  index: number;
}): Promise<string[]> {
  const value = parameters.witness.depositedValues[parameters.index] ?? '0';
  const ownerPub =
    parameters.witness.depositedRecipientPublicKeys[parameters.index] ?? ['0', '0'];
  const escrowNonce = parameters.witness.depositedEscrowNonces[parameters.index] ?? '0';
  const secret = poseidonHash(parameters.poseidon, [
    bigintFromDecimal(
      parameters.witness.depositedEphemeralKeyScalars[parameters.index] ?? '0',
    ),
  ]);
  const ownerMode = ownerModeFromEscrowNonce(escrowNonce);
  const precommitment = precommitmentFromOpening({
    poseidon: parameters.poseidon,
    secret,
    ownerMode,
    ownerPub: [bigintFromDecimal(ownerPub[0]), bigintFromDecimal(ownerPub[1])],
  });
  const asset = parameters.witness.depositedAssets[parameters.index] ?? ['0', '0'];
  const stellar = parameters.witness.outputRecipientStellar[parameters.index] ?? ['0', '0'];
  return [
    frDecimalFromBigint(emptyFlagFromValue(value)),
    value,
    asset[0],
    asset[1],
    frDecimalFromBigint(precommitment),
    parameters.witness.depositedNullifiers[parameters.index] ?? '0',
    ownerPub[0],
    ownerPub[1],
    parameters.witness.outputApplicationIds[parameters.index] ?? '0',
    stellar[0],
    stellar[1],
    escrowNonce,
  ];
}

export async function encryptTransactionCiphertextBlob(parameters: {
  witness: TransactionWitnessInput;
  layout: ZkLayoutParams;
  ecdhShared: EcdhSharedKeyFn;
}): Promise<{
  ciphertextHex: string;
  auditCiphertexts: string[][];
  outputNoteCiphertexts: string[][];
}> {
  const { poseidon } = await primitives();
  const nIns = parameters.witness.withdrawnValues.length;
  const nOuts = parameters.witness.depositedValues.length;
  const nAuditSlots = parameters.layout.nAuditSlots;
  const auditCiphertexts: string[][] = [];
  for (let slot = 0; slot < nAuditSlots; slot += 1) {
    const plaintext =
      slot < nIns
        ? auditPlaintextForWithdraw({
            poseidon,
            witness: parameters.witness,
            index: slot,
          })
        : await auditPlaintextForDeposit({
            poseidon,
            witness: parameters.witness,
            index: slot - nIns,
          });
    const encrypted = await encryptNoteAuditSlot({
      auditPublicKey: parameters.witness.noteAuditPublicKey,
      auditEphemeralScalar: parameters.witness.auditEphemeralScalar,
      plaintext,
      ecdhShared: parameters.ecdhShared,
    });
    auditCiphertexts.push(encrypted.ciphertext);
  }
  const outputNoteCiphertexts: string[][] = [];
  for (let index = 0; index < nOuts; index += 1) {
    const deposit: DepositObject = {
      value: parameters.witness.depositedValues[index] ?? '0',
      nullifier: parameters.witness.depositedNullifiers[index] ?? '0',
      ephemeralKeyScalar: parameters.witness.depositedEphemeralKeyScalars[index] ?? '0',
      asset: parameters.witness.depositedAssets[index] ?? ['0', '0'],
      applicationId: parameters.witness.outputApplicationIds[index] ?? '0',
      recipientPublicKeys:
        parameters.witness.depositedRecipientPublicKeys[index] ?? ['0', '0'],
    };
    const encrypted = await encryptOutputNoteForDeposit({
      deposit,
      ecdhShared: parameters.ecdhShared,
    });
    outputNoteCiphertexts.push([...encrypted.ciphertext]);
  }
  const blob = encodeTransactionCiphertextBlob({
    layout: parameters.layout,
    auditCiphertexts,
    outputNoteCiphertexts,
  });
  return {
    ciphertextHex: blob.toString('hex'),
    auditCiphertexts,
    outputNoteCiphertexts,
  };
}
