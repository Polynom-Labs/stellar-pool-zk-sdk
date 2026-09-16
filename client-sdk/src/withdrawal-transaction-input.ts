import { StrKey } from '@stellar/stellar-sdk';
import { generateRandomScalarHex32 } from './ephemeral-key';
import { decodeStealthAddress } from './stealth-address';
import { canonicalBabyJubScalarFromInteger } from './domain-separators';
import type { TransactionAuditParams } from './transaction-audit';
import { resolveSlotApplicationIds } from './transaction-audit';
import type { WithdrawMerkleWitness } from './types';

/** Matches `Transaction(20, 2, 2, publicNInputs, publicNOutputs, 4, 12, 6)` in `circuits/main.circom`. */
export const TRANSACTION_TREE_DEPTH = 20;
export const TRANSACTION_N_INS = 2;
export const TRANSACTION_N_OUTS = 2;
export const TRANSACTION_N_AUDIT_SLOTS = 4;
export const NOTE_AUDIT_LEN = 12;
export const NOTE_OUTPUT_LEN = 6;
/** Must match `Transaction(..., publicNInputs, publicNOutputs)` and contract `get_public_slot_config`. */
export const TRANSACTION_PUBLIC_N_INPUTS = 1;
export const TRANSACTION_PUBLIC_N_OUTPUTS = 1;

/** BN254 scalar field modulus (ark `Fr`, circom signals). */
export const BN254_SCALAR_MOD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/**
 * BabyJub ECDH in `circuits/encryption.circom` uses `Num2Bits(253)`; scalars must be < 2^253
 * (matches `libs/cryptography` `scalar_mul_253`).
 */
export const BN254_BABYJUB_SCALAR_MAX_EXCLUSIVE = 1n << 253n;

export interface WithdrawalProofPublicParams {
  /** Decimal string, circom `stateRoot`. */
  stateRoot: string;
  /** Decimal string, circom `withdrawAddressHi` (Ed25519 key bytes [0..16] as big-endian u128). */
  withdrawAddressHi: string;
  /** Decimal string, circom `withdrawAddressLo` (Ed25519 key bytes [16..32] as big-endian u128). */
  withdrawAddressLo: string;
  /** Decimal string, circom `escrowRecipientHi`. */
  escrowRecipientHi?: string;
  /** Decimal string, circom `escrowRecipientLo`. */
  escrowRecipientLo?: string;
  /** Decimal string, circom `sweepOutputOwnerPubX`. Zero off-sweep. */
  sweepOutputOwnerPubX?: string;
  /** Decimal string, circom `sweepOutputOwnerPubY`. Zero off-sweep. */
  sweepOutputOwnerPubY?: string;
  /** Decimal string, default owner scalar copied onto dummy withdraw slots. */
  privKeyScalar: string;
}

/** Public accounting legs (`publicWithdrawnAssets`, `publicDepositedAssets`, `publicDeposits`, `publicWithdrawals`). */
export interface TransactionPublicLegParams {
  publicWithdrawnAssets: Array<[string, string]>;
  publicDepositedAssets: Array<[string, string]>;
  publicDeposits: string[];
  publicWithdrawals: string[];
}

/** All-zero public legs (private-only pool moves). */
export function zeroPublicLegs(
  publicNInputs: number = TRANSACTION_PUBLIC_N_INPUTS,
  publicNOutputs: number = TRANSACTION_PUBLIC_N_OUTPUTS,
): TransactionPublicLegParams {
  return {
    publicWithdrawnAssets: Array.from({ length: publicNOutputs }, () => ['0', '0'] as [string, string]),
    publicDepositedAssets: Array.from({ length: publicNInputs }, () => ['0', '0'] as [string, string]),
    publicDeposits: Array.from({ length: publicNInputs }, () => '0'),
    publicWithdrawals: Array.from({ length: publicNOutputs }, () => '0'),
  };
}

export function padPublicLegs(
  legs: TransactionPublicLegParams,
  publicNInputs: number,
  publicNOutputs: number,
): TransactionPublicLegParams {
  const padPairs = (
    values: Array<[string, string]>,
    expected: number,
    label: string,
  ): Array<[string, string]> => {
    if (values.length > expected) {
      throw new Error(`withdrawal-transaction-input: expected at most ${expected} ${label}`);
    }
    return [
      ...values,
      ...Array.from({ length: expected - values.length }, () => ['0', '0'] as [string, string]),
    ];
  };
  const padAmounts = (values: string[], expected: number, label: string): string[] => {
    if (values.length > expected) {
      throw new Error(`withdrawal-transaction-input: expected at most ${expected} ${label}`);
    }
    return [...values, ...Array.from({ length: expected - values.length }, () => '0')];
  };
  return {
    publicWithdrawnAssets: padPairs(legs.publicWithdrawnAssets, publicNOutputs, 'public withdrawn assets'),
    publicDepositedAssets: padPairs(legs.publicDepositedAssets, publicNInputs, 'public deposited assets'),
    publicDeposits: padAmounts(legs.publicDeposits, publicNInputs, 'public deposits'),
    publicWithdrawals: padAmounts(legs.publicWithdrawals, publicNOutputs, 'public withdrawals'),
  };
}

/** Real withdraw leg; coordinates are decimal field strings (same as `CoinData`). */
export interface WithdrawObject {
  value: string;
  nullifier: string;
  secret: string;
  /** Asset contract id as two decimal Fr strings (`asset[0]`, `asset[1]`). */
  asset: [string, string];
  /** BN254 Fr decimal; `0` for dummy slots. */
  applicationId: string;
  /** Owner BabyJubJub public key `[x, y]` as decimal strings. */
  ownerPub: [string, string];
  /** Per-input owner scalar. */
  privKeyScalar: string;
  paddingRandom: string;
  escrowNonce: string;
  recipientStellar: [string, string];
  stateSiblings: string[];
  stateIndex: string;
}

export interface DepositObject {
  value: string;
  nullifier: string;
  ephemeralKeyScalar: string;
  /** Asset contract id as two decimal Fr strings. */
  asset: [string, string];
  /** BN254 Fr decimal; `0` for dummy slots. */
  applicationId: string;
  /** Recipient public key `[x, y]` as decimal strings. */
  recipientPublicKeys: [string, string];
  escrowNonce?: string;
  recipientStellar?: [string, string];
}

export type WithdrawSlot = WithdrawObject | 'dummy';
export type DepositSlot = DepositObject | 'dummy';

/** Witness calculator input for a `Transaction(20, nIns, nOuts, …)` instantiation. */
export interface TransactionWitnessInput {
  stateRoot: string;
  withdrawAddressHi: string;
  withdrawAddressLo: string;
  escrowRecipientHi: string;
  escrowRecipientLo: string;
  sweepOutputOwnerPubX: string;
  sweepOutputOwnerPubY: string;
  privKeyScalars: string[];
  ownerPubs: Array<[string, string]>;
  paddingRandoms: string[];
  withdrawnValues: string[];
  withdrawnNullifiers: string[];
  withdrawnSecrets: string[];
  withdrawnAssets: Array<[string, string]>;
  withdrawnEscrowNonces: string[];
  inputRecipientStellar: Array<[string, string]>;
  stateSiblings: string[][];
  stateIndex: string[];
  depositedValues: string[];
  depositedNullifiers: string[];
  depositedAssets: Array<[string, string]>;
  depositedEphemeralKeyScalars: string[];
  depositedRecipientPublicKeys: Array<[string, string]>;
  depositedEscrowNonces: string[];
  outputRecipientStellar: Array<[string, string]>;
  publicWithdrawnAssets: Array<[string, string]>;
  publicDepositedAssets: Array<[string, string]>;
  publicDeposits: string[];
  publicWithdrawals: string[];
  inputApplicationIds: string[];
  outputApplicationIds: string[];
  auditEphemeralScalar: string;
  noteAuditPublicKey: [string, string];
}

export interface WasmEcdhPointFns {
  ecdhEphemeralPublicKeyFromScalarHex(scalarHex: string): { x: string; y: string };
}

function normalizeHex(hex: string): string {
  const s = hex.trim().replace(/^0x/i, '');
  if (!/^[0-9a-fA-F]*$/.test(s)) {
    throw new Error('withdrawal-transaction-input: invalid hex');
  }
  return s.length % 2 === 0 ? s : `0${s}`;
}

/** 32-byte field coordinate (hex, no 0x) → decimal string mod BN254 scalar field. */
export function coordHexToDecimal(hex: string): string {
  const h = normalizeHex(hex);
  if (h.length > 64) {
    throw new Error('withdrawal-transaction-input: coordinate hex too long');
  }
  const v = BigInt(`0x${h}`);
  return (v % BN254_SCALAR_MOD).toString(10);
}

/**
 * 32-byte big-endian scalar hex → decimal for circom `ephemeralKeyScalar` / ECDH `priv`.
 * Integer must be < 2^253 (not reduced mod r — values ≥ 2^253 are rejected).
 */
export function scalarHexToFrDecimal(hex: string): string {
  const h = normalizeHex(hex);
  if (h.length > 64) {
    throw new Error('withdrawal-transaction-input: scalar hex too long');
  }
  const v = BigInt(`0x${h.padStart(64, '0').slice(-64)}`);
  if (v >= BN254_BABYJUB_SCALAR_MAX_EXCLUSIVE) {
    throw new Error(
      'depositor ephemeral scalar must be < 2^253 (BabyJub Num2Bits); resample with random-scalar',
    );
  }
  return v.toString(10);
}

/**
 * Stellar G-address Ed25519 payload (32 bytes as 64 hex, optional 0x) → two circom public decimals
 * (`withdrawAddressHi` / `withdrawAddressLo`). No mod-r; each half fits in 128 bits.
 */
export function ed25519PubkeyPayloadHexToWithdrawFrDecimals(hex: string): {
  hi: string;
  lo: string;
} {
  const h = normalizeHex(hex).padStart(64, '0').slice(-64);
  const hi = BigInt(`0x${h.slice(0, 32)}`);
  const lo = BigInt(`0x${h.slice(32, 64)}`);
  return { hi: hi.toString(10), lo: lo.toString(10) };
}

/**
 * Stellar contract id (`C…`) → two circom field decimals for `asset[0]`, `asset[1]` (same 32-byte split as accounts).
 */
export function stellarContractAddressToAssetFrDecimals(address: string): [string, string] {
  const raw = StrKey.decodeContract(address);
  const hex = Buffer.from(raw).toString('hex');
  const { hi, lo } = ed25519PubkeyPayloadHexToWithdrawFrDecimals(hex);
  return [hi, lo];
}

/** Uniform random `Fr` as decimal (32 random bytes, mod r). For Poseidon-only inputs (e.g. nullifiers). */
export function randomFrDecimal(): string {
  const hex = generateRandomScalarHex32();
  const v = BigInt(`0x${normalizeHex(hex)}`);
  return (v % BN254_SCALAR_MOD).toString(10);
}

/** Random scalar < 2^253 for BabyJub ECDH / `Num2Bits(253)` (uses {@link generateRandomScalarHex32}). */
export function randomFrDecimal253(): string {
  const hex = generateRandomScalarHex32();
  return BigInt(`0x${normalizeHex(hex)}`).toString(10);
}

/** Spend-scalar hex in `(0, BabyJub subgroup order)` so dummy withdraws satisfy `LessThan(l)`. */
function randomCanonicalBabyJubScalarHex(): string {
  const hex = generateRandomScalarHex32();
  const reduced = canonicalBabyJubScalarFromInteger(BigInt(`0x${normalizeHex(hex)}`));
  return reduced.toString(16).padStart(64, '0');
}

function zerosTreeSiblings(): string[] {
  return Array(TRANSACTION_TREE_DEPTH).fill('0');
}

function dummyWithdraw(wasm: WasmEcdhPointFns): WithdrawObject {
  const nullifier = randomFrDecimal();
  const secretHex = generateRandomScalarHex32();
  const secret = (BigInt(`0x${normalizeHex(secretHex)}`) % BN254_SCALAR_MOD).toString(10);
  const scalarHex = randomCanonicalBabyJubScalarHex();
  const privKeyScalar = scalarHexToFrDecimal(scalarHex);
  const pt = wasm.ecdhEphemeralPublicKeyFromScalarHex(scalarHex);
  return {
    value: '0',
    nullifier,
    secret,
    asset: ['0', '0'],
    applicationId: '0',
    ownerPub: [coordHexToDecimal(pt.x), coordHexToDecimal(pt.y)],
    privKeyScalar,
    paddingRandom: randomFrDecimal(),
    escrowNonce: '0',
    recipientStellar: ['0', '0'],
    stateSiblings: zerosTreeSiblings(),
    stateIndex: '0',
  };
}

function dummyDeposit(wasm: WasmEcdhPointFns): DepositObject {
  const nullifier = randomFrDecimal();
  const ephemeralKeyScalar = randomFrDecimal253();
  const skHex = generateRandomScalarHex32();
  const pt = wasm.ecdhEphemeralPublicKeyFromScalarHex(skHex);
  return {
    value: '0',
    nullifier,
    ephemeralKeyScalar,
    asset: ['0', '0'],
    applicationId: '0',
    recipientPublicKeys: [coordHexToDecimal(pt.x), coordHexToDecimal(pt.y)],
    escrowNonce: '0',
    recipientStellar: ['0', '0'],
  };
}

function resolveWithdraw(slot: WithdrawSlot, wasm: WasmEcdhPointFns): WithdrawObject {
  return slot === 'dummy' ? dummyWithdraw(wasm) : slot;
}

function resolveDeposit(slot: DepositSlot, wasm: WasmEcdhPointFns): DepositObject {
  return slot === 'dummy' ? dummyDeposit(wasm) : slot;
}

export function resolveDepositsForWitness(
  depositSlots: [DepositSlot, DepositSlot],
  wasm: WasmEcdhPointFns,
): [DepositObject, DepositObject] {
  return [
    resolveDeposit(depositSlots[0], wasm),
    resolveDeposit(depositSlots[1], wasm),
  ];
}

export function padWithdrawSlots(slots: WithdrawSlot[], nIns: number): WithdrawSlot[] {
  if (slots.length > nIns) {
    throw new Error(`withdrawal-transaction-input: expected at most ${nIns} withdraw slots`);
  }
  return [...slots, ...Array.from({ length: nIns - slots.length }, () => 'dummy' as const)];
}

export function padDepositSlots(slots: DepositSlot[], nOuts: number): DepositSlot[] {
  if (slots.length > nOuts) {
    throw new Error(`withdrawal-transaction-input: expected at most ${nOuts} deposit slots`);
  }
  return [...slots, ...Array.from({ length: nOuts - slots.length }, () => 'dummy' as const)];
}

export function buildTransactionWitnessInput(
  publicParams: WithdrawalProofPublicParams,
  publicLegs: TransactionPublicLegParams,
  withdrawSlots: WithdrawSlot[],
  depositSlots: DepositSlot[],
  audit: TransactionAuditParams,
  wasm: WasmEcdhPointFns,
  dims: { nIns?: number; nOuts?: number; publicNInputs?: number; publicNOutputs?: number } = {},
): TransactionWitnessInput {
  const nIns = dims.nIns ?? TRANSACTION_N_INS;
  const nOuts = dims.nOuts ?? TRANSACTION_N_OUTS;
  const publicNInputs = dims.publicNInputs ?? TRANSACTION_PUBLIC_N_INPUTS;
  const publicNOutputs = dims.publicNOutputs ?? TRANSACTION_PUBLIC_N_OUTPUTS;
  const paddedWithdraws = padWithdrawSlots(withdrawSlots, nIns);
  const paddedDeposits = padDepositSlots(depositSlots, nOuts);
  const paddedLegs = padPublicLegs(publicLegs, publicNInputs, publicNOutputs);
  const withdraws = paddedWithdraws.map((slot) => resolveWithdraw(slot, wasm));
  const deposits = paddedDeposits.map((slot) => resolveDeposit(slot, wasm));
  const appIds = resolveSlotApplicationIds(audit, paddedWithdraws, paddedDeposits);

  return {
    stateRoot: publicParams.stateRoot,
    withdrawAddressHi: publicParams.withdrawAddressHi,
    withdrawAddressLo: publicParams.withdrawAddressLo,
    escrowRecipientHi: publicParams.escrowRecipientHi ?? '0',
    escrowRecipientLo: publicParams.escrowRecipientLo ?? '0',
    sweepOutputOwnerPubX: publicParams.sweepOutputOwnerPubX ?? '0',
    sweepOutputOwnerPubY: publicParams.sweepOutputOwnerPubY ?? '0',
    privKeyScalars: withdraws.map((w) => w.privKeyScalar),
    ownerPubs: withdraws.map((w) => w.ownerPub),
    paddingRandoms: withdraws.map((w) => w.paddingRandom),
    withdrawnValues: withdraws.map((w) => w.value),
    withdrawnNullifiers: withdraws.map((w) => w.nullifier),
    withdrawnSecrets: withdraws.map((w) => w.secret),
    withdrawnAssets: withdraws.map((w) => w.asset),
    withdrawnEscrowNonces: withdraws.map((w) => w.escrowNonce),
    inputRecipientStellar: withdraws.map((w) => w.recipientStellar),
    stateSiblings: withdraws.map((w) => w.stateSiblings),
    stateIndex: withdraws.map((w) => w.stateIndex),
    depositedValues: deposits.map((d) => d.value),
    depositedNullifiers: deposits.map((d) => d.nullifier),
    depositedAssets: deposits.map((d) => d.asset),
    depositedEphemeralKeyScalars: deposits.map((d) => d.ephemeralKeyScalar),
    depositedRecipientPublicKeys: deposits.map((d) => d.recipientPublicKeys),
    depositedEscrowNonces: deposits.map((d) => d.escrowNonce ?? '0'),
    outputRecipientStellar: deposits.map((d) => d.recipientStellar ?? ['0', '0']),
    inputApplicationIds: appIds.inputApplicationIds,
    outputApplicationIds: appIds.outputApplicationIds,
    auditEphemeralScalar: audit.auditEphemeralScalar,
    noteAuditPublicKey: audit.noteAuditPublicKey,
    publicWithdrawnAssets: paddedLegs.publicWithdrawnAssets,
    publicDepositedAssets: paddedLegs.publicDepositedAssets,
    publicDeposits: paddedLegs.publicDeposits,
    publicWithdrawals: paddedLegs.publicWithdrawals,
  };
}

/** `stpl1…` stealth address → `[x, y]` as decimal field strings for `depositedRecipientPublicKeys`. */
export function recipientPublicKeysDecimalFromStealthAddress(
  stealthAddress: string,
): [string, string] {
  const { x, y } = decodeStealthAddress(stealthAddress);
  return [coordHexToDecimal(x), coordHexToDecimal(y)];
}

/** First withdraw leg: Merkle witness + owner public key (hex) and matching scalar. */
export function withdrawObjectFromMerkleWitness(
  witness: WithdrawMerkleWitness,
  ownerPubHex: { x: string; y: string },
  applicationId: string,
  privKeyScalar: string,
): WithdrawObject {
  return {
    value: witness.value,
    nullifier: witness.nullifier,
    secret: witness.secret,
    asset: witness.withdrawnAsset,
    applicationId,
    ownerPub: [coordHexToDecimal(ownerPubHex.x), coordHexToDecimal(ownerPubHex.y)],
    privKeyScalar,
    paddingRandom: randomFrDecimal(),
    escrowNonce: '0',
    recipientStellar: ['0', '0'],
    stateSiblings: witness.stateSiblings,
    stateIndex: witness.stateIndex,
  };
}
