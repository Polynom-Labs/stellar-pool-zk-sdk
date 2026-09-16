import { Address, StrKey } from '@stellar/stellar-sdk';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { layoutForKnownNonce, stateRootIndex, totalPublicSignals, ciphertextsInPublicSignals, indexAuditTags, indexOutputNoteTags } from './zk-layout';

export const KYT_PASSAGE_AUTH_DOMAIN = 'privacy-pool-kyt-passage-v1';
export const PUBLIC_LEG_CONTEXT_DOMAIN = 'privacy-pool-public-leg-context-v1';
export const PASSAGE_ID_DOMAIN = 'privacy-pool-passage-id-v3';
export const PASSAGE_ID_DOMAIN_V2 = 'privacy-pool-passage-id-v2';
export const PASSAGE_ID_DOMAIN_V1 = 'privacy-pool-passage-id-v1';

export const NOTE_AUDIT_LEN = 12;
export const TOTAL_PUBLIC_SIGNALS = 93;
export const NOTE_AUDIT_PLAINTEXT_LEN = 12;

const FIELD_BYTES = 32;
const LENGTH_PREFIX_BYTES = 4;

export interface PublicLegLayout {
  publicNInputs: number;
  publicNOutputs: number;
}

export interface PublicLegContextInput {
  owner: string;
  withdrawAddress: string;
  publicDeposits: string[];
  publicWithdrawals: string[];
  publicDepositedAssets: [string, string][];
  publicWithdrawnAssets: [string, string][];
}

export interface KytPassageDerivation {
  publicSignalHash: string;
  publicLegContextHash: string;
  passageId: string;
}

export interface KytPassageAuthorization {
  authorizationHash: string;
  poolContract: string;
  kytRegistry: string;
  passageId: string;
  expiresAtLedger: number;
}

function sha256Hex(data: Uint8Array): string {
  return bytesToHex(sha256(data));
}

function publicSignalsBuffer(publicSignalsBytes: Buffer | string): Buffer {
  return typeof publicSignalsBytes === 'string'
    ? Buffer.from(publicSignalsBytes.replace(/^0x/, ''), 'hex')
    : publicSignalsBytes;
}

function expectedSignalCountForNonce(zkConfigNonce: bigint = 0n): number {
  return totalPublicSignals(layoutForKnownNonce(zkConfigNonce));
}

function stateRootIndexForNonce(zkConfigNonce: bigint = 0n): number {
  return stateRootIndex(layoutForKnownNonce(zkConfigNonce));
}

function parsePublicSignalsBytes(
  publicSignalsBytes: Buffer | string,
  zkConfigNonce: bigint = 0n,
): {
  fields: Buffer[];
  hasLengthPrefix: boolean;
} {
  const expectedCount = expectedSignalCountForNonce(zkConfigNonce);
  const buf = publicSignalsBuffer(publicSignalsBytes);
  let offset = 0;
  let hasLengthPrefix = false;
  if (buf.length >= LENGTH_PREFIX_BYTES) {
    const len = buf.readUInt32BE(0);
    if (buf.length === LENGTH_PREFIX_BYTES + len * FIELD_BYTES) {
      offset = LENGTH_PREFIX_BYTES;
      hasLengthPrefix = true;
    }
  }
  const signalBytes = buf.subarray(offset);
  if (signalBytes.length !== expectedCount * FIELD_BYTES) {
    throw new Error(`expected ${expectedCount} public signals`);
  }
  return {
    fields: Array.from({ length: expectedCount }, (_, index) =>
      Buffer.from(signalBytes.subarray(index * FIELD_BYTES, (index + 1) * FIELD_BYTES)),
    ),
    hasLengthPrefix,
  };
}

function encodePublicSignalsBytes(fields: Buffer[], hasLengthPrefix: boolean): Buffer {
  const body = Buffer.concat(fields);
  if (!hasLengthPrefix) {
    return body;
  }
  const prefix = Buffer.alloc(LENGTH_PREFIX_BYTES);
  prefix.writeUInt32BE(fields.length);
  return Buffer.concat([prefix, body]);
}

function appendBytes(parts: Buffer[], chunk: Buffer): void {
  parts.push(chunk);
}

function appendU8(parts: Buffer[], value: number): void {
  parts.push(Buffer.from([value & 0xff]));
}

function appendU32BE(parts: Buffer[], value: number): void {
  const buf = Buffer.alloc(4);
  buf.writeUInt32BE(value >>> 0);
  parts.push(buf);
}

function appendU64BE(parts: Buffer[], value: bigint | number): void {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(value));
  parts.push(buf);
}

function appendU128BE(parts: Buffer[], value: bigint): void {
  const buf = Buffer.alloc(16);
  buf.writeBigUInt64BE(value >> 64n, 0);
  buf.writeBigUInt64BE(value & ((1n << 64n) - 1n), 8);
  parts.push(buf);
}

function appendAddressStrkey(parts: Buffer[], address: string): void {
  const bytes = Buffer.from(address.trim(), 'utf8');
  appendU32BE(parts, bytes.length);
  parts.push(bytes);
}

/** Canonical zero-address sentinel for absent public-leg slots: `u32_be(0)` with no XDR bytes. */
export function zeroAddressSentinelBuffer(): Buffer {
  return Buffer.alloc(4);
}

export function addressToCanonicalXdr(address: string): Buffer {
  return Address.fromString(address.trim()).toScVal().toXDR() as Buffer;
}

function appendAddressXdr(parts: Buffer[], address: string): void {
  const xdr = addressToCanonicalXdr(address);
  appendU32BE(parts, xdr.length);
  parts.push(xdr);
}

function appendBytes32(parts: Buffer[], hex: string): void {
  parts.push(Buffer.from(hex.replace(/^0x/, ''), 'hex'));
}

function appendBytesBlob(parts: Buffer[], data: Buffer): void {
  appendU32BE(parts, data.length);
  parts.push(data);
}

function frToBuffer32(decimal: string): Buffer {
  let value = BigInt(decimal);
  const buf = Buffer.alloc(32);
  for (let i = 31; i >= 0; i -= 1) {
    buf[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return buf;
}

function isPositiveFr(decimal: string): boolean {
  try {
    return BigInt(decimal) > 0n;
  } catch {
    return false;
  }
}

function zeroFrBuffer(): Buffer {
  return Buffer.alloc(32, 0);
}

function zeroAddressBuffer(): Buffer {
  return zeroAddressSentinelBuffer();
}

function encodeLegSlot(
  parts: Buffer[],
  kind: number,
  slot: number,
  isPresent: boolean,
  assetHi: string,
  assetLo: string,
  amount: string,
  address?: string,
): void {
  appendU8(parts, kind);
  appendU32BE(parts, slot);
  appendU8(parts, isPresent ? 1 : 0);
  if (isPresent && address) {
    parts.push(frToBuffer32(assetHi));
    parts.push(frToBuffer32(assetLo));
    appendU128BE(parts, BigInt(amount));
    appendAddressXdr(parts, address);
  } else {
    parts.push(zeroFrBuffer());
    parts.push(zeroFrBuffer());
    appendU128BE(parts, 0n);
    parts.push(zeroAddressBuffer());
  }
}

export function hashPublicSignalBytes(
  publicSignalsBytes: Buffer | string,
  zkConfigNonce: bigint = 0n,
): string {
  const parsed = parsePublicSignalsBytes(publicSignalsBytes, zkConfigNonce);
  parsed.fields[stateRootIndexForNonce(zkConfigNonce)] = Buffer.alloc(FIELD_BYTES);
  return sha256Hex(encodePublicSignalsBytes(parsed.fields, parsed.hasLengthPrefix));
}

export function hashPublicLegContext(
  layout: PublicLegLayout,
  input: PublicLegContextInput,
): string {
  const parts: Buffer[] = [];
  appendBytes(parts, Buffer.from(PUBLIC_LEG_CONTEXT_DOMAIN, 'utf8'));
  appendU32BE(parts, layout.publicNOutputs);
  appendU32BE(parts, layout.publicNInputs);

  for (let i = 0; i < layout.publicNOutputs; i += 1) {
    const amount = input.publicDeposits[i] ?? '0';
    const present = isPositiveFr(amount);
    const asset = input.publicDepositedAssets[i] ?? ['0', '0'];
    encodeLegSlot(
      parts,
      1,
      i,
      present,
      present ? asset[0] : '0',
      present ? asset[1] : '0',
      amount,
      present ? input.owner : undefined,
    );
  }

  for (let j = 0; j < layout.publicNInputs; j += 1) {
    const amount = input.publicWithdrawals[j] ?? '0';
    const present = isPositiveFr(amount);
    const asset = input.publicWithdrawnAssets[j] ?? ['0', '0'];
    encodeLegSlot(
      parts,
      2,
      j,
      present,
      present ? asset[0] : '0',
      present ? asset[1] : '0',
      amount,
      present ? input.withdrawAddress : undefined,
    );
  }

  return sha256Hex(Buffer.concat(parts));
}

export function derivePassageId(
  owner: string,
  nonce: bigint | number,
  publicSignalHash: string,
  publicLegContextHash: string,
  ciphertextHash: string,
): string {
  const parts: Buffer[] = [];
  appendBytes(parts, Buffer.from(PASSAGE_ID_DOMAIN, 'utf8'));
  appendAddressStrkey(parts, owner);
  appendU64BE(parts, nonce);
  appendBytes32(parts, publicSignalHash);
  appendBytes32(parts, publicLegContextHash);
  appendBytes32(parts, ciphertextHash);
  return sha256Hex(Buffer.concat(parts));
}

export function derivePassageIdV2(
  owner: string,
  nonce: bigint | number,
  publicSignalHash: string,
  publicLegContextHash: string,
): string {
  const parts: Buffer[] = [];
  appendBytes(parts, Buffer.from(PASSAGE_ID_DOMAIN_V2, 'utf8'));
  appendAddressStrkey(parts, owner);
  appendU64BE(parts, nonce);
  appendBytes32(parts, publicSignalHash);
  appendBytes32(parts, publicLegContextHash);
  return sha256Hex(Buffer.concat(parts));
}

export function derivePassageIdV1(
  owner: string,
  nonce: bigint | number,
  publicSignalHash: string,
  publicLegContextHash: string,
  onboardingHash: string,
): string {
  const parts: Buffer[] = [];
  appendBytes(parts, Buffer.from(PASSAGE_ID_DOMAIN_V1, 'utf8'));
  appendAddressStrkey(parts, owner);
  appendU64BE(parts, nonce);
  appendBytes32(parts, publicSignalHash);
  appendBytes32(parts, publicLegContextHash);
  appendBytes32(parts, onboardingHash);
  return sha256Hex(Buffer.concat(parts));
}

export function buildKytPassageAuthorization(input: {
  poolContract: string;
  kytRegistry: string;
  passageId: string;
  expiresAtLedger: number;
}): KytPassageAuthorization {
  const parts: Buffer[] = [];
  appendBytes(parts, Buffer.from(KYT_PASSAGE_AUTH_DOMAIN, 'utf8'));
  appendAddressStrkey(parts, input.poolContract);
  appendAddressStrkey(parts, input.kytRegistry);
  appendBytes32(parts, input.passageId);
  appendU32BE(parts, input.expiresAtLedger);
  const authorizationHash = sha256Hex(Buffer.concat(parts));
  return {
    authorizationHash,
    poolContract: input.poolContract,
    kytRegistry: input.kytRegistry,
    passageId: input.passageId,
    expiresAtLedger: input.expiresAtLedger,
  };
}

export function derivePassageFromTransactContext(input: {
  owner: string;
  nonce?: bigint | number;
  publicSignalsBytes: Buffer | string;
  ciphertextBytes?: Buffer | string;
  publicLegContext: PublicLegContextInput;
  layout?: PublicLegLayout;
}): KytPassageDerivation {
  const layout = input.layout ?? { publicNInputs: 1, publicNOutputs: 1 };
  const nonce = BigInt(input.nonce ?? 0);
  const publicSignalHash = hashPublicSignalBytes(input.publicSignalsBytes, nonce);
  const publicLegContextHash = hashPublicLegContext(layout, input.publicLegContext);
  const zkLayout = layoutForKnownNonce(nonce);
  const passageId = ciphertextsInPublicSignals(zkLayout)
    ? derivePassageIdV2(input.owner, nonce, publicSignalHash, publicLegContextHash)
    : derivePassageId(
        input.owner,
        nonce,
        publicSignalHash,
        publicLegContextHash,
        hashCiphertextBytes(input.ciphertextBytes ?? Buffer.alloc(0)),
      );
  return {
    publicSignalHash,
    publicLegContextHash,
    passageId,
  };
}

export function hashCiphertextBytes(ciphertextBytes: Buffer | string): string {
  const buffer =
    typeof ciphertextBytes === 'string'
      ? Buffer.from(ciphertextBytes.replace(/^0x/i, ''), 'hex')
      : ciphertextBytes;
  return sha256Hex(buffer);
}

export function zeroBindingTagsInPublicSignals(
  publicSignalsBytes: Buffer | string,
  zkConfigNonce: bigint = 0n,
): Buffer {
  const layout = layoutForKnownNonce(zkConfigNonce);
  if (ciphertextsInPublicSignals(layout)) {
    return publicSignalsBuffer(publicSignalsBytes);
  }
  const parsed = parsePublicSignalsBytes(publicSignalsBytes, zkConfigNonce);
  const zero = Buffer.alloc(FIELD_BYTES);
  const auditStart = indexAuditTags(layout);
  for (let slot = 0; slot < layout.nAuditSlots; slot += 1) {
    parsed.fields[auditStart + slot] = Buffer.from(zero);
  }
  const outputStart = indexOutputNoteTags(layout);
  for (let note = 0; note < layout.nOuts; note += 1) {
    parsed.fields[outputStart + note] = Buffer.from(zero);
  }
  return encodePublicSignalsBytes(parsed.fields, parsed.hasLengthPrefix);
}

export function spliceBindingTagsIntoPublicSignals(parameters: {
  publicSignalsBytes: Buffer | string;
  zkConfigNonce: bigint;
  auditTags: readonly string[];
  outputNoteTags: readonly string[];
}): Buffer {
  const layout = layoutForKnownNonce(parameters.zkConfigNonce);
  const parsed = parsePublicSignalsBytes(
    parameters.publicSignalsBytes,
    parameters.zkConfigNonce,
  );
  const auditStart = indexAuditTags(layout);
  for (let slot = 0; slot < layout.nAuditSlots; slot += 1) {
    const tag = parameters.auditTags[slot];
    if (tag !== undefined) {
      parsed.fields[auditStart + slot] = fieldElementBuffer(tag);
    }
  }
  const outputStart = indexOutputNoteTags(layout);
  for (let note = 0; note < layout.nOuts; note += 1) {
    const tag = parameters.outputNoteTags[note];
    if (tag !== undefined) {
      parsed.fields[outputStart + note] = fieldElementBuffer(tag);
    }
  }
  return encodePublicSignalsBytes(parsed.fields, parsed.hasLengthPrefix);
}

function fieldElementBuffer(value: string): Buffer {
  const trimmed = value.trim().replace(/^0x/i, '');
  const asBigint = /^[0-9]+$/.test(trimmed)
    ? BigInt(trimmed)
    : BigInt(`0x${trimmed}`);
  const buf = Buffer.alloc(FIELD_BYTES);
  let remaining = asBigint;
  for (let index = FIELD_BYTES - 1; index >= 0; index -= 1) {
    buf[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return buf;
}

export function accountIdFromAddress(address: string): Buffer {
  if (address.startsWith('G')) {
    return Buffer.from(StrKey.decodeEd25519PublicKey(address));
  }
  if (address.startsWith('C')) {
    return Buffer.from(StrKey.decodeContract(address));
  }
  throw new Error(`unsupported address: ${address}`);
}

export interface InspectKytPassageRequest {
  owner: string;
  poolContract: string;
  kytRegistry: string;
  proofBytes: string;
  publicSignalsBytes: string;
  applicationIdsPlaintext: string[];
  ciphertextBytes?: string;
  outputNoteEphemeralScalars?: string[];
  nonce?: string;
  zkConfigNonce?: string;
}

export interface InspectKytPassageApproved {
  status: 'approved';
  passageId: string;
  signature: string;
  expiresAtLedger: number;
}

export async function inspectKytPassage(
  backendUrl: string,
  request: InspectKytPassageRequest,
): Promise<InspectKytPassageApproved> {
  const nonce = BigInt(request.zkConfigNonce ?? 0);
  const body: InspectKytPassageRequest = {
    ...request,
    publicSignalsBytes: zeroBindingTagsInPublicSignals(
      request.publicSignalsBytes,
      nonce,
    ).toString('hex'),
  };
  const response = await fetch(`${backendUrl.replace(/\/$/, '')}/api/kyt/passages/inspect`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    throw new Error(`KYT inspect failed: ${response.status} ${await response.text()}`);
  }
  const payload = await response.json() as InspectKytPassageApproved | { status: string };
  if (payload.status !== 'approved') {
    throw new Error(`KYT inspect rejected: ${JSON.stringify(payload)}`);
  }
  return payload as InspectKytPassageApproved;
}

export function signatureBase64ToBytes(signature: string): Buffer {
  const value = signature.trim();
  if (/^(0x)?[0-9a-fA-F]{128}$/.test(value)) {
    return Buffer.from(value.replace(/^0x/i, ''), 'hex');
  }
  return Buffer.from(value, 'base64');
}
