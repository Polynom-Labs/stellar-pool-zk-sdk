import { ciphertextFieldCount, type ZkLayoutParams } from './zk-layout.js';

export const FR_SIZE = 32;
export const CIPHERTEXT_BLOB_HEADER_BYTES = 4;

const FR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function moduleFr(value: bigint): bigint {
  const reduced = value % FR_MODULUS;
  return reduced >= 0n ? reduced : reduced + FR_MODULUS;
}

function fieldToBytes(value: bigint): Buffer {
  let remaining = moduleFr(value);
  const buf = Buffer.alloc(FR_SIZE);
  for (let index = FR_SIZE - 1; index >= 0; index -= 1) {
    buf[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return buf;
}

function decimalOrHexToBigint(value: string): bigint {
  const trimmed = value.trim();
  if (/^0x/i.test(trimmed) || /^[0-9a-f]{64}$/i.test(trimmed)) {
    return BigInt(`0x${trimmed.replace(/^0x/i, '')}`);
  }
  return BigInt(trimmed);
}

export function encodeCiphertextBlob(fields: readonly string[]): Buffer {
  const prefix = Buffer.alloc(CIPHERTEXT_BLOB_HEADER_BYTES);
  prefix.writeUInt32BE(fields.length);
  return Buffer.concat([
    prefix,
    ...fields.map((field) => fieldToBytes(decimalOrHexToBigint(field))),
  ]);
}

export function decodeCiphertextBlob(blob: Buffer): string[] {
  if (blob.length < CIPHERTEXT_BLOB_HEADER_BYTES) {
    throw new Error('ciphertext_bytes too short');
  }
  const count = blob.readUInt32BE(0);
  const need = CIPHERTEXT_BLOB_HEADER_BYTES + count * FR_SIZE;
  if (blob.length < need) {
    throw new Error('ciphertext_bytes truncated');
  }
  const fields: string[] = [];
  let offset = CIPHERTEXT_BLOB_HEADER_BYTES;
  for (let index = 0; index < count; index += 1) {
    fields.push(blob.subarray(offset, offset + FR_SIZE).toString('hex'));
    offset += FR_SIZE;
  }
  return fields;
}

export function encodeTransactionCiphertextBlob(parameters: {
  layout: ZkLayoutParams;
  auditCiphertexts: readonly (readonly string[])[];
  outputNoteCiphertexts: readonly (readonly string[])[];
}): Buffer {
  const expected = ciphertextFieldCount(parameters.layout);
  const fields: string[] = [];
  for (const slot of parameters.auditCiphertexts) {
    fields.push(...slot);
  }
  for (const note of parameters.outputNoteCiphertexts) {
    fields.push(...note);
  }
  if (fields.length !== expected) {
    throw new Error(
      `ciphertext blob expected ${String(expected)} fields, got ${String(fields.length)}`,
    );
  }
  return encodeCiphertextBlob(fields);
}

export function splitCiphertextBlob(parameters: {
  layout: ZkLayoutParams;
  blob: Buffer;
}): {
  auditCiphertexts: string[][];
  outputNoteCiphertexts: string[][];
} {
  const fields = decodeCiphertextBlob(parameters.blob);
  const expected = ciphertextFieldCount(parameters.layout);
  if (fields.length !== expected) {
    throw new Error(
      `ciphertext blob expected ${String(expected)} fields, got ${String(fields.length)}`,
    );
  }
  const { nAuditSlots, noteAuditLen, nOuts, noteOutputLen } = parameters.layout;
  const auditCiphertexts: string[][] = [];
  let offset = 0;
  for (let slot = 0; slot < nAuditSlots; slot += 1) {
    auditCiphertexts.push(fields.slice(offset, offset + noteAuditLen));
    offset += noteAuditLen;
  }
  const outputNoteCiphertexts: string[][] = [];
  for (let note = 0; note < nOuts; note += 1) {
    outputNoteCiphertexts.push(fields.slice(offset, offset + noteOutputLen));
    offset += noteOutputLen;
  }
  return { auditCiphertexts, outputNoteCiphertexts };
}
