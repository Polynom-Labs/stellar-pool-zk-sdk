import { bech32 } from 'bech32';

import type { DecodedStealthAddress, Hex } from './stealth-address';

/** BabyJubJub affine point for ECDH (depositors’ published keys, etc.). */
export interface DecodedEphemeralKey {
  x: Hex;
  y: Hex;
}

/** Depositor preimage: nonce scalar ‖ recipient stealth point (circuit-aligned). */
export interface DecodedDepositorSharedSecretPreimage {
  randomNonceScalar: Hex;
  recipientStealthAddress: DecodedStealthAddress;
}

export type EncodedEphemeralKey = string;

export type EncodedDepositorSharedSecretPreimage = string;

/** Bech32 HRP for {@link DecodedEphemeralKey} only (`x ‖ y`, 64 bytes). */
export const DECODED_EPHEMERAL_HRP = 'epk1' as const;

/** Bech32 HRP for {@link DecodedDepositorSharedSecretPreimage} (96 bytes). */
export const DEPOSITOR_SHARED_SECRET_PREIMAGE_HRP = 'epk_dep_pre1' as const;

const FIELD_BYTES = 32;
const EPK_POINT_PAYLOAD = FIELD_BYTES * 2;
const EPK_DEP_PRE_PAYLOAD = FIELD_BYTES * 3;
const BECH32_LONG_LIMIT = 1023;

function normalizeHex(hex: Hex): string {
  const s = hex.trim().replace(/^0x/i, '');
  if (!/^[0-9a-fA-F]*$/.test(s)) {
    throw new Error('ephemeral-key: hex must contain only 0-9, a-f');
  }
  return s.length % 2 === 0 ? s : `0${s}`;
}

function hexToBytes(hex: Hex): Uint8Array {
  const norm = normalizeHex(hex);
  const out = new Uint8Array(norm.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(norm.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): Hex {
  let s = '';
  for (let i = 0; i < bytes.length; i++) {
    s += bytes[i]!.toString(16).padStart(2, '0');
  }
  return s;
}

function concat2(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function concat3(a: Uint8Array, b: Uint8Array, c: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length + c.length);
  out.set(a, 0);
  out.set(b, a.length);
  out.set(c, a.length + b.length);
  return out;
}

function require32(label: string, bytes: Uint8Array): void {
  if (bytes.length !== FIELD_BYTES) {
    throw new Error(
      `ephemeral-key: ${label} must encode exactly ${FIELD_BYTES} bytes, got ${bytes.length}`,
    );
  }
}

/**
 * 32-byte big-endian integer as hex (64 chars), **< 2^253**, so BabyJub ECDH matches
 * `circuits/encryption.circom` `Num2Bits(253)` and `libs/cryptography` `scalar_mul_253`.
 */
export function generateRandomScalarHex32(): Hex {
  const g = globalThis.crypto;
  if (!g?.getRandomValues) {
    throw new Error('ephemeral-key: crypto.getRandomValues is required');
  }
  const max = 1n << 253n;
  for (let attempt = 0; attempt < 65536; attempt++) {
    const b = new Uint8Array(32);
    g.getRandomValues(b);
    const hex = bytesToHex(b);
    if (BigInt(`0x${hex}`) < max) {
      return hex;
    }
  }
  throw new Error('ephemeral-key: failed to sample scalar < 2^253');
}

/** Bech32 `epk1`: encodes `x ‖ y` (64 bytes). */
export function encodeDecodedEphemeralKey(decoded: DecodedEphemeralKey): EncodedEphemeralKey {
  const xb = hexToBytes(decoded.x);
  const yb = hexToBytes(decoded.y);
  require32('x', xb);
  require32('y', yb);
  const payload = concat2(xb, yb);
  const words = bech32.toWords(payload);
  return bech32.encode(DECODED_EPHEMERAL_HRP, words, BECH32_LONG_LIMIT);
}

export function decodeDecodedEphemeralKey(encoded: EncodedEphemeralKey): DecodedEphemeralKey {
  const { prefix, words } = bech32.decode(encoded, BECH32_LONG_LIMIT);
  if (prefix !== DECODED_EPHEMERAL_HRP) {
    throw new Error(
      `ephemeral-key: expected HRP ${DECODED_EPHEMERAL_HRP}, got ${JSON.stringify(prefix)}`,
    );
  }
  const bytes = new Uint8Array(bech32.fromWords(words));
  if (bytes.length !== EPK_POINT_PAYLOAD) {
    throw new Error(
      `ephemeral-key: epk1 payload must be ${EPK_POINT_PAYLOAD} bytes, got ${bytes.length}`,
    );
  }
  return {
    x: bytesToHex(bytes.subarray(0, FIELD_BYTES)),
    y: bytesToHex(bytes.subarray(FIELD_BYTES)),
  };
}

/** Bech32 `epk_dep_pre1`: `randomNonceScalar ‖ recipient.x ‖ recipient.y`. */
export function encodeDepositorSharedSecretPreimage(
  decoded: DecodedDepositorSharedSecretPreimage,
): EncodedDepositorSharedSecretPreimage {
  const sb = hexToBytes(decoded.randomNonceScalar);
  const xb = hexToBytes(decoded.recipientStealthAddress.x);
  const yb = hexToBytes(decoded.recipientStealthAddress.y);
  require32('randomNonceScalar', sb);
  require32('recipientStealthAddress.x', xb);
  require32('recipientStealthAddress.y', yb);
  const payload = concat3(sb, xb, yb);
  const words = bech32.toWords(payload);
  return bech32.encode(DEPOSITOR_SHARED_SECRET_PREIMAGE_HRP, words, BECH32_LONG_LIMIT);
}

export function decodeDepositorSharedSecretPreimage(
  encoded: EncodedDepositorSharedSecretPreimage,
): DecodedDepositorSharedSecretPreimage {
  const { prefix, words } = bech32.decode(encoded, BECH32_LONG_LIMIT);
  if (prefix !== DEPOSITOR_SHARED_SECRET_PREIMAGE_HRP) {
    throw new Error(
      `ephemeral-key: expected HRP ${DEPOSITOR_SHARED_SECRET_PREIMAGE_HRP}, got ${JSON.stringify(prefix)}`,
    );
  }
  const bytes = new Uint8Array(bech32.fromWords(words));
  if (bytes.length !== EPK_DEP_PRE_PAYLOAD) {
    throw new Error(
      `ephemeral-key: epk_dep_pre1 payload must be ${EPK_DEP_PRE_PAYLOAD} bytes, got ${bytes.length}`,
    );
  }
  return {
    randomNonceScalar: bytesToHex(bytes.subarray(0, FIELD_BYTES)),
    recipientStealthAddress: {
      x: bytesToHex(bytes.subarray(FIELD_BYTES, FIELD_BYTES * 2)),
      y: bytesToHex(bytes.subarray(FIELD_BYTES * 2)),
    },
  };
}
