import { bech32 } from 'bech32';

import type { DecodedEphemeralKey } from './ephemeral-key';

/** Lowercase hex string (optional `0x` prefix when parsing). */
export type Hex = string;

export type StealthAddress = string;

export interface DecodedStealthAddress {
  x: Hex;
  y: Hex;
}

/** Withdrawer preimage: recipient scalar ‖ depositor-revealed ephemeral point. */
export interface DecodedRecipientSharedSecretPreimage {
  ephemeralKey: DecodedEphemeralKey;
  recipientScalar: Hex;
}

export const STEALTH_ADDRESS_HRP = 'stpl1' as const;

/** BIP-173 default 90 is too small for 64-byte payload (32+32 field coords) after 8→5 bit conversion. */
const BECH32_STEALTH_LIMIT = 1023;

function normalizeHex(hex: Hex): string {
  const s = hex.trim().replace(/^0x/i, '');
  if (!/^[0-9a-fA-F]*$/.test(s)) {
    throw new Error('stealth-address: hex must contain only 0-9, a-f');
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

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/**
 * Encodes `x || y` as Bech32 (BIP-173) with human-readable part {@link STEALTH_ADDRESS_HRP} (`stpl1`).
 * `x` and `y` must have the same byte length so decoding can split the payload in half.
 */
export function encodeStealthAddress(decoded: DecodedStealthAddress): StealthAddress {
  const xb = hexToBytes(decoded.x);
  const yb = hexToBytes(decoded.y);
  if (xb.length !== yb.length) {
    throw new Error(
      'stealth-address: x and y must encode the same number of bytes for a reversible address',
    );
  }
  const payload = concatBytes(xb, yb);
  const words = bech32.toWords(payload);
  return bech32.encode(STEALTH_ADDRESS_HRP, words, BECH32_STEALTH_LIMIT);
}

/**
 * Decodes a `stpl1` Bech32 stealth address into `x` and `y` (each half of the payload, as lowercase hex).
 */
export function decodeStealthAddress(address: StealthAddress): DecodedStealthAddress {
  const { prefix, words } = bech32.decode(address, BECH32_STEALTH_LIMIT);
  if (prefix !== STEALTH_ADDRESS_HRP) {
    throw new Error(
      `stealth-address: expected HRP ${STEALTH_ADDRESS_HRP}, got ${JSON.stringify(prefix)}`,
    );
  }
  const bytes = new Uint8Array(bech32.fromWords(words));
  if (bytes.length === 0 || bytes.length % 2 !== 0) {
    throw new Error('stealth-address: payload length must be positive and even');
  }
  const mid = bytes.length / 2;
  return {
    x: bytesToHex(bytes.subarray(0, mid)),
    y: bytesToHex(bytes.subarray(mid)),
  };
}
