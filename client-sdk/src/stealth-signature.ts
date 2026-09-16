import { canonicalBabyJubScalarFromInteger } from './domain-separators';
import {
  resolveSpendScalarSchemaVersion,
  SPEND_SCALAR_DOMAIN_TAG,
  type SpendScalarDomain,
} from './stealth-sign-message';

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Base64 → bytes via `atob` (browsers; Node 16+). No Node `Buffer`. */
function decodeBase64ToBytes(s: string): Uint8Array {
  const t = s.replace(/\s/g, '');
  if (typeof atob !== 'function') {
    throw new Error('Base64 decoding requires atob (browser or Node 16+)');
  }
  try {
    const binary = atob(t);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      out[i] = binary.charCodeAt(i);
    }
    return out;
  } catch {
    throw new Error('Invalid base64 signature');
  }
}

/**
 * Ed25519 signature as **128 hex chars** (optional `0x`) or **base64** (typically 88 chars for 64 bytes, whitespace ignored).
 */
export function parseStellarEd25519SignatureRaw(input: string): Uint8Array {
  const trimmed = input.trim();
  const no0x = trimmed.replace(/^0x/i, '');
  if (/^[0-9a-fA-F]+$/.test(no0x) && no0x.length === 128) {
    return hexToBytes(no0x.toLowerCase());
  }
  const fromB64 = decodeBase64ToBytes(trimmed);
  if (fromB64.length !== 64) {
    throw new Error(
      `Decoded signature must be 64 bytes (Ed25519); got ${fromB64.length} from base64`,
    );
  }
  return fromB64;
}

/** SHA-256 via Web Crypto only (`crypto.subtle`) — works in browsers and Node 19+ (global `crypto`). */
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error(
      'SHA-256 requires crypto.subtle (HTTPS or localhost in browsers, or Node.js 19+).',
    );
  }
  const copy = new Uint8Array(data.length);
  copy.set(data);
  return new Uint8Array(await subtle.digest('SHA-256', copy));
}

function appendU32BE(parts: Uint8Array[], value: number): void {
  const buf = new Uint8Array(4);
  new DataView(buf.buffer).setUint32(0, value >>> 0, false);
  parts.push(buf);
}

function appendUtf8Prefixed(parts: Uint8Array[], text: string): void {
  const bytes = new TextEncoder().encode(text);
  appendU32BE(parts, bytes.length);
  parts.push(bytes);
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/**
 * Domain-separated spend-scalar digest: SHA-256(
 *   SPEND_SCALAR_DOMAIN_TAG || network || pool || registry || schemaVersion || signature
 * ).
 */
export async function spendScalarDigestFromStellarSignature(
  signature: string,
  domain: SpendScalarDomain,
): Promise<Uint8Array> {
  const raw = parseStellarEd25519SignatureRaw(signature);
  const parts: Uint8Array[] = [new TextEncoder().encode(SPEND_SCALAR_DOMAIN_TAG)];
  appendUtf8Prefixed(parts, domain.networkPassphrase);
  appendUtf8Prefixed(parts, domain.poolContract);
  appendUtf8Prefixed(parts, domain.registryContract);
  appendU32BE(parts, resolveSpendScalarSchemaVersion(domain));
  parts.push(raw);
  return sha256(concatBytes(parts));
}

function digestToCanonicalScalar(digest: Uint8Array): bigint {
  let v = 0n;
  for (let i = 0; i < digest.length; i++) {
    v = (v << 8n) + BigInt(digest[i]!);
  }
  return canonicalBabyJubScalarFromInteger(v);
}

function canonicalScalarHex(scalar: bigint): string {
  return scalar.toString(16).padStart(64, '0');
}

export async function spendScalarHexFromStellarSignature(
  signature: string,
  domain: SpendScalarDomain,
): Promise<string> {
  const digest = await spendScalarDigestFromStellarSignature(signature, domain);
  return canonicalScalarHex(digestToCanonicalScalar(digest));
}

/**
 * Stellar Ed25519 signature (hex or base64) → domain-separated SHA-256 → scalar → WASM ECDH.
 */
export async function stealthAddressFromStellarSignature(
  ecdhFromScalarHex: (scalarHex64: string) => { x: string; y: string },
  encodeStealth: (decoded: { x: string; y: string }) => string,
  signature: string,
  domain: SpendScalarDomain,
): Promise<string> {
  const digest = await spendScalarDigestFromStellarSignature(signature, domain);
  const decoded = ecdhFromScalarHex(canonicalScalarHex(digestToCanonicalScalar(digest)));
  return encodeStealth(decoded);
}

/**
 * Domain-separated SHA-256(signature, network, pool, registry, schema) reduced into
 * `(0, BabyJub subgroup order)` so `privKeyScalar` matches `BabyPbk` and circom `LessThan(l)`.
 */
export async function privKeyScalarDecimalFromStellarSignature(
  signature: string,
  domain: SpendScalarDomain,
): Promise<string> {
  const digest = await spendScalarDigestFromStellarSignature(signature, domain);
  return digestToCanonicalScalar(digest).toString(10);
}
