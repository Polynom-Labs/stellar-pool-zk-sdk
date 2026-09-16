#!/usr/bin/env node
/**
 * Helpers for demo.sh: BN254 Fr decimal from 32-byte hex, Stellar CLI scrape, ephemeral (x,y).
 */
const BN254 = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function frDecFrom32ByteHexBe(h64) {
  const h = h64.replace(/^0x/i, '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(h)) {
    throw new Error(`expected 64 hex chars (32 bytes BE), got len=${h.length}`);
  }
  return (BigInt(`0x${h}`) % BN254).toString(10);
}

/** First 64-hex run in noisy stellar output → Fr decimal (Merkle root / pubkey field encoding). */
function cmdBytesFr(input) {
  const m = String(input).match(/[0-9a-fA-F]{64}/);
  if (!m) throw new Error('bytes-fr: no 64-character hex fragment found');
  console.log(frDecFrom32ByteHexBe(m[0]));
}

/** Legacy: full 32-byte pubkey as one Fr (mod r) — wrong for many G-addresses; use withdraw --withdraw-pubkey-hex. */
function cmdPubkeyFr(input) {
  cmdBytesFr(input);
}

function normalizeCommitmentHex(value) {
  if (typeof value === 'string') {
    const h = value.replace(/^0x/i, '').toLowerCase();
    if (!/^[0-9a-f]{1,64}$/.test(h)) return null;
    return h.padStart(64, '0');
  }
  if (value && typeof value === 'object') {
    const nested =
      value.bytes ??
      value.value ??
      (Array.isArray(value) ? Buffer.from(value).toString('hex') : null);
    if (typeof nested === 'string') {
      return normalizeCommitmentHex(nested);
    }
  }
  return null;
}

function commitmentsFromJsonArray(arr) {
  if (!Array.isArray(arr)) return null;
  const out = [];
  for (const el of arr) {
    const h = normalizeCommitmentHex(el);
    if (h) out.push(h);
  }
  return out.length > 0 ? out : null;
}

/**
 * Stellar CLI 25+ often prints `get_commitments` as a JSON array of 32-byte hex strings.
 * Older / verbose output used `Bytes(64-hex)` fragments — support both.
 */
function parseCommitmentHexStringsFromStellarOutput(s) {
  const text = String(s);

  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('[')) continue;
    try {
      const parsed = commitmentsFromJsonArray(JSON.parse(trimmed));
      if (parsed) return parsed.map((h) => (BigInt(`0x${h}`) % BN254).toString(10));
    } catch {
      /* try next line */
    }
  }

  const bracketed = text.match(/\[[^\]]*\]/g) ?? [];
  for (let i = bracketed.length - 1; i >= 0; i -= 1) {
    try {
      const parsed = commitmentsFromJsonArray(JSON.parse(bracketed[i]));
      if (parsed) return parsed.map((h) => (BigInt(`0x${h}`) % BN254).toString(10));
    } catch {
      /* try previous candidate */
    }
  }

  const re = /Bytes\(([0-9a-fA-F]{64})\)/g;
  const commitments = [];
  let m;
  while ((m = re.exec(text)) !== null) {
    commitments.push((BigInt(`0x${m[1].toLowerCase()}`) % BN254).toString(10));
  }
  return commitments;
}

function cmdCommitmentsFromOutput(input) {
  const commitments = parseCommitmentHexStringsFromStellarOutput(input);
  if (commitments.length === 0) {
    throw new Error(
      'commitments-from-output: no commitments found (expected JSON ["hex",...] or Bytes(64-hex) in output)',
    );
  }
  console.log(JSON.stringify({ commitments }, null, 2));
}

function pickCoordHex(value) {
  if (value == null) return null;
  if (typeof value === 'string') {
    const h = value.replace(/^0x/i, '').toLowerCase();
    return /^[0-9a-f]{64}$/.test(h) ? h : null;
  }
  if (Array.isArray(value)) {
    const h = Buffer.from(value).toString('hex');
    return /^[0-9a-f]{64}$/.test(h) ? h : null;
  }
  if (typeof value === 'object') {
    const nested = value.bytes ?? value.value;
    if (nested != null) return pickCoordHex(nested);
  }
  return null;
}

function tryEphemeralJsonObject(j) {
  const candidates = [
    j,
    j.Some,
    j.some,
    Array.isArray(j.values) ? j.values[0] : null,
    Array.isArray(j.Values) ? j.Values[0] : null,
  ].filter(Boolean);
  for (const inner of candidates) {
    if (!inner || typeof inner !== 'object') continue;
    const rx = pickCoordHex(inner.x ?? inner.X);
    const ry = pickCoordHex(inner.y ?? inner.Y);
    if (rx && ry) {
      return { x: rx, y: ry };
    }
  }
  return null;
}

/** Parse get_leaf_ephemeral / JSON noise → two lines: x64\\ny64 (lowercase hex, no 0x). */
function cmdEphemeralXy(input) {
  const s = String(input).trim();
  let x;
  let y;

  for (const line of s.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('{')) continue;
    try {
      const parsed = tryEphemeralJsonObject(JSON.parse(trimmed));
      if (parsed) {
        x = parsed.x;
        y = parsed.y;
        break;
      }
    } catch {
      /* continue */
    }
  }

  if (!x || !y) {
    try {
      const parsed = tryEphemeralJsonObject(JSON.parse(s));
      if (parsed) {
        x = parsed.x;
        y = parsed.y;
      }
    } catch {
      /* fall through */
    }
  }

  if (!x || !y) {
    const mx = s.match(/"(?:x|ephemeral_x)"\s*:\s*(?:"([0-9a-fA-F]{64})"|\{"bytes":"([0-9a-fA-F]{64})"\})/);
    const my = s.match(/"(?:y|ephemeral_y)"\s*:\s*(?:"([0-9a-fA-F]{64})"|\{"bytes":"([0-9a-fA-F]{64})"\})/);
    if (mx) x = (mx[1] ?? mx[2]).toLowerCase();
    if (my) y = (my[1] ?? my[2]).toLowerCase();
  }

  if (!x || !y) {
    x = readEphemeralCoord(s, 'ephemeral_x') ?? readEphemeralCoord(s, 'x');
    y = readEphemeralCoord(s, 'ephemeral_y') ?? readEphemeralCoord(s, 'y');
  }

  if (!x || !y) {
    const runs = s.match(/[0-9a-fA-F]{64}/g);
    if (runs && runs.length >= 2) {
      x = runs[0].toLowerCase();
      y = runs[1].toLowerCase();
    }
  }

  if (!x || !y) {
    throw new Error('ephemeral-xy: could not parse two 32-byte hex coordinates');
  }
  console.log(`${x}\n${y}`);
}

function readOutputIndex(block) {
  const direct = block.match(/"output_index"\s*:\s*\{\s*"u32"\s*:\s*(\d+)\s*\}/);
  if (direct) return Number(direct[1]);
  const mapped = block.match(
    /\{"key"\s*:\s*\{"symbol"\s*:\s*"output_index"\s*\}\s*,\s*"val"\s*:\s*\{\s*"u32"\s*:\s*(\d+)\s*\}\s*\}/,
  );
  if (mapped) return Number(mapped[1]);
  return null;
}

function readEphemeralCoord(block, axis) {
  const direct = block.match(
    new RegExp(`"${axis}"\\s*:\\s*"([0-9a-fA-F]{64})"`),
  );
  if (direct) return direct[1].toLowerCase();
  const bytesWrapped = block.match(
    new RegExp(`"${axis}"\\s*:\\s*\\{\\s*"bytes"\\s*:\\s*"([0-9a-fA-F]{64})"\\s*\\}`),
  );
  if (bytesWrapped) return bytesWrapped[1].toLowerCase();
  const mapped = block.match(
    new RegExp(
      `\\{"key"\\s*:\\s*\\{"symbol"\\s*:\\s*"${axis}"\\s*\\}\\s*,\\s*"val"\\s*:\\s*\\{\\s*"bytes"\\s*:\\s*"([0-9a-fA-F]{64})"\\s*\\}\\s*\\}`,
    ),
  );
  if (mapped) return mapped[1].toLowerCase();
  return null;
}

function cmdDepositEphemeralXy(input, leafIndexStr) {
  const leafIndex = Number(leafIndexStr ?? 0);
  const s = String(input);
  const blocks = s.split(/output_note/);
  for (const block of blocks) {
    const index = readOutputIndex(block);
    if (index == null || index !== leafIndex) continue;
    const x = readEphemeralCoord(block, 'ephemeral_x');
    const y = readEphemeralCoord(block, 'ephemeral_y');
    if (x && y) {
      console.log(`${x}\n${y}`);
      return;
    }
  }
  throw new Error(`deposit-ephemeral-xy: no output_note event for leaf index ${leafIndex}`);
}

const cmd = process.argv[2];
const arg = process.argv.slice(3).join(' ');

try {
  if (cmd === 'bytes-fr') cmdBytesFr(arg);
  else if (cmd === 'pubkey-fr') cmdPubkeyFr(arg);
  else if (cmd === 'ephemeral-xy') cmdEphemeralXy(arg);
  else if (cmd === 'deposit-ephemeral-xy') {
    const parts = process.argv.slice(3);
    cmdDepositEphemeralXy(parts.slice(0, -1).join(' '), parts.at(-1));
  }
  else if (cmd === 'commitments-from-output') cmdCommitmentsFromOutput(arg);
  else {
    console.error(
      'Usage: demo-stellar-fr.mjs <bytes-fr|pubkey-fr|ephemeral-xy|deposit-ephemeral-xy|commitments-from-output> <text> [leaf_index]',
    );
    process.exit(1);
  }
} catch (e) {
  console.error(e.message || e);
  process.exit(1);
}
