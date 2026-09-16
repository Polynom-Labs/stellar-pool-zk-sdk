#!/usr/bin/env node
/**
 * Build demo_state.json from client-sdk deposit `public_hex` (same layout as
 * `client_sdk::convert::public_to_hex` / Soroban `PublicSignals::from_bytes`).
 *
 * For `Transaction(20,2,2,1,1,4,8)` public layout (`libs/zk` `TransactionLayoutParams`, 73 signals):
 * indices 0–1 = nullifierHashes, 2–3 = commitmentHashes (stateRoot at index 56).
 * Zero commitments (32 zero bytes) are skipped — matches the contract skipping empty leaves.
 */
import fs from 'fs';

const hexPath = process.argv[2];
if (!hexPath) {
  console.error('Usage: demo-state-from-deposit-public.mjs <demo_dep_pub.hex>');
  process.exit(1);
}

const hex = fs.readFileSync(hexPath, 'utf8').trim().replace(/\s/g, '');
const buf = Buffer.from(hex, 'hex');
if (buf.length < 4) {
  console.error('public hex too short');
  process.exit(1);
}

const n = buf.readUInt32BE(0);
const need = 4 + n * 32;
if (buf.length < need) {
  console.error(`expected ${need} bytes, got ${buf.length}`);
  process.exit(1);
}

const signals = [];
for (let i = 0; i < n; i++) {
  signals.push(buf.subarray(4 + i * 32, 4 + (i + 1) * 32));
}

/** Must match `TRANSACTION_N_INS` in `libs/zk` / `main.circom` (nullifier block length). */
const N_INS = 2;
const COMMITMENT_START = N_INS;
const commitments = [];
for (let idx = COMMITMENT_START; idx <= COMMITMENT_START + 1 && idx < signals.length; idx++) {
  const b = signals[idx];
  if (b.length !== 32) break;
  if (b.equals(Buffer.alloc(32))) continue;
  commitments.push(BigInt(`0x${b.toString('hex')}`).toString(10));
}

process.stdout.write(JSON.stringify({ commitments }, null, 2) + '\n');
