#!/usr/bin/env node
import { createRequire } from 'node:module';
import {
  buildKytPassageAuthorization,
  derivePassageFromTransactContext,
  layoutForKnownNonce,
  stateRootIndex,
  totalPublicSignals,
} from '../client-sdk/dist/index.mjs';

const require = createRequire(new URL('../client-sdk/package.json', import.meta.url));
const { Keypair, StrKey, rpc } = require('@stellar/stellar-sdk');

const FIELD_BYTES = 32;
const LENGTH_PREFIX_BYTES = 4;
const DEFAULT_TTL_LEDGERS = 1000;

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (!arg.startsWith('--')) {
      continue;
    }
    const key = arg.slice(2);
    const value = argv[i + 1];
    if (value && !value.startsWith('--')) {
      out[key] = value;
      i += 1;
    } else {
      out[key] = 'true';
    }
  }
  return out;
}

function requireArg(args, name) {
  const value = args[name]?.trim();
  if (!value) {
    throw new Error(`missing --${name}`);
  }
  return value;
}

function normalizeHex(hex) {
  const value = hex.trim().replace(/^0x/i, '');
  if (!/^[0-9a-fA-F]+$/.test(value) || value.length % 2 !== 0) {
    throw new Error('invalid hex input');
  }
  return value;
}

function parsePublicSignals(publicSignalsHex, nonce) {
  const layout = layoutForKnownNonce(nonce);
  const expectedCount = totalPublicSignals(layout);
  const bytes = Buffer.from(normalizeHex(publicSignalsHex), 'hex');
  let offset = 0;
  if (bytes.length >= LENGTH_PREFIX_BYTES) {
    const len = bytes.readUInt32BE(0);
    if (bytes.length === LENGTH_PREFIX_BYTES + len * FIELD_BYTES) {
      offset = LENGTH_PREFIX_BYTES;
    }
  }
  const signalBytes = bytes.subarray(offset);
  if (signalBytes.length !== expectedCount * FIELD_BYTES) {
    throw new Error(`expected ${expectedCount} public signals for nonce ${nonce.toString()}`);
  }
  return {
    layout,
    fields: Array.from({ length: expectedCount }, (_, index) =>
      signalBytes.subarray(index * FIELD_BYTES, (index + 1) * FIELD_BYTES),
    ),
  };
}

function fieldDecimal(field) {
  return BigInt(`0x${field.toString('hex')}`).toString(10);
}

function withdrawAddress(fields, rootIndex) {
  const hi = fields[rootIndex + 1];
  const lo = fields[rootIndex + 2];
  return StrKey.encodeEd25519PublicKey(Buffer.concat([hi.subarray(16), lo.subarray(16)]));
}

async function latestLedger(rpcUrl, explicitLedger) {
  if (explicitLedger !== undefined) {
    return Number(explicitLedger);
  }
  const server = new rpc.Server(rpcUrl);
  const ledger = await server.getLatestLedger();
  return Number(ledger.sequence ?? ledger.id);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const owner = requireArg(args, 'owner');
  const poolContract = requireArg(args, 'pool');
  const kytRegistry = requireArg(args, 'registry');
  const publicSignalsHex = requireArg(args, 'public-signals');
  const secret = requireArg(args, 'secret');
  const nonce = BigInt(args['nonce'] ?? '2');
  const rpcUrl = args['rpc-url'] ?? 'https://soroban-testnet.stellar.org';
  const ttl = Number(args['ttl-ledgers'] ?? DEFAULT_TTL_LEDGERS);
  const currentLedger = await latestLedger(rpcUrl, args['current-ledger']);
  const expiresAtLedger = currentLedger + ttl;
  const { layout, fields } = parsePublicSignals(publicSignalsHex, nonce);
  const rootIndex = stateRootIndex(layout);
  // V2 prefix: stateRoot, withdrawHi/Lo, escrowHi/Lo, sweepX/Y, then public legs.
  const publicWithdrawnAssetHi = rootIndex + layout.publicInputPrefixLen;
  const publicDepositedAssetHi = publicWithdrawnAssetHi + 2 * layout.publicNInputs;
  const publicDepositAmount = publicDepositedAssetHi + 2 * layout.publicNOutputs;
  const publicWithdrawAmount = publicDepositAmount + layout.publicNOutputs;
  const publicLegContext = {
    owner,
    withdrawAddress: withdrawAddress(fields, rootIndex),
    publicDeposits: [fieldDecimal(fields[publicDepositAmount])],
    publicWithdrawals: [fieldDecimal(fields[publicWithdrawAmount])],
    publicDepositedAssets: [[
      fieldDecimal(fields[publicDepositedAssetHi]),
      fieldDecimal(fields[publicDepositedAssetHi + 1]),
    ]],
    publicWithdrawnAssets: [[
      fieldDecimal(fields[publicWithdrawnAssetHi]),
      fieldDecimal(fields[publicWithdrawnAssetHi + 1]),
    ]],
  };
  const derivation = derivePassageFromTransactContext({
    owner,
    nonce,
    publicSignalsBytes: Buffer.from(normalizeHex(publicSignalsHex), 'hex'),
    publicLegContext,
  });
  const authorization = buildKytPassageAuthorization({
    poolContract,
    kytRegistry,
    passageId: derivation.passageId,
    expiresAtLedger,
  });
  const signature = Keypair.fromSecret(secret)
    .sign(Buffer.from(authorization.authorizationHash, 'hex'))
    .toString('hex');
  process.stdout.write(JSON.stringify({
    passageId: derivation.passageId,
    expiresAtLedger,
    signature,
    authorizationHash: authorization.authorizationHash,
  }));
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
