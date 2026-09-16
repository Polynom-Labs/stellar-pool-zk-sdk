#!/usr/bin/env node
/**
 * Call Core KYT inspect then register_passage + pool.transact for a deposit.
 * Expects proof/public hex files and env (see staging-core-kyt-deposit.sh).
 */
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import {
  inspectKytPassage,
  submitWithKytPassage,
} from "../client-sdk/dist/index.mjs";

const require = createRequire(
  new URL("../client-sdk/package.json", import.meta.url),
);
const { Keypair, Networks, StrKey } = require("@stellar/stellar-sdk");

const FIELD_BYTES = 32;
const SIGNAL_COUNT = 79;
const LENGTH_PREFIX_BYTES = 4;
const WITHDRAW_ADDRESS_HI_INDEX = 71;
const WITHDRAW_ADDRESS_LO_INDEX = 72;
const PUBLIC_WITHDRAWN_ASSET_HI_INDEX = 73;
const PUBLIC_WITHDRAWN_ASSET_LO_INDEX = 74;
const PUBLIC_DEPOSITED_ASSET_HI_INDEX = 75;
const PUBLIC_DEPOSITED_ASSET_LO_INDEX = 76;
const PUBLIC_DEPOSIT_AMOUNT_INDEX = 77;
const PUBLIC_WITHDRAW_AMOUNT_INDEX = 78;

function requireEnv(name) {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`missing env ${name}`);
  }
  return value;
}

function normalizeHex(hex) {
  const value = hex.trim().replace(/^0x/i, "");
  if (!/^[0-9a-fA-F]+$/.test(value) || value.length % 2 !== 0) {
    throw new Error("invalid hex");
  }
  return value;
}

function parsePublicSignals(publicSignalsHex) {
  const bytes = Buffer.from(normalizeHex(publicSignalsHex), "hex");
  let offset = 0;
  if (bytes.length >= LENGTH_PREFIX_BYTES) {
    const len = bytes.readUInt32BE(0);
    if (bytes.length === LENGTH_PREFIX_BYTES + len * FIELD_BYTES) {
      offset = LENGTH_PREFIX_BYTES;
    }
  }
  const signalBytes = bytes.subarray(offset);
  if (signalBytes.length !== SIGNAL_COUNT * FIELD_BYTES) {
    throw new Error(`expected ${SIGNAL_COUNT} public signals`);
  }
  return Array.from({ length: SIGNAL_COUNT }, (_, index) =>
    signalBytes.subarray(index * FIELD_BYTES, (index + 1) * FIELD_BYTES),
  );
}

function fieldDecimal(field) {
  return BigInt(`0x${field.toString("hex")}`).toString(10);
}

function withdrawAddress(fields) {
  const hi = fields[WITHDRAW_ADDRESS_HI_INDEX];
  const lo = fields[WITHDRAW_ADDRESS_LO_INDEX];
  return StrKey.encodeEd25519PublicKey(
    Buffer.concat([hi.subarray(16), lo.subarray(16)]),
  );
}

async function fetchLatestLedger(rpcUrl) {
  const response = await fetch(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "getLatestLedger",
    }),
  });
  if (!response.ok) {
    throw new Error(`getLatestLedger HTTP ${String(response.status)}`);
  }
  const payload = await response.json();
  const sequence = payload?.result?.sequence;
  if (!Number.isSafeInteger(sequence) || sequence < 0) {
    throw new Error("getLatestLedger returned invalid sequence");
  }
  return sequence;
}

async function main() {
  const owner = requireEnv("OWNER");
  const pool = requireEnv("POOL");
  const kytRegistry = requireEnv("KYT_REGISTRY");
  const core = requireEnv("CORE_API_URL");
  const appId = requireEnv("APPLICATION_ID");
  const sourceSecret = requireEnv("SOURCE_SECRET");
  const rpcUrl =
    process.env.RPC_URL?.trim() || "https://soroban-testnet.stellar.org";
  const nonce = BigInt(process.env.ZK_CONFIG_NONCE ?? "0");
  const proofPath = process.env.PROOF_HEX_FILE ?? "demo_dep_proof_staging.hex";
  const publicPath = process.env.PUBLIC_HEX_FILE ?? "demo_dep_pub_staging.hex";

  const proofHex = normalizeHex(readFileSync(proofPath, "utf8"));
  const publicHex = normalizeHex(readFileSync(publicPath, "utf8"));
  const fields = parsePublicSignals(publicHex);
  const currentLedger = await fetchLatestLedger(rpcUrl);

  const publicLegContext = {
    owner,
    withdrawAddress: withdrawAddress(fields),
    publicDeposits: [fieldDecimal(fields[PUBLIC_DEPOSIT_AMOUNT_INDEX])],
    publicWithdrawals: [fieldDecimal(fields[PUBLIC_WITHDRAW_AMOUNT_INDEX])],
    publicDepositedAssets: [
      [
        fieldDecimal(fields[PUBLIC_DEPOSITED_ASSET_HI_INDEX]),
        fieldDecimal(fields[PUBLIC_DEPOSITED_ASSET_LO_INDEX]),
      ],
    ],
    publicWithdrawnAssets: [
      [
        fieldDecimal(fields[PUBLIC_WITHDRAWN_ASSET_HI_INDEX]),
        fieldDecimal(fields[PUBLIC_WITHDRAWN_ASSET_LO_INDEX]),
      ],
    ],
  };

  const inspectRequest = {
    owner,
    poolContract: pool,
    kytRegistry,
    proofBytes: `0x${proofHex}`,
    publicSignalsBytes: `0x${publicHex}`,
    applicationIdsPlaintext: ["0", "0", appId, "0"],
    nonce: nonce.toString(),
    currentLedger,
  };

  console.log("BEGIN kyt_inspect");
  const approved = await inspectKytPassage(core, inspectRequest);
  console.log(
    JSON.stringify({
      status: approved.status,
      passageId: approved.passageId,
      expiresAtLedger: approved.expiresAtLedger,
    }),
  );
  console.log("END kyt_inspect");

  console.log("BEGIN onchain_submit");
  const txHash = await submitWithKytPassage({
    source: Keypair.fromSecret(sourceSecret),
    networkPassphrase: Networks.TESTNET,
    rpcUrl,
    poolContract: pool,
    owner,
    nonce,
    proofBytes: Buffer.from(proofHex, "hex"),
    publicSignalsBytes: Buffer.from(publicHex, "hex"),
    kytRegistryId: kytRegistry,
    inspectRequest,
    inspectFn: async () => approved,
    publicLegContext,
  });
  console.log(JSON.stringify({ txHash }));
  console.log("END onchain_submit");
}

main().catch((error) => {
  console.error(
    error instanceof Error ? (error.stack ?? error.message) : String(error),
  );
  process.exit(1);
});
