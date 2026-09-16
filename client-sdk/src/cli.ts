import * as fs from "fs";
import { Keypair, Networks } from "@stellar/stellar-sdk";
import { decodeStealthAddress } from "./stealth-address";
import {
  buildStealthAddressSignMessage,
  DEFAULT_STEALTH_SIGN_NONCE,
  OWNER_BOUND_NOTE_SCHEMA_VERSION,
  type SpendScalarDomain,
} from "./stealth-sign-message";
import { privKeyScalarDecimalFromStellarSignature } from "./stealth-signature";
import { PrivacyPoolSDK } from "./sdk";
import { submitApprovedKytPassage } from "./kyt-flow";
import {
  ed25519PubkeyPayloadHexToWithdrawFrDecimals,
  randomFrDecimal,
  randomFrDecimal253,
  recipientPublicKeysDecimalFromStealthAddress,
  scalarHexToFrDecimal,
  stellarContractAddressToAssetFrDecimals,
  type DepositObject,
  type TransactionPublicLegParams,
} from "./withdrawal-transaction-input";
import type { CoinData, StateFile } from "./types";
import { COIN_VALUE_STROOPS } from "./types";
import {
  DEFAULT_APPLICATION_ID,
  resolveTransactionAuditParams,
} from "./transaction-audit";
import {
  BINDING_ZK_NONCE,
  SIX_BY_SIX_BINDING_ZK_NONCE,
  TEN_BY_ONE_ZK_NONCE,
} from "./zk-layout";

function resolveApplicationIdFromCli(parsed: Record<string, string>): string {
  return (
    parsed["application-id"] ??
    process.env.APPLICATION_ID ??
    DEFAULT_APPLICATION_ID
  );
}

function resolveZkInit(parsed: Record<string, string>): {
  zkConfigNonce: bigint;
} {
  const explicit = parsed["profile"] ?? process.env.ZK_PROFILE;
  if (explicit && (explicit === "10x1" || explicit === "10")) {
    return { zkConfigNonce: TEN_BY_ONE_ZK_NONCE };
  }
  if (
    explicit &&
    (explicit === "6x6" || explicit === "six" || explicit === "6")
  ) {
    return { zkConfigNonce: SIX_BY_SIX_BINDING_ZK_NONCE };
  }
  const envNonce = (process.env.ZK_CONFIG_NONCE ?? "").trim();
  if (envNonce === "10") {
    return { zkConfigNonce: TEN_BY_ONE_ZK_NONCE };
  }
  if (envNonce === "6" || envNonce === "7") {
    return { zkConfigNonce: SIX_BY_SIX_BINDING_ZK_NONCE };
  }
  if (envNonce === "3" || envNonce === "2" || envNonce === "") {
    return { zkConfigNonce: BINDING_ZK_NONCE };
  }
  return { zkConfigNonce: BINDING_ZK_NONCE };
}

async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || args[0] === "--help" || args[0] === "-h") {
    printUsage();
    process.exit(0);
  }

  const command = args[0];

  if (command === "withdraw") {
    await handleWithdraw(args.slice(1));
  } else if (command === "deposit-proof") {
    await handleDepositProof(args.slice(1));
  } else if (command === "generate") {
    await handleGenerate(args.slice(1));
  } else if (command === "random-scalar") {
    handleRandomScalar();
  } else if (command === "stealth-sign-message") {
    handleStealthSignMessage(args.slice(1));
  } else if (command === "stealth-from-signature") {
    await handleStealthFromSignature(args.slice(1));
  } else if (command === "priv-scalar-from-signature") {
    await handlePrivScalarFromSignature(args.slice(1));
  } else if (command === "stealth-pubkey-hex") {
    handleStealthPubkeyHex(args.slice(1));
  } else if (command === "kyt-submit-approved") {
    await handleKytSubmitApproved(args.slice(1));
  } else {
    console.error(`Unknown command: ${command}`);
    printUsage();
    process.exit(1);
  }

  // Exit explicitly so the process doesn't hang (e.g. snarkjs workers / timers)
  process.exit(0);
}

function printUsage() {
  console.error(`Usage: client-sdk-cli <command> [options]

Commands:
  generate                         Generate a new coin
    --output, -o <file>            Output coin to file (default: stdout)
    --amount <stroops>             Coin value in stroops (u64); default: 1000000000 (1 XLM)
    --token <C...>                 Stellar asset contract id (or set TOKEN_ADDRESS)
    --application-id <dec>         Application id (decimal Fr); default: APPLICATION_ID env or 101
    --scalar <hex>                 32-byte depositor ephemeral scalar (64 hex, optional 0x); coin.secret = Poseidon₁(scalar) (deposit.circom)
    --stealth <stpl1...>           With --scalar: ECDH(scalar, recipient) shared secret + aligned commitment (requires WASM ecdhSharedKey)

  random-scalar                    Print random 32-byte hex scalar with integer < 2^253 (BabyJub / circom)

  stealth-sign-message             Print message to sign (Stellar wallet / stellar CLI)
    --address <G...>               Stellar account address (required)
    --network-passphrase <string>  Network passphrase bound into the spend scalar
    --pool <C...>                  Pool contract id bound into the spend scalar
    --registry <C...>              Registry contract id bound into the spend scalar
    --schema-version <u32>         Note schema version (default: 1)
    --nonce <string>               Nonce label (default: "main address")

  stealth-from-signature           Derive stpl1 stealth address from Ed25519 signature
    --signature <value>            128 hex chars (optional 0x) or standard base64 (64 bytes)
    --signature-file <path>        Read signature from file (whitespace trimmed)
    --network-passphrase <string>  Spend-scalar domain (same as stealth-sign-message)
    --pool <C...>
    --registry <C...>
    --schema-version <u32>

  priv-scalar-from-signature       Print privKeyScalar (decimal Fr) from domain-separated spend digest

  stealth-pubkey-hex                Decode a stpl1 stealth address into its BabyJubJub public key
    --stealth <stpl1...>            Stealth address to decode
                                     Prints x hex on line 1, y hex on line 2 (registry public_key_x/public_key_y)

  kyt-submit-approved              Submit helper.register_passage + pool.transact with signed non-root auth
    --source-secret <S...>         Secret seed for the depositing/withdrawing Stellar account (or SOURCE_SECRET env)
    --owner <G...>                 Same account address passed to pool.transact as from
    --pool <C...>                  Privacy pool contract id
    --helper <C...>                KYT submit helper contract id
    --proof <hex>                  Groth16 proof bytes
    --public-signals <hex>         Public signals bytes
    --passage-id <hex>             KYT passage id
    --expires-at-ledger <u32>      Passage expiration ledger
    --signature <hex|base64>       KYT registry signature
    --rpc-url <url>                Soroban RPC URL
    --network <testnet|public|local> or --network-passphrase <string>

  withdraw                         Generate a withdrawal proof
    --coin <file>                  Path to coin JSON file
    --state <file>                 Path to state JSON file
    --withdraw-pubkey-hex <hex>    Stellar account Ed25519 payload (32 bytes = 64 hex); splits to public withdrawAddressHi/Lo
    --withdraw-address-hi <dec>    Optional: override high u128 (decimal) if not using --withdraw-pubkey-hex
    --withdraw-address-lo <dec>    Optional: override low u128 (decimal)
    --priv-key-scalar <dec>        privKeyScalar (decimal Fr)
    --ephemeral-x <hex>            Depositor ECDH point x (64 hex chars, optional 0x)
    --ephemeral-y <hex>            Depositor ECDH point y (64 hex chars, optional 0x)
    --public-withdraw-stroops <u64> Optional: amount to withdraw publicly (must be < coin.value). Rest stays in pool as change.
    --change-stealth <stpl1...>    Required with --public-withdraw-stroops: stealth for the change note (same as deposit)
    --application-id <dec>         Application id (decimal Fr); default: APPLICATION_ID env or 101
    --profile <2x2|6x6|10x1>       Circuit artifact profile (default: ZK_PROFILE / ZK_CONFIG_NONCE=7 → 6x6, 10 → 10x1)
    --output-proof <file>          Write proof hex to file
    --output-public <file>         Write public signals hex to file
    --output-ciphertext <file>     Write userspace MiMC ciphertext blob hex to file

  deposit-proof                  Groth16 proof for deposit-only transact (dummy withdraws, 1 deposit + dummy outs)
    --state-root <dec>           Current Merkle root (decimal Fr), must match pool on submit
    --stealth <stpl1...>         Recipient stealth address (decodes to recipient public key)
    --token <C...>               Asset contract id (or set TOKEN_ADDRESS)
    --coin <file>                With --ephemeral-scalar-hex: use coin nullifier/value (aligned with generate --scalar --stealth)
    --ephemeral-scalar-hex <hex>  Same 32-byte hex as deposit / generate --scalar
    --value <dec>                Deposit amount (stroops as decimal Fr); optional if --coin (must match coin)
    --application-id <dec>       Application id (decimal Fr); default: APPLICATION_ID env or 101
    --profile <2x2|6x6|10x1>     Circuit artifact profile (default: ZK_PROFILE / ZK_CONFIG_NONCE=7 → 6x6, 10 → 10x1)
    --output-proof <file>        Write proof hex to file
    --output-public <file>       Write public signals hex to file
    --output-ciphertext <file>   Write userspace MiMC ciphertext blob hex to file

Output (withdraw, deposit-proof):
  Prints proof_hex on first line and public_hex on second line to stdout.
`);
}

function requireParsedArg(
  parsed: Record<string, string>,
  name: string,
): string {
  const value = parsed[name]?.trim();
  if (!value) {
    console.error(`Error: --${name} is required`);
    process.exit(1);
  }
  return value;
}

function networkPassphraseFromArgs(parsed: Record<string, string>): string {
  if (parsed["network-passphrase"]) {
    return parsed["network-passphrase"];
  }
  const network = parsed["network"] ?? "testnet";
  if (network === "testnet") {
    return Networks.TESTNET;
  }
  if (network === "public") {
    return Networks.PUBLIC;
  }
  if (network === "local") {
    return "Standalone Network ; February 2017";
  }
  console.error("Error: --network must be testnet, public, or local");
  process.exit(1);
}

function hexToBuffer(label: string, value: string): Buffer {
  const hex = value.trim().replace(/^0x/i, "");
  if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) {
    console.error(`Error: --${label} must be even-length hex`);
    process.exit(1);
  }
  return Buffer.from(hex, "hex");
}

function parseArgs(args: string[]): Record<string, string> {
  const parsed: Record<string, string> = {};
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith("--")) {
      const key = arg.slice(2);
      const value = args[i + 1];
      if (value && !value.startsWith("--")) {
        parsed[key] = value;
        i++;
      } else {
        parsed[key] = "true";
      }
    } else if (arg === "-o" && i + 1 < args.length) {
      parsed["output"] = args[++i];
    } else if (arg === "-a" && i + 1 < args.length) {
      parsed["address"] = args[++i];
    } else if (arg === "-n" && i + 1 < args.length) {
      parsed["nonce"] = args[++i];
    } else if (arg === "-s" && i + 1 < args.length) {
      parsed["signature"] = args[++i];
    }
  }
  return parsed;
}

function requireSpendScalarDomain(
  parsed: Record<string, string>,
): SpendScalarDomain {
  const networkPassphrase =
    parsed["network-passphrase"] ?? networkPassphraseFromArgs(parsed);
  const poolContract = requireParsedArg(parsed, "pool");
  const registryContract = requireParsedArg(parsed, "registry");
  const schemaRaw = parsed["schema-version"];
  const domain: SpendScalarDomain = {
    networkPassphrase,
    poolContract,
    registryContract,
  };
  if (schemaRaw !== undefined) {
    domain.schemaVersion = Number(schemaRaw);
  } else {
    domain.schemaVersion = OWNER_BOUND_NOTE_SCHEMA_VERSION;
  }
  return domain;
}

function handleStealthSignMessage(args: string[]) {
  const parsed = parseArgs(args);
  const address = parsed["address"];
  if (!address) {
    console.error("Error: --address <G...> is required");
    process.exit(1);
  }
  const nonce = parsed["nonce"] ?? DEFAULT_STEALTH_SIGN_NONCE;
  console.log(
    buildStealthAddressSignMessage(
      address,
      requireSpendScalarDomain(parsed),
      nonce,
    ),
  );
}

async function handleStealthFromSignature(args: string[]) {
  const parsed = parseArgs(args);
  let sig = parsed["signature"];
  if (parsed["signature-file"]) {
    sig = fs.readFileSync(parsed["signature-file"], "utf-8");
  }
  if (!sig) {
    console.error(
      "Error: --signature <hex> or --signature-file <path> is required",
    );
    process.exit(1);
  }
  const sdk = await PrivacyPoolSDK.init();
  const stealth = await sdk.generateStealthAddressFromStellarSignature(
    sig,
    requireSpendScalarDomain(parsed),
  );
  console.log(stealth);
}

function handleStealthPubkeyHex(args: string[]) {
  const parsed = parseArgs(args);
  const stealth = requireParsedArg(parsed, "stealth");
  const { x, y } = decodeStealthAddress(stealth);
  console.log(x);
  console.log(y);
}

async function handlePrivScalarFromSignature(args: string[]) {
  const parsed = parseArgs(args);
  let sig = parsed["signature"];
  if (parsed["signature-file"]) {
    sig = fs.readFileSync(parsed["signature-file"], "utf-8");
  }
  if (!sig) {
    console.error(
      "Error: --signature <hex> or --signature-file <path> is required",
    );
    process.exit(1);
  }
  const dec = await privKeyScalarDecimalFromStellarSignature(
    sig.trim(),
    requireSpendScalarDomain(parsed),
  );
  console.log(dec);
}

function handleRandomScalar() {
  console.log(PrivacyPoolSDK.generateRandomScalarHex32());
}

async function handleKytSubmitApproved(args: string[]) {
  const parsed = parseArgs(args);
  const sourceSecret =
    parsed["source-secret"]?.trim() ?? process.env.SOURCE_SECRET?.trim();
  if (!sourceSecret) {
    console.error(
      "Error: --source-secret <S...> or SOURCE_SECRET env is required",
    );
    process.exit(1);
  }
  const txHash = await submitApprovedKytPassage({
    source: Keypair.fromSecret(sourceSecret),
    networkPassphrase: networkPassphraseFromArgs(parsed),
    rpcUrl: parsed["rpc-url"] ?? "https://soroban-testnet.stellar.org",
    poolContract: requireParsedArg(parsed, "pool"),
    owner: requireParsedArg(parsed, "owner"),
    nonce: BigInt(parsed["nonce"] ?? "0"),
    proofBytes: hexToBuffer("proof", requireParsedArg(parsed, "proof")),
    publicSignalsBytes: hexToBuffer(
      "public-signals",
      requireParsedArg(parsed, "public-signals"),
    ),
    kytSubmitHelperId: requireParsedArg(parsed, "helper"),
    passageId: requireParsedArg(parsed, "passage-id"),
    expiresAtLedger: Number(requireParsedArg(parsed, "expires-at-ledger")),
    signature: requireParsedArg(parsed, "signature"),
  });
  console.log(txHash);
}

function parseStroopsU64(label: string, raw: string, _min: bigint): bigint {
  if (!/^\d+$/.test(raw)) {
    console.error(`Error: ${label} must be a non-negative decimal integer`);
    process.exit(1);
  }
  return BigInt(raw);
}

function parseCoinValueDecimal(
  label: string,
  raw: string | undefined,
  defaultStroops: bigint,
): string {
  if (raw === undefined) {
    return defaultStroops.toString(10);
  }
  if (!/^\d+$/.test(raw)) {
    console.error(`Error: ${label} must be a non-negative decimal integer`);
    process.exit(1);
  }
  return raw;
}

async function handleGenerate(args: string[]) {
  const parsed = parseArgs(args);
  const sdk = await PrivacyPoolSDK.init();
  const scalar = parsed["scalar"];
  const stealth = parsed["stealth"];
  const amount = parseCoinValueDecimal(
    "--amount",
    parsed["amount"],
    BigInt(COIN_VALUE_STROOPS),
  );
  const applicationId = resolveApplicationIdFromCli(parsed);
  const token = parsed["token"] ?? process.env.TOKEN_ADDRESS;
  if (!token) {
    console.error("Error: --token <C...> or TOKEN_ADDRESS is required");
    process.exit(1);
  }
  const [assetHi, assetLo] = stellarContractAddressToAssetFrDecimals(token);

  if (stealth && !scalar) {
    console.error("Error: --stealth requires --scalar");
    process.exit(1);
  }

  let coin;
  if (scalar && stealth) {
    const { x, y } = decodeStealthAddress(stealth);
    coin = sdk.generateCoinForDepositWithOwnerPubHex(
      scalar,
      x,
      y,
      amount,
      assetHi,
      assetLo,
      applicationId,
    );
  } else if (scalar) {
    coin = sdk.generateCoinFromDepositEphemeralScalarHex(
      scalar,
      amount,
      assetHi,
      assetLo,
      applicationId,
    );
  } else {
    coin = sdk.generateCoin(amount, assetHi, assetLo, applicationId);
  }

  const json = JSON.stringify(coin, null, 2);

  if (parsed["output"]) {
    fs.writeFileSync(parsed["output"], json);
    console.error(`Coin saved to: ${parsed["output"]}`);
    console.error(`Commitment: ${coin.commitment_hex}`);
  } else {
    console.log(json);
  }
}

async function handleWithdraw(args: string[]) {
  const parsed = parseArgs(args);

  if (!parsed["coin"]) {
    console.error("Error: --coin <file> is required");
    process.exit(1);
  }
  if (!parsed["state"]) {
    console.error("Error: --state <file> is required");
    process.exit(1);
  }
  let withdrawHi = parsed["withdraw-address-hi"];
  let withdrawLo = parsed["withdraw-address-lo"];
  const pkHex = parsed["withdraw-pubkey-hex"];
  if (pkHex) {
    const parts = ed25519PubkeyPayloadHexToWithdrawFrDecimals(pkHex);
    withdrawHi = parts.hi;
    withdrawLo = parts.lo;
  }
  if (withdrawHi === undefined || withdrawLo === undefined) {
    console.error(
      "Error: provide --withdraw-pubkey-hex <64 hex> or both --withdraw-address-hi and --withdraw-address-lo",
    );
    process.exit(1);
  }
  if (!parsed["priv-key-scalar"]) {
    console.error("Error: --priv-key-scalar <dec> is required");
    process.exit(1);
  }
  if (!parsed["ephemeral-x"] || !parsed["ephemeral-y"]) {
    console.error(
      "Error: --ephemeral-x <hex> and --ephemeral-y <hex> are required",
    );
    process.exit(1);
  }

  const coinFile = JSON.parse(fs.readFileSync(parsed["coin"], "utf-8"));
  const coin: CoinData = coinFile.coin || coinFile;
  const state: StateFile = JSON.parse(
    fs.readFileSync(parsed["state"], "utf-8"),
  );

  const pubW = parsed["public-withdraw-stroops"];
  const changeStealth = parsed["change-stealth"];
  if (pubW !== undefined && changeStealth === undefined) {
    console.error(
      "Error: --change-stealth <stpl1...> is required when using --public-withdraw-stroops",
    );
    process.exit(1);
  }
  if (pubW === undefined && changeStealth !== undefined) {
    console.error(
      "Error: --change-stealth is only valid with --public-withdraw-stroops",
    );
    process.exit(1);
  }

  const { zkConfigNonce } = resolveZkInit(parsed);
  const sdk = await PrivacyPoolSDK.init({ zkConfigNonce });
  const applicationId = resolveApplicationIdFromCli(parsed);
  const audit = resolveTransactionAuditParams(
    applicationId,
    undefined,
    sdk.getLayout().nAuditSlots,
  );
  const result = await sdk.proveWithdrawal(coin, state, {
    withdrawAddressHi: withdrawHi,
    withdrawAddressLo: withdrawLo,
    privKeyScalar: parsed["priv-key-scalar"],
    ephemeralXHex: parsed["ephemeral-x"],
    ephemeralYHex: parsed["ephemeral-y"],
    applicationId,
    audit,
    ...(pubW !== undefined
      ? {
          publicWithdrawStroops: parseStroopsU64(
            "--public-withdraw-stroops",
            pubW,
            0n,
          ),
          changeRecipientStealthAddress: changeStealth,
        }
      : {}),
  });

  // Output proof and public hex to stdout (newline-separated)
  console.log(result.proof_hex);
  console.log(result.public_hex);

  // Optionally write to files
  if (parsed["output-proof"]) {
    fs.writeFileSync(parsed["output-proof"], result.proof_hex);
    console.error(`Proof written to: ${parsed["output-proof"]}`);
  }
  if (parsed["output-public"]) {
    fs.writeFileSync(parsed["output-public"], result.public_hex);
    console.error(`Public signals written to: ${parsed["output-public"]}`);
  }
  if (parsed["output-ciphertext"] && result.ciphertext_hex) {
    fs.writeFileSync(parsed["output-ciphertext"], result.ciphertext_hex);
    console.error(`Ciphertext written to: ${parsed["output-ciphertext"]}`);
  }
}

async function handleDepositProof(args: string[]) {
  const parsed = parseArgs(args);

  if (!parsed["state-root"]) {
    console.error("Error: --state-root <dec> is required");
    process.exit(1);
  }
  if (!parsed["stealth"]) {
    console.error("Error: --stealth <stpl1...> is required");
    process.exit(1);
  }
  const token = parsed["token"] ?? process.env.TOKEN_ADDRESS;
  if (!token) {
    console.error("Error: --token <C...> or TOKEN_ADDRESS is required");
    process.exit(1);
  }
  const [assetHi, assetLo] = stellarContractAddressToAssetFrDecimals(token);

  const { zkConfigNonce } = resolveZkInit(parsed);
  const sdk = await PrivacyPoolSDK.init({ zkConfigNonce });
  const applicationId = resolveApplicationIdFromCli(parsed);
  const audit = resolveTransactionAuditParams(
    applicationId,
    undefined,
    sdk.getLayout().nAuditSlots,
  );
  const recipientPublicKeys = recipientPublicKeysDecimalFromStealthAddress(
    parsed["stealth"],
  );

  const coinPath = parsed["coin"];
  const ephemeralScalarHex = parsed["ephemeral-scalar-hex"];
  let deposit: DepositObject;

  if (coinPath || ephemeralScalarHex) {
    if (!coinPath || !ephemeralScalarHex) {
      console.error(
        "Error: aligned deposit proof requires both --coin <file> and --ephemeral-scalar-hex <hex>",
      );
      process.exit(1);
    }
    const coinFile = JSON.parse(fs.readFileSync(coinPath, "utf-8"));
    const c: CoinData = coinFile.coin || coinFile;
    const value = parsed["value"] ?? c.value;
    if (parsed["value"] && parsed["value"] !== c.value) {
      console.error("Error: --value must match coin.value when using --coin");
      process.exit(1);
    }
    const ah = c.asset_hi ?? assetHi;
    const al = c.asset_lo ?? assetLo;
    deposit = {
      value,
      nullifier: c.nullifier,
      ephemeralKeyScalar: scalarHexToFrDecimal(ephemeralScalarHex),
      recipientPublicKeys,
      asset: [ah, al],
      applicationId,
    };
  } else {
    if (!parsed["value"]) {
      console.error(
        "Error: --value <dec> is required (unless using --coin and --ephemeral-scalar-hex)",
      );
      process.exit(1);
    }
    deposit = {
      value: parsed["value"],
      nullifier: randomFrDecimal(),
      ephemeralKeyScalar: randomFrDecimal253(),
      recipientPublicKeys,
      asset: [assetHi, assetLo],
      applicationId,
    };
  }

  const publicLegs: TransactionPublicLegParams = {
    publicWithdrawnAssets: [["0", "0"] as [string, string]],
    publicDepositedAssets: [
      [deposit.asset[0], deposit.asset[1]] as [string, string],
    ],
    publicDeposits: [deposit.value],
    publicWithdrawals: ["0"],
  };

  const result = await sdk.proveTransaction(
    {
      stateRoot: parsed["state-root"],
      withdrawAddressHi: "0",
      withdrawAddressLo: "0",
      privKeyScalar: randomFrDecimal253(),
    },
    publicLegs,
    ["dummy", "dummy"],
    [deposit, "dummy"],
    audit,
  );

  console.log(result.proof_hex);
  console.log(result.public_hex);

  if (parsed["output-proof"]) {
    fs.writeFileSync(parsed["output-proof"], result.proof_hex);
    console.error(`Proof written to: ${parsed["output-proof"]}`);
  }
  if (parsed["output-public"]) {
    fs.writeFileSync(parsed["output-public"], result.public_hex);
    console.error(`Public signals written to: ${parsed["output-public"]}`);
  }
  if (parsed["output-ciphertext"] && result.ciphertext_hex) {
    fs.writeFileSync(parsed["output-ciphertext"], result.ciphertext_hex);
    console.error(`Ciphertext written to: ${parsed["output-ciphertext"]}`);
  }
}

main().catch((err) => {
  console.error("Error:", err.message || err);
  process.exit(1);
});
