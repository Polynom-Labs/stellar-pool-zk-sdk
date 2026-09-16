import { loadWasm } from "./wasm";
import { resolveCircuitArtifacts } from "./circuit-artifacts";
import type {
  CoinData,
  GeneratedCoin,
  SDKOptions,
  StateFile,
  WithdrawMerkleWitness,
  WithdrawResult,
} from "./types";
import {
  decodeDecodedEphemeralKey as decodeDecodedEphemeralKeyBech,
  decodeDepositorSharedSecretPreimage as decodeDepositorPreimageBech,
  encodeDecodedEphemeralKey as encodeDecodedEphemeralKeyBech,
  encodeDepositorSharedSecretPreimage as encodeDepositorPreimageBech,
  generateRandomScalarHex32,
  type DecodedDepositorSharedSecretPreimage,
  type DecodedEphemeralKey,
  type EncodedDepositorSharedSecretPreimage,
  type EncodedEphemeralKey,
} from "./ephemeral-key";
import {
  sharedSecretFromDepositorPreimage as sharedSecretFromDepositorPreimageFn,
  sharedSecretFromRecipientPreimage as sharedSecretFromRecipientPreimageFn,
  type SharedSecret,
} from "./shared-secret";
import { encodeStealthAddress } from "./stealth-address";
import {
  buildStealthAddressSignMessage as formatStealthAddressSignMessage,
  DEFAULT_STEALTH_SIGN_NONCE,
  type SpendScalarDomain,
} from "./stealth-sign-message";
import { stealthAddressFromStellarSignature } from "./stealth-signature";
import type { DecodedRecipientSharedSecretPreimage } from "./stealth-address";
import {
  buildTransactionWitnessInput,
  randomFrDecimal,
  randomFrDecimal253,
  recipientPublicKeysDecimalFromStealthAddress,
  withdrawObjectFromMerkleWitness,
  type DepositObject,
  type DepositSlot,
  type TransactionPublicLegParams,
  type WasmEcdhPointFns,
  type WithdrawalProofPublicParams,
  type WithdrawSlot,
} from "./withdrawal-transaction-input";
import {
  DEFAULT_APPLICATION_ID,
  DEMO_AUDIT_PUBLIC_KEY,
  resolveTransactionAuditParams,
  type TransactionAuditParams,
} from "./transaction-audit";
import {
  layoutFromCircuitConfig,
  resolveZkCircuitConfig,
  type ZkCircuitConfig,
  type ZkLayoutParams,
} from "./zk-layout";
import { encryptTransactionCiphertextBlob } from "./output-note-encryption";

/** Stroops amount as a decimal field string. Reject JS `number` so 18-decimal values cannot silently narrow. */
function coinValueDecimal(amount: unknown): string {
  if (typeof amount === "number") {
    throw new TypeError(
      "coin value must be bigint or decimal string, not number",
    );
  }
  if (typeof amount === "bigint") {
    if (amount < 0n) {
      throw new RangeError("amount must be a non-negative integer");
    }
    return amount.toString(10);
  }
  if (typeof amount !== "string") {
    throw new TypeError(
      "coin value must be bigint or decimal string, not number",
    );
  }
  const trimmed = amount.trim();
  if (!/^[0-9]+$/.test(trimmed)) {
    throw new TypeError(
      "coin value decimal string must be a non-negative integer",
    );
  }
  return trimmed;
}

function generatedCoinFromWasm(value: unknown): GeneratedCoin {
  const raw = value as {
    coin: CoinData;
    commitment_hex: string;
    precommitement_hex?: string;
    precommitementHex?: string;
  };
  const precommitementHex = raw.precommitementHex ?? raw.precommitement_hex;
  if (!precommitementHex) {
    throw new Error("generated coin missing precommitement hex");
  }
  return {
    coin: raw.coin,
    commitment_hex: raw.commitment_hex,
    precommitement_hex: precommitementHex,
    precommitementHex,
  };
}

export class PrivacyPoolSDK {
  private wasm: any;
  private options: SDKOptions;
  private zkConfigNonce: bigint;
  private circuitConfig: ZkCircuitConfig;
  private layout: ZkLayoutParams;
  private circuitArtifacts:
    | Awaited<ReturnType<typeof resolveCircuitArtifacts>>
    | undefined;

  private constructor(
    wasm: any,
    options: SDKOptions,
    resolved: ReturnType<typeof resolveZkCircuitConfig>,
  ) {
    this.wasm = wasm;
    this.options = options;
    this.zkConfigNonce = resolved.nonce;
    this.circuitConfig = resolved.config;
    this.layout = layoutFromCircuitConfig(resolved.config);
  }

  getZkConfigNonce(): bigint {
    return this.zkConfigNonce;
  }

  getLayout(): ZkLayoutParams {
    return this.layout;
  }

  /**
   * Initialize the SDK by loading WASM modules.
   *
   * In Node.js, proving artifacts load from `zkArtifactBaseUrl` or
   * `ZK_ARTIFACT_BASE_URL`, defaulting to this package's CDN
   * (`defaultZkArtifactBaseUrl()`). In browser, pass pre-loaded WASM via options:
   * ```ts
   * const sdk = await PrivacyPoolSDK.init({
   *   wasmBinary: await fetch('/pkg/client_sdk_wasm_bg.wasm').then(r => r.arrayBuffer()),
   *   zkArtifactBaseUrl: 'https://cdn.example.com/stellar/0.10.0',
   * });
   * ```
   */
  static async init(options?: SDKOptions): Promise<PrivacyPoolSDK> {
    const opts = options ?? {};
    const wasm = await loadWasm(opts.wasmBinary);
    const resolved = resolveZkCircuitConfig(
      opts.zkCircuits,
      opts.zkConfigNonce,
    );
    const sdk = new PrivacyPoolSDK(wasm, opts, resolved);
    sdk.circuitArtifacts = await resolveCircuitArtifacts(
      resolved.config,
      opts.zkArtifactBaseUrl,
    );
    return sdk;
  }

  /**
   * Uniform 32-byte scalar as lowercase hex (Web Crypto). Same in browser and Node 19+.
   */
  static generateRandomScalarHex32(): string {
    return generateRandomScalarHex32();
  }

  /**
   * Text to sign with a Stellar wallet for spend-key derivation (UTF-8). No WASM required.
   * The message binds network, pool, registry, and schema version (H6).
   */
  static buildStealthAddressSignMessage(
    address: string,
    domain: SpendScalarDomain,
    nonce: string = DEFAULT_STEALTH_SIGN_NONCE,
  ): string {
    return formatStealthAddressSignMessage(address, domain, nonce);
  }

  /**
   * Generate a new coin with random nullifier, secret, and random owner-pub field elements (dev / self-contained tests).
   * @param amount Decimal field element as `bigint` or decimal `string` (never JS `number`).
   * @param assetHiDecimal / assetLoDecimal Decimal Fr strings for Stellar asset contract id (two limbs).
   */
  generateCoin(
    amount: bigint | string,
    assetHiDecimal: string,
    assetLoDecimal: string,
    applicationIdDecimal: string = "0",
  ): GeneratedCoin {
    return generatedCoinFromWasm(
      this.wasm.generateCoin(
        coinValueDecimal(amount),
        assetHiDecimal,
        assetLoDecimal,
        applicationIdDecimal,
      ),
    );
  }

  /**
   * Generate a coin with the same commitment shape as on-chain deposit: pass owner public key (hex x, y).
   * @param amount Decimal field element (`bigint` | `string`).
   */
  generateCoinWithOwnerPub(
    ownerPub: { x: string; y: string },
    amount: bigint | string,
    assetHiDecimal: string,
    assetLoDecimal: string,
    applicationIdDecimal: string = "0",
  ): GeneratedCoin {
    return generatedCoinFromWasm(
      this.wasm.generateCoinWithOwnerPubHex(
        ownerPub.x,
        ownerPub.y,
        coinValueDecimal(amount),
        assetHiDecimal,
        assetLoDecimal,
        applicationIdDecimal,
      ),
    );
  }

  /**
   * Coin for a depositor `ephemeralKeyScalar` (32-byte hex): `coin.secret = Poseidon255(1)(scalar)` as in `deposit.circom`.
   * @param amount Decimal field element (`bigint` | `string`).
   */
  generateCoinFromDepositEphemeralScalarHex(
    scalarHex: string,
    amount: bigint | string,
    assetHiDecimal: string,
    assetLoDecimal: string,
    applicationIdDecimal: string = "0",
  ): GeneratedCoin {
    return generatedCoinFromWasm(
      this.wasm.generateCoinFromDepositEphemeralScalarHex(
        scalarHex,
        coinValueDecimal(amount),
        assetHiDecimal,
        assetLoDecimal,
        applicationIdDecimal,
      ),
    );
  }

  /**
   * Aligned deposit coin: `secret = Poseidon₁(scalar)` and owner pub from recipient hex coords.
   * @param amount Decimal field element (`bigint` | `string`).
   */
  generateCoinForDepositWithOwnerPubHex(
    scalarHex: string,
    ownerXHex: string,
    ownerYHex: string,
    amount: bigint | string,
    assetHiDecimal: string,
    assetLoDecimal: string,
    applicationIdDecimal: string = "0",
  ): GeneratedCoin {
    return generatedCoinFromWasm(
      this.wasm.generateCoinForDepositWithOwnerPubHex(
        scalarHex,
        ownerXHex,
        ownerYHex,
        coinValueDecimal(amount),
        assetHiDecimal,
        assetLoDecimal,
        applicationIdDecimal,
      ),
    );
  }

  /**
   * Merkle root, path, and coin fields for the first withdraw leg (Rust LeanIMT + Poseidon).
   */
  buildWithdrawMerkleWitness(
    coin: CoinData,
    state: StateFile,
  ): WithdrawMerkleWitness {
    const coinJson = JSON.stringify(coin);
    const stateJson = JSON.stringify(state);
    const resultJson = this.wasm.buildWithdrawMerkleWitness(
      coinJson,
      stateJson,
    );
    return JSON.parse(resultJson);
  }

  /**
   * Full `Transaction(20,2,2)` withdrawal proof: one real withdraw + dummies, using coin/state and depositor ECDH point (hex).
   *
   * Optional **partial public withdraw**: spend the full coin commitment `coin.value` (V), send `publicWithdrawStroops` (W) to the
   * Stellar receiver, and re-deposit the remainder (V−W) as a new private note to `changeRecipientStealthAddress` (same circuit balance).
   */
  async proveWithdrawal(
    coin: CoinData,
    state: StateFile,
    params: {
      withdrawAddressHi: string;
      withdrawAddressLo: string;
      privKeyScalar: string;
      ephemeralXHex: string;
      ephemeralYHex: string;
      /** If set, public leg amount W (stroops). Must satisfy 0 < W < V. Remainder (V−W) stays in the pool as a new commitment. */
      publicWithdrawStroops?: bigint;
      /** Required when `publicWithdrawStroops` is set: stealth recipient for the change note (typically same as deposit). */
      changeRecipientStealthAddress?: string;
      applicationId?: string;
      audit?: TransactionAuditParams;
    },
  ): Promise<WithdrawResult> {
    const witness = this.buildWithdrawMerkleWitness(coin, state);
    const ownerPubHex = this.ecdhEphemeralPublicKeyFromScalarHex(
      BigInt(params.privKeyScalar).toString(16).padStart(64, "0"),
    );
    const w0 = withdrawObjectFromMerkleWitness(
      witness,
      ownerPubHex,
      params.applicationId ?? coin.application_id ?? "0",
      params.privKeyScalar,
    );
    const fullV = BigInt(coin.value);
    let publicWithdrawals: string[];
    let deposits: DepositSlot[];

    if (params.publicWithdrawStroops !== undefined) {
      const W = params.publicWithdrawStroops;
      if (params.changeRecipientStealthAddress === undefined) {
        throw new Error(
          "proveWithdrawal: changeRecipientStealthAddress is required when publicWithdrawStroops is set",
        );
      }
      if (W <= 0n || W >= fullV) {
        throw new Error(
          "proveWithdrawal: publicWithdrawStroops must be strictly between 0 and coin.value",
        );
      }
      const change = fullV - W;
      publicWithdrawals = [W.toString()];
      const changeDeposit: DepositObject = {
        value: change.toString(),
        nullifier: randomFrDecimal(),
        ephemeralKeyScalar: randomFrDecimal253(),
        asset: [coin.asset_hi, coin.asset_lo],
        applicationId: params.applicationId ?? "0",
        recipientPublicKeys: recipientPublicKeysDecimalFromStealthAddress(
          params.changeRecipientStealthAddress,
        ),
      };
      deposits = [changeDeposit];
    } else {
      publicWithdrawals = [coin.value];
      deposits = [];
    }

    // On-chain `transact` sends `publicWithdrawals` / `publicWithdrawnAssets` to the withdraw account.
    const publicLegs: TransactionPublicLegParams = {
      publicWithdrawnAssets: [[coin.asset_hi, coin.asset_lo]],
      publicDepositedAssets: [["0", "0"]],
      publicDeposits: ["0"],
      publicWithdrawals,
    };
    return this.proveTransactionSlots(
      {
        stateRoot: witness.stateRoot,
        withdrawAddressHi: params.withdrawAddressHi,
        withdrawAddressLo: params.withdrawAddressLo,
        privKeyScalar: params.privKeyScalar,
      },
      publicLegs,
      [w0],
      deposits,
      params.audit ??
        resolveTransactionAuditParams(
          params.applicationId ?? coin.application_id ?? DEFAULT_APPLICATION_ID,
          DEMO_AUDIT_PUBLIC_KEY,
          this.layout.nAuditSlots,
        ),
    );
  }

  /**
   * Convert a snarkjs proof JSON to hex bytes for Soroban.
   */
  proofToHex(proof: object): string {
    return this.wasm.proofToHex(JSON.stringify(proof));
  }

  /**
   * Convert snarkjs public signals to hex bytes for Soroban.
   */
  publicToHex(publicSignals: string[]): string {
    return this.wasm.publicToHex(JSON.stringify(publicSignals));
  }

  /**
   * BabyJubJub ephemeral point from a 32-byte scalar (hex). For custom {@link WithdrawObject} / tests.
   */
  ecdhEphemeralPublicKeyFromScalarHex(scalarHex: string): {
    x: string;
    y: string;
  } {
    return this.wasm.ecdhEphemeralPublicKeyFromScalarHex(scalarHex);
  }

  /** Circuit `ECDH`: scalar (32-byte hex) × recipient BabyJub point → shared key hex coords. */
  ecdhSharedKey(
    scalarHex: string,
    recipientPubXHex: string,
    recipientPubYHex: string,
  ): SharedSecret {
    return this.wasm.ecdhSharedKey(
      scalarHex,
      recipientPubXHex,
      recipientPubYHex,
    );
  }

  /**
   * `Transaction(20,nIns,nOuts)` proof from high-level legs: maps to witness input (incl. `"dummy"` ECDH via WASM), then Groth16 → Soroban hex.
   * Slots are padded to the selected ZK config layout (bundled 2×2 or 6×6).
   */
  async proveTransaction(
    publicParams: WithdrawalProofPublicParams,
    publicLegs: TransactionPublicLegParams,
    withdraws: WithdrawSlot[],
    deposits: DepositSlot[],
    audit: TransactionAuditParams,
  ): Promise<WithdrawResult> {
    return this.proveTransactionSlots(
      publicParams,
      publicLegs,
      withdraws,
      deposits,
      audit,
    );
  }

  async proveTransactionSlots(
    publicParams: WithdrawalProofPublicParams,
    publicLegs: TransactionPublicLegParams,
    withdraws: WithdrawSlot[],
    deposits: DepositSlot[],
    audit: TransactionAuditParams,
  ): Promise<WithdrawResult> {
    const wasmEcdh: WasmEcdhPointFns = {
      ecdhEphemeralPublicKeyFromScalarHex: (h) =>
        this.wasm.ecdhEphemeralPublicKeyFromScalarHex(h),
    };
    const { nIns, nOuts, publicNInputs, publicNOutputs } =
      this.layout;
    const witnessInput = buildTransactionWitnessInput(
      publicParams,
      publicLegs,
      withdraws,
      deposits,
      audit,
      wasmEcdh,
      { nIns, nOuts, publicNInputs, publicNOutputs },
    );
    const artifacts = this.circuitArtifacts;
    if (!artifacts) {
      throw new Error("PrivacyPoolSDK circuit artifacts are not loaded");
    }
    const proved = this.wasm.proveGroth16(
      artifacts.graph,
      artifacts.provingKey,
      artifacts.r1cs,
      JSON.stringify(witnessInput),
    ) as { proof_hex: string; public_hex: string };
    const encrypted = await encryptTransactionCiphertextBlob({
      witness: witnessInput,
      layout: this.layout,
      ecdhShared: (priv, pubX, pubY) => this.wasm.ecdhSharedKey(priv, pubX, pubY),
    });
    return {
      proof_hex: proved.proof_hex,
      public_hex: proved.public_hex,
      ciphertext_hex: encrypted.ciphertextHex,
      output_note_ephemeral_scalars: witnessInput.depositedEphemeralKeyScalars,
    };
  }

  /**
   * Calculate owner-bound nullifier hash: Poseidon(DOM_NULLIFIER, nullifier, privKeyScalar)
   * @param nullifier Nullifier decimal string from coin data
   * @param privKeyScalar Spend scalar decimal string
   * @returns Hex string (0x...) of the hash bytes
   */
  calculateNullifierHash(nullifier: string, privKeyScalar: string): string {
    return this.wasm.calculateNullifierHash(nullifier, privKeyScalar);
  }

  /**
   * Ed25519 signature from signing {@link buildStealthAddressSignMessage}: **128 hex chars** (optional `0x`)
   * or **base64** (64 raw bytes after decode). Domain-separated SHA-256 → scalar → ECDH → `stpl1` Bech32.
   */
  async generateStealthAddressFromStellarSignature(
    signature: string,
    domain: SpendScalarDomain,
  ): Promise<string> {
    return stealthAddressFromStellarSignature(
      (h) => this.wasm.ecdhEphemeralPublicKeyFromScalarHex(h),
      encodeStealthAddress,
      signature,
      domain,
    );
  }

  encodeDecodedEphemeralKey(decoded: DecodedEphemeralKey): EncodedEphemeralKey {
    return encodeDecodedEphemeralKeyBech(decoded);
  }

  decodeDecodedEphemeralKey(encoded: EncodedEphemeralKey): DecodedEphemeralKey {
    return decodeDecodedEphemeralKeyBech(encoded);
  }

  encodeDepositorSharedSecretPreimage(
    decoded: DecodedDepositorSharedSecretPreimage,
  ): EncodedDepositorSharedSecretPreimage {
    return encodeDepositorPreimageBech(decoded);
  }

  decodeDepositorSharedSecretPreimage(
    encoded: EncodedDepositorSharedSecretPreimage,
  ): DecodedDepositorSharedSecretPreimage {
    return decodeDepositorPreimageBech(encoded);
  }

  sharedSecretFromDepositorPreimage(
    preimage: DecodedDepositorSharedSecretPreimage,
  ): SharedSecret {
    return sharedSecretFromDepositorPreimageFn(
      (a, b, c) => this.wasm.ecdhSharedKey(a, b, c),
      preimage,
    );
  }

  sharedSecretFromRecipientPreimage(
    preimage: DecodedRecipientSharedSecretPreimage,
  ): SharedSecret {
    return sharedSecretFromRecipientPreimageFn(
      (a, b, c) => this.wasm.ecdhSharedKey(a, b, c),
      preimage,
    );
  }
}
