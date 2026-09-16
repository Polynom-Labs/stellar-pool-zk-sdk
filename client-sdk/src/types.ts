export interface CoinData {
  value: string;
  nullifier: string;
  secret: string;
  commitment: string;
  /** Decimal Fr strings for Stellar asset contract id (`asset[0]`, `asset[1]` in `commitment.circom`). */
  asset_hi: string;
  asset_lo: string;
  /** Decimal Fr application id (per-note KYT slot); optional on legacy coins. */
  application_id?: string;
}

export interface GeneratedCoin {
  coin: CoinData;
  commitment_hex: string;
  /** 64-char lowercase hex (no `0x`), Fr big-endian for audit `precommitement`. */
  precommitement_hex: string;
  /** JS alias of {@link GeneratedCoin.precommitement_hex}. */
  precommitementHex: string;
}

/** Pool Merkle tree depth (matches `coin::TREE_DEPTH` / `Transaction` circuit). */
export const POOL_MERKLE_TREE_DEPTH = 20;

/** Default coin value in stroops (1 XLM); matches Rust `coin::COIN_VALUE`. */
export const COIN_VALUE_STROOPS = 1_000_000_000;

/**
 * Merkle path + coin fields for the first withdraw leg (WASM `buildWithdrawMerkleWitness`).
 * Serde: `withdrawnValue`, `stateRoot`, `stateIndex`, `stateSiblings`.
 */
export interface WithdrawMerkleWitness {
  /** Withdrawn amount in stroops as decimal Fr string; matches `coin.value`. */
  withdrawnValue: string;
  /** Coin value as decimal field string. */
  value: string;
  nullifier: string;
  secret: string;
  /** `[asset_hi, asset_lo]` decimal Fr strings (Stellar asset contract id). */
  withdrawnAsset: [string, string];
  stateRoot: string;
  stateIndex: string;
  /** Length is always {@link POOL_MERKLE_TREE_DEPTH}; each entry is a decimal field element. */
  stateSiblings: string[];
}

export interface StateFile {
  commitments: string[];
}

export interface WithdrawResult {
  proof_hex: string;
  public_hex: string;
  ciphertext_hex: string;
  output_note_ephemeral_scalars: string[];
}

export interface SDKOptions {
  /** Pre-loaded Rust WASM binary (ArrayBuffer). Required in browser. */
  wasmBinary?: BufferSource;
  /** Nonce-keyed circuit map. Defaults to {@link DEFAULT_ZK_CIRCUITS}. */
  zkCircuits?: Record<string, import("./zk-layout").ZkCircuitConfig>;
  /** Selected pool `ZkConfig` nonce. Defaults to {@link DEFAULT_ZK_CONFIG_NONCE}. */
  zkConfigNonce?: bigint;
  /**
   * Directory or URL prefix for graph/r1cs/proving-key files.
   * Defaults to the CDN prefix baked in at publish (`defaultZkArtifactBaseUrl()`,
   * version of the last circuit rebuild). Node also reads `ZK_ARTIFACT_BASE_URL`.
   */
  zkArtifactBaseUrl?: string;
}
