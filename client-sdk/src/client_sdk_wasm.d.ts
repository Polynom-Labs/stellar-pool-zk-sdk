/** Type declaration for package subpath pkg/client_sdk_wasm.js */
declare module 'privacy-pool-client-sdk/pkg/client_sdk_wasm.js' {
  /** `amount_decimal`: arbitrary-precision decimal field element (never JS `number`). */
  export function generateCoin(
    amount_decimal: string,
    asset_hi_decimal: string,
    asset_lo_decimal: string,
    application_id_decimal: string,
  ): unknown;
  export function generateCoinWithOwnerPubHex(
    owner_x_hex: string,
    owner_y_hex: string,
    amount_decimal: string,
    asset_hi_decimal: string,
    asset_lo_decimal: string,
    application_id_decimal: string,
  ): unknown;
  export function generateCoinFromDepositEphemeralScalarHex(
    scalar_hex: string,
    amount_decimal: string,
    asset_hi_decimal: string,
    asset_lo_decimal: string,
    application_id_decimal: string,
  ): unknown;
  export function generateCoinForDepositWithOwnerPubHex(
    scalar_hex: string,
    owner_x_hex: string,
    owner_y_hex: string,
    amount_decimal: string,
    asset_hi_decimal: string,
    asset_lo_decimal: string,
    application_id_decimal: string,
  ): unknown;
  export function buildWithdrawMerkleWitness(coin_json: string, state_json: string): string;
  export function proofToHex(proof_json: string): string;
  export function proveGroth16(
    graph: Uint8Array,
    proving_key: Uint8Array,
    r1cs: Uint8Array,
    inputs_json: string,
  ): { proof_hex: string; public_hex: string };
  export function calculateNullifierHash(
    nullifier_decimal: string,
    priv_key_scalar_decimal: string,
  ): string;
  export function derivedEscrowKey(
    nonce_decimal: string,
    recipient_hi_decimal: string,
    recipient_lo_decimal: string,
  ): unknown;
  export function ecdhEphemeralPublicKey(seed: string): { x: string; y: string };
  export function ecdhEphemeralPublicKeyFromScalarHex(scalar_hex: string): { x: string; y: string };
  export function ecdhSharedKey(
    priv_hex: string,
    pub_x_hex: string,
    pub_y_hex: string,
  ): { x: string; y: string };
  export type SyncInitInput = BufferSource | WebAssembly.Module;
  export function initSync(imports: { module: SyncInitInput }): unknown;
  export default function __wbg_init(module_or_path?: unknown): Promise<unknown>;
}
