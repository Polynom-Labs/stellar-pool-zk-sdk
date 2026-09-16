import type { TransactionWitnessInput } from './withdrawal-transaction-input';

/** @deprecated Witness generation is in the main SDK WASM (`proveGroth16`). */
export async function generateWitness(
  _input: TransactionWitnessInput,
  _circuitWasm?: BufferSource,
  _wasmFileName?: string,
): Promise<Uint8Array> {
  throw new Error(
    'generateWitness is removed. Call PrivacyPoolSDK.proveTransaction (graph witness + Groth16 in sdk.wasm).',
  );
}
