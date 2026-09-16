/** @deprecated Groth16 proving is in the main SDK WASM (`proveGroth16`). */
export async function generateProof(
  _wtns: Uint8Array,
  _zkey?: BufferSource,
  _zkeyFileName?: string,
): Promise<{ proof: object; publicSignals: string[] }> {
  throw new Error(
    'generateProof is removed. Call PrivacyPoolSDK.proveTransaction (graph witness + Groth16 in sdk.wasm).',
  );
}
