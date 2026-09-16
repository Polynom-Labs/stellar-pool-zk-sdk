import * as wasmBindings from 'privacy-pool-client-sdk/pkg/client_sdk_wasm.js';

const isNode = typeof process !== 'undefined' && !!process.versions?.node;

let wasmModule: any = null;

export async function loadWasm(wasmBinary?: BufferSource): Promise<any> {
  if (wasmModule) return wasmModule;

  if (isNode) {
    if (wasmBinary) {
      wasmBindings.initSync({ module: wasmBinary });
    } else {
      const path = await import('path');
      const { fileURLToPath } = await import('url');
      const fs = await import('fs');
      const dir = path.dirname(fileURLToPath(import.meta.url));
      const wasmPath = path.resolve(dir, '..', 'pkg', 'client_sdk_wasm_bg.wasm');
      const buffer = fs.readFileSync(wasmPath);
      wasmBindings.initSync({ module: buffer });
    }
    wasmModule = wasmBindings;
  } else {
    if (wasmBinary) {
      wasmBindings.initSync({ module: wasmBinary });
    } else {
      await wasmBindings.default();
    }
    wasmModule = wasmBindings;
  }

  return wasmModule;
}
