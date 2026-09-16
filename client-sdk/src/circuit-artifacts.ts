import {
  BundledZkCircuit,
  bundledCircuitFileNames,
  bundledCircuitStem,
  isDevZkCircuitConfig,
  type ZkCircuitConfig,
} from './zk-layout';
import { fetchArtifact } from './fetch-artifact';
import {
  defaultZkArtifactBaseUrl,
  trimArtifactBaseUrl,
  zkArtifactFileUrl,
} from './zk-artifact-url';

const isNode = typeof process !== 'undefined' && !!process.versions?.node;

export interface ResolvedCircuitArtifacts {
  graph: Uint8Array;
  r1cs: Uint8Array;
  provingKey: Uint8Array;
}

function toUint8Array(src: BufferSource): Uint8Array {
  if (src instanceof Uint8Array) {
    return src;
  }
  if (src instanceof ArrayBuffer) {
    return new Uint8Array(src);
  }
  return new Uint8Array(src.buffer, src.byteOffset, src.byteLength);
}

function nodeEnvArtifactBaseUrl(): string | undefined {
  if (!isNode) {
    return undefined;
  }
  const fromEnv = process.env.ZK_ARTIFACT_BASE_URL?.trim();
  return fromEnv ? trimArtifactBaseUrl(fromEnv) : undefined;
}

export function resolveZkArtifactBaseUrl(explicit?: string): string {
  const trimmed = explicit?.trim();
  if (trimmed) {
    return trimArtifactBaseUrl(trimmed);
  }
  return nodeEnvArtifactBaseUrl() ?? defaultZkArtifactBaseUrl();
}

function isHttpUrl(value: string): boolean {
  return /^https?:\/\//i.test(value) || value.startsWith('file:');
}

async function readNodeAssetFile(filePath: string): Promise<Uint8Array> {
  const fs = await import('fs');
  if (!fs.existsSync(filePath)) {
    throw new Error(
      `Circuit artifact not found at ${filePath}. Set zkArtifactBaseUrl or ZK_ARTIFACT_BASE_URL.`,
    );
  }
  return fs.readFileSync(filePath);
}

function remoteArtifactHref(base: string, fileName: string): string {
  const withSlash = `${trimArtifactBaseUrl(base)}/`;
  if (isHttpUrl(withSlash)) {
    return new URL(fileName, withSlash).href;
  }
  if (typeof window !== 'undefined') {
    return new URL(fileName, new URL(withSlash, window.location.href)).href;
  }
  return `${withSlash}${fileName}`;
}

async function loadNamedArtifact(
  base: string,
  fileName: string,
): Promise<Uint8Array> {
  if (isNode && !isHttpUrl(base)) {
    const nodePath = await import('path');
    return readNodeAssetFile(nodePath.resolve(base, fileName));
  }
  return fetchArtifact(remoteArtifactHref(base, fileName));
}

export async function loadBundledCircuitArtifacts(
  circuit: BundledZkCircuit,
  artifactBaseUrl?: string,
): Promise<ResolvedCircuitArtifacts> {
  const names = bundledCircuitFileNames(circuit);
  const override = artifactBaseUrl?.trim() || nodeEnvArtifactBaseUrl();
  if (override) {
    const base = trimArtifactBaseUrl(override);
    const [graph, r1cs, provingKey] = await Promise.all([
      loadNamedArtifact(base, names.graphFileName),
      loadNamedArtifact(base, names.r1csFileName),
      loadNamedArtifact(base, names.provingKeyFileName),
    ]);
    return { graph, r1cs, provingKey };
  }
  const stem = bundledCircuitStem(circuit);
  const [graph, r1cs, provingKey] = await Promise.all([
    fetchArtifact(zkArtifactFileUrl(names.graphFileName, stem)),
    fetchArtifact(zkArtifactFileUrl(names.r1csFileName, stem)),
    fetchArtifact(zkArtifactFileUrl(names.provingKeyFileName, stem)),
  ]);
  return { graph, r1cs, provingKey };
}

export async function resolveCircuitArtifacts(
  config: ZkCircuitConfig,
  artifactBaseUrl?: string,
): Promise<ResolvedCircuitArtifacts> {
  if (isDevZkCircuitConfig(config)) {
    return {
      graph: toUint8Array(config.circuitGraph),
      r1cs: toUint8Array(config.r1cs),
      provingKey: toUint8Array(config.provingKey),
    };
  }
  return loadBundledCircuitArtifacts(config.circuit, artifactBaseUrl);
}
