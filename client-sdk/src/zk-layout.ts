/** Off-chain ZK layout table. Must stay byte-identical to `libs/zk::ZkLayoutParams`. */

export const LEGACY_ZK_NONCE = 0n;
export const COMMITMENT_V2_ZK_NONCE = 2n;
export const BINDING_ZK_NONCE = 3n;
export const SIX_BY_SIX_ZK_NONCE = 6n;
export const SIX_BY_SIX_BINDING_ZK_NONCE = 7n;
export const TEN_BY_ONE_ZK_NONCE = 10n;

export const LEGACY_PUBLIC_INPUT_PREFIX_LEN = 5;
export const V2_PUBLIC_INPUT_PREFIX_LEN = 7;
export const NOTE_AUDIT_LEN = 12;
export const NOTE_OUTPUT_LEN = 6;

export type CircuitProfileName = '2x2' | '6x6' | '10x1';

export enum BundledZkCircuit {
  TwoByTwo = '2x2',
  SixBySix = '6x6',
  TenByOne = '10x1',
  TwoByTwoDelegated = '2x2_delegated',
  SixBySixDelegated = '6x6_delegated',
  TenByOneDelegated = '10x1_delegated',
}

export interface ZkCircuitLayoutFields {
  nIns: number;
  nOuts: number;
  publicNInputs: number;
  publicNOutputs: number;
}

export type BundledZkCircuitConfig = ZkCircuitLayoutFields & {
  circuit: BundledZkCircuit;
};

export type DevZkCircuitConfig = ZkCircuitLayoutFields & {
  circuitGraph: BufferSource;
  r1cs: BufferSource;
  provingKey: BufferSource;
  zkey?: BufferSource;
};

export type ZkCircuitConfig = BundledZkCircuitConfig | DevZkCircuitConfig;

export function isDevZkCircuitConfig(
  config: ZkCircuitConfig,
): config is DevZkCircuitConfig {
  return !('circuit' in config);
}

export const DEFAULT_ZK_CONFIG_NONCE = BINDING_ZK_NONCE;

export const DEFAULT_ZK_CIRCUITS: Record<string, BundledZkCircuitConfig> = {
  [BINDING_ZK_NONCE.toString()]: {
    nIns: 2,
    nOuts: 2,
    publicNInputs: 1,
    publicNOutputs: 1,
    circuit: BundledZkCircuit.TwoByTwo,
  },
  [SIX_BY_SIX_BINDING_ZK_NONCE.toString()]: {
    nIns: 6,
    nOuts: 6,
    publicNInputs: 1,
    publicNOutputs: 1,
    circuit: BundledZkCircuit.SixBySix,
  },
  [TEN_BY_ONE_ZK_NONCE.toString()]: {
    nIns: 10,
    nOuts: 1,
    publicNInputs: 0,
    publicNOutputs: 1,
    circuit: BundledZkCircuit.TenByOne,
  },
};

export function layoutFromCircuitConfig(config: ZkCircuitConfig): ZkLayoutParams {
  return zkLayoutFromShapeBinding(
    config.nIns,
    config.nOuts,
    config.publicNInputs,
    config.publicNOutputs,
    config.nIns + config.nOuts,
    NOTE_AUDIT_LEN,
    NOTE_OUTPUT_LEN,
  );
}

export function resolveZkCircuitConfig(
  zkCircuits: Record<string, ZkCircuitConfig> | undefined,
  zkConfigNonce: bigint | undefined,
): { nonce: bigint; config: ZkCircuitConfig } {
  const nonce = zkConfigNonce ?? DEFAULT_ZK_CONFIG_NONCE;
  const circuits = zkCircuits ?? DEFAULT_ZK_CIRCUITS;
  const config = circuits[nonce.toString()];
  if (!config) {
    throw new Error(`no zk circuit configured for nonce ${nonce.toString()}`);
  }
  return { nonce, config };
}

export function bundledCircuitStem(circuit: BundledZkCircuit): string {
  switch (circuit) {
    case BundledZkCircuit.SixBySix:
      return 'main_6x6';
    case BundledZkCircuit.TenByOne:
      return 'main_10x1';
    case BundledZkCircuit.TwoByTwoDelegated:
      return 'main_delegated';
    case BundledZkCircuit.SixBySixDelegated:
      return 'main_6x6_delegated';
    case BundledZkCircuit.TenByOneDelegated:
      return 'main_10x1_delegated';
    default:
      return 'main';
  }
}

export function bundledCircuitFileNames(circuit: BundledZkCircuit): {
  graphFileName: string;
  r1csFileName: string;
  provingKeyFileName: string;
  verificationKeyFileName: string;
  zkeyFileName: string;
} {
  const stem = bundledCircuitStem(circuit);
  return {
    graphFileName: `${stem}.graph.bin`,
    r1csFileName: `${stem}.r1cs.gz`,
    provingKeyFileName: `${stem}_proving_key.bin`,
    verificationKeyFileName: `${stem}_verification_key.json`,
    zkeyFileName: `${stem}_final.zkey`,
  };
}

export interface ZkLayoutParams {
  nIns: number;
  nOuts: number;
  publicNInputs: number;
  publicNOutputs: number;
  nAuditSlots: number;
  noteAuditLen: number;
  noteOutputLen: number;
  publicInputPrefixLen: number;
  auditOffset: number;
  outputNoteOffset: number;
}

export interface CircuitProfile {
  name: CircuitProfileName;
  nonce: bigint;
  layout: ZkLayoutParams;
  wasmFileName: string;
  zkeyFileName: string;
}

export function zkLayoutFromShape(
  nIns: number,
  nOuts: number,
  publicNInputs: number,
  publicNOutputs: number,
  nAuditSlots: number,
  noteAuditLen: number,
  noteOutputLen: number,
  publicInputPrefixLen: number = LEGACY_PUBLIC_INPUT_PREFIX_LEN,
): ZkLayoutParams {
  const auditOffset = nIns + nOuts + nOuts * 2;
  const outputNoteOffset =
    auditOffset + nAuditSlots * 2 + nAuditSlots * noteAuditLen + nAuditSlots;
  return {
    nIns,
    nOuts,
    publicNInputs,
    publicNOutputs,
    nAuditSlots,
    noteAuditLen,
    noteOutputLen,
    publicInputPrefixLen,
    auditOffset,
    outputNoteOffset,
  };
}

export function zkLayoutFromShapeBinding(
  nIns: number,
  nOuts: number,
  publicNInputs: number,
  publicNOutputs: number,
  nAuditSlots: number,
  noteAuditLen: number,
  noteOutputLen: number,
): ZkLayoutParams {
  const auditOffset = nIns + nOuts + nOuts * 2;
  const outputNoteOffset = auditOffset + 2 + nAuditSlots;
  return {
    nIns,
    nOuts,
    publicNInputs,
    publicNOutputs,
    nAuditSlots,
    noteAuditLen,
    noteOutputLen,
    publicInputPrefixLen: V2_PUBLIC_INPUT_PREFIX_LEN,
    auditOffset,
    outputNoteOffset,
  };
}

export function ciphertextsInPublicSignals(layout: ZkLayoutParams): boolean {
  const withCiphertext =
    layout.auditOffset +
    layout.nAuditSlots * 2 +
    layout.nAuditSlots * layout.noteAuditLen +
    layout.nAuditSlots;
  return layout.outputNoteOffset === withCiphertext;
}

export function ciphertextFieldCount(layout: ZkLayoutParams): number {
  return layout.nAuditSlots * layout.noteAuditLen + layout.nOuts * layout.noteOutputLen;
}

export function auditEphemeralPublicKeyCount(layout: ZkLayoutParams): number {
  return ciphertextsInPublicSignals(layout) ? layout.nAuditSlots : 1;
}

export function indexAuditEphemeralPublicKeys(layout: ZkLayoutParams): number {
  return layout.auditOffset;
}

export function indexAuditTags(layout: ZkLayoutParams): number {
  if (ciphertextsInPublicSignals(layout)) {
    return (
      layout.auditOffset +
      layout.nAuditSlots * 2 +
      layout.nAuditSlots * layout.noteAuditLen
    );
  }
  return layout.auditOffset + auditEphemeralPublicKeyCount(layout) * 2;
}

export function indexOutputNoteTags(layout: ZkLayoutParams): number {
  if (ciphertextsInPublicSignals(layout)) {
    return layout.outputNoteOffset + layout.nOuts * layout.noteOutputLen;
  }
  return layout.outputNoteOffset;
}

export function publicOutputsLen(layout: ZkLayoutParams): number {
  if (ciphertextsInPublicSignals(layout)) {
    return layout.outputNoteOffset + layout.nOuts * layout.noteOutputLen + layout.nOuts;
  }
  return layout.outputNoteOffset + layout.nOuts;
}

export function totalPublicSignals(layout: ZkLayoutParams): number {
  return (
    publicOutputsLen(layout) +
    layout.publicInputPrefixLen +
    2 * layout.publicNInputs +
    2 * layout.publicNOutputs +
    layout.publicNInputs +
    layout.publicNOutputs
  );
}

export function stateRootIndex(layout: ZkLayoutParams): number {
  return publicOutputsLen(layout);
}

export function legacyOwnerBoundLayout(): ZkLayoutParams {
  return zkLayoutFromShape(2, 2, 1, 1, 4, NOTE_AUDIT_LEN, NOTE_OUTPUT_LEN);
}

export function standardLayout(): ZkLayoutParams {
  return zkLayoutFromShape(
    2,
    2,
    1,
    1,
    4,
    NOTE_AUDIT_LEN,
    NOTE_OUTPUT_LEN,
    V2_PUBLIC_INPUT_PREFIX_LEN,
  );
}

export function sixBySixLayout(): ZkLayoutParams {
  return zkLayoutFromShape(
    6,
    6,
    1,
    1,
    12,
    NOTE_AUDIT_LEN,
    NOTE_OUTPUT_LEN,
    V2_PUBLIC_INPUT_PREFIX_LEN,
  );
}

export function standardBindingLayout(): ZkLayoutParams {
  return zkLayoutFromShapeBinding(2, 2, 1, 1, 4, NOTE_AUDIT_LEN, NOTE_OUTPUT_LEN);
}

export function sixBySixBindingLayout(): ZkLayoutParams {
  return zkLayoutFromShapeBinding(6, 6, 1, 1, 12, NOTE_AUDIT_LEN, NOTE_OUTPUT_LEN);
}

export function tenByOneBindingLayout(): ZkLayoutParams {
  return zkLayoutFromShapeBinding(10, 1, 0, 1, 11, NOTE_AUDIT_LEN, NOTE_OUTPUT_LEN);
}

export function layoutForKnownNonce(nonce: bigint): ZkLayoutParams {
  if (nonce === LEGACY_ZK_NONCE) {
    return legacyOwnerBoundLayout();
  }
  if (nonce === COMMITMENT_V2_ZK_NONCE) {
    return standardLayout();
  }
  if (nonce === BINDING_ZK_NONCE) {
    return standardBindingLayout();
  }
  if (nonce === SIX_BY_SIX_ZK_NONCE) {
    return sixBySixLayout();
  }
  if (nonce === SIX_BY_SIX_BINDING_ZK_NONCE) {
    return sixBySixBindingLayout();
  }
  if (nonce === TEN_BY_ONE_ZK_NONCE) {
    return tenByOneBindingLayout();
  }
  throw new Error(`unknown zk config nonce ${nonce.toString()}`);
}

export function circuitProfileFromName(name: string): CircuitProfile {
  const normalized = name.trim().toLowerCase();
  if (normalized === '6x6' || normalized === 'six' || normalized === '6') {
    return {
      name: '6x6',
      nonce: SIX_BY_SIX_BINDING_ZK_NONCE,
      layout: sixBySixBindingLayout(),
      wasmFileName: 'main_6x6.wasm',
      zkeyFileName: 'main_6x6_final.zkey',
    };
  }
  if (normalized === '10x1' || normalized === '10') {
    return {
      name: '10x1',
      nonce: TEN_BY_ONE_ZK_NONCE,
      layout: tenByOneBindingLayout(),
      wasmFileName: 'main_10x1.wasm',
      zkeyFileName: 'main_10x1_final.zkey',
    };
  }
  if (normalized === '2x2' || normalized === 'standard' || normalized === '2') {
    return {
      name: '2x2',
      nonce: BINDING_ZK_NONCE,
      layout: standardBindingLayout(),
      wasmFileName: 'main.wasm',
      zkeyFileName: 'main_final.zkey',
    };
  }
  throw new Error(`unknown circuit profile ${name}`);
}

export function circuitProfileFromNonce(nonce: bigint): CircuitProfile {
  if (
    nonce === SIX_BY_SIX_ZK_NONCE ||
    nonce === SIX_BY_SIX_BINDING_ZK_NONCE
  ) {
    return circuitProfileFromName('6x6');
  }
  if (nonce === TEN_BY_ONE_ZK_NONCE) {
    return circuitProfileFromName('10x1');
  }
  return circuitProfileFromName('2x2');
}
