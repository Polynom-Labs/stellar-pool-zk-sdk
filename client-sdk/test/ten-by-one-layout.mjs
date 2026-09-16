import assert from "node:assert/strict";
import {
  TEN_BY_ONE_ZK_NONCE,
  bundledCircuitStem,
  BundledZkCircuit,
  circuitProfileFromName,
  hashPublicSignalBytes,
  layoutForKnownNonce,
  tenByOneBindingLayout,
  totalPublicSignals,
} from "../dist/index.mjs";

const layout = tenByOneBindingLayout();
assert.equal(layout.nIns, 10);
assert.equal(layout.nOuts, 1);
assert.equal(layout.publicNInputs, 0);
assert.equal(layout.publicNOutputs, 1);
assert.equal(layout.nAuditSlots, 11);
assert.equal(layout.auditOffset, 13);
assert.equal(layout.outputNoteOffset, 26);
assert.equal(totalPublicSignals(layout), 37);
assert.deepEqual(layoutForKnownNonce(TEN_BY_ONE_ZK_NONCE), layout);
assert.equal(TEN_BY_ONE_ZK_NONCE, 10n);
assert.equal(circuitProfileFromName("10x1").nonce, TEN_BY_ONE_ZK_NONCE);
assert.equal(bundledCircuitStem(BundledZkCircuit.TenByOne), "main_10x1");
assert.equal(
  bundledCircuitStem(BundledZkCircuit.TenByOneDelegated),
  "main_10x1_delegated",
);

const signalsA = Buffer.alloc(37 * 32);
const signalsB = Buffer.alloc(37 * 32);
signalsA[27 * 32 + 31] = 1;
signalsB[27 * 32 + 31] = 2;
assert.equal(
  hashPublicSignalBytes(signalsA, TEN_BY_ONE_ZK_NONCE),
  hashPublicSignalBytes(signalsB, TEN_BY_ONE_ZK_NONCE),
);

console.log("ten-by-one-layout: ok");
