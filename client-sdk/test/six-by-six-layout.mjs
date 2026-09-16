import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  SIX_BY_SIX_BINDING_ZK_NONCE,
  buildTransactionWitnessInput,
  hashPublicSignalBytes,
  layoutForKnownNonce,
  randomFrDecimal,
  randomFrDecimal253,
  resolveTransactionAuditParams,
  sixBySixBindingLayout,
  totalPublicSignals,
} from '../dist/index.mjs';

const layout = sixBySixBindingLayout();
assert.equal(layout.nIns, 6);
assert.equal(layout.nOuts, 6);
assert.equal(layout.nAuditSlots, 12);
assert.equal(layout.auditOffset, 24);
assert.equal(layout.outputNoteOffset, 38);
assert.equal(totalPublicSignals(layout), 57);
assert.deepEqual(layoutForKnownNonce(SIX_BY_SIX_BINDING_ZK_NONCE), layout);

const audit = resolveTransactionAuditParams('101', undefined, 12);
assert.equal(audit.noteAuditPublicKey.length, 2);
assert.equal(typeof audit.auditEphemeralScalar, 'string');

const dummyWasm = {
  ecdhEphemeralPublicKeyFromScalarHex() {
    return { x: '01'.repeat(32), y: '02'.repeat(32) };
  },
};
const witness = buildTransactionWitnessInput(
  {
    stateRoot: '0',
    withdrawAddressHi: '0',
    withdrawAddressLo: '0',
    privKeyScalar: randomFrDecimal253(),
  },
  {
    publicWithdrawnAssets: [['0', '0']],
    publicDepositedAssets: [['1', '1']],
    publicDeposits: ['1'],
    publicWithdrawals: ['0'],
  },
  [],
  [{
    value: '1',
    nullifier: randomFrDecimal(),
    ephemeralKeyScalar: randomFrDecimal253(),
    asset: ['1', '1'],
    applicationId: '101',
    recipientPublicKeys: ['1', '2'],
  }],
  audit,
  dummyWasm,
  { nIns: 6, nOuts: 6 },
);
assert.equal(witness.withdrawnValues.length, 6);
assert.equal(witness.depositedValues.length, 6);
assert.equal(typeof witness.auditEphemeralScalar, 'string');
assert.equal(witness.noteAuditPublicKey.length, 2);
assert.equal(witness.depositedValues[0], '1');
assert.equal(witness.depositedValues[1], '0');

const signalsA = Buffer.alloc(57 * 32);
const signalsB = Buffer.alloc(57 * 32);
signalsA[44 * 32 + 31] = 1;
signalsB[44 * 32 + 31] = 2;
assert.equal(
  hashPublicSignalBytes(signalsA, SIX_BY_SIX_BINDING_ZK_NONCE),
  hashPublicSignalBytes(signalsB, SIX_BY_SIX_BINDING_ZK_NONCE),
);

const scriptDir = dirname(fileURLToPath(import.meta.url));
const r1csPath = resolve(scriptDir, '../../circuits/build/main_6x6.r1cs');
if (existsSync(r1csPath)) {
  assert.ok(existsSync(r1csPath));
}

console.log('six-by-six-layout: ok');
