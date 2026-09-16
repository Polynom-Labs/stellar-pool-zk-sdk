import assert from 'node:assert/strict';
import { Keypair } from '@stellar/stellar-sdk';
import {
  addressToCanonicalXdr,
  hashPublicLegContext,
  zeroAddressSentinelBuffer,
} from '../dist/index.mjs';

const FIXED_G = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF';
const OTHER_G = Keypair.random().publicKey();
const SDK_RUST_EMPTY_LEGS_HASH =
  '269b13e51b4df570d4b3117e599702e2a1b63fa2bf0f27bc98e3825f81d24678';

const emptyLegInput = {
  owner: FIXED_G,
  withdrawAddress: FIXED_G,
  publicDeposits: ['0'],
  publicWithdrawals: ['0'],
  publicDepositedAssets: [['0', '0']],
  publicWithdrawnAssets: [['0', '0']],
};

const layout = { publicNInputs: 1, publicNOutputs: 1 };

const emptyHash = hashPublicLegContext(layout, emptyLegInput);
assert.equal(emptyHash, SDK_RUST_EMPTY_LEGS_HASH);

const xdr = addressToCanonicalXdr(FIXED_G);
assert.equal(xdr.length, 44);
assert.equal(zeroAddressSentinelBuffer().compare(Buffer.alloc(4)), 0);

const otherWithdraw = hashPublicLegContext(layout, {
  ...emptyLegInput,
  withdrawAddress: OTHER_G,
  publicWithdrawals: ['100'],
  publicWithdrawnAssets: [['1', '2']],
});
assert.notEqual(emptyHash, otherWithdraw);

const otherDepositSource = hashPublicLegContext(layout, {
  ...emptyLegInput,
  owner: Keypair.random().publicKey(),
  publicDeposits: ['100'],
  publicDepositedAssets: [['1', '2']],
});
assert.notEqual(emptyHash, otherDepositSource);

console.log('kyt-public-leg-context: ok');
