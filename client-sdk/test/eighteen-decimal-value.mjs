import assert from 'node:assert/strict';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PrivacyPoolSDK } from '../dist/index.mjs';

const EIGHTEEN_DECIMAL_PLUS_ONE = '1000000000000000001';
const ASSET_HI = '1';
const ASSET_LO = '2';
const zkArtifactBaseUrl = resolve(
  dirname(fileURLToPath(import.meta.url)),
  '../../artifacts',
);

const sdk = await PrivacyPoolSDK.init({ zkArtifactBaseUrl });

assert.throws(
  () => sdk.generateCoin(/** @type {never} */ (1e18), ASSET_HI, ASSET_LO),
  /must be bigint or decimal string, not number/,
);

const fromString = sdk.generateCoin(EIGHTEEN_DECIMAL_PLUS_ONE, ASSET_HI, ASSET_LO);
assert.equal(fromString.coin.value, EIGHTEEN_DECIMAL_PLUS_ONE);
assert.equal(typeof fromString.coin.value, 'string');
assert.equal(BigInt(fromString.coin.value), 1000000000000000001n);

const fromBigint = sdk.generateCoin(1000000000000000001n, ASSET_HI, ASSET_LO);
assert.equal(fromBigint.coin.value, EIGHTEEN_DECIMAL_PLUS_ONE);

console.log('eighteen-decimal-value: ok');
