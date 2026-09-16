import assert from 'node:assert/strict';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  PrivacyPoolSDK,
  coordHexToDecimal,
  randomFrDecimal,
  randomFrDecimal253,
  resolveTransactionAuditParams,
  DEMO_AUDIT_PUBLIC_KEY,
  DEFAULT_APPLICATION_ID,
  SIX_BY_SIX_BINDING_ZK_NONCE,
  sixBySixBindingLayout,
  totalPublicSignals,
} from '../dist/index.mjs';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, '../..');
void repoRoot;

console.log('BEGIN six-by-six-witness-proof');
const sdk = await PrivacyPoolSDK.init({
  zkConfigNonce: SIX_BY_SIX_BINDING_ZK_NONCE,
  zkArtifactBaseUrl: resolve(scriptDir, '../../artifacts'),
});
const audit = resolveTransactionAuditParams(DEFAULT_APPLICATION_ID, DEMO_AUDIT_PUBLIC_KEY, 12);
const ownerPub = sdk.ecdhEphemeralPublicKeyFromScalarHex('0b'.padStart(64, '0'));
const deposit = {
  value: '1000000000',
  nullifier: randomFrDecimal(),
  ephemeralKeyScalar: randomFrDecimal253(),
  asset: /** @type {[string, string]} */ (['1', '1']),
  applicationId: DEFAULT_APPLICATION_ID,
  recipientPublicKeys: /** @type {[string, string]} */ ([
    coordHexToDecimal(ownerPub.x),
    coordHexToDecimal(ownerPub.y),
  ]),
};

const layout = sixBySixBindingLayout();
const publicParams = {
  stateRoot: '0',
  withdrawAddressHi: '0',
  withdrawAddressLo: '0',
  privKeyScalar: randomFrDecimal253(),
};
const publicLegs = {
  publicWithdrawnAssets: [['0', '0']],
  publicDepositedAssets: [['1', '1']],
  publicDeposits: ['1000000000'],
  publicWithdrawals: ['0'],
};
console.log('BEGIN proveTransaction 6x6');
const result = await sdk.proveTransaction(
  publicParams,
  publicLegs,
  [],
  [deposit],
  audit,
);
console.log('END proveTransaction 6x6');
assert.equal(typeof result.proof_hex, 'string');
assert.equal(result.proof_hex.length, 512);
assert.equal(typeof result.public_hex, 'string');
const signalCount = Number.parseInt(result.public_hex.slice(0, 8), 16);
assert.equal(signalCount, totalPublicSignals(layout));
assert.ok(result.ciphertext_hex);
assert.equal(Number.parseInt(result.ciphertext_hex.slice(0, 8), 16), 180);
console.log('END six-by-six-witness-proof');
console.log('six-by-six-witness-proof: ok');
