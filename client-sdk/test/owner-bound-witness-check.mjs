import assert from 'node:assert/strict';
import {
  PrivacyPoolSDK,
  withdrawObjectFromMerkleWitness,
  randomFrDecimal,
  randomFrDecimal253,
  scalarHexToFrDecimal,
  coordHexToDecimal,
  resolveTransactionAuditParams,
  DEMO_AUDIT_PUBLIC_KEY,
  DEFAULT_APPLICATION_ID,
} from '../dist/index.mjs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const EIGHTEEN_DECIMAL_PLUS_ONE = '1000000000000000001';
const ASSET = /** @type {[string, string]} */ (['1', '1']);
const OWNER_SCALAR_HEX = '0b'.padStart(64, '0');

/**
 * @param {InstanceType<typeof PrivacyPoolSDK>} sdk
 */
function wasmEcdh(sdk) {
  return {
    ecdhEphemeralPublicKeyFromScalarHex: (hex) => sdk.ecdhEphemeralPublicKeyFromScalarHex(hex),
  };
}
void wasmEcdh;

/**
 * @param {InstanceType<typeof PrivacyPoolSDK>} sdk
 * @param {string} value
 */
function depositObject(sdk, value) {
  const ownerPub = sdk.ecdhEphemeralPublicKeyFromScalarHex(OWNER_SCALAR_HEX);
  return {
    value,
    nullifier: randomFrDecimal(),
    ephemeralKeyScalar: randomFrDecimal253(),
    asset: ASSET,
    applicationId: DEFAULT_APPLICATION_ID,
    recipientPublicKeys: /** @type {[string, string]} */ ([
      coordHexToDecimal(ownerPub.x),
      coordHexToDecimal(ownerPub.y),
    ]),
  };
}

/**
 * @param {InstanceType<typeof PrivacyPoolSDK>} sdk
 * @param {string} value
 */
function spendWithdrawObject(sdk, value) {
  const ownerPub = sdk.ecdhEphemeralPublicKeyFromScalarHex(OWNER_SCALAR_HEX);
  const generated = sdk.generateCoinWithOwnerPub(
    ownerPub,
    value,
    ASSET[0],
    ASSET[1],
    DEFAULT_APPLICATION_ID,
  );
  const padding = sdk.generateCoin('1', ASSET[0], ASSET[1], DEFAULT_APPLICATION_ID);
  const merkle = sdk.buildWithdrawMerkleWitness(generated.coin, {
    commitments: [generated.coin.commitment, padding.coin.commitment],
  });
  return {
    coin: generated.coin,
    withdraw: withdrawObjectFromMerkleWitness(
      merkle,
      ownerPub,
      DEFAULT_APPLICATION_ID,
      scalarHexToFrDecimal(OWNER_SCALAR_HEX),
    ),
    stateRoot: merkle.stateRoot,
  };
}

const sdk = await PrivacyPoolSDK.init({
  zkArtifactBaseUrl: resolve(
    dirname(fileURLToPath(import.meta.url)),
    '../../artifacts',
  ),
});
const audit = resolveTransactionAuditParams(DEFAULT_APPLICATION_ID, DEMO_AUDIT_PUBLIC_KEY);
const ownerPub = sdk.ecdhEphemeralPublicKeyFromScalarHex(OWNER_SCALAR_HEX);
const privKeyScalar = scalarHexToFrDecimal(OWNER_SCALAR_HEX);

const depositProof = await sdk.proveTransaction(
  {
    stateRoot: '0',
    withdrawAddressHi: '0',
    withdrawAddressLo: '0',
    privKeyScalar,
  },
  {
    publicWithdrawnAssets: [['0', '0']],
    publicDepositedAssets: [ASSET],
    publicDeposits: [EIGHTEEN_DECIMAL_PLUS_ONE],
    publicWithdrawals: ['0'],
  },
  [],
  [depositObject(sdk, EIGHTEEN_DECIMAL_PLUS_ONE)],
  audit,
);
assert.equal(typeof depositProof.proof_hex, 'string');
assert.equal(depositProof.proof_hex.length, 512);

const spent = spendWithdrawObject(sdk, EIGHTEEN_DECIMAL_PLUS_ONE);
assert.equal(spent.coin.value, EIGHTEEN_DECIMAL_PLUS_ONE);
const transferProof = await sdk.proveTransaction(
  {
    stateRoot: spent.stateRoot,
    withdrawAddressHi: '0',
    withdrawAddressLo: '0',
    privKeyScalar,
  },
  {
    publicWithdrawnAssets: [['0', '0']],
    publicDepositedAssets: [['0', '0']],
    publicDeposits: ['0'],
    publicWithdrawals: ['0'],
  },
  [spent.withdraw],
  [depositObject(sdk, EIGHTEEN_DECIMAL_PLUS_ONE)],
  audit,
);
assert.equal(transferProof.proof_hex.length, 512);

const withdrawSpend = spendWithdrawObject(sdk, EIGHTEEN_DECIMAL_PLUS_ONE);
const withdrawProof = await sdk.proveTransaction(
  {
    stateRoot: withdrawSpend.stateRoot,
    withdrawAddressHi: '0',
    withdrawAddressLo: '0',
    privKeyScalar,
  },
  {
    publicWithdrawnAssets: [ASSET],
    publicDepositedAssets: [['0', '0']],
    publicDeposits: ['0'],
    publicWithdrawals: [EIGHTEEN_DECIMAL_PLUS_ONE],
  },
  [withdrawSpend.withdraw],
  [],
  audit,
);
assert.equal(withdrawProof.proof_hex.length, 512);

assert.equal(typeof ownerPub.x, 'string');
console.log('owner-bound-witness-check: ok');
