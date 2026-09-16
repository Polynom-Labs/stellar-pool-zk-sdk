import assert from 'node:assert/strict';
import { Keypair, StrKey } from '@stellar/stellar-sdk';
import { planKytSubmit, submitApprovedKytPassage, submitWithKytPassage } from '../dist/index.mjs';

const jit = planKytSubmit(true, true);
assert.equal(jit.atomic, true);
assert.deepEqual(jit.operations, ['helper.submit_with_passage']);

const fallback = planKytSubmit(true);
assert.equal(fallback.atomic, false);
assert.deepEqual(fallback.operations, ['register_passage', 'pool.transact']);

const preapproved = planKytSubmit(false);
assert.equal(preapproved.atomic, true);
assert.deepEqual(preapproved.operations, ['pool.transact']);

const source = Keypair.random();
const owner = source.publicKey();
const poolContract = StrKey.encodeContract(Buffer.alloc(32, 1));
const kytRegistryId = StrKey.encodeContract(Buffer.alloc(32, 2));
let inspectCalled = false;

await assert.rejects(
  () =>
    submitWithKytPassage({
      poolContract,
      kytRegistryId,
      owner,
      proofBytes: Buffer.from([1]),
      publicSignalsBytes: Buffer.alloc(93 * 32),
      publicLegContext: {
        owner,
        withdrawAddress: owner,
        publicDeposits: ['0'],
        publicWithdrawals: ['0'],
        publicDepositedAssets: [['0', '0']],
        publicWithdrawnAssets: [['0', '0']],
      },
      source,
      networkPassphrase: 'Test SDF Network ; September 2015',
      rpcUrl: 'http://127.0.0.1:9',
      inspectRequest: {
        owner,
        poolContract,
        kytRegistry: kytRegistryId,
        proofBytes: '01',
        publicSignalsBytes: Buffer.alloc(93 * 32).toString('hex'),
        applicationIdsPlaintext: ['0', '0', '0', '0'],
      },
      inspectFn: async () => {
        inspectCalled = true;
        return {
          passageId: 'f'.repeat(64),
          signature: '',
          expiresAtLedger: 123,
        };
      },
    }),
  /passageId does not match/,
);
assert.equal(inspectCalled, true);

await assert.rejects(
  () =>
    submitApprovedKytPassage({
      poolContract,
      owner: Keypair.random().publicKey(),
      proofBytes: Buffer.from([1]),
      publicSignalsBytes: Buffer.alloc(93 * 32),
      source,
      networkPassphrase: 'Test SDF Network ; September 2015',
      rpcUrl: 'http://127.0.0.1:9',
      kytSubmitHelperId: StrKey.encodeContract(Buffer.alloc(32, 3)),
      passageId: 'f'.repeat(64),
      signature: Buffer.alloc(64).toString('base64'),
      expiresAtLedger: 123,
    }),
  /source keypair must match/,
);

console.log('kyt-flow-atomic: ok');
