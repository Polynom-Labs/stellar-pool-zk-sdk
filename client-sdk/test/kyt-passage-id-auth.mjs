import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  buildKytPassageAuthorization,
  derivePassageId,
  derivePassageIdV1,
  derivePassageIdV2,
  hashPublicSignalBytes,
  NOTE_AUDIT_PLAINTEXT_LEN,
  SIX_BY_SIX_ZK_NONCE,
  TOTAL_PUBLIC_SIGNALS,
} from '../dist/index.mjs';

const FIXED_G = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF';
const FIXED_POOL = 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM';
const FIXED_REGISTRY = 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAK3IM';

const PUBLIC_SIGNAL_HASH = '11'.repeat(32);
const PUBLIC_LEG_CONTEXT_HASH = '22'.repeat(32);
const ONBOARDING_HASH = '33'.repeat(32);
const CIPHERTEXT_HASH = '55'.repeat(32);
const PASSAGE_ID = '44'.repeat(32);
const EXPIRES_AT_LEDGER = 1_234_567;
const FIXED_ZK_CONFIG_NONCE = 42n;

const SDK_RUST_PASSAGE_ID =
  '6132dd696151443711ede41813a330632428be1c50d8e8dd0406f0cdd478a071';
const SDK_RUST_PASSAGE_ID_V3 =
  '91a1baa6461e446c55a01658226a87e937e5c7dc2617932a3056e4fb6806e8ef';
const SDK_RUST_PASSAGE_ID_V1 =
  '92aa0b3135d042e01a9b93aba33f0ce7f0b0abbf43d77297dcf88199f83b00d3';
const SDK_RUST_AUTHORIZATION_HASH =
  '27fa9c075782e1be6117306fc60bf43c489f06f284c3215152fad00cefeb54d5';
const SDK_RUST_AUDIT_PLAINTEXT_HASH =
  'ceb0da1efcdd5a15ed6b1f20a0446ac50576b9ae1f27e0699765b443d7b3df77';

const passageId = derivePassageIdV2(
  FIXED_G,
  FIXED_ZK_CONFIG_NONCE,
  PUBLIC_SIGNAL_HASH,
  PUBLIC_LEG_CONTEXT_HASH,
);
assert.equal(passageId, SDK_RUST_PASSAGE_ID);

const passageIdV3 = derivePassageId(
  FIXED_G,
  FIXED_ZK_CONFIG_NONCE,
  PUBLIC_SIGNAL_HASH,
  PUBLIC_LEG_CONTEXT_HASH,
  CIPHERTEXT_HASH,
);
assert.equal(passageIdV3, SDK_RUST_PASSAGE_ID_V3);
assert.notEqual(passageIdV3, passageId);

const v1 = derivePassageIdV1(
  FIXED_G,
  FIXED_ZK_CONFIG_NONCE,
  PUBLIC_SIGNAL_HASH,
  PUBLIC_LEG_CONTEXT_HASH,
  ONBOARDING_HASH,
);
assert.equal(v1, SDK_RUST_PASSAGE_ID_V1);
assert.notEqual(v1, passageId);

const auth = buildKytPassageAuthorization({
  poolContract: FIXED_POOL,
  kytRegistry: FIXED_REGISTRY,
  passageId: PASSAGE_ID,
  expiresAtLedger: EXPIRES_AT_LEDGER,
});
assert.equal(auth.authorizationHash, SDK_RUST_AUTHORIZATION_HASH);

const signalsA = Buffer.alloc(TOTAL_PUBLIC_SIGNALS * 32);
const signalsB = Buffer.alloc(TOTAL_PUBLIC_SIGNALS * 32);
signalsA[82 * 32 + 31] = 1;
signalsB[82 * 32 + 31] = 2;
assert.equal(hashPublicSignalBytes(signalsA), hashPublicSignalBytes(signalsB));
assert.throws(
  () => hashPublicSignalBytes(signalsA, 1n),
  /unknown zk config nonce/i,
);
const signalsV2A = Buffer.alloc(95 * 32);
const signalsV2B = Buffer.alloc(95 * 32);
signalsV2A[82 * 32 + 31] = 1;
signalsV2B[82 * 32 + 31] = 2;
assert.equal(hashPublicSignalBytes(signalsV2A, 2n), hashPublicSignalBytes(signalsV2B, 2n));
const signals6A = Buffer.alloc(259 * 32);
const signals6B = Buffer.alloc(259 * 32);
signals6A[246 * 32 + 31] = 1;
signals6B[246 * 32 + 31] = 2;
assert.equal(
  hashPublicSignalBytes(signals6A, SIX_BY_SIX_ZK_NONCE),
  hashPublicSignalBytes(signals6B, SIX_BY_SIX_ZK_NONCE),
);

const fields = [];
for (let index = 0; index < NOTE_AUDIT_PLAINTEXT_LEN; index += 1) {
  const field = Buffer.alloc(32);
  field[31] = index;
  fields.push(field);
}
assert.equal(
  createHash('sha256').update(Buffer.concat(fields)).digest('hex'),
  SDK_RUST_AUDIT_PLAINTEXT_HASH,
);

console.log('kyt-passage-id-auth: ok');
