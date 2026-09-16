import assert from 'node:assert/strict';
import { BABYJUB_SUBGROUP_ORDER, sampleDerivedEscrowKey } from '../dist/index.mjs';

const { nonce, key } = await sampleDerivedEscrowKey(1n, 2n);
const scalar = BigInt(`0x${key.scalarHex}`);
assert.equal(key.scalarHex.length, 64);
assert.equal(key.pointXHex.length, 64);
assert.equal(key.pointYHex.length, 64);
assert.ok(scalar > 0n && scalar < BABYJUB_SUBGROUP_ORDER);
assert.ok(nonce > 0n);
console.log(`derived-escrow-key: ok nonce=${nonce.toString()}`);
