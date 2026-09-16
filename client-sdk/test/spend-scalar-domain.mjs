import assert from 'node:assert/strict';
import {
  BABYJUB_SUBGROUP_ORDER,
  buildStealthAddressSignMessage,
  OWNER_BOUND_NOTE_SCHEMA_VERSION,
  privKeyScalarDecimalFromStellarSignature,
} from '../dist/index.mjs';

const ADDRESS = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF';
const SIGNATURE = '11'.repeat(64);

const BASE_DOMAIN = {
  networkPassphrase: 'Test SDF Network ; September 2015',
  poolContract: 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM',
  registryContract: 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAK3IM',
  schemaVersion: OWNER_BOUND_NOTE_SCHEMA_VERSION,
};

const message = buildStealthAddressSignMessage(ADDRESS, BASE_DOMAIN);
assert.match(message, /Test SDF Network ; September 2015/);
assert.match(message, /CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM/);
assert.match(message, /CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAK3IM/);
assert.match(message, /owner-bound-note-v1/);
assert.doesNotMatch(message, /will not authorize any transaction/i);
assert.doesNotMatch(message, /does not authorize/i);
assert.match(message, /authorizes spending/i);

const base = await privKeyScalarDecimalFromStellarSignature(SIGNATURE, BASE_DOMAIN);
const otherNetwork = await privKeyScalarDecimalFromStellarSignature(SIGNATURE, {
  ...BASE_DOMAIN,
  networkPassphrase: 'Public Global Stellar Network ; September 2015',
});
const otherPool = await privKeyScalarDecimalFromStellarSignature(SIGNATURE, {
  ...BASE_DOMAIN,
  poolContract: 'CBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFCT4',
});
const otherRegistry = await privKeyScalarDecimalFromStellarSignature(SIGNATURE, {
  ...BASE_DOMAIN,
  registryContract: 'CBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFCT4',
});
const otherSchema = await privKeyScalarDecimalFromStellarSignature(SIGNATURE, {
  ...BASE_DOMAIN,
  schemaVersion: OWNER_BOUND_NOTE_SCHEMA_VERSION + 1,
});

assert.notEqual(base, otherNetwork);
assert.notEqual(base, otherPool);
assert.notEqual(base, otherRegistry);
assert.notEqual(base, otherSchema);
assert.notEqual(otherNetwork, otherPool);
assert.equal(/^[0-9]+$/.test(base), true);
assert.equal(BigInt(base) > 0n, true);
assert.equal(BigInt(base) < BABYJUB_SUBGROUP_ORDER, true);

console.log('spend-scalar-domain: ok');
