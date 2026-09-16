// Regenerates tests/fixtures/sequential-real-zk/*: two REAL Groth16 proofs (deposit then
// withdraw of that same note) plus the production verification key, used by
// `contract/pool/tests/sequential_real_zk_proof.rs` to exercise `transact` twice in sequence
// with genuine proofs (no `set_bypass_proof_verification`).
//
// Uses locally available circuit artifacts. Never regenerate ptau.
// Production pot20 lives in this SDK repo (`ptau/pot20_final.ptau`). Contract-side
// `circom2soroban` lives in the soroban-privacy-pools submodule:
//   cargo run -p circom2soroban --manifest-path $POOLS_DIR/Cargo.toml -- vk \
//     $PWD/artifacts/main_verification_key.json
//
// Run from the `client-sdk` directory (needs its own node_modules + built dist/):
//   npm run build && node scripts/generate-sequential-zk-fixtures.mjs
//
// To also refresh production_vk.hex (only needed if the VK itself changed):
//   cargo run -p circom2soroban --manifest-path soroban-privacy-pools/Cargo.toml -- vk \
//     artifacts/main_verification_key.json \
//     | grep -A1 '^VK Hex encoding:' | tail -1 \
//     > soroban-privacy-pools/tests/fixtures/sequential-real-zk/production_vk.hex

import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync, unlinkSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Keypair, StrKey } from '@stellar/stellar-sdk';
import { PrivacyPoolSDK } from '../dist/index.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI_ROOT = join(__dirname, '..');
const SDK_ROOT = join(__dirname, '..', '..');
const POOLS_DIR = process.env.POOLS_DIR ?? join(SDK_ROOT, 'soroban-privacy-pools');
const OUT_DIR = join(POOLS_DIR, 'tests', 'fixtures', 'sequential-real-zk');
const ZK_ARTIFACT_BASE_URL = process.env.ZK_ARTIFACT_BASE_URL ?? join(SDK_ROOT, 'artifacts');

function cli(args) {
  return execFileSync('node', ['dist/cli.js', ...args], {
    cwd: CLI_ROOT,
    encoding: 'utf8',
    env: { ...process.env, ZK_ARTIFACT_BASE_URL },
  });
}

function cliLastLine(args) {
  return cli(args).trim().split('\n').filter(Boolean).pop();
}

async function main() {
  mkdirSync(OUT_DIR, { recursive: true });

  // Fixed, arbitrary 32-byte "token" contract id shared between this offline generator and the
  // Rust test, which does `env.register_at(&this_address, MockToken, ())` at the same bytes.
  const tokenIdBytes = Buffer.from('11'.repeat(32), 'hex');
  const tokenAddress = StrKey.encodeContract(tokenIdBytes);

  // Recipient identity: ephemeral, in-memory-only Ed25519 keypair (never written to disk or
  // `~/.config`) used purely to derive a stealth address + spending scalar for this fixture.
  const receiver = Keypair.random();
  const domainFlags = [
    '--network-passphrase', 'Test SDF Network ; September 2015',
    '--pool', 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM',
    '--registry', 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAK3IM',
  ];
  const message = cliLastLine([
    'stealth-sign-message',
    '--address', receiver.publicKey(),
    ...domainFlags,
  ]);
  const sigHex = receiver.sign(Buffer.from(message, 'utf8')).toString('hex');

  const stealth = cliLastLine(['stealth-from-signature', '--signature', sigHex, ...domainFlags]);
  const depositScalarHex = cliLastLine(['random-scalar']);

  const coinFile = join(OUT_DIR, '.coin.json.tmp');
  cli([
    'generate',
    '--token', tokenAddress,
    '--scalar', depositScalarHex,
    '--stealth', stealth,
    '--amount', '1000000000',
    '-o', coinFile,
  ]);
  const coin = JSON.parse(readFileSync(coinFile, 'utf8'));

  // Genesis root for a fresh `PrivacyPoolsContract` deployed with tree_depth=20
  // (`PairwiseLeanIMT::new` in `libs/lean-imt`, called from `PrivacyPoolsContract::init_storage`
  // at construction) -- NOT 32 zero bytes; it is the real depth-20 empty-tree root computed by
  // recursively hashing zero leaves up the tree. Obtained by instantiating the actual contract in
  // a Rust test and reading `get_merkle_root()` before any `transact` call (see
  // `contract/pool/src/sequential_real_zk_proof_test.rs`); re-derive the same way if tree_depth
  // or the zero-hash convention ever changes.
  const root0Dec = '15019797232609675441998260052101280400536945603062888308240081994073687793470';

  const depProofFile = join(OUT_DIR, 'deposit1_proof.hex');
  const depPubFile = join(OUT_DIR, 'deposit1_public_signals.hex');
  const depCtFile = join(OUT_DIR, 'deposit1_ciphertext.hex');
  cli([
    'deposit-proof',
    '--state-root', root0Dec,
    '--stealth', stealth,
    '--token', tokenAddress,
    '--coin', coinFile,
    '--ephemeral-scalar-hex', depositScalarHex,
    '--output-proof', depProofFile,
    '--output-public', depPubFile,
    '--output-ciphertext', depCtFile,
  ]);

  const sdk = await PrivacyPoolSDK.init({ zkArtifactBaseUrl: ZK_ARTIFACT_BASE_URL });
  const eph = sdk.ecdhEphemeralPublicKeyFromScalarHex(depositScalarHex);

  // Leaves are inserted pairwise: commitment_hash(0) is our real deposit output,
  // commitment_hash(1) is the circuit's paired "dummy" output (a real, nonzero Poseidon
  // commitment for an unspendable value=0 note). Both must go into the withdraw proof's
  // Merkle witness, in order, to match the on-chain tree exactly.
  const depPubBytes = readFileSync(depPubFile, 'utf8').trim();
  const buf = Buffer.from(depPubBytes, 'hex');
  const readFr = (i) =>
    BigInt('0x' + buf.subarray(4 + i * 32, 4 + i * 32 + 32).toString('hex')).toString(10);
  const nIns = 2; // ZkLayoutParams::standard().n_ins
  const leaf0 = readFr(nIns + 0);
  const leaf1 = readFr(nIns + 1);
  if (leaf0 !== coin.coin.commitment) {
    throw new Error(`commitment_hash(0) mismatch: expected ${coin.coin.commitment}, got ${leaf0}`);
  }

  const stateFile = join(OUT_DIR, '.state1.json.tmp');
  writeFileSync(stateFile, JSON.stringify({ commitments: [leaf0, leaf1] }, null, 2));

  const privKeyScalarDec = cliLastLine([
    'priv-scalar-from-signature',
    '--signature',
    sigHex,
    ...domainFlags,
  ]);
  const withdrawPubkeyHex = StrKey.decodeEd25519PublicKey(receiver.publicKey()).toString('hex');

  const wdProofFile = join(OUT_DIR, 'withdraw2_proof.hex');
  const wdPubFile = join(OUT_DIR, 'withdraw2_public_signals.hex');
  const wdCtFile = join(OUT_DIR, 'withdraw2_ciphertext.hex');
  cli([
    // No --public-withdraw-stroops/--change-stealth: `withdraw` defaults to a full public
    // payout of the coin's entire value back to --withdraw-pubkey-hex.
    'withdraw',
    '--coin', coinFile,
    '--state', stateFile,
    '--withdraw-pubkey-hex', withdrawPubkeyHex,
    '--priv-key-scalar', privKeyScalarDec,
    '--ephemeral-x', eph.x,
    '--ephemeral-y', eph.y,
    '--output-proof', wdProofFile,
    '--output-public', wdPubFile,
    '--output-ciphertext', wdCtFile,
  ]);

  const wdPubBytes = Buffer.from(readFileSync(wdPubFile, 'utf8').trim(), 'hex');
  const readWdFr = (i) =>
    BigInt('0x' + wdPubBytes.subarray(4 + i * 32, 4 + i * 32 + 32).toString('hex')).toString(10);
  const root1Dec = readWdFr(16); // ZkLayoutParams::standard_binding().idx_state_root()

  const metadata = {
    tokenAddress,
    tokenIdHex: tokenIdBytes.toString('hex'),
    receiverAddress: receiver.publicKey(),
    receiverSecret: receiver.secret(),
    stealth,
    depositScalarHex,
    coinCommitmentDecimal: coin.coin.commitment,
    ephemeralX: eph.x,
    ephemeralY: eph.y,
    withdrawPubkeyHex,
    depositAmountStroops: '1000000000',
    withdrawalAmountStroops: '1000000000',
    root0Decimal: root0Dec,
    root1Decimal: root1Dec,
    leaf0CommitmentDecimal: leaf0,
    leaf1DummyCommitmentDecimal: leaf1,
    note:
      'Fixtures for the sequential real-ZK-proof transact test (contract/pool/tests/sequential_real_zk_proof.rs). ' +
      'Regenerate via this script (see header comment) if artifacts/main_final.zkey change. ' +
      'root0 is the empty-tree root (32 zero bytes) that deposit1 was built against; root1 is the tree root after leaf0 ' +
      '(real deposit output) + leaf1 (paired dummy output) are inserted, computed off-chain by client-sdk\'s own LeanIMT and ' +
      'embedded as withdraw2\'s stateRoot public signal -- the Rust test asserts the on-chain root after tx1 equals root1 exactly.',
  };
  writeFileSync(join(OUT_DIR, 'metadata.json'), JSON.stringify(metadata, null, 2));
  unlinkSync(coinFile);
  unlinkSync(stateFile);

  console.error('Fixtures written to', OUT_DIR);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
