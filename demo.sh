#!/bin/bash
set -e
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"
POOLS_DIR="${POOLS_DIR:-$REPO_ROOT/soroban-privacy-pools}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-$REPO_ROOT/artifacts}"
SHAPES_JSON="${SHAPES_JSON:-$REPO_ROOT/shapes.json}"
[ -d "$POOLS_DIR" ] || { echo "missing POOLS_DIR=$POOLS_DIR (git submodule update --init)"; exit 1; }

echo "🚀 Starting Privacy Pool Demo..."

# NETWORK=local # testnet, local
# TOKEN_ADDRESS=CDMLFMKMMD7MWZP3FKUBZPVHTUEDLSX4BYGYKH4GCESXYHS3IHQ4EIG4 # XLM token address on testnet
NETWORK=testnet # testnet, local
TOKEN_ADDRESS=CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC # XLM token address on testnet
# Demo deposit/withdraw amount in stroops (1 XLM = 10^9); override: DEMO_AMOUNT_STROOPS=500000000 ./demo.sh
DEMO_AMOUNT_STROOPS="${DEMO_AMOUNT_STROOPS:-1000000000}"
APPLICATION_ID="${APPLICATION_ID:-101}"
export APPLICATION_ID
export NOTE_AUDIT_PUBLIC_KEY_X="${NOTE_AUDIT_PUBLIC_KEY_X:-21605515851820432880964235241069234202284600780825340516808373216881770219365}"
export NOTE_AUDIT_PUBLIC_KEY_Y="${NOTE_AUDIT_PUBLIC_KEY_Y:-18856460861531942120859708048677603751294231190189224157283439874962410808705}"
DEPLOY_STATE_FILE="demo_deploy_state.json"
TREE_DEPTH=20
# Nonce of the ZK config registered via add_zk_config.sh --shape-json ./shapes.json;
# passed on every `transact` invoke. Override to exercise a different registered circuit shape.
ZK_CONFIG_NONCE="${ZK_CONFIG_NONCE:-3}"
if [ -z "${ZK_PROFILE:-}" ]; then
  if [ "$ZK_CONFIG_NONCE" = "6" ] || [ "$ZK_CONFIG_NONCE" = "7" ]; then
    ZK_PROFILE="6x6"
  else
    ZK_PROFILE="2x2"
  fi
fi
if [ -z "${ZK_CONFIG_SHAPE:-}" ]; then
  if [ "$ZK_CONFIG_NONCE" = "6" ] || [ "$ZK_CONFIG_NONCE" = "7" ]; then
    ZK_CONFIG_SHAPE="6x6"
  else
    ZK_CONFIG_SHAPE="2x2"
  fi
fi
export ZK_PROFILE
export ZK_CONFIG_NONCE
MAX_RETRIES="${MAX_RETRIES:-5}"
RETRY_DELAY_SEC="${RETRY_DELAY_SEC:-2}"
STELLAR_FR_HELPER="$REPO_ROOT/scripts/demo-stellar-fr.mjs"
DEMO_KYT_HELPER="$REPO_ROOT/scripts/demo-kyt-passage.mjs"
RPC_URL="${STELLAR_RPC_URL:-https://soroban-testnet.stellar.org}"

# stellar message sign mixes release notices (stderr), ℹ️ lines, and the raw signature on stdout and/or stderr.
# Ed25519 signature: standard base64 (~88 chars) or 128 hex chars.
extract_sep53_signature() {
  # Slash inside /.../ ends the awk regex unless escaped as \/
  printf '%s\n' "$1" | awk '
    /^[0-9a-fA-F]{128}$/ { sig = $0 }
    /^[A-Za-z0-9+\/]+=*$/ && length($0) >= 80 { sig = $0 }
    END { if (sig != "") print sig }
  ' | tr -d '\r\n'
}

decimal_to_bytes32_hex() {
  node -e "const v=BigInt(process.argv[1]); if (v < 0n || v >= (1n << 256n)) process.exit(1); process.stdout.write(v.toString(16).padStart(64, '0'));" "$1"
}

# Registers the receiver's permanent private-address public key (decoded from their stpl1
# stealth address) in the private-address registry, so senders can resolve it by Stellar
# address instead of requiring an onboarding round-trip. No-op (idempotent) on re-runs.
register_private_address_in_registry() {
  local stealth="$1"
  local owner_identity="$2"
  if [ -z "${REGISTRY_ID:-}" ] || [ "${REGISTRY_ID:-}" = "null" ]; then
    echo "⚠️  Registry not configured; skipping private address registration"
    return 0
  fi
  local xy x y
  xy=$(npm run --silent --prefix client-sdk cli -- stealth-pubkey-hex --stealth "$stealth")
  x=$(printf '%s\n' "$xy" | sed -n '1p')
  y=$(printf '%s\n' "$xy" | sed -n '2p')
  echo "📇 Registering private address for ${owner_identity} in registry..."
  retry_stellar_cmd "register_private_address" stellar contract invoke --id "$REGISTRY_ID" --source "$owner_identity" --network "$NETWORK" -- \
    register_private_address --owner "$owner_identity" --public_key_x "$x" --public_key_y "$y" || { echo "❌ Error: register_private_address failed"; exit 1; }
}

retry_stellar_cmd() {
  local description="$1"
  shift
  local attempt=1
  while true; do
    if "$@"; then
      return 0
    fi
    if [ "$attempt" -ge "$MAX_RETRIES" ]; then
      echo "❌ Retry limit reached: $description" >&2
      return 1
    fi
    echo "⚠️  $description failed (attempt $attempt/$MAX_RETRIES), retrying in ${RETRY_DELAY_SEC}s..."
    attempt=$((attempt + 1))
    sleep "$RETRY_DELAY_SEC"
  done
}

sync_demo_commitments() {
  local attempt=1
  local commits_capture=""
  while true; do
    commits_capture=$(stellar contract invoke --id "$CONTRACT_ID" --source demo_user --network "$NETWORK" --send no -- get_commitments 2>&1) || true
    if node "$STELLAR_FR_HELPER" commitments-from-output "$commits_capture" > demo_state.json 2>/dev/null; then
      echo "   $(jq '.commitments | length' demo_state.json) commitment(s) from chain"
      return 0
    fi
    if [ "$attempt" -ge "$MAX_RETRIES" ]; then
      echo "⚠️  Could not parse get_commitments; using deposit public signals (same tx only)."
      node "$REPO_ROOT/scripts/demo-state-from-deposit-public.mjs" demo_dep_pub.hex > demo_state.json
      return 1
    fi
    echo "⚠️  get_commitments unreadable (attempt $attempt/$MAX_RETRIES), retrying in ${RETRY_DELAY_SEC}s..."
    attempt=$((attempt + 1))
    sleep "$RETRY_DELAY_SEC"
  done
}

fetch_leaf_ephemeral_xy() {
  local attempt=1
  local eph_capture=""
  local eph_xy=""
  while true; do
    eph_capture=$(stellar contract invoke --id "$CONTRACT_ID" --source demo_user --network "$NETWORK" --send no -- get_leaf_ephemeral --leaf_index "$EPH_LEAF_INDEX" 2>&1) || true
    if eph_xy=$(node "$STELLAR_FR_HELPER" ephemeral-xy "$eph_capture" 2>/dev/null); then
      EPH_X=$(printf '%s\n' "$eph_xy" | sed -n '1p')
      EPH_Y=$(printf '%s\n' "$eph_xy" | sed -n '2p')
      return 0
    fi
    if [ -n "${DEPOSIT_TX_OUTPUT:-}" ] && eph_xy=$(node "$STELLAR_FR_HELPER" deposit-ephemeral-xy "$DEPOSIT_TX_OUTPUT" "$EPH_LEAF_INDEX" 2>/dev/null); then
      echo "   Using depositor ephemeral from deposit transact events (leaf $EPH_LEAF_INDEX)"
      EPH_X=$(printf '%s\n' "$eph_xy" | sed -n '1p')
      EPH_Y=$(printf '%s\n' "$eph_xy" | sed -n '2p')
      return 0
    fi
    if [ "$attempt" -ge "$MAX_RETRIES" ]; then
      echo "❌ Error: could not read leaf ephemeral for index $EPH_LEAF_INDEX" >&2
      printf '%s\n' "$eph_capture" >&2
      return 1
    fi
    echo "⚠️  get_leaf_ephemeral unreadable (attempt $attempt/$MAX_RETRIES), retrying in ${RETRY_DELAY_SEC}s..."
    attempt=$((attempt + 1))
    sleep "$RETRY_DELAY_SEC"
  done
}

# Clean up only regenerated temp files (keep demo_state.json and demo_deploy_state.json for resume)
echo "🧹 Cleaning up temporary files..."
rm -f demo_coin.json demo_association.json vk_hex.txt proof_hex.txt public_hex.txt withdrawal_input.json \
  demo_dep_proof.hex demo_dep_pub.hex demo_wd_proof.hex demo_wd_pub.hex demo_scalar_hex.txt \
  circuits/witness.wtns circuits/proof.json circuits/public.json 2>/dev/null || true

# Check prerequisites
echo "🔍 Checking prerequisites..."
command -v jq >/dev/null 2>&1 || { echo "❌ Error: jq is required but not installed. Please install jq first."; exit 1; }
command -v node >/dev/null 2>&1 || { echo "❌ Error: node (>=19) is required."; exit 1; }
command -v stellar >/dev/null 2>&1 || { echo "❌ Error: stellar CLI is required but not installed."; exit 1; }
command -v stellar-audit >/dev/null 2>&1 || { echo "❌ Error: stellar-audit CLI is required but not installed."; exit 1; }
[ -f "$STELLAR_FR_HELPER" ] || { echo "❌ Error: missing $STELLAR_FR_HELPER"; exit 1; }
[ -f "$DEMO_KYT_HELPER" ] || { echo "❌ Error: missing $DEMO_KYT_HELPER"; exit 1; }

USE_EXISTING_CONTRACT=false
if [ -f "$DEPLOY_STATE_FILE" ]; then
    echo "📂 Deploy state file found: $DEPLOY_STATE_FILE"
    read -p "Continue with existing contract? (y/n): " -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        USE_EXISTING_CONTRACT=true
        echo "📥 Loading variables from $DEPLOY_STATE_FILE..."
        STELLAR_AUDIT_PUBLIC_KEY=$(jq -r '.stellar_audit_public_key' "$DEPLOY_STATE_FILE")
        STELLAR_AUDIT_PRIVATE_KEY=$(jq -r '.stellar_audit_private_key' "$DEPLOY_STATE_FILE")
        CONTRACT_ID=$(jq -r '.contract_id' "$DEPLOY_STATE_FILE")
        REGISTRY_ID=$(jq -r '.registry_id // empty' "$DEPLOY_STATE_FILE")
        KYT_REGISTRY_ID=$(jq -r '.kyt_registry_id // empty' "$DEPLOY_STATE_FILE")
        KYT_SIGNER_SECRET=$(jq -r '.kyt_signer_secret // empty' "$DEPLOY_STATE_FILE")
        export STELLAR_AUDIT_PUBLIC_KEY STELLAR_AUDIT_PRIVATE_KEY KYT_SIGNER_SECRET
        if [ -z "$CONTRACT_ID" ] || [ "$CONTRACT_ID" = "null" ]; then
            echo "❌ Error: Invalid or missing data in $DEPLOY_STATE_FILE"
            exit 1
        fi
        echo "   Contract ID: $CONTRACT_ID"
        if [ -n "$REGISTRY_ID" ] && [ "$REGISTRY_ID" != "null" ]; then
            echo "   Registry ID: $REGISTRY_ID"
        fi
        if [ -n "$KYT_REGISTRY_ID" ] && [ "$KYT_REGISTRY_ID" != "null" ]; then
            echo "   KYT Registry ID: $KYT_REGISTRY_ID"
        fi
    else
        echo "🗑️  Removing state files for fresh deploy..."
        rm -f "$DEPLOY_STATE_FILE" demo_state.json
    fi
fi

submit_demo_kyt_transact() {
    local public_hex="$1"
    local label="$2"
    local proof_hex="$3"
    if [ -z "${KYT_REGISTRY_ID:-}" ] || [ "${KYT_REGISTRY_ID:-}" = "null" ]; then
        echo "❌ Error: KYT registry is not configured"
        exit 1
    fi
    if [ -z "${KYT_SIGNER_SECRET:-}" ] || [ "${KYT_SIGNER_SECRET:-}" = "null" ]; then
        echo "❌ Error: KYT signer secret is missing"
        exit 1
    fi
    local owner
    owner=$(stellar keys address demo_user)
    echo "🛂 Submitting ${label} through pool.transact with KYT authorization..."
    local kyt_json
    kyt_json=$(node "$DEMO_KYT_HELPER" \
        --owner "$owner" \
        --pool "$CONTRACT_ID" \
        --registry "$KYT_REGISTRY_ID" \
        --public-signals "$public_hex" \
        --secret "$KYT_SIGNER_SECRET" \
        --rpc-url "$RPC_URL" \
        --nonce "$ZK_CONFIG_NONCE")
    local expires signature
    expires=$(printf '%s' "$kyt_json" | jq -r '.expiresAtLedger')
    signature=$(printf '%s' "$kyt_json" | jq -r '.signature')
    local kyt_auth_json
    kyt_auth_json=$(jq -cn \
      --argjson expiration_ledger "$expires" \
      --arg signature "$signature" \
      '{expiration_ledger: $expiration_ledger, signature: $signature}')
    local tx_output=""
    set +e
    tx_output=$(stellar contract invoke \
      --id "$CONTRACT_ID" \
      --source demo_user \
      --network "$NETWORK" \
      -- transact \
      --from demo_user \
      --nonce "$ZK_CONFIG_NONCE" \
      --proof_bytes "$proof_hex" \
      --pub_signals_bytes "$public_hex" \
      --kyt_authorization "$kyt_auth_json" 2>&1)
    local tx_ec=$?
    set -e
    printf '%s\n' "$tx_output"
    if [ "$tx_ec" -ne 0 ]; then
      echo "❌ Error: ${label} transact failed"
      exit 1
    fi
    if [ "$label" = "deposit" ]; then
      DEPOSIT_TX_OUTPUT="$tx_output"
    fi
}

if [ "$USE_EXISTING_CONTRACT" = false ]; then
    # --- Full flow: keygen, deploy ---
    # Fund demo_user account if needed
    echo "🏦 Ensuring demo_user account is funded..."
    if ! stellar keys ls 2>/dev/null | grep -q "demo_user"; then
        echo "   Generating demo_user key..."
        stellar keys generate demo_user > /dev/null 2>&1
    fi
    echo "   Funding demo_user account..."
    stellar keys fund demo_user --network $NETWORK 2>&1 | grep -q "funded" && echo "   ✅ Account funded" || echo "⚠️  demo_user may already be funded"
    eval "$(stellar-audit keygen --export)"

    echo "Audit encryption key: $STELLAR_AUDIT_PUBLIC_KEY"
    echo "Audit decryption key: $STELLAR_AUDIT_PRIVATE_KEY"
    KYT_SIGNER_SECRET="${KYT_SIGNER_SECRET:-$(node -e "const {Keypair}=require('./client-sdk/node_modules/@stellar/stellar-sdk'); process.stdout.write(Keypair.random().secret());")}"
    export KYT_SIGNER_SECRET

    stellar keys rm private_sender --force 2>/dev/null || echo "⚠️  private_sender was not created"
    stellar keys rm private_receiver --force 2>/dev/null || echo "⚠️  private_receiver was not created"

    stellar keys generate private_sender
    stellar keys generate private_receiver --fund
    SENDER_ADDRESS=$(stellar keys address private_sender)
    RECEIVER_ADDRESS=$(stellar keys address private_receiver)

    echo "Hidden sender address: ${SENDER_ADDRESS}"
    echo "Hidden receiver address: ${RECEIVER_ADDRESS}"

    # Step 1: Build and deploy pool + private address registry
    echo "📦 Building contracts (pool + registry + KYT registry)..."
    (cd "$POOLS_DIR" && cargo build --target wasm32v1-none --release -p privacy-pools -p private-address-registry -p kyt-passage-registry) || { echo "❌ Error: Failed to build contracts"; exit 1; }
    echo "📦 Optimizing WASM..."
    stellar contract optimize --wasm "$POOLS_DIR/target/wasm32v1-none/release/privacy_pools.wasm" --wasm-out "$POOLS_DIR/target/wasm32v1-none/release/privacy_pools.optimized.wasm" || { echo "❌ Error: Failed to optimize pool WASM"; exit 1; }
    stellar contract optimize --wasm "$POOLS_DIR/target/wasm32v1-none/release/private_address_registry.wasm" --wasm-out "$POOLS_DIR/target/wasm32v1-none/release/private_address_registry.optimized.wasm" || { echo "❌ Error: Failed to optimize registry WASM"; exit 1; }
    stellar contract optimize --wasm "$POOLS_DIR/target/wasm32v1-none/release/kyt_passage_registry.wasm" --wasm-out "$POOLS_DIR/target/wasm32v1-none/release/kyt_passage_registry.optimized.wasm" || { echo "❌ Error: Failed to optimize KYT registry WASM"; exit 1; }

    echo "🚀 Deploying privacy pool to $NETWORK..."
    if ! DEPLOY_OUTPUT=$(stellar contract deploy --wasm "$POOLS_DIR/target/wasm32v1-none/release/privacy_pools.optimized.wasm" --source demo_user --network $NETWORK -- --tree_depth $TREE_DEPTH --admin demo_user 2>&1); then
        echo "❌ Error: Pool deployment failed"
        echo "$DEPLOY_OUTPUT"
        exit 1
    fi
    CONTRACT_ID=$(echo "$DEPLOY_OUTPUT" | grep -oE 'C[A-Z0-9]{55}' | tail -1)
    if [ -z "$CONTRACT_ID" ]; then
        echo "❌ Error: Failed to extract pool contract ID from deployment"
        echo "Deployment output:"
        echo "$DEPLOY_OUTPUT"
        exit 1
    fi
    echo "✅ Pool deployed with ID: $CONTRACT_ID"

    echo "🚀 Deploying private address registry to $NETWORK..."
    if ! REGISTRY_DEPLOY_OUTPUT=$(stellar contract deploy --wasm "$POOLS_DIR/target/wasm32v1-none/release/private_address_registry.optimized.wasm" --source demo_user --network $NETWORK -- --admin demo_user 2>&1); then
        echo "❌ Error: Registry deployment failed"
        echo "$REGISTRY_DEPLOY_OUTPUT"
        exit 1
    fi
    REGISTRY_ID=$(echo "$REGISTRY_DEPLOY_OUTPUT" | grep -oE 'C[A-Z0-9]{55}' | tail -1)
    if [ -z "$REGISTRY_ID" ]; then
        echo "❌ Error: Failed to extract registry contract ID from deployment"
        echo "Deployment output:"
        echo "$REGISTRY_DEPLOY_OUTPUT"
        exit 1
    fi
    echo "✅ Registry deployed with ID: $REGISTRY_ID"

    echo "🔗 Linking pool to registry (set_registry)..."
    retry_stellar_cmd "set_registry" stellar contract invoke --id "$CONTRACT_ID" --source demo_user --network "$NETWORK" -- set_registry --registry "$REGISTRY_ID" || { echo "❌ Error: set_registry failed"; exit 1; }
    echo "✅ Pool configured with registry"

    KYT_PUBLIC_KEY_HEX=$(node -e "const {Keypair}=require('./client-sdk/node_modules/@stellar/stellar-sdk'); const kp=Keypair.fromSecret(process.env.KYT_SIGNER_SECRET); process.stdout.write(Buffer.from(kp.rawPublicKey()).toString('hex'));")
    echo "🚀 Deploying KYT passage registry to $NETWORK..."
    if ! KYT_DEPLOY_OUTPUT=$(stellar contract deploy --wasm "$POOLS_DIR/target/wasm32v1-none/release/kyt_passage_registry.optimized.wasm" --source demo_user --network $NETWORK -- --admin demo_user --pool "$CONTRACT_ID" --kyt_public_key "$KYT_PUBLIC_KEY_HEX" --max_ttl_ledgers 500000 2>&1); then
        echo "❌ Error: KYT registry deployment failed"
        echo "$KYT_DEPLOY_OUTPUT"
        exit 1
    fi
    KYT_REGISTRY_ID=$(echo "$KYT_DEPLOY_OUTPUT" | grep -oE 'C[A-Z0-9]{55}' | tail -1)
    if [ -z "$KYT_REGISTRY_ID" ]; then
        echo "❌ Error: Failed to extract KYT registry contract ID from deployment"
        echo "Deployment output:"
        echo "$KYT_DEPLOY_OUTPUT"
        exit 1
    fi
    echo "✅ KYT registry deployed with ID: $KYT_REGISTRY_ID"
    sleep "$RETRY_DELAY_SEC"
    retry_stellar_cmd "set_kyt_registry" stellar contract invoke --id "$CONTRACT_ID" --source demo_user --network "$NETWORK" -- set_kyt_registry --kyt_registry "$KYT_REGISTRY_ID" || { echo "❌ Error: set_kyt_registry failed"; exit 1; }
    echo "✅ Pool configured with KYT registry"

    echo "🧬 Registering $ZK_CONFIG_SHAPE ZK config (nonce $ZK_CONFIG_NONCE)..."
    VK_STEM="main"
    if [ "$ZK_CONFIG_SHAPE" = "6x6" ]; then
      VK_STEM="main_6x6"
    fi
    VK_JSON="${VK_JSON:-$ARTIFACTS_DIR/${VK_STEM}_verification_key.json}"
    "$POOLS_DIR/scripts/add_zk_config.sh" --contract-id "$CONTRACT_ID" --network "$NETWORK" --admin demo_user \
      --nonce "$ZK_CONFIG_NONCE" --vk-json "$VK_JSON" --shape-json "$SHAPES_JSON" --shape-id "$ZK_CONFIG_SHAPE" || { echo "❌ Error: add_zk_config ($ZK_CONFIG_SHAPE) failed"; exit 1; }

    echo "💾 Saving deploy state to $DEPLOY_STATE_FILE..."
    jq -n \
        --arg pk "$STELLAR_AUDIT_PUBLIC_KEY" \
        --arg sk "$STELLAR_AUDIT_PRIVATE_KEY" \
        --arg cid "$CONTRACT_ID" \
        --arg rid "$REGISTRY_ID" \
        --arg kid "$KYT_REGISTRY_ID" \
        --arg ksk "$KYT_SIGNER_SECRET" \
        '{stellar_audit_public_key: $pk, stellar_audit_private_key: $sk, contract_id: $cid, registry_id: $rid, kyt_registry_id: $kid, kyt_signer_secret: $ksk}' > "$DEPLOY_STATE_FILE"

    # Check who the admin is
    echo "👤 Checking contract admin..."
    stellar contract invoke --id $CONTRACT_ID --source demo_user --network $NETWORK -- get_admin || { echo "❌ Error: Failed to get admin"; exit 1; }
else
    # --- Resume: only deposit/withdraw, reuse contract and audit keys ---
    stellar keys rm private_sender --force 2>/dev/null || echo "⚠️  private_sender was not created"
    stellar keys rm private_receiver --force 2>/dev/null || echo "⚠️  private_receiver was not created"
    stellar keys generate private_sender
    stellar keys generate private_receiver --fund
    SENDER_ADDRESS=$(stellar keys address private_sender)
    RECEIVER_ADDRESS=$(stellar keys address private_receiver)
    echo "Hidden sender address: ${SENDER_ADDRESS}"
    echo "Hidden receiver address: ${RECEIVER_ADDRESS}"
fi

echo "🔧 Ensuring client-sdk build (WASM + dist)..."
if [ ! -f client-sdk/pkg/client_sdk_wasm_bg.wasm ]; then
    (cd client-sdk && npm run build:wasm) || { echo "❌ wasm-pack build failed"; exit 1; }
fi
if [ ! -f client-sdk/dist/cli.js ] \
    || [ client-sdk/src/cli.ts -nt client-sdk/dist/cli.js ] \
    || [ client-sdk/src/kyt-flow.ts -nt client-sdk/dist/index.mjs ] \
    || [ client-sdk/src/kyt-passage.ts -nt client-sdk/dist/index.mjs ]; then
    (cd client-sdk && npm run build) || { echo "❌ client-sdk rollup build failed"; exit 1; }
fi

echo "🧩 Using local circuit artifacts from $ARTIFACTS_DIR..."
export ZK_ARTIFACT_BASE_URL="${ZK_ARTIFACT_BASE_URL:-$ARTIFACTS_DIR}"
[ -f "$ZK_ARTIFACT_BASE_URL/main.graph.bin" ] || { echo "❌ Missing $ZK_ARTIFACT_BASE_URL/main.graph.bin (run ./scripts/build-shape.sh 2x2 direct)"; exit 1; }
[ -f "$ZK_ARTIFACT_BASE_URL/main_proving_key.bin" ] || { echo "❌ Missing $ZK_ARTIFACT_BASE_URL/main_proving_key.bin"; exit 1; }
[ -f "$ZK_ARTIFACT_BASE_URL/main.r1cs.gz" ] || { echo "❌ Missing $ZK_ARTIFACT_BASE_URL/main.r1cs.gz"; exit 1; }
if [ "$ZK_PROFILE" = "6x6" ]; then
  [ -f "$ZK_ARTIFACT_BASE_URL/main_6x6.graph.bin" ] || { echo "❌ Missing $ZK_ARTIFACT_BASE_URL/main_6x6.graph.bin"; exit 1; }
  [ -f "$ZK_ARTIFACT_BASE_URL/main_6x6_proving_key.bin" ] || { echo "❌ Missing $ZK_ARTIFACT_BASE_URL/main_6x6_proving_key.bin"; exit 1; }
  [ -f "$ZK_ARTIFACT_BASE_URL/main_6x6.r1cs.gz" ] || { echo "❌ Missing $ZK_ARTIFACT_BASE_URL/main_6x6.r1cs.gz"; exit 1; }
fi

# --- Scalar, stealth (SEP-53 sign), aligned coin ---
echo "🔢 Random depositor ephemeral scalar..."
SCALAR_HEX=$(npm run --silent --prefix client-sdk cli -- random-scalar | tail -n 1 | tr -d '\r\n')

echo "🔏 Stealth sign message for receiver $RECEIVER_ADDRESS..."
STEALTH_MSG=$(npm run --silent --prefix client-sdk cli -- stealth-sign-message --address "$RECEIVER_ADDRESS" --network "$NETWORK" --pool "$CONTRACT_ID" --registry "$REGISTRY_ID")

echo "✍️  Stellar SEP-53 message sign (private_receiver)..."
set +e
# stellar message sign has no --network (local key only); do not pass global flags after subcommand.
SIGN_OUT=$(printf '%s' "$STEALTH_MSG" | stellar message sign --sign-with-key private_receiver 2>&1)
SIGN_EC=$?
set -e
SIG=$(extract_sep53_signature "$SIGN_OUT")
if [ "$SIGN_EC" -ne 0 ]; then
    echo "❌ Error: stellar message sign exited with $SIGN_EC"
    printf '%s\n' "$SIGN_OUT"
    exit 1
fi
if [ -z "$SIG" ]; then
    echo "❌ Error: could not parse signature (expected base64 or 128 hex) from stellar output:"
    printf '%s\n' "$SIGN_OUT"
    exit 1
fi

echo "🥷 Derive stealth address from signature..."
STEALTH=$(npm run --silent --prefix client-sdk cli -- stealth-from-signature --signature "$SIG" --network "$NETWORK" --pool "$CONTRACT_ID" --registry "$REGISTRY_ID" | tail -n 1 | tr -d '\r\n')
echo "Stealth address: $STEALTH"

register_private_address_in_registry "$STEALTH" private_receiver

echo "🪙 Generate coin (scalar + stealth ECDH), amount ${DEMO_AMOUNT_STROOPS} stroops..."
npm run --silent --prefix client-sdk cli -- generate --token "$TOKEN_ADDRESS" --scalar "$SCALAR_HEX" --stealth "$STEALTH" --amount "$DEMO_AMOUNT_STROOPS" -o ../demo_coin.json || { echo "❌ Error: Failed to generate coin"; exit 1; }

COMMITMENT_HEX=$(jq -r '.commitment_hex' demo_coin.json | sed 's/^0x//')
if [ -z "$COMMITMENT_HEX" ]; then
    echo "❌ Error: Failed to extract commitment hex"
    exit 1
fi
echo "Generated coin with commitment: $COMMITMENT_HEX"

# Audit CLI expects 32-byte field elements as hex; coin JSON stores Fr decimals (matches privacy-client decimalFieldToBytes).
COIN_VALUE=$(jq -r '.coin.value' demo_coin.json)
PRECOMM_HEX=$(node -e "const j=require('./demo_coin.json'); console.log(j.precommitement_hex)")
COIN_NULLIFIER_HEX=$(node -e "const j=require('./demo_coin.json'); console.log(BigInt(j.coin.nullifier).toString(16).padStart(64,'0'))")

echo "📌 Current Merkle root (decimal Fr for proof)..."
ROOT_CAPTURE=$(stellar contract invoke --id "$CONTRACT_ID" --source demo_user --network "$NETWORK" --send no -- get_merkle_root 2>&1) || true
STATE_ROOT_DEC=$(node "$STELLAR_FR_HELPER" bytes-fr "$ROOT_CAPTURE")

echo "🔐 Deposit transact proof..."
npm run --silent --prefix client-sdk cli -- deposit-proof \
  --profile "$ZK_PROFILE" \
  --state-root "$STATE_ROOT_DEC" \
  --stealth "$STEALTH" \
  --token "$TOKEN_ADDRESS" \
  --coin ../demo_coin.json \
  --ephemeral-scalar-hex "$SCALAR_HEX" \
  --output-proof ../demo_dep_proof.hex \
  --output-public ../demo_dep_pub.hex \
  >/dev/null
DEP_PROOF_HEX=$(tr -d '\r\n' < demo_dep_proof.hex)
DEP_PUB_HEX=$(tr -d '\r\n' < demo_dep_pub.hex)

echo "🔏 Audit deposit encrypt (receiver = stealth G-address, payload from demo_coin.json)..."
DEPOSIT_AUDIT_CT=$(stellar-audit encrypt deposit --receiver "$STEALTH" --value "$COIN_VALUE" --precommitement "$PRECOMM_HEX" --nullifier "$COIN_NULLIFIER_HEX" --asset "$TOKEN_ADDRESS")

submit_demo_kyt_transact "$DEP_PUB_HEX" "deposit" "$DEP_PROOF_HEX"
echo "Deposit successful!"

sleep "$RETRY_DELAY_SEC"

echo "📊 Checking balance..."
stellar contract invoke --id "$CONTRACT_ID" --source demo_user --network "$NETWORK" -- get_token_balance --token "$TOKEN_ADDRESS" || { echo "❌ Error: Failed to get balance"; exit 1; }

echo "📋 Syncing demo_state.json from on-chain get_commitments..."
# Stellar CLI 25+ returns a JSON array of 32-byte hex strings; older builds used Bytes(...) text.
# Fallback (deposit public only) is wrong once the pool has more history — Merkle witness then fails (ForceEqualIfEnabled).
sync_demo_commitments

COMMITMENT_DEC=$(jq -r '.coin.commitment' demo_coin.json)
EPH_LEAF_INDEX=$(jq -r --arg c "$COMMITMENT_DEC" '.commitments | index($c) | if . == null then error("coin commitment not in on-chain state") else . end' demo_state.json)

echo "📡 Depositor ephemeral (leaf $EPH_LEAF_INDEX) for withdraw witness..."
fetch_leaf_ephemeral_xy || exit 1

RECEIVER_PUB=$(stellar keys address private_receiver)
PK_HEX=$(stellar strkey decode "$RECEIVER_PUB" | jq -r '.public_key_ed25519')

echo "🔑 privKeyScalar from same SEP-53 signature (receiver)..."
PRIV_SCALAR_DEC=$(npm run --silent --prefix client-sdk cli -- priv-scalar-from-signature --signature "$SIG" --network "$NETWORK" --pool "$CONTRACT_ID" --registry "$REGISTRY_ID" | tail -n 1 | tr -d '\r\n')

echo "🔐 Withdrawal proof..."
npm run --silent --prefix client-sdk cli -- withdraw \
  --profile "$ZK_PROFILE" \
  --coin ../demo_coin.json \
  --state ../demo_state.json \
  --withdraw-pubkey-hex "$PK_HEX" \
  --priv-key-scalar "$PRIV_SCALAR_DEC" \
  --ephemeral-x "$EPH_X" \
  --ephemeral-y "$EPH_Y" \
  --output-proof ../demo_wd_proof.hex \
  --output-public ../demo_wd_pub.hex \
  >/dev/null
WD_PROOF_HEX=$(tr -d '\r\n' < demo_wd_proof.hex)
WD_PUB_HEX=$(tr -d '\r\n' < demo_wd_pub.hex)

echo "🔏 Audit withdraw encrypt (single-slot Transaction, fields from demo_coin.json)..."
WITHDRAW_AUDIT_CT=$(stellar-audit encrypt withdraw --value "$COIN_VALUE" --precommitement "$PRECOMM_HEX" --nullifier "$COIN_NULLIFIER_HEX" --asset "$TOKEN_ADDRESS")

submit_demo_kyt_transact "$WD_PUB_HEX" "withdraw" "$WD_PROOF_HEX"
echo "Withdrawal successful!"

echo "✅ Verifying final balance..."
stellar contract invoke --id "$CONTRACT_ID" --source demo_user --network "$NETWORK" -- get_token_balance --token "$TOKEN_ADDRESS" || { echo "❌ Error: Failed to get final balance"; exit 1; }
echo "🎉 Demo completed successfully!"
