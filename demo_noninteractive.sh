#!/bin/bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"
POOLS_DIR="${POOLS_DIR:-$REPO_ROOT/soroban-privacy-pools}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-$REPO_ROOT/artifacts}"
SHAPES_JSON="${SHAPES_JSON:-$REPO_ROOT/shapes.json}"
[ -d "$POOLS_DIR" ] || { echo "missing POOLS_DIR=$POOLS_DIR (git submodule update --init)" >&2; exit 1; }

NETWORK="${NETWORK:-testnet}"
# Default XLM SAC on testnet (only used when USE_ISSUER_ASSETS=0).
TOKEN_ADDRESS="${TOKEN_ADDRESS:-CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC}"
# 1: USDT/USDC from local key `issuer` (mint on SAC) + optional XLM in round-robin. 0: single TOKEN_ADDRESS (e.g. XLM SAC).
USE_ISSUER_ASSETS="${USE_ISSUER_ASSETS:-1}"
# Asset codes issued by `issuer` (mint + trustlines only; not the full round order).
ISSUER_ASSET_CODES="${ISSUER_ASSET_CODES:-USDT USDC}"
# Per-cycle token order when USE_ISSUER_ASSETS=1. Include XLM for native (wrapped) SAC; USDT/USDC use issuer SAC.
ROUND_ROBIN_ASSETS="${ROUND_ROBIN_ASSETS:-USDT USDC XLM}"
# Native XLM Stellar Asset Contract id (optional). If empty, resolved via `stellar contract id asset --asset native`.
XLM_SAC_ADDRESS="${XLM_SAC_ADDRESS:-}"
# Number of deposit+withdraw cycles (alternates assets). Default 0 = run until Ctrl+C.
NUM_ROUNDS="${NUM_ROUNDS:-0}"
# Random deposit amount per cycle (stroops, 7 decimals for issued assets: 1 unit = 1e7 stroops).
MIN_DEPOSIT_STROOPS="${MIN_DEPOSIT_STROOPS:-400000000}"
MAX_DEPOSIT_STROOPS="${MAX_DEPOSIT_STROOPS:-900000000}"
# Partial withdraw: public amount W is random in [MIN_WITHDRAW_PERCENT, MAX_WITHDRAW_PERCENT] of deposit D (W < D; remainder stays in pool as a private note).
MIN_WITHDRAW_PERCENT="${MIN_WITHDRAW_PERCENT:-30}"
MAX_WITHDRAW_PERCENT="${MAX_WITHDRAW_PERCENT:-95}"
# Minted per user per asset on SAC before the demo (issuer-only mint).
MINT_PER_USER_STROOPS="${MINT_PER_USER_STROOPS:-10000000000000}"
DEMO_AMOUNT_STROOPS="${DEMO_AMOUNT_STROOPS:-1000000000}"
APPLICATION_ID="${APPLICATION_ID:-101}"
export APPLICATION_ID
export NOTE_AUDIT_PUBLIC_KEY_X="${NOTE_AUDIT_PUBLIC_KEY_X:-21605515851820432880964235241069234202284600780825340516808373216881770219365}"
export NOTE_AUDIT_PUBLIC_KEY_Y="${NOTE_AUDIT_PUBLIC_KEY_Y:-18856460861531942120859708048677603751294231190189224157283439874962410808705}"
TREE_DEPTH="${TREE_DEPTH:-20}"
CSV_FILE="${CSV_FILE:-demo_noninteractive.csv}"
FAILED_SUBMIT_XDR_FILE="${FAILED_SUBMIT_XDR_FILE:-demo_noninteractive_failed_submit.xdr}"
MAX_RETRIES="${MAX_RETRIES:-5}"
RETRY_DELAY_SEC="${RETRY_DELAY_SEC:-2}"
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
KYT_SIGNER_SECRET="${KYT_SIGNER_SECRET:-$(node -e "const {Keypair}=require('./client-sdk/node_modules/@stellar/stellar-sdk'); process.stdout.write(Keypair.random().secret());")}"
RPC_URL="${STELLAR_RPC_URL:-https://soroban-testnet.stellar.org}"

STELLAR_FR_HELPER="$REPO_ROOT/scripts/demo-stellar-fr.mjs"
DEMO_KYT_HELPER="$REPO_ROOT/scripts/demo-kyt-passage.mjs"
TMP_DIR="$REPO_ROOT/.demo_noninteractive_tmp"
STATE_FILE="$TMP_DIR/state.json"
COIN_FILE="$TMP_DIR/coin.json"
DEP_PROOF_FILE="$TMP_DIR/dep_proof.hex"
DEP_PUB_FILE="$TMP_DIR/dep_pub.hex"
WD_PROOF_FILE="$TMP_DIR/wd_proof.hex"
WD_PUB_FILE="$TMP_DIR/wd_pub.hex"

mkdir -p "$TMP_DIR"
trap 'rm -rf "$TMP_DIR"' EXIT

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing command: $1" >&2
    exit 1
  }
}

now_ms() {
  node -e 'process.stdout.write(String(Date.now()))'
}

retry_cmd() {
  local description="$1"
  shift
  local attempt=1
  while true; do
    if "$@"; then
      return 0
    fi
    if [ "$attempt" -ge "$MAX_RETRIES" ]; then
      echo "Retry limit reached: $description" >&2
      return 1
    fi
    attempt=$((attempt + 1))
    sleep "$RETRY_DELAY_SEC"
  done
}

# Registers the receiver's permanent private-address public key (decoded from their stpl1
# stealth address) in the private-address registry, so senders can resolve it by Stellar
# address instead of requiring an onboarding round-trip. No-op (idempotent) on re-runs.
register_private_address_in_registry() {
  local stealth="$1"
  local owner_identity="$2"
  if [ -z "${REGISTRY_ID:-}" ] || [ "${REGISTRY_ID:-}" = "null" ]; then
    return 0
  fi
  local xy x y
  xy="$(npm run --silent --prefix client-sdk cli -- stealth-pubkey-hex --stealth "$stealth")"
  x="$(printf '%s\n' "$xy" | sed -n '1p')"
  y="$(printf '%s\n' "$xy" | sed -n '2p')"
  retry_cmd "register_private_address for ${owner_identity}" stellar contract invoke --id "$REGISTRY_ID" --source "$owner_identity" --network "$NETWORK" -- \
    register_private_address --owner "$owner_identity" --public_key_x "$x" --public_key_y "$y" >/dev/null
}

extract_sep53_signature() {
  printf '%s\n' "$1" | awk '
    /^[0-9a-fA-F]{128}$/ { sig = $0 }
    /^[A-Za-z0-9+\/]+=*$/ && length($0) >= 80 { sig = $0 }
    END { if (sig != "") print sig }
  ' | tr -d '\r\n'
}

parse_submit_metrics() {
  local submit_output="$1"
  TX_HASH="$(printf '%s\n' "$submit_output" | sed -nE 's/.*Signing transaction: ([0-9a-fA-F]{64}).*/\1/p' | tail -n 1 | tr 'A-F' 'a-f')"
  TX_FEE="$(printf '%s\n' "$submit_output" | sed -nE 's/.*Fee Charged: ([0-9]+).*/\1/p' | tail -n 1)"
  TX_GAS="$(printf '%s\n' "$submit_output" | sed -nE 's/.*Non-Refundable: ([0-9]+).*/\1/p' | tail -n 1)"
  if [ -z "${TX_GAS:-}" ]; then
    TX_GAS="$(printf '%s\n' "$submit_output" | sed -nE 's/.*cpu instructions[^0-9]*([0-9]+).*/\1/p' | tail -n 1)"
  fi
  if [ -z "${TX_HASH:-}" ]; then
    TX_HASH="unknown"
  fi
  if [ -z "${TX_FEE:-}" ]; then
    TX_FEE="unknown"
  fi
  if [ -z "${TX_GAS:-}" ]; then
    TX_GAS="unknown"
  fi
}

extract_xdr_from_output() {
  local output="$1"
  printf '%s\n' "$output" | awk '
    /^[A-Za-z0-9+\/=]+$/ && length($0) > 100 { xdr = $0 }
    END { if (xdr != "") print xdr }
  '
}

build_and_save_failed_submit_xdr() {
  local proof_hex="$1"
  local public_hex="$2"
  local kyt_auth_json="$3"
  local build_output=""
  local xdr=""

  set +e
  build_output="$(stellar contract invoke --id "$CONTRACT_ID" --source demo_user --network "$NETWORK" --build-only -- transact \
    --from demo_user \
    --nonce "$ZK_CONFIG_NONCE" \
    --proof_bytes "$proof_hex" \
    --pub_signals_bytes "$public_hex" \
    --kyt_authorization "$kyt_auth_json" 2>&1)"
  set -e

  xdr="$(extract_xdr_from_output "$build_output")"
  if [ -n "$xdr" ]; then
    printf '%s\n' "$xdr" > "$FAILED_SUBMIT_XDR_FILE"
  else
    : > "$FAILED_SUBMIT_XDR_FILE"
  fi
}

build_kyt_authorization_json() {
  local public_hex="$1"
  local owner
  owner="$(stellar keys address demo_user)"
  local kyt_json
  kyt_json="$(node "$DEMO_KYT_HELPER" \
    --owner "$owner" \
    --pool "$CONTRACT_ID" \
    --registry "$KYT_REGISTRY_ID" \
    --public-signals "$public_hex" \
    --secret "$KYT_SIGNER_SECRET" \
    --rpc-url "$RPC_URL" \
    --nonce "$ZK_CONFIG_NONCE")"
  local expires
  local signature
  expires="$(printf '%s' "$kyt_json" | jq -r '.expiresAtLedger')"
  signature="$(printf '%s' "$kyt_json" | jq -r '.signature')"
  jq -cn \
    --argjson expiration_ledger "$expires" \
    --arg signature "$signature" \
    '{expiration_ledger: $expiration_ledger, signature: $signature}'
}

log_failed_submit_details() {
  local tx_type="$1"
  local proof_ts="$2"
  parse_submit_metrics "$SUBMIT_OUTPUT"
  local tx_url
  tx_url="$(stellar_expert_url "$TX_HASH")"
  echo "failed_submit tx_type=$tx_type loop=$LOOP_INDEX tx_index=$TX_INDEX proof_ts=$proof_ts fee=$TX_FEE gas=$TX_GAS tx_hash=$TX_HASH url=$tx_url exit_code=${SUBMIT_EXIT_CODE:-unknown}"
  echo "failed_submit_output_begin"
  printf '%s\n' "$SUBMIT_OUTPUT"
  echo "failed_submit_output_end"
}

stellar_expert_url() {
  local tx_hash="$1"
  if [ "$NETWORK" = "testnet" ]; then
    printf 'https://stellar.expert/explorer/testnet/tx/%s' "$tx_hash"
    return
  fi
  if [ "$NETWORK" = "public" ] || [ "$NETWORK" = "pubnet" ]; then
    printf 'https://stellar.expert/explorer/public/tx/%s' "$tx_hash"
    return
  fi
  printf 'https://stellar.expert/explorer/%s/tx/%s' "$NETWORK" "$tx_hash"
}

horizon_base_url() {
  case "${NETWORK}" in
    testnet) echo "${HORIZON_URL:-https://horizon-testnet.stellar.org}" ;;
    futurenet) echo "${HORIZON_URL:-https://horizon-futurenet.stellar.org}" ;;
    public | pubnet) echo "${HORIZON_URL:-https://horizon.stellar.org}" ;;
    *) echo "" ;;
  esac
}

horizon_asset_exists() {
  local code="$1"
  local issuer="$2"
  local base
  base="$(horizon_base_url)"
  [ -n "$base" ] || return 1
  curl -sf "${base}/assets?asset_code=${code}&asset_issuer=${issuer}" | jq -e '._embedded.records | length > 0' >/dev/null 2>&1
}

random_stroops_between() {
  node -e '
    const min = BigInt(process.argv[1]);
    const max = BigInt(process.argv[2]);
    const span = Number(max - min);
    if (!Number.isFinite(span) || span < 0) process.exit(1);
    const r = min + BigInt(Math.floor(Math.random() * (span + 1)));
    process.stdout.write(r.toString());
  ' "$1" "$2"
}

ensure_issuer_key() {
  if ! stellar keys ls 2>/dev/null | grep -qx 'issuer'; then
    echo "Generating local Stellar identity 'issuer'..."
    stellar keys generate issuer
  fi
  stellar keys fund issuer --network "$NETWORK" >/dev/null 2>&1 || true
}

sac_id_for_classic_asset() {
  local code="$1"
  local issuer_g="$2"
  stellar contract id asset --asset "${code}:${issuer_g}" --network "$NETWORK" 2>/dev/null | tail -1 | tr -d '\r\n'
}

deploy_sac_for_asset_line() {
  local line="$1"
  set +e
  stellar contract asset deploy --asset "$line" --source-account issuer --network "$NETWORK" >/dev/null 2>&1
  set -e
}

# SAC mint credits the account's Soroban balance but Stellar still requires a classic trustline to the asset first.
ensure_classic_trustline() {
  local line="$1"
  local identity="$2"
  retry_cmd "change-trust ${line} for ${identity}" stellar tx new change-trust \
    --network "$NETWORK" \
    --source-account "$identity" \
    --line "$line" \
    --sign-with-key "$identity"
}

mint_sac_to_identity() {
  local sac_id="$1"
  local to_identity="$2"
  local amount="$3"
  local to_addr
  to_addr="$(stellar keys address "$to_identity")"
  retry_cmd "mint SAC to ${to_identity}" stellar contract invoke \
    --id "$sac_id" \
    --source issuer \
    --network "$NETWORK" \
    -- \
    mint \
    --to "$to_addr" \
    --amount "$amount"
}

# Ensures issuer key, USDT/USDC SAC deployed, and mints test tokens to demo_user + private_receiver.
# Horizon is used only to log whether classic assets were already indexed (optional).
setup_issuer_usdt_usdc() {
  require_cmd curl
  ensure_issuer_key
  ISSUER_ADDR="$(stellar keys address issuer | tr -d '\r\n')"
  echo "Issuer account: ${ISSUER_ADDR}"

  for code in $ISSUER_ASSET_CODES; do
    local line="${code}:${ISSUER_ADDR}"
    local hb
    hb="$(horizon_base_url)"
    if [ -n "$hb" ]; then
      if horizon_asset_exists "$code" "$ISSUER_ADDR"; then
        echo "   Horizon: asset ${code}:${ISSUER_ADDR} is already indexed"
      else
        echo "   Horizon: no ${code} yet for this issuer (will deploy/mint)"
      fi
    fi
    echo "   Deploying SAC for ${line} (no-op if already deployed)..."
    deploy_sac_for_asset_line "$line"
    SAC_ID="$(sac_id_for_classic_asset "$code" "$ISSUER_ADDR")"
    if [ -z "$SAC_ID" ] || [ "${#SAC_ID}" -lt 50 ]; then
      echo "Failed to resolve SAC contract id for ${line}" >&2
      exit 1
    fi
    echo "   ${code} SAC: ${SAC_ID}"
    echo "   Classic trustlines for ${line} (required before mint)..."
    ensure_classic_trustline "$line" demo_user
    ensure_classic_trustline "$line" private_receiver
    echo "   Minting ${MINT_PER_USER_STROOPS} stroops of ${code} to demo_user and private_receiver..."
    mint_sac_to_identity "$SAC_ID" demo_user "$MINT_PER_USER_STROOPS"
    mint_sac_to_identity "$SAC_ID" private_receiver "$MINT_PER_USER_STROOPS"
  done

  export ISSUER_ADDR
  echo "Issuer SAC contract ids:"
  for c in $ISSUER_ASSET_CODES; do
    echo "  ${c}: $(sac_id_for_classic_asset "$c" "$ISSUER_ADDR")"
  done
}

ensure_demo_user() {
  if ! stellar keys ls 2>/dev/null | awk '$1=="demo_user"{found=1} END{exit(found?0:1)}'; then
    stellar keys generate demo_user >/dev/null 2>&1
  fi
  stellar keys fund demo_user --network "$NETWORK" >/dev/null 2>&1 || true
}

prepare_receiver_key() {
  stellar keys rm private_receiver --force >/dev/null 2>&1 || true
  stellar keys generate private_receiver --fund >/dev/null 2>&1
}

build_and_deploy_contract() {
  (cd "$POOLS_DIR" && cargo build --target wasm32v1-none --release -p privacy-pools -p private-address-registry -p kyt-passage-registry >/dev/null)
  stellar contract optimize \
    --wasm "$POOLS_DIR/target/wasm32v1-none/release/privacy_pools.wasm" \
    --wasm-out "$POOLS_DIR/target/wasm32v1-none/release/privacy_pools.optimized.wasm" \
    >/dev/null 2>&1
  stellar contract optimize \
    --wasm "$POOLS_DIR/target/wasm32v1-none/release/private_address_registry.wasm" \
    --wasm-out "$POOLS_DIR/target/wasm32v1-none/release/private_address_registry.optimized.wasm" \
    >/dev/null 2>&1
  stellar contract optimize \
    --wasm "$POOLS_DIR/target/wasm32v1-none/release/kyt_passage_registry.wasm" \
    --wasm-out "$POOLS_DIR/target/wasm32v1-none/release/kyt_passage_registry.optimized.wasm" \
    >/dev/null 2>&1

  local deploy_output
  set +e
  deploy_output=$(stellar contract deploy \
    --wasm "$POOLS_DIR/target/wasm32v1-none/release/privacy_pools.optimized.wasm" \
    --source demo_user \
    --network "$NETWORK" \
    -- \
    --tree_depth "$TREE_DEPTH" \
    --admin demo_user 2>&1)
  local deploy_ec=$?
  set -e
  if [ "$deploy_ec" -ne 0 ]; then
    printf '%s\n' "$deploy_output" >&2
    exit 1
  fi

  CONTRACT_ID="$(printf '%s\n' "$deploy_output" | sed -nE 's/.*(C[A-Z0-9]{55}).*/\1/p' | tail -n 1)"
  if [ -z "${CONTRACT_ID:-}" ]; then
    echo "Failed to parse deployed contract id" >&2
    exit 1
  fi

  local registry_output
  set +e
  registry_output=$(stellar contract deploy \
    --wasm "$POOLS_DIR/target/wasm32v1-none/release/private_address_registry.optimized.wasm" \
    --source demo_user \
    --network "$NETWORK" \
    -- \
    --admin demo_user 2>&1)
  local registry_ec=$?
  set -e
  if [ "$registry_ec" -ne 0 ]; then
    printf '%s\n' "$registry_output" >&2
    exit 1
  fi

  REGISTRY_ID="$(printf '%s\n' "$registry_output" | sed -nE 's/.*(C[A-Z0-9]{55}).*/\1/p' | tail -n 1)"
  if [ -z "${REGISTRY_ID:-}" ]; then
    echo "Failed to parse deployed registry id" >&2
    exit 1
  fi

  local kyt_public_key_hex
  kyt_public_key_hex="$(node -e "const {Keypair}=require('./client-sdk/node_modules/@stellar/stellar-sdk'); process.stdout.write(Buffer.from(Keypair.fromSecret(process.argv[1]).rawPublicKey()).toString('hex'));" "$KYT_SIGNER_SECRET")"
  local kyt_registry_output
  set +e
  kyt_registry_output=$(stellar contract deploy \
    --wasm "$POOLS_DIR/target/wasm32v1-none/release/kyt_passage_registry.optimized.wasm" \
    --source demo_user \
    --network "$NETWORK" \
    -- \
    --admin demo_user \
    --pool "$CONTRACT_ID" \
    --kyt_public_key "$kyt_public_key_hex" \
    --max_ttl_ledgers 500000 2>&1)
  local kyt_registry_ec=$?
  set -e
  if [ "$kyt_registry_ec" -ne 0 ]; then
    printf '%s\n' "$kyt_registry_output" >&2
    exit 1
  fi

  KYT_REGISTRY_ID="$(printf '%s\n' "$kyt_registry_output" | sed -nE 's/.*(C[A-Z0-9]{55}).*/\1/p' | tail -n 1)"
  if [ -z "${KYT_REGISTRY_ID:-}" ]; then
    echo "Failed to parse deployed KYT registry id" >&2
    exit 1
  fi

  stellar contract invoke --id "$CONTRACT_ID" --source demo_user --network "$NETWORK" -- set_registry --registry "$REGISTRY_ID" >/dev/null
  stellar contract invoke --id "$CONTRACT_ID" --source demo_user --network "$NETWORK" -- set_kyt_registry --kyt_registry "$KYT_REGISTRY_ID" >/dev/null

  VK_STEM="main"
  if [ "$ZK_CONFIG_SHAPE" = "6x6" ]; then
    VK_STEM="main_6x6"
  fi
  VK_JSON="${VK_JSON:-$ARTIFACTS_DIR/${VK_STEM}_verification_key.json}"
  "$POOLS_DIR/scripts/add_zk_config.sh" --contract-id "$CONTRACT_ID" --network "$NETWORK" --admin demo_user \
    --nonce "$ZK_CONFIG_NONCE" --vk-json "$VK_JSON" --shape-json "$SHAPES_JSON" --shape-id "$ZK_CONFIG_SHAPE" >/dev/null
}

ensure_client_assets() {
  if [ ! -f client-sdk/pkg/client_sdk_wasm_bg.wasm ]; then
    (cd client-sdk && npm run build:wasm >/dev/null)
  fi
  if [ ! -f client-sdk/dist/cli.js ]; then
    (cd client-sdk && npm run build >/dev/null)
  fi
  export ZK_ARTIFACT_BASE_URL="${ZK_ARTIFACT_BASE_URL:-$ARTIFACTS_DIR}"
}

get_state_root() {
  local capture
  capture="$(stellar contract invoke --id "$CONTRACT_ID" --source demo_user --network "$NETWORK" --send no -- get_merkle_root 2>&1)" || return 1
  STATE_ROOT_DEC="$(node "$STELLAR_FR_HELPER" bytes-fr "$capture" 2>/dev/null)" || return 1
  [ -n "${STATE_ROOT_DEC:-}" ]
}

sync_state_and_leaf() {
  local commitments_capture
  commitments_capture="$(stellar contract invoke --id "$CONTRACT_ID" --source demo_user --network "$NETWORK" --send no -- get_commitments 2>&1)" || return 1
  node "$STELLAR_FR_HELPER" commitments-from-output "$commitments_capture" > "$STATE_FILE" 2>/dev/null || return 1
  EPH_LEAF_INDEX="$(jq -r --arg c "$COMMITMENT_DEC" '.commitments | index($c) | if . == null then error("not found") else . end' "$STATE_FILE" 2>/dev/null)" || return 1
  [ -n "${EPH_LEAF_INDEX:-}" ]
}

get_leaf_ephemeral() {
  local eph_capture eph_xy
  eph_capture="$(stellar contract invoke --id "$CONTRACT_ID" --source demo_user --network "$NETWORK" --send no -- get_leaf_ephemeral --leaf_index "$EPH_LEAF_INDEX" 2>&1)" || return 1
  eph_xy="$(node "$STELLAR_FR_HELPER" ephemeral-xy "$eph_capture" 2>/dev/null)" || return 1
  EPH_X="$(printf '%s\n' "$eph_xy" | sed -n '1p')"
  EPH_Y="$(printf '%s\n' "$eph_xy" | sed -n '2p')"
  [ -n "${EPH_X:-}" ] && [ -n "${EPH_Y:-}" ]
}

submit_transact() {
  local proof_hex="$1"
  local public_hex="$2"
  local kyt_auth_json
  kyt_auth_json="$(build_kyt_authorization_json "$public_hex")"
  local output=""

  set +e
  output="$(stellar contract invoke --id "$CONTRACT_ID" --source demo_user --network "$NETWORK" --cost -- transact \
    --from demo_user \
    --nonce "$ZK_CONFIG_NONCE" \
    --proof_bytes "$proof_hex" \
    --pub_signals_bytes "$public_hex" \
    --kyt_authorization "$kyt_auth_json" 2>&1)"
  local ec=$?
  set -e

  SUBMIT_EXIT_CODE="$ec"
  SUBMIT_OUTPUT="$output"
  SUBMIT_KYT_AUTH_JSON="$kyt_auth_json"
  return "$ec"
}

# Resolves native XLM SAC once (used when ROUND_ROBIN includes XLM).
resolve_xlm_sac_address() {
  if [ -n "${XLM_SAC_ADDRESS:-}" ]; then
    export XLM_SAC_ADDRESS
    echo "XLM SAC (from env): ${XLM_SAC_ADDRESS}"
    return
  fi
  local out
  out="$(stellar contract id asset --asset native --network "$NETWORK" 2>/dev/null | tail -1 | tr -d '\r\n')" || true
  if [ -n "$out" ] && [ "${#out}" -ge 50 ]; then
    XLM_SAC_ADDRESS="$out"
  else
    XLM_SAC_ADDRESS="${TOKEN_ADDRESS:-CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC}"
    echo "Warning: could not resolve native SAC via CLI; using default XLM SAC ${XLM_SAC_ADDRESS}" >&2
  fi
  export XLM_SAC_ADDRESS
  echo "XLM SAC: ${XLM_SAC_ADDRESS}"
}

# Sets TOKEN_ADDRESS and ASSET_LABEL for the current LOOP_INDEX (ROUND_ROBIN_ASSETS: USDT / USDC / XLM / …).
pick_token_for_round() {
  if [ "$USE_ISSUER_ASSETS" = "1" ]; then
    read -r -a codes <<< "${ROUND_ROBIN_ASSETS:-USDT USDC XLM}"
    local n=${#codes[@]}
    if [ "$n" -eq 0 ]; then
      echo "ROUND_ROBIN_ASSETS is empty" >&2
      exit 1
    fi
    local idx=$(( (LOOP_INDEX - 1) % n ))
    local sym
    sym="$(printf '%s' "${codes[$idx]}" | tr '[:lower:]' '[:upper:]')"
    case "$sym" in
      XLM | NATIVE)
        ASSET_LABEL="XLM"
        TOKEN_ADDRESS="$XLM_SAC_ADDRESS"
        ;;
      *)
        ASSET_LABEL="$sym"
        TOKEN_ADDRESS="$(sac_id_for_classic_asset "$sym" "$ISSUER_ADDR")"
        ;;
    esac
  else
    ASSET_LABEL="${SINGLE_ASSET_LABEL:-TOKEN}"
  fi
}

append_csv_row() {
  local tx_type="$1"
  local cycle="$2"
  local amount="$3"
  local proof_ts="$4"
  local proof_ms="$5"
  local fee="$6"
  local gas="$7"
  local url="$8"
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$TX_INDEX" "$tx_type" "$cycle" "$ASSET_LABEL" "$amount" \
    "$proof_ts" "$proof_ms" "$fee" "$gas" "$url" >> "$CSV_FILE"
}

# Pick public withdraw stroops W so MIN_WITHDRAW_PERCENT%*D <= W <= MAX_WITHDRAW_PERCENT%*D and W < D.
pick_public_withdraw_stroops() {
  local d="$1"
  node -e '
    const D = BigInt(process.argv[1]);
    const loP = BigInt(process.argv[2]);
    const hiP = BigInt(process.argv[3]);
    let lo = (D * loP) / 100n;
    let hi = (D * hiP) / 100n;
    if (lo < 1n) lo = 1n;
    if (hi >= D) hi = D - 1n;
    if (hi <= lo) {
      console.error("deposit too small for withdraw range (raise MIN_DEPOSIT_STROOPS or adjust MIN_/MAX_WITHDRAW_PERCENT)");
      process.exit(1);
    }
    const span = Number(hi - lo);
    const w = lo + BigInt(Math.floor(Math.random() * (span + 1)));
    process.stdout.write(w.toString());
  ' "$d" "${MIN_WITHDRAW_PERCENT:-30}" "${MAX_WITHDRAW_PERCENT:-95}"
}

# One deposit + withdraw for current TOKEN_ADDRESS / ASSET_LABEL / DEMO_AMOUNT_STROOPS and LOOP_INDEX.
run_deposit_withdraw_cycle() {
  SCALAR_HEX="$(npm run --silent --prefix client-sdk cli -- random-scalar | tail -n 1 | tr -d '\r\n')"
  STEALTH_MSG="$(npm run --silent --prefix client-sdk cli -- stealth-sign-message \
    --address "$RECEIVER_ADDRESS" \
    --network "$NETWORK" \
    --pool "$CONTRACT_ID" \
    --registry "$REGISTRY_ID" | tail -n 1)"

  set +e
  SIGN_OUT="$(printf '%s' "$STEALTH_MSG" | stellar message sign --sign-with-key private_receiver 2>&1)"
  SIGN_EC=$?
  set -e
  if [ "$SIGN_EC" -ne 0 ]; then
    echo "stop: signature generation failed on loop $LOOP_INDEX" >&2
    return 1
  fi

  SIG="$(extract_sep53_signature "$SIGN_OUT")"
  if [ -z "$SIG" ]; then
    echo "stop: signature parse failed on loop $LOOP_INDEX" >&2
    return 1
  fi

  STEALTH="$(npm run --silent --prefix client-sdk cli -- stealth-from-signature \
    --signature "$SIG" \
    --network "$NETWORK" \
    --pool "$CONTRACT_ID" \
    --registry "$REGISTRY_ID" | tail -n 1 | tr -d '\r\n')"

  register_private_address_in_registry "$STEALTH" private_receiver

  npm run --silent --prefix client-sdk cli -- generate \
    --token "$TOKEN_ADDRESS" \
    --scalar "$SCALAR_HEX" \
    --stealth "$STEALTH" \
    --amount "$DEMO_AMOUNT_STROOPS" \
    -o "$COIN_FILE" \
    >/dev/null

  COMMITMENT_DEC="$(jq -r '.coin.commitment' "$COIN_FILE")"
  COIN_VALUE="$(jq -r '.coin.value' "$COIN_FILE")"
  PUBLIC_WITHDRAW_STROOPS="$(pick_public_withdraw_stroops "$COIN_VALUE")"
  PRECOMM_HEX="$(jq -r '.precommitement_hex' "$COIN_FILE")"
  COIN_NULLIFIER_HEX="$(node -e "const j=require('$COIN_FILE');process.stdout.write(BigInt((j.coin||j).nullifier).toString(16).padStart(64,'0'))")"

  retry_cmd "state root sync" get_state_root

  PROOF_START_MS="$(now_ms)"
  retry_cmd "deposit proof generation" npm run --silent --prefix client-sdk cli -- deposit-proof \
    --profile "$ZK_PROFILE" \
    --state-root "$STATE_ROOT_DEC" \
    --stealth "$STEALTH" \
    --token "$TOKEN_ADDRESS" \
    --coin "$COIN_FILE" \
    --ephemeral-scalar-hex "$SCALAR_HEX" \
    --output-proof "$DEP_PROOF_FILE" \
    --output-public "$DEP_PUB_FILE" \
    >/dev/null
  DEP_PROOF_MS="$(( $(now_ms) - PROOF_START_MS ))"
  DEP_PROOF_TS="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

  DEP_PROOF_HEX="$(tr -d '\r\n' < "$DEP_PROOF_FILE")"
  DEP_PUB_HEX="$(tr -d '\r\n' < "$DEP_PUB_FILE")"
  if ! submit_transact "$DEP_PROOF_HEX" "$DEP_PUB_HEX"; then
    build_and_save_failed_submit_xdr "$DEP_PROOF_HEX" "$DEP_PUB_HEX" "$SUBMIT_KYT_AUTH_JSON"
    log_failed_submit_details "deposit" "$DEP_PROOF_TS"
    echo "failed_submit_xdr_file=$FAILED_SUBMIT_XDR_FILE"
    echo "stop: submit error on deposit in loop $LOOP_INDEX"
    return 1
  fi

  parse_submit_metrics "$SUBMIT_OUTPUT"
  TX_INDEX=$((TX_INDEX + 1))
  DEP_URL="$(stellar_expert_url "$TX_HASH")"
  append_csv_row "deposit" "$LOOP_INDEX" "$COIN_VALUE" "$DEP_PROOF_TS" "$DEP_PROOF_MS" "$TX_FEE" "$TX_GAS" "$DEP_URL"
  echo "tx#$TX_INDEX deposit ($ASSET_LABEL) $DEP_URL proof_ms=$DEP_PROOF_MS fee=$TX_FEE gas=$TX_GAS deposit_stroops=$COIN_VALUE"

  retry_cmd "state commitments sync" sync_state_and_leaf
  retry_cmd "leaf ephemeral sync" get_leaf_ephemeral

  PRIV_SCALAR_DEC="$(npm run --silent --prefix client-sdk cli -- priv-scalar-from-signature \
    --signature "$SIG" \
    --network "$NETWORK" \
    --pool "$CONTRACT_ID" \
    --registry "$REGISTRY_ID" | tail -n 1 | tr -d '\r\n')"

  PROOF_START_MS="$(now_ms)"
  retry_cmd "withdraw proof generation" npm run --silent --prefix client-sdk cli -- withdraw \
    --profile "$ZK_PROFILE" \
    --coin "$COIN_FILE" \
    --state "$STATE_FILE" \
    --withdraw-pubkey-hex "$RECEIVER_PUBKEY_HEX" \
    --priv-key-scalar "$PRIV_SCALAR_DEC" \
    --ephemeral-x "$EPH_X" \
    --ephemeral-y "$EPH_Y" \
    --public-withdraw-stroops "$PUBLIC_WITHDRAW_STROOPS" \
    --change-stealth "$STEALTH" \
    --output-proof "$WD_PROOF_FILE" \
    --output-public "$WD_PUB_FILE" \
    >/dev/null
  WD_PROOF_MS="$(( $(now_ms) - PROOF_START_MS ))"
  WD_PROOF_TS="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

  WD_PROOF_HEX="$(tr -d '\r\n' < "$WD_PROOF_FILE")"
  WD_PUB_HEX="$(tr -d '\r\n' < "$WD_PUB_FILE")"
  if ! submit_transact "$WD_PROOF_HEX" "$WD_PUB_HEX"; then
    build_and_save_failed_submit_xdr "$WD_PROOF_HEX" "$WD_PUB_HEX" "$SUBMIT_KYT_AUTH_JSON"
    log_failed_submit_details "withdraw" "$WD_PROOF_TS"
    echo "failed_submit_xdr_file=$FAILED_SUBMIT_XDR_FILE"
    echo "stop: submit error on withdraw in loop $LOOP_INDEX"
    return 1
  fi

  parse_submit_metrics "$SUBMIT_OUTPUT"
  TX_INDEX=$((TX_INDEX + 1))
  WD_URL="$(stellar_expert_url "$TX_HASH")"
  append_csv_row "withdraw" "$LOOP_INDEX" "$PUBLIC_WITHDRAW_STROOPS" "$WD_PROOF_TS" "$WD_PROOF_MS" "$TX_FEE" "$TX_GAS" "$WD_URL"
  echo "tx#$TX_INDEX withdraw ($ASSET_LABEL) $WD_URL proof_ms=$WD_PROOF_MS fee=$TX_FEE gas=$TX_GAS withdraw_stroops=$PUBLIC_WITHDRAW_STROOPS (deposit was $COIN_VALUE)"
  return 0
}

require_cmd jq
require_cmd node
require_cmd stellar
require_cmd stellar-audit
require_cmd cargo
[ -f "$STELLAR_FR_HELPER" ] || { echo "Missing helper: $STELLAR_FR_HELPER" >&2; exit 1; }
[ -f "$DEMO_KYT_HELPER" ] || { echo "Missing helper: $DEMO_KYT_HELPER" >&2; exit 1; }
[ -f "$ARTIFACTS_DIR/main.graph.bin" ] || { echo "Missing $ARTIFACTS_DIR/main.graph.bin (run ./scripts/build-shape.sh 2x2 direct)" >&2; exit 1; }
[ -f "$ARTIFACTS_DIR/main_proving_key.bin" ] || { echo "Missing $ARTIFACTS_DIR/main_proving_key.bin" >&2; exit 1; }
[ -f "$ARTIFACTS_DIR/main.r1cs.gz" ] || { echo "Missing $ARTIFACTS_DIR/main.r1cs.gz" >&2; exit 1; }
if [ "$ZK_PROFILE" = "6x6" ]; then
  [ -f "$ARTIFACTS_DIR/main_6x6.graph.bin" ] || { echo "Missing $ARTIFACTS_DIR/main_6x6.graph.bin" >&2; exit 1; }
  [ -f "$ARTIFACTS_DIR/main_6x6_proving_key.bin" ] || { echo "Missing $ARTIFACTS_DIR/main_6x6_proving_key.bin" >&2; exit 1; }
  [ -f "$ARTIFACTS_DIR/main_6x6.r1cs.gz" ] || { echo "Missing $ARTIFACTS_DIR/main_6x6.r1cs.gz" >&2; exit 1; }
fi

ensure_demo_user
prepare_receiver_key
if [ "$USE_ISSUER_ASSETS" = "1" ]; then
  setup_issuer_usdt_usdc
  if echo " ${ROUND_ROBIN_ASSETS} " | grep -qiE '(^| )(xlm|native)( |$)'; then
    resolve_xlm_sac_address
  fi
fi
eval "$(stellar-audit keygen --export)"
build_and_deploy_contract
ensure_client_assets

echo "Audit encoding key: $STELLAR_AUDIT_PUBLIC_KEY"
echo "Audit decoding key: $STELLAR_AUDIT_PRIVATE_KEY"

echo "contract_id,$CONTRACT_ID"
echo "Note: withdraw amount_stroops is the public payout (less than deposit); the difference stays in the pool as a private change note."
printf 'tx_index,tx_type,cycle,asset_code,amount_stroops,proof_generated_at_utc,proof_generation_ms,fee_charged,gas_used,stellar_expert_url\n' > "$CSV_FILE"
rm -f "$FAILED_SUBMIT_XDR_FILE"

RECEIVER_ADDRESS="$(stellar keys address private_receiver)"
RECEIVER_PUBKEY_HEX="$(stellar strkey decode "$RECEIVER_ADDRESS" | jq -r '.public_key_ed25519')"

TX_INDEX=0

run_rounds() {
  pick_token_for_round
  DEMO_AMOUNT_STROOPS="$(random_stroops_between "${MIN_DEPOSIT_STROOPS}" "${MAX_DEPOSIT_STROOPS}")"
  echo "--- cycle $LOOP_INDEX asset=$ASSET_LABEL deposit_stroops=$DEMO_AMOUNT_STROOPS ---"
  if ! run_deposit_withdraw_cycle; then
    return 1
  fi
  return 0
}

if [ "${NUM_ROUNDS:-0}" -eq 0 ] 2>/dev/null; then
  LOOP_INDEX=1
  while true; do
    if ! run_rounds; then
      break
    fi
    LOOP_INDEX=$((LOOP_INDEX + 1))
  done
else
  _nr="${NUM_ROUNDS:-0}"
  for ((LOOP_INDEX = 1; LOOP_INDEX <= _nr; LOOP_INDEX++)); do
    if ! run_rounds; then
      break
    fi
  done
fi
