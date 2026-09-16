#!/usr/bin/env bash
# Non-interactive deposit against the staging pool that hits Core KYT inspect,
# then register_passage + pool.transact. Deposit-only (no withdraw).
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

export PATH="${HOME}/.cargo/bin:/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:${HOME}/.nvm/versions/node/v24.9.0/bin:${PATH:-}"
STELLAR_BIN="$(command -v stellar)"
log_pre() { printf '%s\n' "$*"; }
# Early version gate: SEP-53 `message sign` requires stellar-cli >= ~23.
if ! "$STELLAR_BIN" message --help >/dev/null 2>&1; then
  echo "stellar CLI at $STELLAR_BIN lacks 'message' (need ~/.cargo/bin/stellar 27+)" >&2
  exit 1
fi


NETWORK="${NETWORK:-testnet}"
TOKEN_ADDRESS="${TOKEN_ADDRESS:-CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC}"
DEMO_AMOUNT_STROOPS="${DEMO_AMOUNT_STROOPS:-100000000}"
ZK_CONFIG_NONCE="${ZK_CONFIG_NONCE:-2}"
RPC_URL="${STELLAR_RPC_URL:-https://soroban-testnet.stellar.org}"
CORE_API_URL="${CORE_API_URL:-https://privacy-layer-staging-backend-gf66o.ondigitalocean.app}"
DEPLOY_STATE_FILE="${DEPLOY_STATE_FILE:-demo_deploy_state.json}"
STELLAR_FR_HELPER="$REPO_ROOT/scripts/demo-stellar-fr.mjs"
SUBMIT_HELPER="$REPO_ROOT/scripts/staging-core-kyt-submit.mjs"
CLI=(node "$REPO_ROOT/client-sdk/dist/cli.js")
LOG="${LOG:-/tmp/staging-core-kyt-deposit.log}"
export ZK_ARTIFACT_BASE_URL="${ZK_ARTIFACT_BASE_URL:-$REPO_ROOT/artifacts}"

# Live staging App 1 (association.audit_id) + Storage SoT pubs (decimal Fr for circuit).
APPLICATION_ID="${APPLICATION_ID:-7268826780317162}"
export APPLICATION_ID
export NOTE_AUDIT_PUBLIC_KEY_X="${NOTE_AUDIT_PUBLIC_KEY_X:-16658271807730636882067958739162313032120068740802356101694075256555385248168}"
export NOTE_AUDIT_PUBLIC_KEY_Y="${NOTE_AUDIT_PUBLIC_KEY_Y:-11323916679659322582604594140572931036911087081522155237777516882395686330945}"

CONTRACT_ID="$(jq -r '.contract_id' "$DEPLOY_STATE_FILE")"
REGISTRY_ID="$(jq -r '.registry_id' "$DEPLOY_STATE_FILE")"
KYT_REGISTRY_ID="$(jq -r '.kyt_registry_id' "$DEPLOY_STATE_FILE")"

: > "$LOG"
log() { printf '%s\n' "$*" | tee -a "$LOG"; }

command -v jq >/dev/null
command -v node >/dev/null
command -v stellar >/dev/null
[ -f client-sdk/dist/cli.js ]
[ -f client-sdk/dist/index.mjs ]
[ -f "$STELLAR_FR_HELPER" ]
[ -f "$SUBMIT_HELPER" ]

extract_sep53_signature() {
  printf '%s\n' "$1" | awk '
    /^[0-9a-fA-F]{128}$/ { sig = $0 }
    /^[A-Za-z0-9+\/]+=*$/ && length($0) >= 80 { sig = $0 }
    END { if (sig != "") print sig }
  ' | tr -d '\r\n'
}

retry_stellar_cmd() {
  local label="$1"; shift
  local attempt=1
  until "$@"; do
    if [ "$attempt" -ge 5 ]; then
      log "retry exhausted: $label"
      return 1
    fi
    sleep 2
    attempt=$((attempt + 1))
  done
}

log "staging-core-kyt-deposit: core=$CORE_API_URL pool=$CONTRACT_ID app=$APPLICATION_ID amount=$DEMO_AMOUNT_STROOPS"

RECEIVER_ID="staging_receiver_$(date +%s)"
stellar keys generate "$RECEIVER_ID" --fund --network "$NETWORK" >>"$LOG" 2>&1
RECEIVER_ADDRESS="$(stellar keys address "$RECEIVER_ID")"
OWNER="$(stellar keys address demo_user)"
SOURCE_SECRET="$(stellar keys show demo_user)"

log "receiver_id=$RECEIVER_ID receiver=$RECEIVER_ADDRESS owner=$OWNER"

log "BEGIN random_scalar"
SCALAR_HEX="$("${CLI[@]}" random-scalar | tr -d '\r\n')"
log "SCALAR_HEX=$SCALAR_HEX"

log "BEGIN stealth_sign_message"
STEALTH_MSG="$("${CLI[@]}" stealth-sign-message --address "$RECEIVER_ADDRESS" | tr -d '\r\n')"
log "BEGIN message_sign"
SIGN_OUT="$(printf '%s' "$STEALTH_MSG" | stellar message sign --sign-with-key "$RECEIVER_ID" 2>&1)" || true
SIG="$(extract_sep53_signature "$SIGN_OUT")"
[ -n "$SIG" ] || { log "failed to parse SEP-53 signature"; printf '%s\n' "$SIGN_OUT" | tee -a "$LOG"; exit 1; }
log "BEGIN stealth_from_signature"
STEALTH="$("${CLI[@]}" stealth-from-signature --signature "$SIG" | tail -n 1 | tr -d '\r\n')"
log "stealth=$STEALTH"

log "BEGIN register_private_address"
PK_LINES="$("${CLI[@]}" stealth-pubkey-hex --stealth "$STEALTH")"
PK_X="$(printf '%s\n' "$PK_LINES" | sed -n '1p')"
PK_Y="$(printf '%s\n' "$PK_LINES" | sed -n '2p')"
retry_stellar_cmd register_private_address stellar contract invoke \
  --id "$REGISTRY_ID" --source "$RECEIVER_ID" --network "$NETWORK" -- \
  register_private_address --owner "$RECEIVER_ID" --public_key_x "$PK_X" --public_key_y "$PK_Y" >>"$LOG" 2>&1

log "BEGIN generate_coin"
"${CLI[@]}" generate \
  --token "$TOKEN_ADDRESS" \
  --scalar "$SCALAR_HEX" \
  --stealth "$STEALTH" \
  --amount "$DEMO_AMOUNT_STROOPS" \
  --application-id "$APPLICATION_ID" \
  -o demo_coin_staging.json >>"$LOG" 2>&1

log "BEGIN get_merkle_root"
ROOT_CAPTURE="$(stellar contract invoke --id "$CONTRACT_ID" --source demo_user --network "$NETWORK" --send no -- get_merkle_root 2>&1)" || true
STATE_ROOT_DEC="$(node "$STELLAR_FR_HELPER" bytes-fr "$ROOT_CAPTURE")"
log "STATE_ROOT_DEC=$STATE_ROOT_DEC"

log "BEGIN deposit_proof"
"${CLI[@]}" deposit-proof \
  --state-root "$STATE_ROOT_DEC" \
  --stealth "$STEALTH" \
  --token "$TOKEN_ADDRESS" \
  --coin demo_coin_staging.json \
  --ephemeral-scalar-hex "$SCALAR_HEX" \
  --application-id "$APPLICATION_ID" \
  --output-proof demo_dep_proof_staging.hex \
  --output-public demo_dep_pub_staging.hex \
  >>"$LOG" 2>&1

log "proof+public ready; submitting via Core KYT..."
export OWNER POOL="$CONTRACT_ID" KYT_REGISTRY="$KYT_REGISTRY_ID" CORE_API_URL \
  SOURCE_SECRET RPC_URL ZK_CONFIG_NONCE APPLICATION_ID \
  PROOF_HEX_FILE="$REPO_ROOT/demo_dep_proof_staging.hex" \
  PUBLIC_HEX_FILE="$REPO_ROOT/demo_dep_pub_staging.hex"

node "$SUBMIT_HELPER" 2>&1 | tee -a "$LOG"
log "staging-core-kyt-deposit: done"
