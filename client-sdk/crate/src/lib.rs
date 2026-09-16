pub mod coin;
pub mod convert;
pub mod derived_escrow;
pub mod groth16;
pub mod merkle;
pub mod params;
pub mod poseidon;
pub mod poseidon_opt;
pub mod poseidon_opt_params;
pub mod stealth;
pub mod utils;

pub use cryptography::{
    ecdh_ephemeral_public_key, ecdh_shared_key, CoordBytes, PointError, ScalarBytes,
};

use wasm_bindgen::prelude::*;

use crate::utils::decimal_to_fr_result;

/// Generate a new coin with random nullifier, secret, and owner public-key field elements.
/// `amount_decimal` is an arbitrary-precision decimal field element (never JS `number`).
/// `asset_hi_decimal` / `asset_lo_decimal` are decimal Fr strings for the Stellar asset contract id (two limbs).
/// Returns JSON: { coin: { value, nullifier, secret, commitment, asset_hi, asset_lo }, commitment_hex, precommitement_hex }
#[wasm_bindgen(js_name = "generateCoin")]
pub fn generate_coin(
    amount_decimal: &str,
    asset_hi_decimal: &str,
    asset_lo_decimal: &str,
    application_id_decimal: &str,
) -> Result<JsValue, JsValue> {
    let hi = decimal_to_fr_result(asset_hi_decimal).map_err(|e| JsValue::from_str(&e))?;
    let lo = decimal_to_fr_result(asset_lo_decimal).map_err(|e| JsValue::from_str(&e))?;
    let generated = coin::generate_coin(amount_decimal, hi, lo, application_id_decimal)
        .map_err(|e| JsValue::from_str(&e))?;
    serde_wasm_bindgen::to_value(&generated).map_err(|e| JsValue::from_str(&format!("{e}")))
}

/// Same as `generateCoin`, but commitment uses the given owner public key (64-char hex coords).
#[wasm_bindgen(js_name = "generateCoinWithOwnerPubHex")]
pub fn generate_coin_with_owner_pub_hex(
    owner_x_hex: &str,
    owner_y_hex: &str,
    amount_decimal: &str,
    asset_hi_decimal: &str,
    asset_lo_decimal: &str,
    application_id_decimal: &str,
) -> Result<JsValue, JsValue> {
    let owner_pub = coin::OwnerPub::from_coord_hex(owner_x_hex, owner_y_hex)
        .map_err(|e| JsValue::from_str(&e))?;
    let hi = decimal_to_fr_result(asset_hi_decimal).map_err(|e| JsValue::from_str(&e))?;
    let lo = decimal_to_fr_result(asset_lo_decimal).map_err(|e| JsValue::from_str(&e))?;
    let generated = coin::generate_coin_with_owner_pub(
        owner_pub,
        amount_decimal,
        hi,
        lo,
        application_id_decimal,
    )
    .map_err(|e| JsValue::from_str(&e))?;
    serde_wasm_bindgen::to_value(&generated).map_err(|e| JsValue::from_str(&format!("{e}")))
}

/// `secret` in coin = `Poseidon255(1)(scalar)` per `deposit.circom`; scalar is 32-byte hex (64 chars, optional `0x`).
#[wasm_bindgen(js_name = "generateCoinFromDepositEphemeralScalarHex")]
pub fn generate_coin_from_deposit_ephemeral_scalar_hex(
    scalar_hex: &str,
    amount_decimal: &str,
    asset_hi_decimal: &str,
    asset_lo_decimal: &str,
    application_id_decimal: &str,
) -> Result<JsValue, JsValue> {
    let hi = decimal_to_fr_result(asset_hi_decimal).map_err(|e| JsValue::from_str(&e))?;
    let lo = decimal_to_fr_result(asset_lo_decimal).map_err(|e| JsValue::from_str(&e))?;
    let generated = coin::generate_coin_with_deposit_ephemeral_scalar_hex(
        scalar_hex,
        amount_decimal,
        hi,
        lo,
        application_id_decimal,
    )
    .map_err(|e| JsValue::from_str(&e))?;
    serde_wasm_bindgen::to_value(&generated).map_err(|e| JsValue::from_str(&format!("{e}")))
}

/// `Poseidon₁(scalar)` secret + recipient owner public key (hex), matching an aligned deposit witness.
#[wasm_bindgen(js_name = "generateCoinForDepositWithOwnerPubHex")]
pub fn generate_coin_for_deposit_with_owner_pub_hex(
    scalar_hex: &str,
    owner_x_hex: &str,
    owner_y_hex: &str,
    amount_decimal: &str,
    asset_hi_decimal: &str,
    asset_lo_decimal: &str,
    application_id_decimal: &str,
) -> Result<JsValue, JsValue> {
    let hi = decimal_to_fr_result(asset_hi_decimal).map_err(|e| JsValue::from_str(&e))?;
    let lo = decimal_to_fr_result(asset_lo_decimal).map_err(|e| JsValue::from_str(&e))?;
    let generated = coin::generate_coin_for_deposit_with_owner_pub_hex(
        scalar_hex,
        owner_x_hex,
        owner_y_hex,
        amount_decimal,
        hi,
        lo,
        application_id_decimal,
    )
    .map_err(|e| JsValue::from_str(&e))?;
    serde_wasm_bindgen::to_value(&generated).map_err(|e| JsValue::from_str(&format!("{e}")))
}

/// Merkle root, path, and coin field strings for the first withdraw leg (JSON → JSON).
#[wasm_bindgen(js_name = "buildWithdrawMerkleWitness")]
pub fn build_withdraw_merkle_witness_js(
    coin_json: &str,
    state_json: &str,
) -> Result<String, JsValue> {
    let coin: coin::CoinData = serde_json::from_str(coin_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid coin JSON: {}", e)))?;
    let state: coin::StateFile = serde_json::from_str(state_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid state JSON: {}", e)))?;

    let witness =
        coin::build_withdraw_merkle_witness(&coin, &state).map_err(|e| JsValue::from_str(&e))?;

    serde_json::to_string(&witness).map_err(|e| {
        JsValue::from_str(&format!(
            "Failed to serialize withdraw merkle witness: {}",
            e
        ))
    })
}

/// Convert snarkjs proof JSON to hex bytes for Soroban contract.
#[wasm_bindgen(js_name = "proofToHex")]
pub fn proof_to_hex(proof_json: &str) -> String {
    convert::proof_to_hex(proof_json)
}

/// Convert snarkjs public signals JSON to hex bytes for Soroban contract.
#[wasm_bindgen(js_name = "publicToHex")]
pub fn public_to_hex(public_json: &str) -> String {
    convert::public_to_hex(public_json)
}

/// Calculate owner-bound nullifier hash from nullifier and spend-scalar decimal strings.
/// Returns hex string (0x...)
#[wasm_bindgen(js_name = "calculateNullifierHash")]
pub fn calculate_nullifier_hash(
    nullifier_decimal: &str,
    priv_key_scalar_decimal: &str,
) -> Result<String, JsValue> {
    coin::calculate_nullifier_hash(nullifier_decimal, priv_key_scalar_decimal)
        .map_err(|e| JsValue::from_str(&e))
}

/// UTF-8 seed → `SHA256` → scalar → BabyJubJub `BASE8 * r` (circom `ECDHEphemeralKey`).
/// `x` and `y` are lowercase hex (no `0x`). Bech32 / stealth string: TypeScript `encodeStealthAddress`.
#[wasm_bindgen(js_name = "ecdhEphemeralPublicKey")]
pub fn ecdh_ephemeral_public_key_js(seed: &str) -> Result<JsValue, JsValue> {
    let (x, y) = stealth::stealth_coords_from_string(seed);
    #[derive(serde::Serialize)]
    struct Out {
        x: String,
        y: String,
    }
    let out = Out {
        x: hex::encode(x),
        y: hex::encode(y),
    };
    serde_wasm_bindgen::to_value(&out).map_err(|e| JsValue::from_str(&format!("{e}")))
}

/// 32-byte scalar as 64 hex chars (optional `0x`) → `ecdh_ephemeral_public_key` (no UTF-8 seed hash).
#[wasm_bindgen(js_name = "ecdhEphemeralPublicKeyFromScalarHex")]
pub fn ecdh_ephemeral_public_key_from_scalar_hex(scalar_hex: &str) -> Result<JsValue, JsValue> {
    let (x, y) =
        stealth::stealth_coords_from_scalar_hex(scalar_hex).map_err(|e| JsValue::from_str(&e))?;
    #[derive(serde::Serialize)]
    struct Out {
        x: String,
        y: String,
    }
    let out = Out {
        x: hex::encode(x),
        y: hex::encode(y),
    };
    serde_wasm_bindgen::to_value(&out).map_err(|e| JsValue::from_str(&format!("{e}")))
}

/// `R = Poseidon255(2)(hi, lo)`; `scalar` is the raw Poseidon hash when it is
/// already in `(0, BabyJub subgroup order)`. Out-of-range hashes fail so the
/// caller can rejection-sample a new nonce.
#[wasm_bindgen(js_name = "derivedEscrowKey")]
pub fn derived_escrow_key_js(
    nonce_decimal: &str,
    recipient_hi_decimal: &str,
    recipient_lo_decimal: &str,
) -> Result<JsValue, JsValue> {
    let nonce = decimal_to_fr_result(nonce_decimal).map_err(|e| JsValue::from_str(&e))?;
    let hi = decimal_to_fr_result(recipient_hi_decimal).map_err(|e| JsValue::from_str(&e))?;
    let lo = decimal_to_fr_result(recipient_lo_decimal).map_err(|e| JsValue::from_str(&e))?;
    let key = derived_escrow::try_derived_escrow_key(nonce, hi, lo).ok_or_else(|| {
        JsValue::from_str("derived escrow hash is outside BabyJub subgroup; retry nonce")
    })?;
    #[derive(serde::Serialize)]
    struct Out {
        #[serde(rename = "scalarHex")]
        scalar_hex: String,
        #[serde(rename = "pointXHex")]
        point_x_hex: String,
        #[serde(rename = "pointYHex")]
        point_y_hex: String,
    }
    serde_wasm_bindgen::to_value(&Out {
        scalar_hex: key.scalar_hex,
        point_x_hex: key.point_x_hex,
        point_y_hex: key.point_y_hex,
    })
    .map_err(|e| JsValue::from_str(&format!("{e}")))
}

/// Graph witness + arkworks Groth16 prove. Returns `{ proof_hex, public_hex }`.
#[wasm_bindgen(js_name = "proveGroth16")]
pub fn prove_groth16(
    graph: &[u8],
    proving_key: &[u8],
    r1cs: &[u8],
    inputs_json: &str,
) -> Result<JsValue, JsValue> {
    let calc = groth16::witness::WitnessCalculator::from_graph(graph)
        .map_err(|e| JsValue::from_str(&format!("witness graph: {e:#}")))?;
    let witness = calc
        .compute_witness(inputs_json)
        .map_err(|e| JsValue::from_str(&format!("witness: {e:#}")))?;
    let prover = groth16::prover::Prover::new(proving_key, r1cs)
        .map_err(|e| JsValue::from_str(&format!("prover init: {e:#}")))?;
    let proof_bytes = prover
        .prove_bytes_uncompressed(&witness)
        .map_err(|e| JsValue::from_str(&format!("prove: {e:#}")))?;
    let public_le = prover
        .extract_public_inputs(&witness)
        .map_err(|e| JsValue::from_str(&format!("public inputs: {e:#}")))?;
    let public_hex = groth16::prover::public_inputs_le_to_soroban_hex(&public_le)
        .map_err(|e| JsValue::from_str(&format!("public hex: {e:#}")))?;
    #[derive(serde::Serialize)]
    struct Out {
        proof_hex: String,
        public_hex: String,
    }
    serde_wasm_bindgen::to_value(&Out {
        proof_hex: hex::encode(proof_bytes),
        public_hex,
    })
    .map_err(|e| JsValue::from_str(&format!("{e}")))
}

/// Circuit `ECDH`: `priv * (pub_x, pub_y)` → shared key (`key[0], key[1]` hex).
#[wasm_bindgen(js_name = "ecdhSharedKey")]
pub fn ecdh_shared_key_js(
    priv_hex: &str,
    pub_x_hex: &str,
    pub_y_hex: &str,
) -> Result<JsValue, JsValue> {
    let priv_b = stealth::parse_scalar_hex(priv_hex).map_err(|e| JsValue::from_str(&e))?;
    let pub_x = stealth::parse_scalar_hex(pub_x_hex).map_err(|e| JsValue::from_str(&e))?;
    let pub_y = stealth::parse_scalar_hex(pub_y_hex).map_err(|e| JsValue::from_str(&e))?;
    let (x, y) = ecdh_shared_key(&priv_b, &pub_x, &pub_y)
        .map_err(|e| JsValue::from_str(&format!("ecdh_shared_key: {:?}", e)))?;
    #[derive(serde::Serialize)]
    struct Out {
        x: String,
        y: String,
    }
    let out = Out {
        x: hex::encode(x),
        y: hex::encode(y),
    };
    serde_wasm_bindgen::to_value(&out).map_err(|e| JsValue::from_str(&format!("{e}")))
}
