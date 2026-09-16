use ark_bn254::Fr;
use ark_ff::PrimeField;
use serde::{Deserialize, Serialize};

use crate::poseidon::{poseidon_hash_1, poseidon_hash_2, poseidon_hash_3};
use crate::poseidon_opt::poseidon_hash_n;
use crate::stealth::parse_scalar_hex;
use crate::utils::{decimal_to_fr, decimal_to_fr_result, fr_to_bytes_be, fr_to_decimal};

/// Circom `DOM_NULLIFIER` (`0x504E554C`). Must match `circuits/domain_separators.circom`.
pub const DOM_NULLIFIER: u64 = 0x504E_554C;

/// Circom BabyJub `Num2Bits(253)` / `libs/cryptography` `scalar_mul_253`: BE integer < 2^253.
fn require_scalar_babyjub_range(sb: &[u8; 32]) -> Result<(), String> {
    if sb[0] & 0xE0 != 0 {
        return Err(
            "scalar must represent an integer < 2^253 (BabyJub ECDH / circom Num2Bits(253))".into(),
        );
    }
    Ok(())
}

/// Coin value in stroops (1 XLM = 10^9 stroops)
pub const COIN_VALUE: u64 = 1_000_000_000;

/// Tree depth (must match the circuit and contract)
pub const TREE_DEPTH: u32 = 20;

/// Owner BabyJubJub public key (`ownerPub` in `circuits/commitment.circom`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnerPub {
    pub x: Fr,
    pub y: Fr,
}

impl OwnerPub {
    pub fn from_field_elements(x: Fr, y: Fr) -> Self {
        Self { x, y }
    }

    /// Parse 32-byte big-endian coordinates from hex.
    pub fn from_coord_hex(x_hex: &str, y_hex: &str) -> Result<Self, String> {
        let xb = parse_scalar_hex(x_hex)?;
        let yb = parse_scalar_hex(y_hex)?;
        Ok(Self {
            x: Fr::from_be_bytes_mod_order(&xb),
            y: Fr::from_be_bytes_mod_order(&yb),
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CoinData {
    pub value: String,
    pub nullifier: String,
    pub secret: String,
    pub commitment: String,
    /// Decimal Fr strings for Stellar asset contract id (`asset[0]`, `asset[1]` in `commitment.circom`).
    pub asset_hi: String,
    pub asset_lo: String,
    #[serde(default = "default_application_id")]
    pub application_id: String,
}

fn default_application_id() -> String {
    "0".to_string()
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GeneratedCoin {
    pub coin: CoinData,
    pub commitment_hex: String,
    /// 64-char lowercase hex (no `0x`), Fr big-endian bytes for `precommitement` in audit protobuf.
    pub precommitement_hex: String,
}

/// Merkle path + coin fields for the first withdraw leg (`Transaction` circuit).
#[derive(Serialize, Deserialize, Debug)]
pub struct WithdrawMerkleWitness {
    #[serde(rename = "withdrawnValue")]
    pub withdrawn_value: String,
    pub value: String,
    pub nullifier: String,
    pub secret: String,
    #[serde(rename = "withdrawnAsset")]
    pub withdrawn_asset: [String; 2],
    #[serde(rename = "stateRoot")]
    pub state_root: String,
    #[serde(rename = "stateIndex")]
    pub state_index: String,
    #[serde(rename = "stateSiblings")]
    pub state_siblings: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct StateFile {
    pub commitments: Vec<String>,
}

/// Privacy-pool leaf hash (matches `circuits/commitment.circom` `CommitmentHasher`):
/// `ownerKeyHash = Poseidon(ownerPub[0], ownerPub[1])`,
/// `precommitment = Poseidon(secret, ownerMode, ownerKeyHash)`,
/// V2 `commitment = Poseidon(9)(value, secret, nullifier, ownerPubX, ownerPubY, ownerMode, asset0, asset1, applicationId)`.
/// Registered notes use `owner_mode = 0`.
pub fn commitment_and_precommitment(
    nullifier: Fr,
    value: Fr,
    secret: Fr,
    owner_pub: OwnerPub,
    asset: [Fr; 2],
    application_id: Fr,
    owner_mode: Fr,
) -> (Fr, Fr) {
    let owner_key_hash = poseidon_hash_2(owner_pub.x, owner_pub.y);
    let precommitment = poseidon_hash_3(secret, owner_mode, owner_key_hash);
    let commitment = poseidon_hash_n(&[
        value,
        secret,
        nullifier,
        owner_pub.x,
        owner_pub.y,
        owner_mode,
        asset[0],
        asset[1],
        application_id,
    ]);
    (commitment, precommitment)
}

pub fn generate_commitment(
    nullifier: Fr,
    value: Fr,
    secret: Fr,
    owner_pub: OwnerPub,
    asset: [Fr; 2],
    application_id: Fr,
) -> Fr {
    commitment_and_precommitment(
        nullifier,
        value,
        secret,
        owner_pub,
        asset,
        application_id,
        Fr::from(0u64),
    )
    .0
}

fn application_id_fr(application_id_decimal: &str) -> Result<Fr, String> {
    Ok(decimal_to_fr(application_id_decimal))
}

fn generated_coin_from_fields(
    nullifier: Fr,
    value: Fr,
    secret: Fr,
    owner_pub: OwnerPub,
    asset: [Fr; 2],
    application_id: Fr,
) -> GeneratedCoin {
    let (commitment, precommitment) = commitment_and_precommitment(
        nullifier,
        value,
        secret,
        owner_pub,
        asset,
        application_id,
        Fr::from(0u64),
    );
    let commitment_bytes = fr_to_bytes_be(&commitment);
    let precommitment_bytes = fr_to_bytes_be(&precommitment);
    GeneratedCoin {
        coin: CoinData {
            value: fr_to_decimal(&value),
            nullifier: fr_to_decimal(&nullifier),
            secret: fr_to_decimal(&secret),
            commitment: fr_to_decimal(&commitment),
            asset_hi: fr_to_decimal(&asset[0]),
            asset_lo: fr_to_decimal(&asset[1]),
            application_id: fr_to_decimal(&application_id),
        },
        commitment_hex: format!("0x{}", hex::encode(commitment_bytes)),
        precommitement_hex: hex::encode(precommitment_bytes),
    }
}

/// Generate a complete coin with random nullifier, secret, and owner public-key coordinates.
/// `amount_decimal` is the coin value as a decimal field element (arbitrary precision).
/// `asset_hi` / `asset_lo` are decimal Fr strings for the Stellar asset contract id (two limbs).
pub fn generate_coin(
    amount_decimal: &str,
    asset_hi: Fr,
    asset_lo: Fr,
    application_id_decimal: &str,
) -> Result<GeneratedCoin, String> {
    let mut ss_x = [0u8; 32];
    let mut ss_y = [0u8; 32];
    getrandom::getrandom(&mut ss_x).map_err(|e| e.to_string())?;
    getrandom::getrandom(&mut ss_y).map_err(|e| e.to_string())?;
    let owner_pub = OwnerPub {
        x: Fr::from_be_bytes_mod_order(&ss_x),
        y: Fr::from_be_bytes_mod_order(&ss_y),
    };
    generate_coin_with_owner_pub(
        owner_pub,
        amount_decimal,
        asset_hi,
        asset_lo,
        application_id_decimal,
    )
}

/// Build coin with a specific owner public key, matching on-chain deposit semantics.
pub fn generate_coin_with_owner_pub(
    owner_pub: OwnerPub,
    amount_decimal: &str,
    asset_hi: Fr,
    asset_lo: Fr,
    application_id_decimal: &str,
) -> Result<GeneratedCoin, String> {
    let application_id = application_id_fr(application_id_decimal)?;
    let value = decimal_to_fr_result(amount_decimal)?;

    let mut nullifier_bytes = [0u8; 32];
    let mut secret_bytes = [0u8; 32];
    getrandom::getrandom(&mut nullifier_bytes).map_err(|e| e.to_string())?;
    getrandom::getrandom(&mut secret_bytes).map_err(|e| e.to_string())?;

    let nullifier = Fr::from_be_bytes_mod_order(&nullifier_bytes);
    let secret = Fr::from_be_bytes_mod_order(&secret_bytes);
    let asset = [asset_hi, asset_lo];
    Ok(generated_coin_from_fields(
        nullifier,
        value,
        secret,
        owner_pub,
        asset,
        application_id,
    ))
}

/// Same as [`generate_coin_with_owner_pub`], but `secret` is `Poseidon255(1)(ephemeral_key_scalar)`
/// matching `circuits/deposit.circom` (`ephemeralKeyScalar` → hashed `secret` in `CommitmentHasher`).
pub fn generate_coin_with_deposit_ephemeral_scalar_hex(
    scalar_hex: &str,
    amount_decimal: &str,
    asset_hi: Fr,
    asset_lo: Fr,
    application_id_decimal: &str,
) -> Result<GeneratedCoin, String> {
    let application_id = application_id_fr(application_id_decimal)?;
    let sb = parse_scalar_hex(scalar_hex)?;
    require_scalar_babyjub_range(&sb)?;
    let ephemeral_key_scalar = Fr::from_be_bytes_mod_order(&sb);
    let secret = poseidon_hash_1(ephemeral_key_scalar);

    let value = decimal_to_fr_result(amount_decimal)?;

    let mut nullifier_bytes = [0u8; 32];
    let mut ss_x = [0u8; 32];
    let mut ss_y = [0u8; 32];
    getrandom::getrandom(&mut nullifier_bytes).map_err(|e| e.to_string())?;
    getrandom::getrandom(&mut ss_x).map_err(|e| e.to_string())?;
    getrandom::getrandom(&mut ss_y).map_err(|e| e.to_string())?;

    let nullifier = Fr::from_be_bytes_mod_order(&nullifier_bytes);
    let owner_pub = OwnerPub {
        x: Fr::from_be_bytes_mod_order(&ss_x),
        y: Fr::from_be_bytes_mod_order(&ss_y),
    };

    let asset = [asset_hi, asset_lo];
    Ok(generated_coin_from_fields(
        nullifier,
        value,
        secret,
        owner_pub,
        asset,
        application_id,
    ))
}

/// `secret = Poseidon₁(scalar)` and `owner_pub` = recipient BabyJub public key (hex coords),
/// matching `deposit.circom` when the depositor ephemeral scalar and recipient keys align.
pub fn generate_coin_for_deposit_with_owner_pub_hex(
    scalar_hex: &str,
    owner_x_hex: &str,
    owner_y_hex: &str,
    amount_decimal: &str,
    asset_hi: Fr,
    asset_lo: Fr,
    application_id_decimal: &str,
) -> Result<GeneratedCoin, String> {
    let application_id = application_id_fr(application_id_decimal)?;
    let sb = parse_scalar_hex(scalar_hex)?;
    require_scalar_babyjub_range(&sb)?;
    let ephemeral_key_scalar = Fr::from_be_bytes_mod_order(&sb);
    let secret = poseidon_hash_1(ephemeral_key_scalar);
    let owner_pub = OwnerPub::from_coord_hex(owner_x_hex, owner_y_hex)?;
    let value = decimal_to_fr_result(amount_decimal)?;

    let mut nullifier_bytes = [0u8; 32];
    getrandom::getrandom(&mut nullifier_bytes).map_err(|e| e.to_string())?;
    let nullifier = Fr::from_be_bytes_mod_order(&nullifier_bytes);

    let asset = [asset_hi, asset_lo];
    Ok(generated_coin_from_fields(
        nullifier,
        value,
        secret,
        owner_pub,
        asset,
        application_id,
    ))
}

/// Build Merkle witness and public path fields for a withdraw from `coin` against `state.commitments`.
pub fn build_withdraw_merkle_witness(
    coin: &CoinData,
    state: &StateFile,
) -> Result<WithdrawMerkleWitness, String> {
    let value = decimal_to_fr(&coin.value);
    let nullifier = decimal_to_fr(&coin.nullifier);
    let secret = decimal_to_fr(&coin.secret);
    let commitment = decimal_to_fr(&coin.commitment);
    let asset_hi = decimal_to_fr(&coin.asset_hi);
    let asset_lo = decimal_to_fr(&coin.asset_lo);

    // Build merkle tree from state (on-chain tree appends two commitments per transact).
    let n = state.commitments.len();
    if n % 2 != 0 {
        return Err(format!(
            "expected an even number of commitments in state (pairs), got {}",
            n
        ));
    }

    let mut tree = crate::merkle::LeanIMT::new(TREE_DEPTH);
    let mut commitment_index: Option<usize> = None;

    for pair_start in (0..n).step_by(2) {
        let a = decimal_to_fr(&state.commitments[pair_start]);
        let b = decimal_to_fr(&state.commitments[pair_start + 1]);
        tree.insert_two(a, b).map_err(|e| {
            format!(
                "Failed to insert commitment pair at indices {}..{}: {}",
                pair_start,
                pair_start + 1,
                e
            )
        })?;

        if a == commitment {
            commitment_index = Some(pair_start);
        } else if b == commitment {
            commitment_index = Some(pair_start + 1);
        }
    }

    let commitment_index =
        commitment_index.ok_or_else(|| "Commitment not found in state".to_string())?;

    let (siblings, _depth) = tree
        .generate_proof(commitment_index as u32)
        .ok_or_else(|| "Failed to generate merkle proof".to_string())?;

    let root = tree.get_root();

    Ok(WithdrawMerkleWitness {
        withdrawn_value: coin.value.clone(),
        value: fr_to_decimal(&value),
        nullifier: fr_to_decimal(&nullifier),
        secret: fr_to_decimal(&secret),
        withdrawn_asset: [fr_to_decimal(&asset_hi), fr_to_decimal(&asset_lo)],
        state_root: fr_to_decimal(&root),
        state_index: commitment_index.to_string(),
        state_siblings: siblings.iter().map(|s| fr_to_decimal(s)).collect(),
    })
}

/// Calculate owner-bound nullifier hash: Poseidon(DOM_NULLIFIER, nullifier, privKeyScalar).
/// Returns hex string of the hash bytes (32 bytes).
pub fn calculate_nullifier_hash(
    nullifier_decimal: &str,
    priv_key_scalar_decimal: &str,
) -> Result<String, String> {
    let nullifier = decimal_to_fr_result(nullifier_decimal)?;
    let priv_key_scalar = decimal_to_fr_result(priv_key_scalar_decimal)?;
    let domain = Fr::from(DOM_NULLIFIER);
    let hash = poseidon_hash_3(domain, nullifier, priv_key_scalar);
    let hash_bytes = fr_to_bytes_be(&hash);
    Ok(format!("0x{}", hex::encode(hash_bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon::{poseidon_hash_1, poseidon_hash_2};
    use crate::utils::decimal_to_fr;

    #[test]
    fn test_deposit_ephemeral_scalar_secret_matches_poseidon1() {
        let hex_scalar = format!("{:064x}", 123456789u64);
        let az = Fr::from(0u64);
        let coin = generate_coin_with_deposit_ephemeral_scalar_hex(
            &hex_scalar,
            &COIN_VALUE.to_string(),
            az,
            az,
            "0",
        )
        .unwrap();
        let sb = parse_scalar_hex(&hex_scalar).unwrap();
        let s_fr = Fr::from_be_bytes_mod_order(&sb);
        assert_eq!(coin.coin.secret, fr_to_decimal(&poseidon_hash_1(s_fr)));
    }

    #[test]
    fn test_deposit_owner_pub_coin_matches_commitment_hasher() {
        let hex_scalar = format!("{:064x}", 42u64);
        let sx = format!("{:064x}", 11u64);
        let sy = format!("{:064x}", 13u64);
        let az = Fr::from(0u64);
        let coin = generate_coin_for_deposit_with_owner_pub_hex(
            &hex_scalar,
            &sx,
            &sy,
            &COIN_VALUE.to_string(),
            az,
            az,
            "0",
        )
        .unwrap();
        let sb = parse_scalar_hex(&hex_scalar).unwrap();
        let s_fr = Fr::from_be_bytes_mod_order(&sb);
        let secret = poseidon_hash_1(s_fr);
        let owner_pub = OwnerPub::from_coord_hex(&sx, &sy).unwrap();
        let nullifier = decimal_to_fr(&coin.coin.nullifier);
        let value = decimal_to_fr(&coin.coin.value);
        let asset = [az, az];
        let app_id = Fr::from(0u64);
        let expected = generate_commitment(nullifier, value, secret, owner_pub, asset, app_id);
        assert_eq!(coin.coin.commitment, fr_to_decimal(&expected));
    }

    #[test]
    fn test_generate_coin() {
        let az = Fr::from(0u64);
        let coin = generate_coin(&COIN_VALUE.to_string(), az, az, "0").unwrap();
        assert!(!coin.coin.value.is_empty());
        assert!(!coin.coin.nullifier.is_empty());
        assert!(!coin.coin.secret.is_empty());
        assert!(!coin.coin.commitment.is_empty());
        assert!(coin.commitment_hex.starts_with("0x"));
        assert_eq!(coin.precommitement_hex.len(), 64);
    }

    #[test]
    fn test_eighteen_decimal_value_survives_without_js_number() {
        let az = Fr::from(0u64);
        let amount = "1000000000000000001";
        let coin = generate_coin(amount, az, az, "0").unwrap();
        assert_eq!(coin.coin.value, amount);
    }

    #[test]
    fn v1_precommitment_cannot_open_a_v2_escrow_commitment() {
        let secret = Fr::from(401u64);
        let nullifier = Fr::from(301u64);
        let value = Fr::from(100u64);
        let asset = [Fr::from(1u64), Fr::from(1u64)];
        let application_id = Fr::from(101u64);
        let owner_pub = OwnerPub::from_field_elements(Fr::from(11u64), Fr::from(13u64));
        let owner_key_hash = poseidon_hash_2(owner_pub.x, owner_pub.y);
        let v1_precommitment = poseidon_hash_2(secret, owner_key_hash);
        let v2_registered = commitment_and_precommitment(
            nullifier,
            value,
            secret,
            owner_pub,
            asset,
            application_id,
            Fr::from(0u64),
        );
        let v2_escrow = commitment_and_precommitment(
            nullifier,
            value,
            secret,
            owner_pub,
            asset,
            application_id,
            Fr::from(1u64),
        );
        assert_ne!(
            v1_precommitment, v2_escrow.1,
            "old 2-ary precommitment must not equal a V2 escrow opening"
        );
        assert_ne!(
            v2_registered.0, v2_escrow.0,
            "spending an escrow leaf as registered must not reproduce the committed leaf"
        );
        assert_ne!(
            v2_registered.1, v2_escrow.1,
            "registered mode-0 opening must not match escrow mode-1 precommitment"
        );
    }

    #[test]
    fn test_build_withdraw_merkle_witness() {
        let az = Fr::from(0u64);
        let coin = generate_coin(&COIN_VALUE.to_string(), az, az, "0").unwrap();
        // On-chain tree appends two commitments per transact; witness builder expects pairs.
        let other = generate_coin(&(COIN_VALUE + 1).to_string(), az, az, "0").unwrap();
        let state = StateFile {
            commitments: vec![coin.coin.commitment.clone(), other.coin.commitment.clone()],
        };
        let result = build_withdraw_merkle_witness(&coin.coin, &state);
        assert!(result.is_ok());
        let w = result.unwrap();
        assert_eq!(w.state_index, "0");
        assert_eq!(w.state_siblings.len(), TREE_DEPTH as usize);
        assert_eq!(w.withdrawn_value, w.value);
        assert_eq!(w.value, coin.coin.value);
    }

    #[test]
    fn test_commitment_not_found() {
        let az = Fr::from(0u64);
        let coin = generate_coin(&COIN_VALUE.to_string(), az, az, "0").unwrap();
        let state = StateFile {
            commitments: vec!["999".to_string()],
        };
        let result = build_withdraw_merkle_witness(&coin.coin, &state);
        assert!(result.is_err());
    }

    #[test]
    fn test_commitment_wide_poseidon() {
        let n = Fr::from(7u64);
        let v = Fr::from(8u64);
        let s = Fr::from(9u64);
        let a0 = Fr::from(3u64);
        let a1 = Fr::from(4u64);
        let app_id = Fr::from(0u64);
        let owner_pub = OwnerPub::from_field_elements(Fr::from(10u64), Fr::from(11u64));
        let expected = poseidon_hash_n(&[
            v,
            s,
            n,
            owner_pub.x,
            owner_pub.y,
            Fr::from(0u64),
            a0,
            a1,
            app_id,
        ]);
        assert_eq!(
            generate_commitment(n, v, s, owner_pub, [a0, a1], app_id),
            expected
        );
    }
}
