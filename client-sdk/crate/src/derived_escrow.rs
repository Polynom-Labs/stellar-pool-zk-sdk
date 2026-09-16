use ark_bn254::Fr;
use cryptography::{ecdh_ephemeral_public_key, CoordBytes};
use num_bigint::BigUint;
use num_traits::Zero;

use crate::poseidon::{poseidon_hash_2, poseidon_hash_3};
use crate::utils::fr_to_bytes_be;

/// Domain tag `PESC` (`0x50455343`). Byte-identical across Rust, JS, and Core.
pub const DOM_ESCROW: u64 = 0x5045_5343;

const BABYJUB_SUBGROUP_ORDER: &str =
    "2736030358979909402780800718157159386076813972158567259200215660948447373041";

const OUT_OF_RANGE_MESSAGE: &str = "derived escrow hash is outside BabyJub subgroup; retry nonce";

pub struct DerivedEscrowKey {
    pub scalar_hex: String,
    pub point_x_hex: String,
    pub point_y_hex: String,
}

fn fr_from_u64(value: u64) -> Fr {
    Fr::from(value)
}

fn coord_to_hex(bytes: &CoordBytes) -> String {
    hex::encode(bytes)
}

fn babyjub_subgroup_order() -> BigUint {
    BigUint::parse_bytes(BABYJUB_SUBGROUP_ORDER.as_bytes(), 10)
        .expect("BabyJubJub subgroup order is a valid decimal")
}

fn is_canonical_babyjub_scalar(scalar: &Fr) -> bool {
    let value = BigUint::from_bytes_be(&fr_to_bytes_be(scalar));
    let order = babyjub_subgroup_order();
    value > BigUint::zero() && value < order
}

fn raw_derived_scalar(nonce: Fr, recipient_hi: Fr, recipient_lo: Fr) -> Fr {
    let domain = fr_from_u64(DOM_ESCROW);
    let r = poseidon_hash_2(recipient_hi, recipient_lo);
    poseidon_hash_3(domain, nonce, r)
}

fn key_from_in_range_scalar(scalar: Fr) -> DerivedEscrowKey {
    let scalar_bytes = fr_to_bytes_be(&scalar);
    let (x, y) = ecdh_ephemeral_public_key(&scalar_bytes);
    DerivedEscrowKey {
        scalar_hex: hex::encode(scalar_bytes),
        point_x_hex: coord_to_hex(&x),
        point_y_hex: coord_to_hex(&y),
    }
}

/// `R = Poseidon255(2)(hi, lo)`; `scalar = Poseidon255(3)(DOM_ESCROW, nonce, R)`.
/// Returns `None` when the hash is not in `(0, BabyJub subgroup order)` so callers
/// can rejection-sample a new nonce. The circuit compares this raw hash — never a
/// modular reduction of it.
pub fn try_derived_escrow_key(
    nonce: Fr,
    recipient_hi: Fr,
    recipient_lo: Fr,
) -> Option<DerivedEscrowKey> {
    let scalar = raw_derived_scalar(nonce, recipient_hi, recipient_lo);
    if !is_canonical_babyjub_scalar(&scalar) {
        return None;
    }
    Some(key_from_in_range_scalar(scalar))
}

/// Same as [`try_derived_escrow_key`], panicking when the hash is out of range.
pub fn derived_escrow_key(nonce: Fr, recipient_hi: Fr, recipient_lo: Fr) -> DerivedEscrowKey {
    try_derived_escrow_key(nonce, recipient_hi, recipient_lo).expect(OUT_OF_RANGE_MESSAGE)
}

/// Walks `start_nonce..start_nonce+window` until Poseidon lands in the subgroup.
pub fn sample_derived_escrow_key(
    recipient_hi: Fr,
    recipient_lo: Fr,
    start_nonce: u64,
    window: u64,
) -> (Fr, DerivedEscrowKey) {
    for offset in 0..window {
        let nonce = Fr::from(start_nonce + offset);
        if let Some(key) = try_derived_escrow_key(nonce, recipient_hi, recipient_lo) {
            return (nonce, key);
        }
    }
    panic!("{OUT_OF_RANGE_MESSAGE}");
}

#[cfg(test)]
fn scalar_from_hex(hex_str: &str) -> Fr {
    let bytes = hex::decode(hex_str).expect("hex");
    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(&bytes);
    crate::utils::bytes_be_to_fr(&padded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_escrow_key_rejects_out_of_range_hash() {
        let hi = Fr::from(1u64);
        let lo = Fr::from(2u64);
        let (nonce, key) = sample_derived_escrow_key(hi, lo, 0, 1024);
        let sampled = try_derived_escrow_key(nonce, hi, lo).expect("sampled nonce is in range");
        assert_eq!(sampled.scalar_hex, key.scalar_hex);
        assert_eq!(sampled.point_x_hex.len(), 64);
        assert_eq!(sampled.point_y_hex.len(), 64);
        assert!(is_canonical_babyjub_scalar(&scalar_from_hex(
            &key.scalar_hex
        )));
    }

    #[test]
    fn derived_escrow_key_does_not_reduce_modulo_order() {
        let hi = Fr::from(1u64);
        let lo = Fr::from(2u64);
        let (nonce, key) = sample_derived_escrow_key(hi, lo, 0, 1024);
        let raw = raw_derived_scalar(nonce, hi, lo);
        assert_eq!(hex::encode(fr_to_bytes_be(&raw)), key.scalar_hex);
    }
}
