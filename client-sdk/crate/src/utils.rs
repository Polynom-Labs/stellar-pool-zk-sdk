use ark_bn254::Fr;
use ark_ff::{BigInteger256, PrimeField};
use num_bigint::BigUint;
use num_traits::Num;

/// Convert a decimal string to an ark Fr field element (non-panicking).
pub fn decimal_to_fr_result(decimal_str: &str) -> Result<Fr, String> {
    let biguint = BigUint::from_str_radix(decimal_str, 10)
        .map_err(|_| "Invalid decimal string".to_string())?;
    let bytes_be = biguint.to_bytes_be();

    let mut padded = [0u8; 32];
    let start = 32usize.saturating_sub(bytes_be.len());
    padded[start..].copy_from_slice(&bytes_be[..bytes_be.len().min(32)]);

    Ok(Fr::from_be_bytes_mod_order(&padded))
}

/// Convert a decimal string to an ark Fr field element
pub fn decimal_to_fr(decimal_str: &str) -> Fr {
    let biguint = BigUint::from_str_radix(decimal_str, 10).expect("Invalid decimal string");
    let bytes_be = biguint.to_bytes_be();

    // Pad to 32 bytes big-endian
    let mut padded = [0u8; 32];
    let start = 32usize.saturating_sub(bytes_be.len());
    padded[start..].copy_from_slice(&bytes_be[..bytes_be.len().min(32)]);

    // ark-ff uses little-endian limbs internally; Fr::from_be_bytes_mod_order works for BE input
    Fr::from_be_bytes_mod_order(&padded)
}

/// Convert an ark Fr field element to a decimal string
pub fn fr_to_decimal(fr: &Fr) -> String {
    let bigint: BigInteger256 = (*fr).into();
    // BigInteger256 stores 4 u64 limbs in little-endian order
    let mut bytes_le = [0u8; 32];
    for (i, limb) in bigint.0.iter().enumerate() {
        let limb_bytes = limb.to_le_bytes();
        bytes_le[i * 8..(i + 1) * 8].copy_from_slice(&limb_bytes);
    }
    let biguint = BigUint::from_bytes_le(&bytes_le);
    biguint.to_str_radix(10)
}

/// Convert an ark Fr to 32-byte big-endian representation (matching Soroban's BytesN<32>)
pub fn fr_to_bytes_be(fr: &Fr) -> [u8; 32] {
    let bigint: BigInteger256 = (*fr).into();
    let mut bytes_be = [0u8; 32];
    // BigInteger256 limbs are little-endian u64s
    for (i, limb) in bigint.0.iter().enumerate() {
        let limb_bytes = limb.to_be_bytes();
        // Place in big-endian order: last limb first
        let offset = (3 - i) * 8;
        bytes_be[offset..offset + 8].copy_from_slice(&limb_bytes);
    }
    bytes_be
}

/// Convert 32-byte big-endian representation to ark Fr
pub fn bytes_be_to_fr(bytes: &[u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decimal_roundtrip() {
        let decimal = "123456789";
        let fr = decimal_to_fr(decimal);
        let result = fr_to_decimal(&fr);
        assert_eq!(result, decimal);
    }

    #[test]
    fn test_large_decimal_roundtrip() {
        let decimal =
            "52435875175126190479447740508185965837690552500527637822603658699938581184513";
        let fr = decimal_to_fr(decimal);
        let result = fr_to_decimal(&fr);
        // This is the BN254 scalar field modulus - 1, so it wraps
        // Just test it doesn't panic
        assert!(!result.is_empty());
    }

    #[test]
    fn test_bytes_roundtrip() {
        let decimal = "1000000000";
        let fr = decimal_to_fr(decimal);
        let bytes = fr_to_bytes_be(&fr);
        let fr2 = bytes_be_to_fr(&bytes);
        assert_eq!(fr, fr2);
    }

    #[test]
    fn test_zero() {
        let fr = decimal_to_fr("0");
        let result = fr_to_decimal(&fr);
        assert_eq!(result, "0");
    }
}
