//! Stealth public key from string: SHA256(seed) → BabyJubJub ephemeral pubkey (x, y as hex).
//! Bech32 / `stpl1` encoding is done in TypeScript.

use cryptography::{ecdh_ephemeral_public_key, CoordBytes, ScalarBytes};
use sha2::{Digest, Sha256};

/// Derive a 32-byte scalar from an arbitrary UTF-8 string (SHA-256).
pub fn scalar_bytes_from_string_seed(seed: &str) -> ScalarBytes {
    let digest = Sha256::digest(seed.as_bytes());
    let mut out = ScalarBytes::default();
    out.copy_from_slice(&digest);
    out
}

/// UTF-8 seed → SHA-256 → scalar → `ecdh_ephemeral_public_key` → (x, y) big-endian coords.
pub fn stealth_coords_from_string(seed: &str) -> (CoordBytes, CoordBytes) {
    let r = scalar_bytes_from_string_seed(seed);
    ecdh_ephemeral_public_key(&r)
}

pub fn parse_scalar_hex(scalar_hex: &str) -> Result<ScalarBytes, String> {
    let s = scalar_hex.trim();
    let s = s
        .strip_prefix("0x")
        .unwrap_or(s)
        .strip_prefix("0X")
        .unwrap_or(s);
    if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("scalar must be 64 hex characters (32 bytes)".into());
    }
    let bytes = hex::decode(s).map_err(|e| e.to_string())?;
    let mut out = ScalarBytes::default();
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// 32-byte scalar from hex (no extra hashing) → `ecdh_ephemeral_public_key`.
pub fn stealth_coords_from_scalar_hex(
    scalar_hex: &str,
) -> Result<(CoordBytes, CoordBytes), String> {
    let s = parse_scalar_hex(scalar_hex)?;
    Ok(ecdh_ephemeral_public_key(&s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptography::ecdh_ephemeral_public_key;

    #[test]
    fn scalar_from_string_is_sha256() {
        let s = scalar_bytes_from_string_seed("abc");
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(s, expected);
    }

    #[test]
    fn stealth_coords_matches_hash_then_ecdh() {
        let seed = "roundtrip-check";
        let r = scalar_bytes_from_string_seed(seed);
        let (x, y) = ecdh_ephemeral_public_key(&r);
        let (x2, y2) = stealth_coords_from_string(seed);
        assert_eq!(x, x2);
        assert_eq!(y, y2);
    }

    #[test]
    fn scalar_hex_matches_raw_scalar_not_utf8_seed_hash() {
        let r = scalar_bytes_from_string_seed("direct");
        let hex: String = r.iter().map(|b| format!("{b:02x}")).collect();
        let (x, y) = stealth_coords_from_scalar_hex(&hex).unwrap();
        let (x2, y2) = ecdh_ephemeral_public_key(&r);
        assert_eq!((x, y), (x2, y2));
        let (x3, y3) = stealth_coords_from_string(&hex);
        assert_ne!(
            (x, y),
            (x3, y3),
            "passing scalar hex as a UTF-8 seed must hash different bytes",
        );
    }
}
