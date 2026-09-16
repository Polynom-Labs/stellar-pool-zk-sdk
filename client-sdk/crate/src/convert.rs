use ark_bn254::{Fq, Fq2};
use ark_ff::{BigInteger, Field, PrimeField, Zero};
use core::str::FromStr;
use num_bigint::BigUint;
use num_traits::Num;
use serde::Deserialize;

const G1_SERIALIZED_SIZE: usize = 64;
const G2_SERIALIZED_SIZE: usize = 128;

#[derive(Deserialize)]
struct ProofJson {
    pi_a: [String; 3],
    pi_b: [[String; 2]; 3],
    pi_c: [String; 3],
}

fn write_fq_be32(out: &mut [u8], offset: usize, val: &Fq) {
    let bytes = val.into_bigint().to_bytes_be();
    out[offset + 32 - bytes.len()..offset + 32].copy_from_slice(&bytes);
}

fn g1_serialize(x: &str, y: &str, z: &str) -> [u8; G1_SERIALIZED_SIZE] {
    let x = Fq::from_str(x).expect("Invalid Fq x");
    let y = Fq::from_str(y).expect("Invalid Fq y");
    let z = Fq::from_str(z).expect("Invalid Fq z");

    if z.is_zero() {
        return [0u8; G1_SERIALIZED_SIZE];
    }

    let z2 = z.square();
    let z3 = z2 * z;
    let x_aff = x * z2.inverse().expect("Invalid G1 z");
    let y_aff = y * z3.inverse().expect("Invalid G1 z");

    let mut out = [0u8; G1_SERIALIZED_SIZE];
    write_fq_be32(&mut out, 0, &x_aff);
    write_fq_be32(&mut out, 32, &y_aff);
    out
}

fn g2_serialize(
    x1: &str,
    x2: &str,
    y1: &str,
    y2: &str,
    z1: &str,
    z2: &str,
) -> [u8; G2_SERIALIZED_SIZE] {
    let x = Fq2::new(
        Fq::from_str(x1).expect("Invalid Fq2 x1"),
        Fq::from_str(x2).expect("Invalid Fq2 x2"),
    );
    let y = Fq2::new(
        Fq::from_str(y1).expect("Invalid Fq2 y1"),
        Fq::from_str(y2).expect("Invalid Fq2 y2"),
    );
    let z = Fq2::new(
        Fq::from_str(z1).expect("Invalid Fq2 z1"),
        Fq::from_str(z2).expect("Invalid Fq2 z2"),
    );

    if z.is_zero() {
        return [0u8; G2_SERIALIZED_SIZE];
    }

    let z2 = z.square();
    let z3 = z2 * z;
    let x_aff = x * z2.inverse().expect("Invalid G2 z");
    let y_aff = y * z3.inverse().expect("Invalid G2 z");

    let mut out = [0u8; G2_SERIALIZED_SIZE];
    write_fq_be32(&mut out, 0, &x_aff.c1);
    write_fq_be32(&mut out, 32, &x_aff.c0);
    write_fq_be32(&mut out, 64, &y_aff.c1);
    write_fq_be32(&mut out, 96, &y_aff.c0);
    out
}

pub fn proof_to_hex(proof_json: &str) -> String {
    let proof: ProofJson = serde_json::from_str(proof_json).expect("Invalid proof JSON");

    let a_bytes = g1_serialize(&proof.pi_a[0], &proof.pi_a[1], &proof.pi_a[2]);
    let b_bytes = g2_serialize(
        &proof.pi_b[0][0],
        &proof.pi_b[0][1],
        &proof.pi_b[1][0],
        &proof.pi_b[1][1],
        &proof.pi_b[2][0],
        &proof.pi_b[2][1],
    );
    let c_bytes = g1_serialize(&proof.pi_c[0], &proof.pi_c[1], &proof.pi_c[2]);

    let mut all_bytes =
        Vec::with_capacity(G1_SERIALIZED_SIZE + G2_SERIALIZED_SIZE + G1_SERIALIZED_SIZE);
    all_bytes.extend_from_slice(&a_bytes);
    all_bytes.extend_from_slice(&b_bytes);
    all_bytes.extend_from_slice(&c_bytes);

    hex::encode(all_bytes)
}

pub fn public_to_hex(public_json: &str) -> String {
    let signals: Vec<String> =
        serde_json::from_str(public_json).expect("Invalid public signals JSON");

    let mut all_bytes = Vec::new();

    let len = signals.len() as u32;
    all_bytes.extend_from_slice(&len.to_be_bytes());

    for signal in &signals {
        let value = BigUint::from_str_radix(signal, 10).expect("Invalid decimal signal");
        let mut bytes = value.to_bytes_be();
        if bytes.len() < 32 {
            let mut padded = vec![0u8; 32 - bytes.len()];
            padded.extend_from_slice(&bytes);
            bytes = padded;
        }
        all_bytes.extend_from_slice(&bytes[..32]);
    }

    hex::encode(all_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_to_hex_format() {
        let proof_json = r#"{
            "pi_a": ["1", "2", "1"],
            "pi_b": [["3", "4"], ["5", "6"], ["1", "0"]],
            "pi_c": ["7", "8", "1"],
            "protocol": "groth16",
            "curve": "bn128"
        }"#;
        let hex = proof_to_hex(proof_json);
        assert_eq!(hex.len(), 512);
    }

    #[test]
    fn test_public_to_hex_format() {
        let public_json = r#"["123", "456"]"#;
        let hex = public_to_hex(public_json);
        assert_eq!(hex.len(), 136);
        assert_eq!(&hex[..8], "00000002");
    }
}
