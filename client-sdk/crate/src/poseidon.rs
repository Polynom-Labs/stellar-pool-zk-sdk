use ark_bn254::Fr;
use ark_ff::{Field, PrimeField};
use std::sync::OnceLock;

use crate::params;

/// Circom `Poseidon255` partial rounds by input arity (`nInputs`).
/// Source: `circuits/poseidon255.circom`, `N_P_ARRAY`.
const CIRCOM_N_P_ARRAY: [usize; 16] = [
    // For Poseidon255 template: nInputs = t-1.
    // BN254 Poseidon rounds_p: t=2 => 56, t=3 => 57, t=4 => 56.
    // Here nInputs=2 (t=3) is at index 1.
    56, 57, 56, 56, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57,
];

/// Parsed Poseidon parameters cached for reuse
struct PoseidonParams {
    mds: Vec<Vec<Fr>>,
    rc: Vec<Vec<Fr>>,
    rounds_f: usize,
    rounds_p: usize,
    t: usize,
}

fn parse_hex_to_fr(hex: &str) -> Fr {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(hex, &mut bytes).expect("Invalid hex constant");
    Fr::from_be_bytes_mod_order(&bytes)
}

fn rounds_p_for_inputs(n_inputs: usize) -> usize {
    CIRCOM_N_P_ARRAY[n_inputs - 1]
}

fn load_params_t2() -> PoseidonParams {
    let t = 2;
    let rounds_f = 8;
    let rounds_p = rounds_p_for_inputs(1);
    let total_rounds = rounds_f + rounds_p;
    assert_eq!(params::MDS_T2.len(), t * t, "MDS_T2 size mismatch");
    assert_eq!(
        params::RC_T2.len(),
        t * total_rounds,
        "RC_T2 size mismatch with circom rounds"
    );

    let mut mds = vec![vec![Fr::from(0u64); t]; t];
    for i in 0..t {
        for j in 0..t {
            mds[i][j] = parse_hex_to_fr(params::MDS_T2[i * t + j]);
        }
    }

    let mut rc = vec![vec![Fr::from(0u64); t]; total_rounds];
    for r in 0..total_rounds {
        for j in 0..t {
            rc[r][j] = parse_hex_to_fr(params::RC_T2[r * t + j]);
        }
    }

    PoseidonParams {
        mds,
        rc,
        rounds_f,
        rounds_p,
        t,
    }
}

fn load_params_t3() -> PoseidonParams {
    let t = 3;
    let rounds_f = 8;
    let rounds_p = rounds_p_for_inputs(2);
    let total_rounds = rounds_f + rounds_p;
    assert_eq!(params::MDS_T3.len(), t * t, "MDS_T3 size mismatch");
    assert_eq!(
        params::RC_T3.len(),
        t * total_rounds,
        "RC_T3 size mismatch with circom rounds"
    );

    // Parse MDS matrix
    let mut mds = vec![vec![Fr::from(0u64); t]; t];
    for i in 0..t {
        for j in 0..t {
            mds[i][j] = parse_hex_to_fr(params::MDS_T3[i * t + j]);
        }
    }

    // Parse round constants
    let mut rc = vec![vec![Fr::from(0u64); t]; total_rounds];
    for r in 0..total_rounds {
        for j in 0..t {
            rc[r][j] = parse_hex_to_fr(params::RC_T3[r * t + j]);
        }
    }

    PoseidonParams {
        mds,
        rc,
        rounds_f,
        rounds_p,
        t,
    }
}

fn load_params_t4() -> PoseidonParams {
    let t = 4;
    let rounds_f = 8;
    let rounds_p = rounds_p_for_inputs(3);
    let total_rounds = rounds_f + rounds_p;
    assert_eq!(params::MDS_T4.len(), t * t, "MDS_T4 size mismatch");
    assert_eq!(
        params::RC_T4.len(),
        t * total_rounds,
        "RC_T4 size mismatch with circom rounds"
    );

    let mut mds = vec![vec![Fr::from(0u64); t]; t];
    for i in 0..t {
        for j in 0..t {
            mds[i][j] = parse_hex_to_fr(params::MDS_T4[i * t + j]);
        }
    }

    let mut rc = vec![vec![Fr::from(0u64); t]; total_rounds];
    for r in 0..total_rounds {
        for j in 0..t {
            rc[r][j] = parse_hex_to_fr(params::RC_T4[r * t + j]);
        }
    }

    PoseidonParams {
        mds,
        rc,
        rounds_f,
        rounds_p,
        t,
    }
}

static PARAMS_T2: OnceLock<PoseidonParams> = OnceLock::new();
static PARAMS_T3: OnceLock<PoseidonParams> = OnceLock::new();
static PARAMS_T4: OnceLock<PoseidonParams> = OnceLock::new();

/// Poseidon permutation: the core hash computation.
/// Implements the standard Poseidon hash matching circom's implementation.
fn poseidon_permutation(state: &mut [Fr], params: &PoseidonParams) {
    let t = params.t;
    let half_f = params.rounds_f / 2;

    for round in 0..(params.rounds_f + params.rounds_p) {
        // Add round constants
        for j in 0..t {
            state[j] += params.rc[round][j];
        }

        // S-box
        if round < half_f || round >= half_f + params.rounds_p {
            // Full round: apply S-box to all elements
            for j in 0..t {
                let x2 = state[j].square();
                let x4 = x2.square();
                state[j] = x4 * state[j]; // x^5
            }
        } else {
            // Partial round: apply S-box only to first element
            let x2 = state[0].square();
            let x4 = x2.square();
            state[0] = x4 * state[0]; // x^5
        }

        // MDS matrix multiplication
        let mut new_state = vec![Fr::from(0u64); t];
        for i in 0..t {
            for j in 0..t {
                new_state[i] += params.mds[i][j] * state[j];
            }
        }
        state.copy_from_slice(&new_state);
    }
}

/// Poseidon hash with 1 input (state size 2) - used for nullifier hash
/// Matches circom Poseidon255(1): state [capacity=0, nullifier]
pub fn poseidon_hash_1(a: Fr) -> Fr {
    let params = PARAMS_T2.get_or_init(load_params_t2);
    let mut state = vec![Fr::from(0u64), a];
    poseidon_permutation(&mut state, params);
    state[0]
}

/// Poseidon hash with 2 inputs (state size 3) - used for merkle tree
pub fn poseidon_hash_2(a: Fr, b: Fr) -> Fr {
    let params = PARAMS_T3.get_or_init(load_params_t3);
    // State: [capacity=0, a, b]
    let mut state = vec![Fr::from(0u64), a, b];
    poseidon_permutation(&mut state, params);
    state[0]
}

/// Poseidon hash with 3 inputs (state size 4) - used for commitment
pub fn poseidon_hash_3(a: Fr, b: Fr, c: Fr) -> Fr {
    let params = PARAMS_T4.get_or_init(load_params_t4);
    // State: [capacity=0, a, b, c]
    let mut state = vec![Fr::from(0u64), a, b, c];
    poseidon_permutation(&mut state, params);
    state[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circom_partial_rounds_alignment_for_used_arities() {
        // We use Poseidon255(1), Poseidon255(2), Poseidon255(3) in client-sdk.
        assert_eq!(rounds_p_for_inputs(1), 56);
        assert_eq!(rounds_p_for_inputs(2), 57);
        assert_eq!(rounds_p_for_inputs(3), 56);
    }

    #[test]
    fn test_poseidon_hash_2_deterministic() {
        let a = Fr::from(123u64);
        let b = Fr::from(456u64);
        let result1 = poseidon_hash_2(a, b);
        let result2 = poseidon_hash_2(a, b);
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_poseidon_hash_3_deterministic() {
        let a = Fr::from(100u64);
        let b = Fr::from(200u64);
        let c = Fr::from(300u64);
        let result1 = poseidon_hash_3(a, b, c);
        let result2 = poseidon_hash_3(a, b, c);
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_poseidon_hash_2_nonzero() {
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        let result = poseidon_hash_2(a, b);
        assert_ne!(result, Fr::from(0u64));
    }

    #[test]
    fn test_poseidon_hash_3_nonzero() {
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        let c = Fr::from(3u64);
        let result = poseidon_hash_3(a, b, c);
        assert_ne!(result, Fr::from(0u64));
    }

    /// Sanity check for a stable BN254 vector.
    #[test]
    fn test_poseidon_hash_2_known_vector() {
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        let result = poseidon_hash_2(a, b);

        // Fixed vector for current BN254 parameters.
        let expected_hex = "115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a";
        let expected = parse_hex_to_fr(expected_hex);
        assert_eq!(
            result, expected,
            "poseidon_hash_2(1,2) does not match known vector"
        );
    }

    /// Sanity check for a stable BN254 vector.
    #[test]
    fn test_poseidon_hash_3_known_vector() {
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        let c = Fr::from(3u64);
        let result = poseidon_hash_3(a, b, c);

        // Fixed vector for current BN254 parameters.
        let expected_hex = "0e7732d89e6939c0ff03d5e58dab6302f3230e269dc5b968f725df34ab36d732";
        let expected = parse_hex_to_fr(expected_hex);
        assert_eq!(
            result, expected,
            "poseidon_hash_3(1,2,3) does not match known vector"
        );
    }
}
