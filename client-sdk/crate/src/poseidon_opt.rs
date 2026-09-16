use ark_bn254::Fr;
use ark_ff::{Field, PrimeField};
use std::sync::OnceLock;

use crate::poseidon_opt_params;

const N_ROUNDS_F: usize = 8;
const N_ROUNDS_P: [usize; 16] = [
    56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68,
];

struct OptParams {
    c: Vec<Fr>,
    s: Vec<Fr>,
    m: Vec<Fr>,
    p: Vec<Fr>,
    t: usize,
    n_rounds_p: usize,
}

fn parse_hex_to_fr(hex: &str) -> Fr {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(hex, &mut bytes).expect("Invalid hex constant");
    Fr::from_be_bytes_mod_order(&bytes)
}

fn parse_list(values: &[&str]) -> Vec<Fr> {
    values.iter().copied().map(parse_hex_to_fr).collect()
}

fn load_t(t: usize) -> OptParams {
    let n_rounds_p = N_ROUNDS_P[t - 2];
    let (c, s, m, p) = match t {
        10 => (
            parse_list(&poseidon_opt_params::POSEIDON_C_T10),
            parse_list(&poseidon_opt_params::POSEIDON_S_T10),
            parse_list(&poseidon_opt_params::POSEIDON_M_T10),
            parse_list(&poseidon_opt_params::POSEIDON_P_T10),
        ),
        11 => (
            parse_list(&poseidon_opt_params::POSEIDON_C_T11),
            parse_list(&poseidon_opt_params::POSEIDON_S_T11),
            parse_list(&poseidon_opt_params::POSEIDON_M_T11),
            parse_list(&poseidon_opt_params::POSEIDON_P_T11),
        ),
        _ => panic!("unsupported circomlib Poseidon t={t}"),
    };
    OptParams {
        c,
        s,
        m,
        p,
        t,
        n_rounds_p,
    }
}

fn pow5(value: Fr) -> Fr {
    let x2 = value.square();
    let x4 = x2.square();
    x4 * value
}

fn mix(state: &[Fr], matrix: &[Fr], t: usize) -> Vec<Fr> {
    let mut out = vec![Fr::from(0u64); t];
    for i in 0..t {
        let mut acc = Fr::from(0u64);
        for j in 0..t {
            acc += matrix[j * t + i] * state[j];
        }
        out[i] = acc;
    }
    out
}

fn poseidon_opt(inputs: &[Fr]) -> Fr {
    let t = inputs.len() + 1;
    let params = match t {
        10 => PARAMS_T10.get_or_init(|| load_t(10)),
        11 => PARAMS_T11.get_or_init(|| load_t(11)),
        _ => panic!(
            "poseidon_hash_n supports 9 or 10 inputs, got {}",
            inputs.len()
        ),
    };
    debug_assert_eq!(params.t, t);
    let n_rounds_p = params.n_rounds_p;
    let mut state = vec![Fr::from(0u64)];
    state.extend_from_slice(inputs);
    for i in 0..t {
        state[i] += params.c[i];
    }

    for r in 0..(N_ROUNDS_F / 2 - 1) {
        for value in state.iter_mut() {
            *value = pow5(*value);
        }
        for i in 0..t {
            state[i] += params.c[(r + 1) * t + i];
        }
        state = mix(&state, &params.m, t);
    }

    for value in state.iter_mut() {
        *value = pow5(*value);
    }
    for i in 0..t {
        state[i] += params.c[(N_ROUNDS_F / 2) * t + i];
    }
    state = mix(&state, &params.p, t);

    for r in 0..n_rounds_p {
        state[0] = pow5(state[0]);
        state[0] += params.c[(N_ROUNDS_F / 2 + 1) * t + r];
        let mut s0 = Fr::from(0u64);
        for j in 0..t {
            s0 += params.s[(t * 2 - 1) * r + j] * state[j];
        }
        let s0_coeff_state0 = state[0];
        for k in 1..t {
            state[k] += s0_coeff_state0 * params.s[(t * 2 - 1) * r + t + k - 1];
        }
        state[0] = s0;
    }

    for r in 0..(N_ROUNDS_F / 2 - 1) {
        for value in state.iter_mut() {
            *value = pow5(*value);
        }
        for i in 0..t {
            state[i] += params.c[(N_ROUNDS_F / 2 + 1) * t + n_rounds_p + r * t + i];
        }
        state = mix(&state, &params.m, t);
    }
    for value in state.iter_mut() {
        *value = pow5(*value);
    }
    state = mix(&state, &params.m, t);
    state[0]
}

static PARAMS_T10: OnceLock<OptParams> = OnceLock::new();
static PARAMS_T11: OnceLock<OptParams> = OnceLock::new();

/// Circomlib `Poseidon(n)` for n=9 (V2 commitment) or n=10 (V3 commitment).
pub fn poseidon_hash_n(inputs: &[Fr]) -> Fr {
    poseidon_opt(inputs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poseidon_9_matches_circomlibjs() {
        let inputs: Vec<Fr> = (1u64..=9).map(Fr::from).collect();
        let expected =
            parse_hex_to_fr("1e0b893aa2ad802275e749d260330b7675b22bb3aaa4461d204af32e60cd9078");
        assert_eq!(poseidon_hash_n(&inputs), expected);
    }

    #[test]
    fn poseidon_10_matches_circomlibjs() {
        let mut inputs = vec![Fr::from(10u64)];
        inputs.extend((1u64..=9).map(Fr::from));
        let expected =
            parse_hex_to_fr("2549fabeaa19d7e2ef65570f8d92882d38c98cd1e1392c9abddfe2873d8c22b5");
        assert_eq!(poseidon_hash_n(&inputs), expected);
    }
}
