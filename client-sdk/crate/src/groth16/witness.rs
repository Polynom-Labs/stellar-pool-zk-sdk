//! Graph-based Circom witness calculator (circom-witness-rs).

use anyhow::{bail, ensure, Context as _, Result};
use ark_bn254_zk::Fr as BbfFr;
use ark_ff_zk::{BigInteger as _, Field as _, PrimeField as _};
use circom_witness_rs::{calculate_witness, init_graph, BlackBoxFunction, Graph, M};
use ruint::aliases::U256;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

pub struct WitnessCalculator {
    graph: Graph,
    bbfs: HashMap<String, BlackBoxFunction>,
    input_hashes: HashSet<u64>,
    input_sizes: HashMap<u64, usize>,
}

impl WitnessCalculator {
    pub fn from_graph(graph_bytes: &[u8]) -> Result<WitnessCalculator> {
        let graph = init_graph(graph_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to load witness graph: {e}"))?;
        let mut input_hashes = HashSet::with_capacity(graph.input_mapping.len());
        let mut input_sizes = HashMap::with_capacity(graph.input_mapping.len());
        for info in &graph.input_mapping {
            input_hashes.insert(info.hash);
            input_sizes.insert(
                info.hash,
                usize::try_from(info.signalsize).unwrap_or(usize::MAX),
            );
        }
        Ok(WitnessCalculator {
            graph,
            bbfs: circomlib_black_box_functions(),
            input_hashes,
            input_sizes,
        })
    }

    pub fn compute_witness(&self, inputs_json: &str) -> Result<Vec<u8>> {
        let inputs = parse_inputs(inputs_json)?;
        let mut unknown: Vec<&str> = inputs
            .keys()
            .filter(|key| !self.input_hashes.contains(&fnv1a(key)))
            .map(String::as_str)
            .collect();
        unknown.sort_unstable();
        if !unknown.is_empty() {
            bail!("unknown circuit input signal(s): {}", unknown.join(", "));
        }
        for (key, values) in &inputs {
            let hash = fnv1a(key);
            if let Some(&expected_size) = self.input_sizes.get(&hash) {
                if values.len() > expected_size {
                    bail!(
                        "input signal '{key}' length {} exceeds declared size {}",
                        values.len(),
                        expected_size
                    );
                }
            }
        }
        let witness = calculate_witness(inputs, &self.graph, Some(&self.bbfs))
            .map_err(|e| anyhow::anyhow!("Witness calculation failed: {e}"))?;
        Ok(witness_to_bytes(&witness))
    }
}

fn circomlib_black_box_functions() -> HashMap<String, BlackBoxFunction> {
    let mut bbfs: HashMap<String, BlackBoxFunction> = HashMap::new();
    let bbf_inv: BlackBoxFunction = Arc::new(|params: &[BbfFr]| {
        params
            .first()
            .and_then(|p| p.inverse())
            .unwrap_or_else(|| BbfFr::from(0u64))
    });
    bbfs.insert(String::from("bbf_inv"), bbf_inv);
    let bbf_bit: BlackBoxFunction = Arc::new(|params: &[BbfFr]| {
        let value = match params.first() {
            Some(v) => v.into_bigint(),
            None => return BbfFr::from(0u64),
        };
        let bit_index = match params.get(1) {
            Some(p) => usize::try_from(p.into_bigint().as_ref()[0]).unwrap_or(usize::MAX),
            None => return BbfFr::from(0u64),
        };
        BbfFr::from(u64::from(value.get_bit(bit_index)))
    });
    bbfs.insert(String::from("bbf_bit"), bbf_bit);
    bbfs
}

fn flatten_field_values(key: &str, val: &serde_json::Value) -> Result<Vec<U256>> {
    match val {
        serde_json::Value::String(s) => Ok(vec![parse_field(s)?]),
        serde_json::Value::Number(n) => Ok(vec![parse_field(&n.to_string())?]),
        serde_json::Value::Array(items) => {
            let mut out = Vec::new();
            for item in items {
                out.extend(flatten_field_values(key, item)?);
            }
            Ok(out)
        }
        other => bail!("signal {key} must be a field string or nested array, got: {other}"),
    }
}

fn parse_inputs(inputs_json: &str) -> Result<HashMap<String, Vec<U256>>> {
    let value: serde_json::Value = serde_json::from_str(inputs_json).context("Invalid JSON")?;
    let obj = value.as_object().context("Inputs must be a JSON object")?;
    let mut out = HashMap::with_capacity(obj.len());
    for (key, val) in obj {
        out.insert(key.clone(), flatten_field_values(key, val)?);
    }
    Ok(out)
}

fn fnv1a(s: &str) -> u64 {
    let mut hash: u64 = 0xCBF2_9CE4_8422_2325;
    for byte in s.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    hash
}

fn parse_field(s: &str) -> Result<U256> {
    let s = s.trim();
    let value = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => U256::from_str_radix(hex, 16),
        None => U256::from_str_radix(s, 10),
    }
    .map_err(|e| anyhow::anyhow!("invalid field element {s:?}: {e}"))?;
    ensure!(value < M, "witness input exceeds BN254 field modulus");
    Ok(value)
}

fn witness_to_bytes(witness: &[U256]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        witness
            .len()
            .checked_mul(32)
            .expect("Overflow in witness size"),
    );
    for value in witness {
        bytes.extend_from_slice(&value.to_le_bytes::<32>());
    }
    bytes
}
