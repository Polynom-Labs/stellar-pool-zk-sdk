//! Circom `.r1cs` parser (BN254). Accepts Circom, compact `R1CD`, or gzip.

use anyhow::{anyhow, Result};
use ark_bn254_zk::Fr;
use ark_ff_zk::PrimeField;
use r1cs_compact::R1cs as CompactR1cs;

#[derive(Clone, Debug)]
pub struct Term {
    pub wire_id: u32,
    pub coefficient: Fr,
}

#[derive(Clone, Debug, Default)]
pub struct LinearCombination {
    pub terms: Vec<Term>,
}

#[derive(Clone, Debug)]
pub struct Constraint {
    pub a: LinearCombination,
    pub b: LinearCombination,
    pub c: LinearCombination,
}

#[derive(Clone, Debug)]
pub struct R1CS {
    pub num_wires: u32,
    pub num_pub_out: u32,
    pub num_pub_in: u32,
    pub num_prv_in: u32,
    pub num_public: u32,
    pub constraints: Vec<Constraint>,
}

impl R1CS {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let parsed = r1cs_compact::parse_any(data).map_err(|err| anyhow!("{err}"))?;
        Self::from_compact(parsed)
    }

    fn from_compact(parsed: CompactR1cs) -> Result<Self> {
        let num_public = parsed
            .header
            .num_pub_out
            .checked_add(parsed.header.num_pub_in)
            .ok_or_else(|| anyhow!("Overflow calculating num_public"))?;
        Ok(R1CS {
            num_wires: parsed.header.num_wires,
            num_pub_out: parsed.header.num_pub_out,
            num_pub_in: parsed.header.num_pub_in,
            num_prv_in: parsed.header.num_prv_in,
            num_public,
            constraints: parsed
                .constraints
                .into_iter()
                .map(|constraint| Constraint {
                    a: map_lc(constraint.a),
                    b: map_lc(constraint.b),
                    c: map_lc(constraint.c),
                })
                .collect(),
        })
    }

    pub fn num_constraints(&self) -> usize {
        self.constraints.len()
    }
}

fn map_lc(terms: Vec<r1cs_compact::Term>) -> LinearCombination {
    LinearCombination {
        terms: terms
            .into_iter()
            .map(|term| Term {
                wire_id: term.wire_id,
                coefficient: Fr::from_le_bytes_mod_order(&term.coefficient),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use r1cs_compact::{
        Constraint as CompactConstraint, Header, R1cs as CompactFile, Term as CompactTerm,
    };

    fn coeff(byte: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0] = byte;
        out
    }

    fn tiny_gzip() -> Vec<u8> {
        CompactFile {
            header: Header {
                num_wires: 4,
                num_pub_out: 1,
                num_pub_in: 1,
                num_prv_in: 1,
            },
            constraints: vec![CompactConstraint {
                a: vec![CompactTerm {
                    wire_id: 1,
                    coefficient: coeff(3),
                }],
                b: vec![CompactTerm {
                    wire_id: 2,
                    coefficient: coeff(1),
                }],
                c: vec![CompactTerm {
                    wire_id: 3,
                    coefficient: coeff(3),
                }],
            }],
        }
        .compress()
        .expect("compress tiny r1cs")
    }

    #[test]
    fn parse_gzip_compact_matches_header() {
        let gz = tiny_gzip();
        assert_eq!(&gz[..2], &[0x1f, 0x8b]);
        let parsed = R1CS::parse(&gz).unwrap();
        assert_eq!(parsed.num_wires, 4);
        assert_eq!(parsed.num_pub_out, 1);
        assert_eq!(parsed.num_pub_in, 1);
        assert_eq!(parsed.num_public, 2);
        assert_eq!(parsed.num_constraints(), 1);
        assert_eq!(parsed.constraints[0].a.terms[0].wire_id, 1);
        assert_eq!(parsed.constraints[0].c.terms[0].wire_id, 3);
    }
}
