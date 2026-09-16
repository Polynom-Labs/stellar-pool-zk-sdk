use ark_bn254::Fr;
use std::collections::HashMap;

use crate::poseidon::poseidon_hash_2;

/// Lean Incremental Merkle Tree - standalone version without Soroban Env.
/// Same algorithm as libs/lean-imt but using ark Fr directly.
/// Inserts are always in pairs of leaves (matches on-chain contract).
pub struct LeanIMT {
    leaves: Vec<Fr>,
    depth: u32,
    capacity: u32,
    root: Fr,
    /// Cache for empty subtree hashes at each level
    subtree_cache: HashMap<u32, Fr>,
    /// Cache for specific nodes updated during incremental inserts
    /// Key: (level, node_index)
    sparse_cache: HashMap<(u32, u32), Fr>,
}

impl LeanIMT {
    /// Creates a new LeanIMT with a fixed depth. Missing leaves are zero.
    pub fn new(depth: u32) -> Self {
        let capacity = 1u32.checked_shl(depth).unwrap_or(u32::MAX);
        let mut tree = Self {
            leaves: Vec::new(),
            depth,
            capacity,
            root: Fr::from(0u64),
            subtree_cache: HashMap::new(),
            sparse_cache: HashMap::new(),
        };
        tree.recompute_tree();
        tree
    }

    /// Appends two leaves and updates the root (same as on-chain `insert_two`).
    pub fn insert_two(&mut self, leaf_a: Fr, leaf_b: Fr) -> Result<(), &'static str> {
        if self.leaves.len() as u32 + 2 > self.capacity {
            return Err("Tree is at capacity");
        }
        self.leaves.push(leaf_a);
        self.leaves.push(leaf_b);
        self.incremental_update_two();
        Ok(())
    }

    /// Gets the current root
    pub fn get_root(&self) -> Fr {
        self.root
    }

    /// Gets the number of leaves
    pub fn get_leaf_count(&self) -> u32 {
        self.leaves.len() as u32
    }

    #[inline]
    fn empty_leaf_scalar(&self) -> Fr {
        self.subtree_cache
            .get(&0)
            .copied()
            .unwrap_or_else(|| Fr::from(0u64))
    }

    #[inline]
    fn is_empty_subtree(&self, level: u32, node_index: u32) -> bool {
        let width = 1u64.checked_shl(level).unwrap_or(u64::MAX);
        let start = (node_index as u64).saturating_mul(width);
        start >= self.leaves.len() as u64
    }

    fn get_cached_node(&self, level: u32, node_index: u32) -> Option<Fr> {
        if let Some(&v) = self.sparse_cache.get(&(level, node_index)) {
            return Some(v);
        }
        if self.is_empty_subtree(level, node_index) {
            return self.subtree_cache.get(&level).copied();
        }
        None
    }

    /// Generates a merkle proof for a given leaf index.
    /// Returns (siblings, depth).
    pub fn generate_proof(&self, leaf_index: u32) -> Option<(Vec<Fr>, u32)> {
        if leaf_index >= self.get_leaf_count() {
            return None;
        }

        let mut siblings = Vec::new();

        if self.depth == 1 && self.get_leaf_count() == 2 {
            if leaf_index == 0 {
                siblings.push(self.leaves[1]);
            } else {
                siblings.push(self.leaves[0]);
            }
        } else {
            let mut current_index = leaf_index;
            let mut current_depth = 0u32;

            while current_depth < self.depth {
                let sibling_index = if current_index % 2 == 0 {
                    current_index + 1
                } else {
                    current_index - 1
                };

                let sibling = if current_depth == 0 {
                    if sibling_index < self.get_leaf_count() {
                        self.leaves[sibling_index as usize]
                    } else {
                        self.empty_leaf_scalar()
                    }
                } else {
                    self.compute_node_at_level(sibling_index, current_depth)
                };

                siblings.push(sibling);
                current_index /= 2;
                current_depth += 1;
            }
        }

        Some((siblings, self.depth))
    }

    /// Computes the value of an internal node at a specific level
    fn compute_node_at_level(&self, node_index: u32, target_level: u32) -> Fr {
        if target_level > self.depth {
            return Fr::from(0u64);
        }

        if let Some(cached) = self.get_cached_node(target_level, node_index) {
            return cached;
        }

        if target_level == 0 {
            if node_index < self.get_leaf_count() {
                self.leaves[node_index as usize]
            } else {
                self.empty_leaf_scalar()
            }
        } else {
            let left = self.compute_node_at_level(node_index * 2, target_level - 1);
            let right = self.compute_node_at_level(node_index * 2 + 1, target_level - 1);
            poseidon_hash_2(left, right)
        }
    }

    fn get_node_scalar_during_batch(&self, level: u32, index: u32) -> Fr {
        if let Some(s) = self.sparse_cache.get(&(level, index)) {
            return *s;
        }
        self.compute_node_at_level(index, level)
    }

    fn recompute_sparse_node_at_level(&mut self, level: u32, index: u32) {
        let scalar = if level == 0 {
            if index < self.get_leaf_count() {
                self.leaves[index as usize]
            } else {
                self.empty_leaf_scalar()
            }
        } else {
            let left = self.get_node_scalar_during_batch(level - 1, index * 2);
            let right = self.get_node_scalar_during_batch(level - 1, index * 2 + 1);
            poseidon_hash_2(left, right)
        };
        self.sparse_cache.insert((level, index), scalar);
    }

    fn incremental_update_two(&mut self) {
        let i0 = self.leaves.len() as u32 - 2;
        let i1 = self.leaves.len() as u32 - 1;

        for idx in [i0, i1] {
            self.sparse_cache
                .insert((0, idx), self.leaves[idx as usize]);
        }

        for level in 1..=self.depth {
            let a = i0 >> level;
            let b = i1 >> level;
            if a == b {
                self.recompute_sparse_node_at_level(level, a);
            } else {
                let lo = a.min(b);
                let hi = a.max(b);
                self.recompute_sparse_node_at_level(level, lo);
                self.recompute_sparse_node_at_level(level, hi);
            }
        }

        self.root = *self
            .sparse_cache
            .get(&(self.depth, 0))
            .or_else(|| self.subtree_cache.get(&self.depth))
            .unwrap_or(&Fr::from(0u64));
    }

    /// Recomputes the entire tree (used for initial empty tree)
    fn recompute_tree(&mut self) {
        if self.depth == 0 {
            self.root = Fr::from(0u64);
            return;
        }

        let zero = Fr::from(0u64);
        let mut current = zero;

        for level in 0..=self.depth {
            if level == 0 {
                current = zero;
            } else {
                current = poseidon_hash_2(current, current);
            }
            self.subtree_cache.insert(level, current);
        }

        self.root = current;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_tree() {
        let tree = LeanIMT::new(5);
        // Empty tree should have a deterministic root
        let root = tree.get_root();
        assert_ne!(root, Fr::from(0u64)); // Root of empty tree is hash of zeros, not zero itself
    }

    #[test]
    fn test_insert_two_and_proof() {
        let mut tree = LeanIMT::new(5);
        tree.insert_two(Fr::from(42u64), Fr::from(43u64)).unwrap();

        let proof = tree.generate_proof(0);
        assert!(proof.is_some());
        let (siblings, depth) = proof.unwrap();
        assert_eq!(depth, 5);
        assert_eq!(siblings.len(), 5);
    }

    #[test]
    fn test_two_leaves() {
        let mut tree = LeanIMT::new(5);
        tree.insert_two(Fr::from(1u64), Fr::from(2u64)).unwrap();

        let proof0 = tree.generate_proof(0).unwrap();
        let proof1 = tree.generate_proof(1).unwrap();
        assert_eq!(proof0.0.len(), 5);
        assert_eq!(proof1.0.len(), 5);
    }
}
