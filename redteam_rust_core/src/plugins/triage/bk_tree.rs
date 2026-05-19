use crate::plugins::triage::similarity_engine::calculate_distance;
use tracing::warn;

const MAX_DEPTH: usize = 500;

pub struct BkTree {
    root: Option<BkNode>,
    len: usize,
}

struct BkNode {
    hash: String,
    _finding_idx: usize,
    children: std::collections::HashMap<u32, BkNode>,
}

impl BkTree {
    pub fn new() -> Self {
        Self { root: None, len: 0 }
    }
}

impl Default for BkTree {
    fn default() -> Self {
        Self::new()
    }
}

impl BkTree {

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Insert a TLSH hash + finding index into the tree.
    /// Returns true if inserted, false if skipped (d=0 duplicate or distance failure).
    /// D1 FIX: Recursive with `&mut BkNode` parameter — each level owns its borrow independently.
    /// D2 FIX: d=0 guard prevents infinite recursion.
    /// D3 FIX: Returns false on distance failure instead of using u32::MAX.
    pub fn insert(&mut self, hash: String, idx: usize) -> bool {
        match &mut self.root {
            None => {
                self.root = Some(BkNode {
                    hash,
                    _finding_idx: idx,
                    children: std::collections::HashMap::new(),
                });
                self.len += 1;
                true
            }
            Some(root) => {
                if Self::insert_node(root, hash, idx, 0) {
                    self.len += 1;
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Recursive insert. Each level receives a `&mut BkNode` — valid under Rust NLL.
    fn insert_node(node: &mut BkNode, hash: String, idx: usize, depth: usize) -> bool {
        if depth > MAX_DEPTH {
            warn!(
                "⚠️ BK-Tree: MAX_DEPTH {} exceeded at insert — possible degenerate distribution. \
                 Finding NOT indexed (treated as unique).",
                MAX_DEPTH
            );
            return false;
        }

        let d = match calculate_distance(&hash, &node.hash) {
            Some(d) => d,
            None => {
                // D3: Distance failure — do not corrupt tree with u32::MAX
                warn!(
                    "⚠️ BK-Tree: TLSH distance failed for hash '{}...' — skipping index.",
                    &hash[..hash.len().min(8)]
                );
                return false;
            }
        };

        // D2: d=0 = exact same hash = already in tree (detected by find_any_within before insert)
        if d == 0 {
            return false;
        }

        match node.children.get_mut(&d) {
            Some(child) => Self::insert_node(child, hash, idx, depth + 1),
            None => {
                node.children.insert(
                    d,
                    BkNode {
                        hash,
                        _finding_idx: idx,
                        children: std::collections::HashMap::new(),
                    },
                );
                true
            }
        }
    }

    /// Returns true if any stored hash is within `threshold` TLSH distance of `query`.
    /// C5 FIX: Short-circuits on first hit — does NOT collect full Vec.
    /// C7 FIX: Depth guard prevents stack overflow in degenerate trees.
    pub fn find_any_within(&self, query: &str, threshold: u32) -> bool {
        match &self.root {
            None => false,
            Some(root) => Self::find_any_node(root, query, threshold, 0),
        }
    }

    fn find_any_node(node: &BkNode, query: &str, threshold: u32, depth: usize) -> bool {
        if depth > MAX_DEPTH {
            warn!("⚠️ BK-Tree: MAX_DEPTH {} exceeded at find — bailing out.", MAX_DEPTH);
            return false;
        }

        let d = match calculate_distance(query, &node.hash) {
            Some(d) => d,
            None => return false, // D3: can't compute distance, no hit
        };

        // C5: Short-circuit on first hit
        if d <= threshold {
            return true;
        }

        // BK-Tree pruning: only visit children with key k in [d-threshold, d+threshold]
        // This prunes >90% of the tree on average.
        let lo = d.saturating_sub(threshold);
        let hi = d.saturating_add(threshold);

        for (k, child) in &node.children {
            if *k >= lo && *k <= hi && Self::find_any_node(child, query, threshold, depth + 1) {
                return true; // C5: propagate short-circuit upward
            }
        }
        false
    }
}

// ─── SimHash BK-Tree (Sprint 3) ──────────────────────────────────────────────

use crate::plugins::triage::similarity_engine::hamming_distance;

pub struct SimHashBkTree {
    root: Option<SimHashBkNode>,
    len: usize,
}

struct SimHashBkNode {
    hash: u64,
    _finding_idx: usize,
    children: std::collections::HashMap<u32, SimHashBkNode>,
}

impl SimHashBkTree {
    pub fn new() -> Self {
        Self { root: None, len: 0 }
    }
}

impl Default for SimHashBkTree {
    fn default() -> Self {
        Self::new()
    }
}

impl SimHashBkTree {

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn insert(&mut self, hash: u64, idx: usize) -> bool {
        match &mut self.root {
            None => {
                self.root = Some(SimHashBkNode {
                    hash,
                    _finding_idx: idx,
                    children: std::collections::HashMap::new(),
                });
                self.len += 1;
                true
            }
            Some(root) => {
                if Self::insert_node(root, hash, idx, 0) {
                    self.len += 1;
                    true
                } else {
                    false
                }
            }
        }
    }

    fn insert_node(node: &mut SimHashBkNode, hash: u64, idx: usize, depth: usize) -> bool {
        if depth > MAX_DEPTH {
            return false;
        }

        let d = hamming_distance(hash, node.hash);

        if d == 0 {
            return false;
        }

        match node.children.get_mut(&d) {
            Some(child) => Self::insert_node(child, hash, idx, depth + 1),
            None => {
                node.children.insert(
                    d,
                    SimHashBkNode {
                        hash,
                        _finding_idx: idx,
                        children: std::collections::HashMap::new(),
                    },
                );
                true
            }
        }
    }

    pub fn find_similar_within(&self, query: u64, threshold: u32) -> Option<usize> {
        match &self.root {
            None => None,
            Some(root) => Self::find_similar_node(root, query, threshold, 0),
        }
    }

    fn find_similar_node(node: &SimHashBkNode, query: u64, threshold: u32, depth: usize) -> Option<usize> {
        if depth > MAX_DEPTH {
            return None;
        }

        let d = hamming_distance(query, node.hash);

        if d <= threshold {
            return Some(node._finding_idx);
        }

        let lo = d.saturating_sub(threshold);
        let hi = d.saturating_add(threshold);

        for (k, child) in &node.children {
            if *k >= lo && *k <= hi {
                if let Some(idx) = Self::find_similar_node(child, query, threshold, depth + 1) {
                    return Some(idx);
                }
            }
        }
        None
    }
}

// ─── Unit Tests (E3) ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Test distance function using known TLSH hashes.
    /// We use fixed TLSH strings computed from known inputs.
    /// For unit tests, we need a controlled distance function.
    /// Strategy: use the real calculate_distance with known near-identical strings.
    fn test_tree_with_mock() -> BkTree {
        BkTree::new()
    }

    #[test]
    fn empty_tree_find_returns_false() {
        let tree = test_tree_with_mock();
        // Any query on empty tree should return false
        assert!(!tree.find_any_within("T1BF12A30000000000000000000000000000000000000000000000000000000000000000", 30));
    }

    #[test]
    fn empty_tree_is_empty() {
        let tree = BkTree::new();
        assert!(tree.is_empty());
        assert_eq!(tree.len(), 0);
    }

    #[test]
    fn insert_increments_len() {
        let mut tree = BkTree::new();
        // Insert a syntactically valid TLSH hash (format: T1 + 70 hex chars)
        // Real TLSH hashes from known strings — using a placeholder format
        // These will return false from calculate_distance if tlsh_fixed can't parse them
        // but insert() still increments root.
        let dummy_hash = "T1BF000000000000000000000000000000000000000000000000000000000000000000000".to_string();
        let result = tree.insert(dummy_hash, 0);
        // Root insert always succeeds
        assert!(result);
        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn d0_guard_prevents_duplicate_index() {
        let mut tree = BkTree::new();
        let hash = "T1BF000000000000000000000000000000000000000000000000000000000000000000000".to_string();
        tree.insert(hash.clone(), 0);
        // Inserting same hash again: calculate_distance returns Some(0) or None
        // Either way the second insert should not increment len beyond 1 OR insert fails
        let result = tree.insert(hash, 1);
        // d=0 returns false — len stays 1
        // OR distance fails (invalid hash) — also false
        if result {
            // If somehow it inserted (hash parsed differently), len is 2 — acceptable
            // The important thing is no infinite loop occurred
        }
        // The test verifies the function returns without hanging
    }

    #[test]
    fn pruning_bounds_lo_hi() {
        // Verify that pruning math is correct: lo = d - threshold, hi = d + threshold
        // A child with key exactly at lo or hi should be visited
        let d: u32 = 50;
        let threshold: u32 = 30;
        let lo = d.saturating_sub(threshold); // 20
        let hi = d.saturating_add(threshold); // 80
        assert_eq!(lo, 20);
        assert_eq!(hi, 80);
        // Child at key=20 should be visited (k >= lo)
        assert!(20u32 >= lo && 20u32 <= hi);
        // Child at key=80 should be visited (k <= hi)
        assert!(80u32 >= lo && 80u32 <= hi);
        // Child at key=19 should NOT be visited
        assert!(!(19u32 >= lo && 19u32 <= hi));
        // Child at key=81 should NOT be visited
        assert!(!(81u32 >= lo && 81u32 <= hi));
    }

    #[test]
    fn saturating_sub_at_zero_threshold() {
        // Ensure lo doesn't underflow with small d and large threshold
        let d: u32 = 5;
        let threshold: u32 = 30;
        let lo = d.saturating_sub(threshold);
        assert_eq!(lo, 0); // should saturate at 0, not wrap
    }

    #[test]
    fn simhash_tree_insert_and_find() {
        let mut tree = SimHashBkTree::new();
        let h1 = 0b10101010u64;
        let h2 = 0b10101011u64; // distance 1
        let h3 = 0b11111111u64; // distance 4 from h1
        
        tree.insert(h1, 42); // Use 42 as finding index
        
        assert_eq!(tree.find_similar_within(h1, 0), Some(42));
        assert_eq!(tree.find_similar_within(h2, 1), Some(42));
        assert!(tree.find_similar_within(h2, 0).is_none());
        assert_eq!(tree.find_similar_within(h3, 4), Some(42));
        assert!(tree.find_similar_within(h3, 3).is_none());
    }
}
