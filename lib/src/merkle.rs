//! Blake2s-256 binary Merkle tree proof verification for the ZKsync OS flat storage model.
//!
//! The storage tree is a depth-64 binary Merkle tree with Blake2s-256 as the hash function.
//! Leaves are `(key: B256, value: B256, next_index: u64)` forming a sorted linked list.
//! This module verifies inclusion/exclusion proofs against a known root hash.

use alloy_primitives::B256;
use blake2::digest::FixedOutput;
use blake2::{Blake2s256, Digest};
use serde::{Deserialize, Serialize};

/// Maximum tree depth (64 bits of key space).
pub const TREE_DEPTH: u8 = 64;

// ---------------------------------------------------------------------------
// Blake2s helpers
// ---------------------------------------------------------------------------

pub fn blake2s(data: &[u8]) -> B256 {
    let mut h = Blake2s256::new();
    h.update(data);
    B256::from_slice(&h.finalize_fixed())
}

fn blake2s_compress(lhs: &B256, rhs: &B256) -> B256 {
    let mut h = Blake2s256::new();
    h.update(lhs.as_slice());
    h.update(rhs.as_slice());
    B256::from_slice(&h.finalize_fixed())
}

/// Hash a leaf: Blake2s(key || value || next_index_le_8).
pub fn hash_leaf(key: &B256, value: &B256, next_index: u64) -> B256 {
    let mut buf = [0u8; 72]; // 32 + 32 + 8
    buf[..32].copy_from_slice(key.as_slice());
    buf[32..64].copy_from_slice(value.as_slice());
    buf[64..72].copy_from_slice(&next_index.to_le_bytes());
    blake2s(&buf)
}

/// Precomputed empty subtree hashes for each depth 0..=64.
fn empty_subtree_hashes() -> &'static Vec<B256> {
    use std::sync::OnceLock;
    static CACHE: OnceLock<Vec<B256>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let empty_leaf = hash_leaf(&B256::ZERO, &B256::ZERO, 0);
        let mut hashes = vec![empty_leaf];
        for _ in 0..TREE_DEPTH {
            let prev = *hashes.last().unwrap();
            hashes.push(blake2s_compress(&prev, &prev));
        }
        hashes
    })
}

/// Get the empty subtree hash at the given depth.
pub fn empty_subtree_hash(depth: u8) -> B256 {
    empty_subtree_hashes()[depth as usize]
}

/// Returns a Vec of empty subtree hashes for each depth 0..TREE_DEPTH.
pub fn empty_subtree_hashes_vec() -> Vec<B256> {
    empty_subtree_hashes().clone()
}

// ---------------------------------------------------------------------------
// Proof types
// ---------------------------------------------------------------------------

/// Merkle proof entry for a single storage slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotProofEntry {
    pub index: u64,
    pub value: B256,
    pub next_index: u64,
    /// Sibling hashes from leaf (depth 0) upward. If shorter than TREE_DEPTH,
    /// missing entries are filled with `empty_subtree_hash(depth)`.
    pub siblings: Vec<B256>,
}

impl SlotProofEntry {
    /// Verify this proof entry for the given leaf key and recover the tree root hash.
    pub fn recover_root(&self, leaf_key: &B256) -> B256 {
        let empty = empty_subtree_hashes();
        let mut hash = hash_leaf(leaf_key, &self.value, self.next_index);
        let mut idx = self.index;
        for depth in 0..TREE_DEPTH {
            let sibling = self
                .siblings
                .get(depth as usize)
                .copied()
                .unwrap_or(empty[depth as usize]);
            hash = if idx % 2 == 0 {
                blake2s_compress(&hash, &sibling)
            } else {
                blake2s_compress(&sibling, &hash)
            };
            idx /= 2;
        }
        hash
    }
}

/// Proof for a single storage slot (existing or non-existing).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageProof {
    /// The key exists in the tree.
    Existing(SlotProofEntry),
    /// The key does NOT exist. Proved by showing two adjacent leaves in the
    /// sorted linked list that bracket the missing key.
    NonExisting {
        left_neighbor: NeighborProofEntry,
        right_neighbor: NeighborProofEntry,
    },
}

/// Neighbor entry used in non-existence proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeighborProofEntry {
    pub entry: SlotProofEntry,
    pub leaf_key: B256,
}

impl StorageProof {
    /// Verify the proof for the given flat storage key and return (root_hash, value).
    /// For existing keys, value is Some. For non-existing, value is None.
    pub fn verify(&self, flat_key: &B256) -> Result<(B256, Option<B256>), ProofError> {
        match self {
            StorageProof::Existing(entry) => {
                let root = entry.recover_root(flat_key);
                Ok((root, Some(entry.value)))
            }
            StorageProof::NonExisting {
                left_neighbor,
                right_neighbor,
            } => {
                if left_neighbor.leaf_key >= *flat_key {
                    return Err(ProofError::LeftNeighborNotSmaller);
                }
                if *flat_key >= right_neighbor.leaf_key {
                    return Err(ProofError::RightNeighborNotLarger);
                }
                if left_neighbor.entry.next_index != right_neighbor.entry.index {
                    return Err(ProofError::NeighborsNotAdjacent);
                }
                let root_left = left_neighbor.entry.recover_root(&left_neighbor.leaf_key);
                let root_right = right_neighbor.entry.recover_root(&right_neighbor.leaf_key);
                if root_left != root_right {
                    return Err(ProofError::RootMismatch);
                }
                Ok((root_left, None))
            }
        }
    }
}

#[derive(Debug)]
pub enum ProofError {
    LeftNeighborNotSmaller,
    RightNeighborNotLarger,
    NeighborsNotAdjacent,
    RootMismatch,
}

impl core::fmt::Display for ProofError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::LeftNeighborNotSmaller => write!(f, "left neighbor key >= queried key"),
            Self::RightNeighborNotLarger => write!(f, "right neighbor key <= queried key"),
            Self::NeighborsNotAdjacent => {
                write!(f, "neighbor leaves not adjacent in linked list")
            }
            Self::RootMismatch => write!(f, "left and right neighbor recover different roots"),
        }
    }
}

impl std::error::Error for ProofError {}

// ---------------------------------------------------------------------------
// Batch tree update — verify old root, apply writes, compute new root
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeLeaf {
    pub key: B256,
    pub value: B256,
    pub next_index: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WriteOp {
    Update { index: u64 },
    Insert { prev_index: u64 },
}

/// Batch tree proof for verifying the old root and computing the new root
/// after applying a set of writes.
///
/// `sorted_leaves` is the pre-state of every touched leaf plus any *anchor*
/// leaves: untouched leaves included so that the old-root pass authenticates
/// tree regions the new-root pass needs as siblings. The new root is a pure
/// function of (authenticated old state, verified write entries) — there is no
/// trusted post-state input of any kind.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchTreeUpdate {
    pub operations: Vec<WriteOp>,
    pub entries: Vec<(B256, B256)>,
    pub sorted_leaves: Vec<(u64, TreeLeaf)>,
    /// Intermediate sibling hashes for reconstructing the OLD root from
    /// sorted_leaves, in traversal order. Authenticated by the old-root check.
    pub intermediate_hashes: Vec<B256>,
    pub leaf_count_before: u64,
}

impl BatchTreeUpdate {
    /// Verify the old root matches `expected_old_root`, apply writes, and return
    /// (new_root_hash, new_leaf_count).
    ///
    /// Soundness: pass 1 reconstructs the old root from `sorted_leaves` +
    /// `intermediate_hashes`, recording every node it consumes or computes into
    /// an authenticated (depth, index) -> hash map. Pass 2 computes the new
    /// root over the post-write leaf set, resolving every off-path sibling
    /// from that map or from empty-subtree constants (positions at or beyond
    /// `leaf_count_before` hold no pre-existing leaves; inserted leaves are
    /// dense, so anything not in the computed set there is empty). Any sibling
    /// that is neither authenticated nor provably empty is a hard error — the
    /// witness must carry an anchor leaf for that region.
    pub fn apply(&self, expected_old_root: &B256) -> (B256, u64) {
        // Pass 1: verify the old root, authenticating node hashes.
        let mut authenticated: std::collections::HashMap<(u8, u64), B256> =
            std::collections::HashMap::new();
        let old_root =
            self.zip_and_record(&self.sorted_leaves, self.leaf_count_before, &mut authenticated);
        assert_eq!(
            old_root, *expected_old_root,
            "batch tree update: old root mismatch: computed {old_root}, expected {expected_old_root}"
        );

        let mut leaves: Vec<(u64, TreeLeaf)> = self.sorted_leaves.clone();
        let mut next_tree_index = self.leaf_count_before;

        // Index map: tree_index -> position in `leaves` vec, for O(1) lookup.
        let mut pos_of: std::collections::HashMap<u64, usize> = leaves
            .iter()
            .enumerate()
            .map(|(pos, (idx, _))| (*idx, pos))
            .collect();

        for (op, (key, new_value)) in self.operations.iter().zip(&self.entries) {
            match op {
                WriteOp::Update { index } => {
                    let pos = pos_of[index];
                    assert_eq!(leaves[pos].1.key, *key, "update key mismatch");
                    leaves[pos].1.value = *new_value;
                }
                WriteOp::Insert { prev_index } => {
                    let this_index = next_tree_index;
                    next_tree_index += 1;

                    let prev_pos = pos_of[prev_index];
                    let old_next = leaves[prev_pos].1.next_index;

                    // Linked-list ordering: the predecessor must bracket the
                    // new key together with its successor, or non-existence
                    // semantics of the resulting tree are corrupted. The
                    // successor leaf must be present in the witness set.
                    assert!(
                        leaves[prev_pos].1.key < *key,
                        "insert ordering violation: predecessor key {} >= inserted key {key}",
                        leaves[prev_pos].1.key,
                    );
                    let next_pos = *pos_of
                        .get(&old_next)
                        .unwrap_or_else(|| panic!("successor leaf {old_next} missing from witness"));
                    assert!(
                        *key < leaves[next_pos].1.key,
                        "insert ordering violation: inserted key {key} >= successor key {}",
                        leaves[next_pos].1.key,
                    );

                    let new_pos = leaves.len();
                    leaves.push((
                        this_index,
                        TreeLeaf {
                            key: *key,
                            value: *new_value,
                            next_index: old_next,
                        },
                    ));
                    pos_of.insert(this_index, new_pos);

                    // Update prev leaf's next_index (re-lookup pos since vec wasn't reordered)
                    leaves[prev_pos].1.next_index = this_index;
                }
            }
        }

        leaves.sort_by_key(|(idx, _)| *idx);
        // Pass 2: independent new-root computation from authenticated data only.
        let new_root = self.zip_from_authenticated(&leaves, next_tree_index, &authenticated);
        (new_root, next_tree_index)
    }

    /// Reconstruct the old root from `sorted_leaves`, consuming
    /// `intermediate_hashes` in traversal order and recording every node this
    /// pass touches (leaf hashes, consumed siblings, computed internal nodes)
    /// into `authenticated`, keyed by (depth, index-at-depth).
    fn zip_and_record(
        &self,
        sorted_leaves: &[(u64, TreeLeaf)],
        leaf_count: u64,
        authenticated: &mut std::collections::HashMap<(u8, u64), B256>,
    ) -> B256 {
        let empty_hashes = empty_subtree_hashes();
        let mut hashes_iter = self.intermediate_hashes.iter();

        let mut node_hashes: Vec<(u64, B256)> = sorted_leaves
            .iter()
            .map(|(idx, leaf)| (*idx, hash_leaf(&leaf.key, &leaf.value, leaf.next_index)))
            .collect();
        for (idx, h) in &node_hashes {
            authenticated.insert((0, *idx), *h);
        }

        let mut last_idx_on_level = leaf_count - 1;

        for depth in 0..TREE_DEPTH {
            let mut i = 0;
            let mut next_level_i = 0;

            while i < node_hashes.len() {
                let (current_idx, current_hash) = node_hashes[i];

                let next_level_hash = if current_idx % 2 == 1 {
                    i += 1;
                    let lhs = hashes_iter.next().expect("ran out of intermediate hashes");
                    authenticated.insert((depth, current_idx - 1), *lhs);
                    blake2s_compress(lhs, &current_hash)
                } else if node_hashes
                    .get(i + 1)
                    .is_some_and(|(next_idx, _)| *next_idx == current_idx + 1)
                {
                    let next_hash = node_hashes[i + 1].1;
                    i += 2;
                    blake2s_compress(&current_hash, &next_hash)
                } else {
                    i += 1;
                    let rhs = if current_idx == last_idx_on_level {
                        empty_hashes[depth as usize]
                    } else {
                        let h = *hashes_iter.next().expect("ran out of intermediate hashes");
                        authenticated.insert((depth, current_idx + 1), h);
                        h
                    };
                    blake2s_compress(&current_hash, &rhs)
                };

                node_hashes[next_level_i] = (current_idx / 2, next_level_hash);
                authenticated.insert((depth + 1, current_idx / 2), next_level_hash);
                next_level_i += 1;
            }

            node_hashes.truncate(next_level_i);
            last_idx_on_level /= 2;
        }

        assert!(hashes_iter.next().is_none(), "not all intermediate hashes consumed");
        node_hashes[0].1
    }

    /// Compute the new root over the post-write leaf set. Every sibling not in
    /// the computed set must be either authenticated by the old-root pass or a
    /// provably-empty subtree; anything else is a hard error.
    ///
    /// Empty-subtree rule: inserted leaves are assigned dense indices starting
    /// at `leaf_count_before`, so a sibling subtree that starts at or beyond
    /// `leaf_count_before` and contains no computed node holds no leaves at
    /// all in the new tree.
    fn zip_from_authenticated(
        &self,
        sorted_leaves: &[(u64, TreeLeaf)],
        leaf_count: u64,
        authenticated: &std::collections::HashMap<(u8, u64), B256>,
    ) -> B256 {
        let empty_hashes = empty_subtree_hashes();
        let _ = leaf_count;

        let mut node_hashes: Vec<(u64, B256)> = sorted_leaves
            .iter()
            .map(|(idx, leaf)| (*idx, hash_leaf(&leaf.key, &leaf.value, leaf.next_index)))
            .collect();

        for depth in 0..TREE_DEPTH {
            let mut i = 0;
            let mut next_level_i = 0;

            while i < node_hashes.len() {
                let (current_idx, current_hash) = node_hashes[i];
                let sibling_idx = current_idx ^ 1;

                let paired_with_computed = node_hashes
                    .get(i + 1)
                    .is_some_and(|(next_idx, _)| *next_idx == sibling_idx);

                let next_level_hash = if paired_with_computed {
                    let next_hash = node_hashes[i + 1].1;
                    i += 2;
                    blake2s_compress(&current_hash, &next_hash)
                } else {
                    i += 1;
                    let sibling_hash = Self::resolve_sibling(
                        depth,
                        sibling_idx,
                        self.leaf_count_before,
                        authenticated,
                        &empty_hashes,
                    );
                    if current_idx % 2 == 1 {
                        blake2s_compress(&sibling_hash, &current_hash)
                    } else {
                        blake2s_compress(&current_hash, &sibling_hash)
                    }
                };

                node_hashes[next_level_i] = (current_idx / 2, next_level_hash);
                next_level_i += 1;
            }

            node_hashes.truncate(next_level_i);
        }

        node_hashes[0].1
    }

    /// Resolve an off-path sibling for the new-root pass.
    fn resolve_sibling(
        depth: u8,
        sibling_idx: u64,
        leaf_count_before: u64,
        authenticated: &std::collections::HashMap<(u8, u64), B256>,
        empty_hashes: &[B256],
    ) -> B256 {
        if let Some(h) = authenticated.get(&(depth, sibling_idx)) {
            return *h;
        }
        let subtree_start = sibling_idx << depth;
        if subtree_start >= leaf_count_before {
            return empty_hashes[depth as usize];
        }
        panic!(
            "unauthenticated sibling at depth {depth}, index {sibling_idx}: \
             the witness must include an anchor leaf for this subtree"
        );
    }
}

// ---------------------------------------------------------------------------
// Account properties decoding (from 0x8003 storage)
// ---------------------------------------------------------------------------

/// Account properties as stored in the merkle tree at address 0x8003.
/// Layout: versioning(8) | nonce(8) | balance(32) | bytecode_hash(32) |
///         unpadded_code_len(4) | artifacts_len(4) | observable_bytecode_hash(32) |
///         observable_bytecode_len(4) = 124 bytes.
#[derive(Debug, Clone)]
pub struct AccountProperties {
    pub versioning: u64,
    pub nonce: u64,
    pub balance: [u8; 32],
    pub bytecode_hash: B256,
    pub unpadded_code_len: u32,
    pub artifacts_len: u32,
    pub observable_bytecode_hash: B256,
    pub observable_bytecode_len: u32,
}

impl AccountProperties {
    pub const ENCODED_SIZE: usize = 124;

    pub fn decode(data: &[u8]) -> Self {
        assert_eq!(
            data.len(),
            Self::ENCODED_SIZE,
            "account properties blob must be exactly {} bytes, got {}",
            Self::ENCODED_SIZE,
            data.len(),
        );
        let versioning = u64::from_be_bytes(data[0..8].try_into().unwrap());
        let nonce = u64::from_be_bytes(data[8..16].try_into().unwrap());
        let mut balance = [0u8; 32];
        balance.copy_from_slice(&data[16..48]);
        let bytecode_hash = B256::from_slice(&data[48..80]);
        let unpadded_code_len = u32::from_be_bytes(data[80..84].try_into().unwrap());
        let artifacts_len = u32::from_be_bytes(data[84..88].try_into().unwrap());
        let observable_bytecode_hash = B256::from_slice(&data[88..120]);
        let observable_bytecode_len = u32::from_be_bytes(data[120..124].try_into().unwrap());

        Self {
            versioning,
            nonce,
            balance,
            bytecode_hash,
            unpadded_code_len,
            artifacts_len,
            observable_bytecode_hash,
            observable_bytecode_len,
        }
    }

    /// Compute the Blake2s hash of the encoded account properties.
    pub fn hash(encoded: &[u8]) -> B256 {
        blake2s(encoded)
    }

}

// ---------------------------------------------------------------------------
// Flat storage key derivation
// ---------------------------------------------------------------------------

/// Derive the flat storage key from (address, storage_slot).
/// flat_key = Blake2s256( zero_pad_12(address_be_20) || slot_be_32 )
pub fn derive_flat_storage_key(address: &[u8; 20], slot: &B256) -> B256 {
    let mut h = Blake2s256::new();
    h.update([0u8; 12]);
    h.update(address);
    h.update(slot.as_slice());
    B256::from_slice(&h.finalize_fixed())
}

/// The special address where account properties are stored.
pub const ACCOUNT_PROPERTIES_ADDRESS: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80, 0x03,
];

/// Derive the flat key for an account's properties.
/// Stored at address 0x8003, key = left-padded account address.
pub fn derive_account_properties_key(account: &[u8; 20]) -> B256 {
    let mut account_key = B256::ZERO;
    account_key.0[12..32].copy_from_slice(account);
    derive_flat_storage_key(&ACCOUNT_PROPERTIES_ADDRESS, &account_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_leaf_hash_matches_server() {
        let expected: B256 =
            "0xe3cdc93b3c2beb30f6a7c7cc45a32da012df9ae1be880e2c074885cb3f4e1e53"
                .parse()
                .unwrap();
        assert_eq!(empty_subtree_hash(0), expected);
    }

    #[test]
    fn empty_level1_hash_matches_server() {
        let expected: B256 =
            "0xc45bfaf4bb5d0fee27d3178b8475155a07a1fa8ada9a15133a9016f7d0435f0f"
                .parse()
                .unwrap();
        assert_eq!(empty_subtree_hash(1), expected);
    }

    #[test]
    fn empty_level63_hash_matches_server() {
        let expected: B256 =
            "0xb720fe53e6bd4e997d967b8649e10036802a4fd3aca6d7dcc43ed9671f41cb31"
                .parse()
                .unwrap();
        assert_eq!(empty_subtree_hash(63), expected);
    }

    #[test]
    fn min_guard_hash_matches_server() {
        let expected: B256 =
            "0x9903897e51baa96a5ea51b4c194d3e0c6bcf20947cce9fd646dfb4bf754c8d28"
                .parse()
                .unwrap();
        assert_eq!(hash_leaf(&B256::ZERO, &B256::ZERO, 1), expected);
    }

    #[test]
    fn max_guard_hash_matches_server() {
        let expected: B256 =
            "0xb35299e7564e05e335094c02064bccf83d58745b417874b1fee3f523ec2007a9"
                .parse()
                .unwrap();
        assert_eq!(
            hash_leaf(&B256::repeat_byte(0xff), &B256::ZERO, 1),
            expected
        );
    }

    /// Dense reference: compute the root of a small tree by hashing every
    /// position up from the leaves, padding with empty subtrees.
    fn dense_root(leaves: &[(u64, TreeLeaf)], leaf_count: u64) -> B256 {
        let empty = empty_subtree_hashes_vec();
        let mut level: std::collections::HashMap<u64, B256> = leaves
            .iter()
            .map(|(i, l)| (*i, hash_leaf(&l.key, &l.value, l.next_index)))
            .collect();
        let mut width = leaf_count;
        for depth in 0..TREE_DEPTH {
            let mut next: std::collections::HashMap<u64, B256> = std::collections::HashMap::new();
            let next_width = width.div_ceil(2);
            for i in 0..next_width {
                let l = level.get(&(2 * i)).copied().unwrap_or(empty[depth as usize]);
                let r = level.get(&(2 * i + 1)).copied().unwrap_or(empty[depth as usize]);
                next.insert(i, blake2s_compress(&l, &r));
            }
            level = next;
            width = next_width;
        }
        level[&0]
    }

    /// Regression: the new-root computation in `apply()` must be correct for
    /// inserts whose sibling path was not visited by the old-root traversal —
    /// WITHOUT any trusted `expected_root_after`.
    ///
    /// Old tree (leaf_count = 5): MIN(0) -> data k2(2) -> k3(3) -> k4(4) -> MAX(1).
    /// Touched set: leaf 0 only (predecessor of the new key). Insert K with
    /// k0 < K < k2 at index 5. The new leaf's depth-0 sibling is leaf 4, which
    /// the old traversal never consumed.
    #[test]
    fn apply_insert_without_trusted_root_is_correct() {
        let k = |b: u8| B256::repeat_byte(b);
        let v = |b: u8| B256::repeat_byte(b);

        let leaf0 = TreeLeaf { key: B256::ZERO, value: B256::ZERO, next_index: 2 };
        let leaf1 = TreeLeaf { key: B256::repeat_byte(0xff), value: B256::ZERO, next_index: 1 };
        let leaf2 = TreeLeaf { key: k(0x20), value: v(0xa2), next_index: 3 };
        let leaf3 = TreeLeaf { key: k(0x30), value: v(0xa3), next_index: 4 };
        let leaf4 = TreeLeaf { key: k(0x40), value: v(0xa4), next_index: 1 };
        let old_leaves = vec![
            (0u64, leaf0.clone()),
            (1u64, leaf1.clone()),
            (2u64, leaf2.clone()),
            (3u64, leaf3.clone()),
            (4u64, leaf4.clone()),
        ];
        let old_root = dense_root(&old_leaves, 5);

        // New key between MIN and k2 -> predecessor is leaf 0, insert at index 5.
        let new_key = k(0x10);
        let new_value = v(0xb5);
        let leaf0_after = TreeLeaf { next_index: 5, ..leaf0.clone() };
        let leaf5 = TreeLeaf { key: new_key, value: new_value, next_index: 2 };
        let mut new_leaves = old_leaves.clone();
        new_leaves[0] = (0, leaf0_after);
        new_leaves.push((5, leaf5));
        let correct_new_root = dense_root(&new_leaves, 6);

        // Witness as the guest receives it: only leaf 0 in the touched set.
        // Old-traversal siblings for {0} at count 5:
        //   d0: sibling = leaf 1 hash; d1: node over leaves 2..3; d2: node over leaves 4..7.
        let h = |l: &TreeLeaf| hash_leaf(&l.key, &l.value, l.next_index);
        let empty = empty_subtree_hashes_vec();
        let sib_d2 = blake2s_compress(&blake2s_compress(&h(&leaf4), &empty[0]), &empty[1]);

        // Without an anchor for the ridge subtree (leaf 4's region), the
        // new-root pass must refuse rather than fall back to anything trusted.
        // Successor of the insert is leaf 2, which must be in the witness for
        // the ordering check, so include it; leaf 4's region stays uncovered.
        // Witness set {0, 2}: d0 siblings: leaf1 (for 0), leaf3 (for 2);
        // d1: nodes 0 and 1 both computed -> pair; d2: node over leaves 4..7.
        let update_no_anchor = BatchTreeUpdate {
            operations: vec![WriteOp::Insert { prev_index: 0 }],
            entries: vec![(new_key, new_value)],
            sorted_leaves: vec![(0, leaf0.clone()), (2, leaf2.clone())],
            intermediate_hashes: vec![h(&leaf1), h(&leaf3), sib_d2],
            leaf_count_before: 5,
        };
        let result = std::panic::catch_unwind(|| update_no_anchor.apply(&old_root));
        assert!(
            result.is_err(),
            "new-root pass must hard-fail on an unauthenticated sibling, not guess or trust"
        );

        // With leaf 4 included as an anchor, the new root must be computed
        // correctly — from authenticated data only.
        // Witness set {0, 2, 4}: d0 siblings: leaf1 (for 0), leaf3 (for 2),
        // empty (leaf 4 is last); d1: nodes 0,1 pair; node 2 last -> empty;
        // d2: nodes 0,1 pair; beyond: empty.
        let update_with_anchor = BatchTreeUpdate {
            operations: vec![WriteOp::Insert { prev_index: 0 }],
            entries: vec![(new_key, new_value)],
            sorted_leaves: vec![(0, leaf0), (2, leaf2), (4, leaf4)],
            intermediate_hashes: vec![h(&leaf1), h(&leaf3)],
            leaf_count_before: 5,
        };
        let (computed_root, new_count) = update_with_anchor.apply(&old_root);
        assert_eq!(new_count, 6);
        assert_eq!(
            computed_root, correct_new_root,
            "independent new-root computation must match the dense reference"
        );
    }

    /// Two chained inserts: the second insert's predecessor is the first new
    /// leaf; new leaves pair with each other in the new-root pass.
    #[test]
    fn apply_chained_inserts_is_correct() {
        let k = |b: u8| B256::repeat_byte(b);
        let leaf0 = TreeLeaf { key: B256::ZERO, value: B256::ZERO, next_index: 2 };
        let leaf1 = TreeLeaf { key: B256::repeat_byte(0xff), value: B256::ZERO, next_index: 1 };
        let leaf2 = TreeLeaf { key: k(0x40), value: k(0xa2), next_index: 1 };
        let old_leaves = vec![(0u64, leaf0.clone()), (1u64, leaf1.clone()), (2u64, leaf2.clone())];
        let old_root = dense_root(&old_leaves, 3);

        // Insert 0x10 (prev = leaf 0), then 0x20 (prev = the new leaf 3).
        let leaf3 = TreeLeaf { key: k(0x10), value: k(0xb3), next_index: 4 };
        let leaf4 = TreeLeaf { key: k(0x20), value: k(0xb4), next_index: 2 };
        let leaf0_after = TreeLeaf { next_index: 3, ..leaf0.clone() };
        let new_leaves = vec![
            (0u64, leaf0_after),
            (1u64, leaf1.clone()),
            (2u64, leaf2.clone()),
            (3u64, leaf3),
            (4u64, leaf4),
        ];
        let correct_new_root = dense_root(&new_leaves, 5);

        let h = |l: &TreeLeaf| hash_leaf(&l.key, &l.value, l.next_index);
        // Witness {0, 2}: d0 siblings: leaf1 (for 0), empty (leaf2 is last);
        // d1: node0 computed, node1 (from leaf2) computed -> pair. Beyond: empty.
        let update = BatchTreeUpdate {
            operations: vec![
                WriteOp::Insert { prev_index: 0 },
                WriteOp::Insert { prev_index: 3 },
            ],
            entries: vec![(k(0x10), k(0xb3)), (k(0x20), k(0xb4))],
            sorted_leaves: vec![(0, leaf0), (2, leaf2)],
            intermediate_hashes: vec![h(&leaf1)],
            leaf_count_before: 3,
        };
        let (computed_root, new_count) = update.apply(&old_root);
        assert_eq!(new_count, 5);
        assert_eq!(computed_root, correct_new_root);
    }

    /// An insert whose predecessor does not bracket the key must be rejected.
    #[test]
    fn apply_rejects_insert_ordering_violation() {
        let k = |b: u8| B256::repeat_byte(b);
        let leaf0 = TreeLeaf { key: B256::ZERO, value: B256::ZERO, next_index: 2 };
        let leaf1 = TreeLeaf { key: B256::repeat_byte(0xff), value: B256::ZERO, next_index: 1 };
        let leaf2 = TreeLeaf { key: k(0x40), value: k(0xa2), next_index: 1 };
        let old_leaves = vec![(0u64, leaf0.clone()), (1u64, leaf1.clone()), (2u64, leaf2.clone())];
        let old_root = dense_root(&old_leaves, 3);

        let h = |l: &TreeLeaf| hash_leaf(&l.key, &l.value, l.next_index);
        // Key 0x50 belongs after leaf2 (0x40), but the witness claims leaf 0
        // (key 0) is the predecessor — succeeding leaf 2 (0x40) < 0x50.
        let update = BatchTreeUpdate {
            operations: vec![WriteOp::Insert { prev_index: 0 }],
            entries: vec![(k(0x50), k(0xb3))],
            sorted_leaves: vec![(0, leaf0), (2, leaf2)],
            intermediate_hashes: vec![h(&leaf1)],
            leaf_count_before: 3,
        };
        let result = std::panic::catch_unwind(|| update.apply(&old_root));
        assert!(result.is_err(), "mis-bracketed insert must be rejected");
    }
}
