//! Campaign oracles: forged storage proofs and sibling paths, aimed at the
//! pre-state root binding. Owned by the `ws-proofs` campaign agent. Other
//! agents must not edit this file.

use std::collections::HashSet;

use revm::primitives::{B256, U256};
use zksync_os_zisk_lib::hash::keccak256;
use zksync_os_zisk_lib::merkle::{
    self, NeighborProofEntry, SlotProofEntry, StorageProof, TreeLeaf, TREE_DEPTH,
};
use zksync_os_zisk_lib::types::BatchInput;

use super::WitnessOracle;

/// The oracles this axis contributes to a sweep.
pub fn oracles() -> Vec<Box<dyn WitnessOracle>> {
    vec![
        Box::new(SwappedSlotProofs),
        Box::new(ForgedSiblingInProof),
        Box::new(TamperedProofNextIndex),
        Box::new(TamperedProofIndex),
        Box::new(TruncatedSiblingPath),
        Box::new(ExtendedSiblingPath),
        Box::new(SwappedNonExistingNeighbors),
        Box::new(BrokenNonExistingAdjacency),
        Box::new(ForgedBlockReadRoot),
        Box::new(EchoedBlockReadRoot),
        Box::new(ForgedReadTree),
        Box::new(ForgedInteropSlChainIdProof),
        Box::new(ShuffledStorageProofs),
        Box::new(DuplicatedStorageProof),
        Box::new(ReusedCommitmentTreeEndAsBegin),
        Box::new(ReusedCommitmentTreeBeginAsEnd),
        Box::new(SwappedInteropMultichainProofs),
        Box::new(ReusedSlChainIdProofAsMultichainHeight),
        Box::new(TamperedInteropMultichainRootProof),
        Box::new(Eip2935HistorySlotClaimsExisting),
        Box::new(Eip2935HistorySlotProofDropped),
        Box::new(Eip2935AccountUnproven),
        Box::new(DuplicatedBlockHashOverriding),
        Box::new(DuplicatedBlockHashShadowed),
        Box::new(NonExistingLeftBoundaryKey),
        Box::new(NonExistingRightBoundaryKey),
        Box::new(SortedAnchorLeafForged),
        Box::new(SortedLeavesOrderPermuted),
        Box::new(InsertPrevAtMinGuard),
        Box::new(InsertPrevAtMaxGuard),
        Box::new(InsertSuccessorDropped),
        Box::new(SortedLeafNextIndexSelfLoop),
        Box::new(NonExistingRightIndexBeyondCount),
        Box::new(NonExistingBeyondCountAdjacencySynced),
        Box::new(CrossGapBracketReuse),
        Box::new(MinGuardCannotBracketRight),
        Box::new(MaxGuardCannotBracketLeft),
        Box::new(WrongSubtreeSiblingPath),
        Box::new(ProofPathRebasedAtParent),
        Box::new(ZeroPrefixedSiblingPath),
        Box::new(ConflictingDuplicateStorageProof),
        Box::new(ShadowedEquivalentDuplicate),
        Box::new(DuplicateNonExistingClaimsExisting),
        Box::new(ConsistentRingForgery),
        Box::new(BlockHashesOrderInverted),
        Box::new(OutOfWindowBlockHashEntry),
        Box::new(OwnBlockHashEntry),
        Box::new(ParentHashEntryDropped),
        Box::new(PreviousBlockHashesSlotZeroed),
    ]
}

/// The first `StorageProof` in the batch matching `predicate`, mutably.
fn first_proof_mut<'a>(
    input: &'a mut BatchInput,
    predicate: impl Fn(&StorageProof) -> bool,
) -> Option<&'a mut StorageProof> {
    input
        .blocks
        .iter_mut()
        .flat_map(|block| block.storage_proofs.iter_mut())
        .map(|(_, proof)| proof)
        .find(|proof| predicate(proof))
}

/// The proofs of the first two storage entries of the first block, exchanged
/// while the map keys stay in place. Each leaf hash commits the queried key,
/// so a proof that recovered the pinned root under its own key recovers a
/// different root under the other key.
pub struct SwappedSlotProofs;

impl WitnessOracle for SwappedSlotProofs {
    fn name(&self) -> &str {
        "swapped_slot_proofs"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let proofs = &mut mutated.blocks.first_mut()?.storage_proofs;
        if proofs.len() < 2 {
            return None;
        }
        let (first, second) = proofs.split_at_mut(1);
        std::mem::swap(&mut first[0].1, &mut second[0].1);
        Some(mutated)
    }
}

/// A junk depth-0 sibling in the first `Existing` proof. Every sibling folds
/// into the recovered root, so the root check must fire.
pub struct ForgedSiblingInProof;

impl WitnessOracle for ForgedSiblingInProof {
    fn name(&self) -> &str {
        "forged_sibling_in_proof"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let proof = first_proof_mut(&mut mutated, |p| matches!(p, StorageProof::Existing(_)))?;
        let StorageProof::Existing(entry) = proof else {
            unreachable!("the predicate selected an Existing proof");
        };
        *entry.siblings.first_mut()? = B256::repeat_byte(0x5a);
        Some(mutated)
    }
}

/// The `next_index` of an `Existing` proof's leaf, flipped. The pointer is
/// hashed into the leaf, so the recovered root moves.
pub struct TamperedProofNextIndex;

impl WitnessOracle for TamperedProofNextIndex {
    fn name(&self) -> &str {
        "tampered_proof_next_index"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let proof = first_proof_mut(&mut mutated, |p| matches!(p, StorageProof::Existing(_)))?;
        let StorageProof::Existing(entry) = proof else {
            unreachable!("the predicate selected an Existing proof");
        };
        entry.next_index ^= 1;
        Some(mutated)
    }
}

/// The tree `index` of an `Existing` proof, low bit flipped. The index drives
/// the path bits of the root walk, so the recovered root moves.
pub struct TamperedProofIndex;

impl WitnessOracle for TamperedProofIndex {
    fn name(&self) -> &str {
        "tampered_proof_index"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let proof = first_proof_mut(&mut mutated, |p| matches!(p, StorageProof::Existing(_)))?;
        let StorageProof::Existing(entry) = proof else {
            unreachable!("the predicate selected an Existing proof");
        };
        entry.index ^= 1;
        Some(mutated)
    }
}

/// An `Existing` proof with its trailing canonical empty-subtree siblings
/// dropped. `recover_root` fills missing depths with the same canonical
/// hashes, so the truncated path recovers the identical root: those bytes
/// bind nothing, and the correct verdict is accepted with the honest
/// commitment. Anything else here is a finding.
pub struct TruncatedSiblingPath;

impl WitnessOracle for TruncatedSiblingPath {
    fn name(&self) -> &str {
        "truncated_sibling_path"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let proof = first_proof_mut(&mut mutated, |p| matches!(p, StorageProof::Existing(_)))?;
        let StorageProof::Existing(entry) = proof else {
            unreachable!("the predicate selected an Existing proof");
        };
        let mut dropped = 0;
        while let Some(&last) = entry.siblings.last() {
            let depth = entry.siblings.len() as u8 - 1;
            if last != merkle::empty_subtree_hash(depth) {
                break;
            }
            entry.siblings.pop();
            dropped += 1;
        }
        (dropped > 0).then_some(mutated)
    }
}

/// An `Existing` proof with a junk sibling appended past `TREE_DEPTH`.
/// `recover_root` reads depths 0..64 only, so the tail is unauthenticated and
/// the commitment must not move. Anything else here is a finding.
pub struct ExtendedSiblingPath;

impl WitnessOracle for ExtendedSiblingPath {
    fn name(&self) -> &str {
        "extended_sibling_path"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let proof = first_proof_mut(&mut mutated, |p| matches!(p, StorageProof::Existing(_)))?;
        let StorageProof::Existing(entry) = proof else {
            unreachable!("the predicate selected an Existing proof");
        };
        entry.siblings.push(B256::repeat_byte(0xe7));
        Some(mutated)
    }
}

/// The two bracketing leaves of a `NonExisting` proof, swapped. The left
/// neighbour must sit below the queried key, so the orientation check fires.
pub struct SwappedNonExistingNeighbors;

impl WitnessOracle for SwappedNonExistingNeighbors {
    fn name(&self) -> &str {
        "swapped_nonexisting_neighbors"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let proof = first_proof_mut(&mut mutated, |p| {
            matches!(p, StorageProof::NonExisting { .. })
        })?;
        let StorageProof::NonExisting {
            left_neighbor,
            right_neighbor,
        } = proof
        else {
            unreachable!("the predicate selected a NonExisting proof");
        };
        std::mem::swap(left_neighbor, right_neighbor);
        Some(mutated)
    }
}

/// A `NonExisting` proof whose left neighbour no longer names the right
/// neighbour as its linked-list successor. The adjacency check is what proves
/// the gap holds no leaf, so it must fire.
pub struct BrokenNonExistingAdjacency;

impl WitnessOracle for BrokenNonExistingAdjacency {
    fn name(&self) -> &str {
        "broken_nonexisting_adjacency"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let proof = first_proof_mut(&mut mutated, |p| {
            matches!(p, StorageProof::NonExisting { .. })
        })?;
        let StorageProof::NonExisting { left_neighbor, .. } = proof else {
            unreachable!("the predicate selected a NonExisting proof");
        };
        left_neighbor.entry.next_index = left_neighbor.entry.next_index.wrapping_add(1);
        Some(mutated)
    }
}

/// Every block's `expected_tree_root` replaced by a fabricated root, proofs
/// untouched. The witness scalar must never serve as a read-authentication
/// root; the up-front gate rejects anything that is neither zero nor the
/// pinned `tree_root_before`.
pub struct ForgedBlockReadRoot;

impl WitnessOracle for ForgedBlockReadRoot {
    fn name(&self) -> &str {
        "forged_block_read_root"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let forged = keccak256(b"ws-proofs forged read root");
        if forged == honest.batch_meta.tree_root_before {
            return None;
        }
        let mut mutated = honest.clone();
        for block in &mut mutated.blocks {
            block.expected_tree_root = forged;
        }
        Some(mutated)
    }
}

/// Every block's `expected_tree_root` set to the pinned `tree_root_before`.
/// The field authenticates nothing: the guest reads the pinned root from
/// `batch_meta` and ignores this scalar, so the correct verdict is accepted
/// with the honest commitment. A regression that trusts the field turns this
/// oracle into a finding.
pub struct EchoedBlockReadRoot;

impl WitnessOracle for EchoedBlockReadRoot {
    fn name(&self) -> &str {
        "echoed_block_read_root"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let pinned = honest.batch_meta.tree_root_before;
        let mut mutated = honest.clone();
        for block in &mut mutated.blocks {
            block.expected_tree_root = pinned;
        }
        Some(mutated)
    }
}

/// The well-formed lie of the read-root axis: a fabricated pre-state tree
/// carrying every key the honest witness proves, one existing slot's value
/// forged, every storage proof rebuilt so it recovers the fabricated root,
/// and every block's `expected_tree_root` pointed at it. If the guest
/// authenticated reads against the per-block witness root instead of the
/// pinned `tree_root_before`, this witness would verify and commit a
/// transition over a fabricated state.
pub struct ForgedReadTree;

impl WitnessOracle for ForgedReadTree {
    fn name(&self) -> &str {
        "forged_read_tree"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        // The proven pre-state of every key the witness proves, taken from the
        // honest proofs themselves.
        let mut proven: Vec<(B256, Option<B256>)> = Vec::new();
        for block in &honest.blocks {
            for (key, proof) in &block.storage_proofs {
                if proven.iter().any(|(known, _)| known == key) {
                    continue;
                }
                let value = match proof {
                    StorageProof::Existing(entry) => Some(entry.value),
                    StorageProof::NonExisting { .. } => None,
                };
                proven.push((*key, value));
            }
        }
        // Forge one existing value. An account-properties leaf stays honest so
        // the lie keeps its consistency with the account preimages; the target
        // of the probe is the read-root binding alone.
        let account_keys: HashSet<B256> = honest
            .blocks
            .iter()
            .flat_map(|block| block.account_preimages.iter())
            .map(|(address, _)| merkle::derive_account_properties_key(&address.into_array()))
            .collect();
        let target = proven
            .iter()
            .position(|(key, value)| value.is_some() && !account_keys.contains(key))
            .or_else(|| proven.iter().position(|(_, value)| value.is_some()))?;
        proven[target].1 = Some(B256::repeat_byte(0x66));

        let data: Vec<(B256, B256)> = proven
            .iter()
            .filter_map(|(key, value)| value.map(|value| (*key, value)))
            .collect();
        let tree = FabricatedTree::build(&data);

        let mut mutated = honest.clone();
        for block in &mut mutated.blocks {
            for (key, proof) in &mut block.storage_proofs {
                *proof = tree.prove(key);
            }
            block.expected_tree_root = tree.root;
        }
        Some(mutated)
    }
}

/// The `sl_chain_id` interop slot proof, tampered: the value of an `Existing`
/// proof, or the linked-list adjacency of a `NonExisting` one. The proof
/// authenticates against the in-guest `tree_root_after`, so the forgery must
/// fail the interop proof check.
pub struct ForgedInteropSlChainIdProof;

impl WitnessOracle for ForgedInteropSlChainIdProof {
    fn name(&self) -> &str {
        "forged_interop_sl_chain_id_proof"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let proofs = mutated.batch_meta.interop_proofs.as_mut()?;
        match &mut proofs.sl_chain_id {
            StorageProof::Existing(entry) => entry.value.0[0] ^= 0xff,
            StorageProof::NonExisting { left_neighbor, .. } => {
                left_neighbor.entry.next_index = left_neighbor.entry.next_index.wrapping_add(1);
            }
        }
        Some(mutated)
    }
}

/// The first block's storage proofs in reverse order. Every proof is
/// verified against the pinned root and the values come from the proofs, so
/// the order the server lists them in binds nothing: the correct verdict is
/// accepted with the honest commitment.
pub struct ShuffledStorageProofs;

impl WitnessOracle for ShuffledStorageProofs {
    fn name(&self) -> &str {
        "shuffled_storage_proofs"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let proofs = &mut mutated.blocks.first_mut()?.storage_proofs;
        if proofs.len() < 2 {
            return None;
        }
        proofs.reverse();
        Some(mutated)
    }
}

/// A second copy of the first block's first proof, appended. Both copies are
/// verified against the pinned root and the first insert wins, so a duplicate
/// binds nothing: the correct verdict is accepted with the honest commitment.
pub struct DuplicatedStorageProof;

impl WitnessOracle for DuplicatedStorageProof {
    fn name(&self) -> &str {
        "duplicated_storage_proof"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let proofs = &mut mutated.blocks.first_mut()?.storage_proofs;
        let first = proofs.first()?.clone();
        proofs.push(first);
        Some(mutated)
    }
}

/// The interop commitment tree's POST-batch proofs served as its PRE-batch
/// proofs. The begin root is authenticated against the L1-pinned
/// `tree_root_before` and the end root against the in-guest `tree_root_after`;
/// a batch with writes anchors the two at different roots, so the reused end
/// proof must fail the begin root assert. A no-write batch makes the anchors
/// coincide and this oracle degenerates to accepted with the honest
/// commitment, which is the correct verdict there.
pub struct ReusedCommitmentTreeEndAsBegin;

impl WitnessOracle for ReusedCommitmentTreeEndAsBegin {
    fn name(&self) -> &str {
        "reused_commitment_tree_end_as_begin"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        if honest.batch_meta.tree_update.is_none() {
            // No writes: the two anchors are one root, so the reuse binds
            // nothing and the probe degenerates.
            return None;
        }
        let mut mutated = honest.clone();
        let proofs = mutated.batch_meta.interop_proofs.as_mut()?;
        let tree = proofs.commitment_tree.as_mut()?;
        tree.height_begin = tree.height_end.clone();
        tree.root_begin = tree.root_end.clone();
        Some(mutated)
    }
}

/// The interop commitment tree's PRE-batch proofs served as its POST-batch
/// proofs, the mirror of `ReusedCommitmentTreeEndAsBegin`. The reused begin
/// proof must fail the end root assert against `tree_root_after`.
pub struct ReusedCommitmentTreeBeginAsEnd;

impl WitnessOracle for ReusedCommitmentTreeBeginAsEnd {
    fn name(&self) -> &str {
        "reused_commitment_tree_begin_as_end"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        if honest.batch_meta.tree_update.is_none() {
            return None;
        }
        let mut mutated = honest.clone();
        let proofs = mutated.batch_meta.interop_proofs.as_mut()?;
        let tree = proofs.commitment_tree.as_mut()?;
        tree.height_end = tree.height_begin.clone();
        tree.root_end = tree.root_begin.clone();
        Some(mutated)
    }
}

/// The MessageRoot height proof and the derived `nodes[height][0]` root proof,
/// exchanged. Each proof is verified against its own derived flat key, so a
/// proof that brackets one key's gap must fail the other key's orientation
/// check — unless both keys fall in one linked-list gap of the pre-state, in
/// which case each proof is a true statement about the other's key and the
/// correct verdict is accepted with the honest commitment.
pub struct SwappedInteropMultichainProofs;

impl WitnessOracle for SwappedInteropMultichainProofs {
    fn name(&self) -> &str {
        "swapped_interop_multichain_proofs"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let proofs = mutated.batch_meta.interop_proofs.as_mut()?;
        std::mem::swap(&mut proofs.multichain_height, &mut proofs.multichain_root);
        Some(mutated)
    }
}

/// The `sl_chain_id` slot proof served as the multichain height proof. The
/// `sl_chain_id` proof is `Existing` on a settlement-configured rig, so this
/// is the repurposing of a genuine existence proof under a different derived
/// key: the queried key enters the leaf hash, so the recovered root moves and
/// the interop root assert must fire.
pub struct ReusedSlChainIdProofAsMultichainHeight;

impl WitnessOracle for ReusedSlChainIdProofAsMultichainHeight {
    fn name(&self) -> &str {
        "reused_sl_chain_id_proof_as_multichain_height"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let proofs = mutated.batch_meta.interop_proofs.as_mut()?;
        proofs.multichain_height = proofs.sl_chain_id.clone();
        Some(mutated)
    }
}

/// The multichain `nodes[height][0]` slot proof, tampered: the value of an
/// `Existing` proof, or the linked-list adjacency of a `NonExisting` one. The
/// proof authenticates against the in-guest `tree_root_after`, so the forgery
/// must fail the interop proof check.
pub struct TamperedInteropMultichainRootProof;

impl WitnessOracle for TamperedInteropMultichainRootProof {
    fn name(&self) -> &str {
        "tampered_interop_multichain_root_proof"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let proofs = mutated.batch_meta.interop_proofs.as_mut()?;
        match &mut proofs.multichain_root {
            StorageProof::Existing(entry) => entry.value.0[0] ^= 0xff,
            StorageProof::NonExisting { left_neighbor, .. } => {
                left_neighbor.entry.next_index = left_neighbor.entry.next_index.wrapping_add(1);
            }
        }
        Some(mutated)
    }
}

/// The EIP-2935 history contract, address `0x0000f908…2935`. The constant is
/// `pub(super)` in the guest, so the oracle pins its own copy; the guest's
/// `history_address_matches_native` test pins the value against native.
const HISTORY_STORAGE_ADDRESS: [u8; 20] = [
    0x00, 0x00, 0xf9, 0x08, 0x27, 0xf1, 0xc5, 0x3a, 0x10, 0xcb, 0x7a, 0x02, 0x33, 0x5b, 0x17, 0x53,
    0x20, 0x00, 0x29, 0x35,
];

/// The number of parent hashes the history ring holds (`HISTORY_SERVE_WINDOW`).
const HISTORY_SERVE_WINDOW: u64 = 8191;

/// The flat storage key of the history ring slot that block `number` writes.
fn eip2935_history_slot_key(number: u64) -> B256 {
    let slot = B256::from(U256::from((number - 1) % HISTORY_SERVE_WINDOW).to_be_bytes::<32>());
    merkle::derive_flat_storage_key(&HISTORY_STORAGE_ADDRESS, &slot)
}

/// The history slot's proof upgraded from `NonExisting` to `Existing`, built
/// from its own left neighbour's entry: the witness claims the slot the
/// pre-block write reads holds a value the pre-state tree does not contain.
/// The queried key is hashed into the leaf, so the recovered root moves and
/// the per-proof root assert must fire.
pub struct Eip2935HistorySlotClaimsExisting;

impl WitnessOracle for Eip2935HistorySlotClaimsExisting {
    fn name(&self) -> &str {
        "eip2935_history_slot_claims_existing"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        for block in &mut mutated.blocks {
            let key = eip2935_history_slot_key(block.number);
            let Some((_, proof)) = block
                .storage_proofs
                .iter_mut()
                .find(|(k, _)| *k == key)
            else {
                continue;
            };
            // A rig where the slot already holds a value offers no
            // non-existence proof to upgrade.
            let StorageProof::NonExisting { left_neighbor, .. } = proof else {
                return None;
            };
            let entry = left_neighbor.entry.clone();
            *proof = StorageProof::Existing(entry);
            return Some(mutated);
        }
        None
    }
}

/// The history slot's proof removed from the witness. The pre-block write
/// reads the slot through the proof-verified database and must fail closed:
/// no proof, no read, no write.
pub struct Eip2935HistorySlotProofDropped;

impl WitnessOracle for Eip2935HistorySlotProofDropped {
    fn name(&self) -> &str {
        "eip2935_history_slot_proof_dropped"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        for block in &mut mutated.blocks {
            let key = eip2935_history_slot_key(block.number);
            let before = block.storage_proofs.len();
            block.storage_proofs.retain(|(k, _)| *k != key);
            if block.storage_proofs.len() != before {
                return Some(mutated);
            }
        }
        None
    }
}

/// The history contract's account-properties proof removed from the witness,
/// together with its account preimage where the rig carries one. The
/// pre-block write gates on the account being a contract and must fail
/// closed when the witness carries no authenticated pre-state for it.
pub struct Eip2935AccountUnproven;

impl WitnessOracle for Eip2935AccountUnproven {
    fn name(&self) -> &str {
        "eip2935_account_unproven"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let key = merkle::derive_account_properties_key(&HISTORY_STORAGE_ADDRESS);
        let mut removed = false;
        for block in &mut mutated.blocks {
            let before = block.storage_proofs.len();
            block.storage_proofs.retain(|(k, _)| *k != key);
            removed |= block.storage_proofs.len() != before;
            let address = revm::primitives::Address::from(HISTORY_STORAGE_ADDRESS);
            let before = block.account_preimages.len();
            block.account_preimages.retain(|(a, _)| *a != address);
            removed |= block.account_preimages.len() != before;
        }
        removed.then_some(mutated)
    }
}

/// A forged copy of an in-window `block_hashes` entry, appended after the
/// honest one. `reconstruct_ring` is last-write-wins, so the forged hash
/// lands in the ring and the Blake2s commitment must fail against the
/// L1-pinned `block_hashes_blake_before`.
pub struct DuplicatedBlockHashOverriding;

impl WitnessOracle for DuplicatedBlockHashOverriding {
    fn name(&self) -> &str {
        "duplicated_block_hash_overriding"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let block = mutated.blocks.first_mut()?;
        let owner = block.number;
        let &(num, hash) = block
            .block_hashes
            .iter()
            .find(|&&(num, _)| num < owner && owner - num <= 256)?;
        let mut forged = hash;
        forged.0[0] ^= 0xff;
        block.block_hashes.push((num, forged));
        Some(mutated)
    }
}

/// A forged copy of an in-window `block_hashes` entry, inserted before the
/// honest one. The ring's last-write-wins fold keeps the honest hash, and the
/// BLOCKHASH map is seeded from the authenticated ring rather than by a
/// first-match scan of the witness list, so the shadowed copy binds nothing:
/// the correct verdict is accepted with the honest commitment.
pub struct DuplicatedBlockHashShadowed;

impl WitnessOracle for DuplicatedBlockHashShadowed {
    fn name(&self) -> &str {
        "duplicated_block_hash_shadowed"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let block = mutated.blocks.first_mut()?;
        let owner = block.number;
        let position = block
            .block_hashes
            .iter()
            .position(|&(num, _)| num < owner && owner - num <= 256)?;
        let (num, hash) = block.block_hashes[position];
        let mut forged = hash;
        forged.0[0] ^= 0xff;
        block.block_hashes.insert(position, (num, forged));
        Some(mutated)
    }
}

/// The first `NonExisting` proof in the batch with its key, mutably.
fn first_nonexisting_with_key_mut(input: &mut BatchInput) -> Option<(B256, &mut StorageProof)> {
    input
        .blocks
        .iter_mut()
        .flat_map(|block| block.storage_proofs.iter_mut())
        .find(|(_, proof)| matches!(proof, StorageProof::NonExisting { .. }))
        .map(|(key, proof)| (*key, proof))
}

/// A `NonExisting` proof whose left neighbour claims the queried key itself.
/// The bracketing is strict — the left neighbour must sit strictly below the
/// queried key — so the equality boundary must fail the orientation check
/// before any root is recovered.
pub struct NonExistingLeftBoundaryKey;

impl WitnessOracle for NonExistingLeftBoundaryKey {
    fn name(&self) -> &str {
        "nonexisting_left_boundary_key"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let (key, proof) = first_nonexisting_with_key_mut(&mut mutated)?;
        let StorageProof::NonExisting { left_neighbor, .. } = proof else {
            unreachable!("the predicate selected a NonExisting proof");
        };
        left_neighbor.leaf_key = key;
        Some(mutated)
    }
}

/// A `NonExisting` proof whose right neighbour claims the queried key itself,
/// the mirror of `NonExistingLeftBoundaryKey`. The queried key must sit
/// strictly below the right neighbour, so the equality boundary must fail the
/// orientation check.
pub struct NonExistingRightBoundaryKey;

impl WitnessOracle for NonExistingRightBoundaryKey {
    fn name(&self) -> &str {
        "nonexisting_right_boundary_key"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let (key, proof) = first_nonexisting_with_key_mut(&mut mutated)?;
        let StorageProof::NonExisting { right_neighbor, .. } = proof else {
            unreachable!("the predicate selected a NonExisting proof");
        };
        right_neighbor.leaf_key = key;
        Some(mutated)
    }
}

// ---------------------------------------------------------------------------
// Round 3: sorted_leaves structure, bracketing edges, proof-path shape,
// duplicate proofs, and the block-hash ring.
// ---------------------------------------------------------------------------

/// The batch's tree update, mutably.
fn tree_update_mut(input: &mut BatchInput) -> Option<&mut merkle::BatchTreeUpdate> {
    input.batch_meta.tree_update.as_mut()
}

/// An extra anchor leaf with fabricated content, spliced into `sorted_leaves`
/// at a free old-tree position. Anchors exist so the old-root pass can
/// authenticate tree regions the new-root pass needs as siblings; nothing
/// upstream checks an anchor's content, so the old-root assertion in
/// `BatchTreeUpdate::apply` is the only thing that authenticates it. The
/// forged leaf hash enters the bottom-up walk and the computed old root must
/// diverge from the pinned `tree_root_before` (or the walk's
/// intermediate-hash accounting must run out of room) — a hard failure either
/// way. Accepted with any commitment would mean anchor content is trusted.
pub struct SortedAnchorLeafForged;

impl WitnessOracle for SortedAnchorLeafForged {
    fn name(&self) -> &str {
        "sorted_anchor_leaf_forged"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let update = tree_update_mut(&mut mutated)?;
        let leaf_count = update.leaf_count_before;
        let used: HashSet<u64> = update.sorted_leaves.iter().map(|(index, _)| *index).collect();
        // An old-tree position the honest witness does not name.
        let index = (0..leaf_count).find(|index| !used.contains(index))?;
        let forged = merkle::TreeLeaf {
            key: B256::repeat_byte(0x77),
            value: B256::repeat_byte(0x88),
            next_index: 1,
        };
        // Keep the vector ascending by index so the strict-increase guard is
        // not what fires.
        let position = update.sorted_leaves.partition_point(|(i, _)| *i < index);
        update.sorted_leaves.insert(position, (index, forged));
        Some(mutated)
    }
}

/// Two adjacent `sorted_leaves` entries exchanged. The guest requires the list
/// strictly increasing by tree index (the linked-list order is carried by
/// `next_index` pointers, not by vector order), so any reorder must fail the
/// ordering guard before any root is computed.
pub struct SortedLeavesOrderPermuted;

impl WitnessOracle for SortedLeavesOrderPermuted {
    fn name(&self) -> &str {
        "sorted_leaves_order_permuted"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let update = tree_update_mut(&mut mutated)?;
        if update.sorted_leaves.len() < 2 {
            return None;
        }
        update.sorted_leaves.swap(0, 1);
        Some(mutated)
    }
}

/// An insert whose `prev_index` is retargeted at the MIN guard (index 0). The
/// MIN guard's successor is the smallest-key data leaf, so unless the inserted
/// key belongs in the very first gap — in which case the honest predecessor IS
/// the MIN guard — the successor-side ordering assert must fire. Pins that the
/// insert position is the unique linked-list gap, not any witness leaf below
/// the key.
pub struct InsertPrevAtMinGuard;

impl WitnessOracle for InsertPrevAtMinGuard {
    fn name(&self) -> &str {
        "insert_prev_at_min_guard"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let update = tree_update_mut(&mut mutated)?;
        // The guard leaf must be in the witness, or the retarget dies at the
        // index-map lookup instead of the ordering check under test.
        if !update.sorted_leaves.iter().any(|(index, _)| *index == 0) {
            return None;
        }
        let prev = update.operations.iter_mut().find_map(|op| match op {
            merkle::WriteOp::Insert { prev_index } if *prev_index != 0 => Some(prev_index),
            _ => None,
        })?;
        *prev = 0;
        Some(mutated)
    }
}

/// An insert whose `prev_index` is retargeted at the MAX guard (index 1). The
/// MAX guard's key is `0xff…ff`, above every real key, so the predecessor-side
/// ordering assert must fire. Mirror of `InsertPrevAtMinGuard`.
pub struct InsertPrevAtMaxGuard;

impl WitnessOracle for InsertPrevAtMaxGuard {
    fn name(&self) -> &str {
        "insert_prev_at_max_guard"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let update = tree_update_mut(&mut mutated)?;
        if !update.sorted_leaves.iter().any(|(index, _)| *index == 1) {
            return None;
        }
        let prev = update.operations.iter_mut().find_map(|op| match op {
            merkle::WriteOp::Insert { prev_index } => Some(prev_index),
            _ => None,
        })?;
        *prev = 1;
        Some(mutated)
    }
}

/// The successor leaf of an insert removed from `sorted_leaves`. The insert
/// rewires its predecessor to point at the new leaf, and the new leaf takes
/// the predecessor's old successor — that successor must be in the witness,
/// both for the ordering check and to keep the linked list closed. Dropping
/// it must fail closed, not silently splice.
pub struct InsertSuccessorDropped;

impl WitnessOracle for InsertSuccessorDropped {
    fn name(&self) -> &str {
        "insert_successor_dropped"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let update = tree_update_mut(&mut mutated)?;
        // An insert whose predecessor is an old-tree leaf (a chained insert's
        // predecessor is a fresh index absent from sorted_leaves) and whose
        // successor no other operation names, so the drop reaches the insert's
        // own successor lookup rather than an unrelated index-map panic.
        let mut referenced: HashSet<u64> = update
            .operations
            .iter()
            .map(|op| match op {
                merkle::WriteOp::Update { index } => *index,
                merkle::WriteOp::Insert { prev_index } => *prev_index,
            })
            .collect();
        for op in &update.operations {
            let merkle::WriteOp::Insert { prev_index } = op else {
                continue;
            };
            referenced.remove(prev_index);
            let Some((_, prev_leaf)) = update
                .sorted_leaves
                .iter()
                .find(|(index, _)| index == prev_index)
            else {
                continue;
            };
            let successor = prev_leaf.next_index;
            if referenced.contains(&successor) {
                continue;
            }
            let position = update
                .sorted_leaves
                .iter()
                .position(|(index, _)| *index == successor)?;
            update.sorted_leaves.remove(position);
            return Some(mutated);
        }
        None
    }
}

/// A `sorted_leaves` entry whose `next_index` is pointed at its own index.
/// Every field of an old leaf is hashed into the old root, so the self-loop
/// must fail the old-root assertion. The tampered leaf is chosen among the
/// entries no insert uses as a predecessor, so the walk — not the insert
/// ordering check — is what sees it.
pub struct SortedLeafNextIndexSelfLoop;

impl WitnessOracle for SortedLeafNextIndexSelfLoop {
    fn name(&self) -> &str {
        "sorted_leaf_next_index_self_loop"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let update = tree_update_mut(&mut mutated)?;
        let predecessors: HashSet<u64> = update
            .operations
            .iter()
            .filter_map(|op| match op {
                merkle::WriteOp::Insert { prev_index } => Some(*prev_index),
                _ => None,
            })
            .collect();
        let (index, leaf) = update
            .sorted_leaves
            .iter_mut()
            .find(|(index, _)| !predecessors.contains(index))?;
        leaf.next_index = *index;
        Some(mutated)
    }
}

/// A `NonExisting` proof whose right neighbour is claimed at
/// `leaf_count_before`, the first position the old tree holds empty, with the
/// left neighbour's `next_index` left honest. The adjacency check
/// (`left.next_index == right.index`) is the desync detector and must fire.
pub struct NonExistingRightIndexBeyondCount;

impl WitnessOracle for NonExistingRightIndexBeyondCount {
    fn name(&self) -> &str {
        "nonexisting_right_index_beyond_count"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let count = honest.batch_meta.leaf_count_before;
        let mut mutated = honest.clone();
        let (_, proof) = first_nonexisting_with_key_mut(&mut mutated)?;
        let StorageProof::NonExisting { right_neighbor, .. } = proof else {
            unreachable!("the predicate selected a NonExisting proof");
        };
        if right_neighbor.entry.index == count {
            return None;
        }
        right_neighbor.entry.index = count;
        Some(mutated)
    }
}

/// The same beyond-`leaf_count_before` displacement with the adjacency
/// re-synchronised: the left neighbour's `next_index` is moved to match the
/// right neighbour's forged index. Adjacency and orientation both pass; what
/// remains is that both neighbours must recover one root — the left leaf hash
/// carries `next_index` and the right path is driven by `index`, so both
/// recovered roots move and the root-mismatch check must fire. A guest that
/// skipped the root equality would accept a bracket hanging off an empty
/// position.
pub struct NonExistingBeyondCountAdjacencySynced;

impl WitnessOracle for NonExistingBeyondCountAdjacencySynced {
    fn name(&self) -> &str {
        "nonexisting_beyond_count_adjacency_synced"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let count = honest.batch_meta.leaf_count_before;
        let mut mutated = honest.clone();
        let (_, proof) = first_nonexisting_with_key_mut(&mut mutated)?;
        let StorageProof::NonExisting {
            left_neighbor,
            right_neighbor,
        } = proof
        else {
            unreachable!("the predicate selected a NonExisting proof");
        };
        if right_neighbor.entry.index == count {
            return None;
        }
        right_neighbor.entry.index = count;
        left_neighbor.entry.next_index = count;
        Some(mutated)
    }
}

/// The bracketing pairs of two `NonExisting` proofs in different linked-list
/// gaps, exchanged while the queried keys stay in place. Distinct adjacency
/// intervals of one sorted list are disjoint, so each queried key falls
/// outside the other's gap and the orientation check must fire. (When two
/// queries share one gap their brackets are identical and there is nothing to
/// exchange — no site.)
pub struct CrossGapBracketReuse;

impl WitnessOracle for CrossGapBracketReuse {
    fn name(&self) -> &str {
        "cross_gap_bracket_reuse"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let proofs = &mut mutated.blocks.first_mut()?.storage_proofs;
        let gaps: Vec<usize> = proofs
            .iter()
            .enumerate()
            .filter_map(|(i, (_, proof))| {
                matches!(proof, StorageProof::NonExisting { .. }).then_some(i)
            })
            .collect();
        if gaps.len() < 2 {
            return None;
        }
        let (i, j) = (gaps[0], gaps[1]);
        let same_gap = match (&proofs[i].1, &proofs[j].1) {
            (
                StorageProof::NonExisting {
                    left_neighbor: a_left,
                    right_neighbor: a_right,
                },
                StorageProof::NonExisting {
                    left_neighbor: b_left,
                    right_neighbor: b_right,
                },
            ) => a_left.leaf_key == b_left.leaf_key && a_right.leaf_key == b_right.leaf_key,
            _ => unreachable!("the positions were selected as NonExisting"),
        };
        if same_gap {
            return None;
        }
        let (first, second) = proofs.split_at_mut(j);
        std::mem::swap(&mut first[i].1, &mut second[0].1);
        Some(mutated)
    }
}

/// A `NonExisting` proof whose right neighbour claims the MIN guard's key
/// (`0x00…00`). No flat key sorts below MIN, so the orientation check must
/// fire before any root is recovered: the MIN guard can only ever bracket
/// from the left.
pub struct MinGuardCannotBracketRight;

impl WitnessOracle for MinGuardCannotBracketRight {
    fn name(&self) -> &str {
        "min_guard_cannot_bracket_right"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let (key, proof) = first_nonexisting_with_key_mut(&mut mutated)?;
        if key.is_zero() {
            return None;
        }
        let StorageProof::NonExisting { right_neighbor, .. } = proof else {
            unreachable!("the predicate selected a NonExisting proof");
        };
        right_neighbor.leaf_key = B256::ZERO;
        Some(mutated)
    }
}

/// A `NonExisting` proof whose left neighbour claims the MAX guard's key
/// (`0xff…ff`). No flat key sorts above MAX, so the orientation check must
/// fire: the MAX guard can only ever bracket from the right.
pub struct MaxGuardCannotBracketLeft;

impl WitnessOracle for MaxGuardCannotBracketLeft {
    fn name(&self) -> &str {
        "max_guard_cannot_bracket_left"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let (key, proof) = first_nonexisting_with_key_mut(&mut mutated)?;
        if key == B256::repeat_byte(0xff) {
            return None;
        }
        let StorageProof::NonExisting { left_neighbor, .. } = proof else {
            unreachable!("the predicate selected a NonExisting proof");
        };
        left_neighbor.leaf_key = B256::repeat_byte(0xff);
        Some(mutated)
    }
}

/// An `Existing` proof served with the sibling path of a DIFFERENT proved key
/// of the same honest tree — genuine tree hashes, wrong subtree. The index
/// stays the proof's own, so the path bits disagree with the donated siblings
/// and the recovered root must move.
pub struct WrongSubtreeSiblingPath;

impl WitnessOracle for WrongSubtreeSiblingPath {
    fn name(&self) -> &str {
        "wrong_subtree_sibling_path"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let proofs = &mut mutated.blocks.first_mut()?.storage_proofs;
        let existing: Vec<usize> = proofs
            .iter()
            .enumerate()
            .filter_map(|(i, (_, proof))| {
                matches!(proof, StorageProof::Existing(_)).then_some(i)
            })
            .collect();
        if existing.len() < 2 {
            return None;
        }
        let (i, j) = (existing[0], existing[1]);
        let (first, second) = proofs.split_at_mut(j);
        let (StorageProof::Existing(target), StorageProof::Existing(donor)) =
            (&mut first[i].1, &second[0].1)
        else {
            unreachable!("the positions were selected as Existing");
        };
        target.siblings = donor.siblings.clone();
        Some(mutated)
    }
}

/// An `Existing` proof rebased at its parent: the depth-0 sibling dropped and
/// the index halved, so the walk starts one level up the honest tree.
/// `recover_root` always starts from the leaf hash, so the rebased path
/// recovers a hash that is not the tree root and the root assert must fire.
pub struct ProofPathRebasedAtParent;

impl WitnessOracle for ProofPathRebasedAtParent {
    fn name(&self) -> &str {
        "proof_path_rebased_at_parent"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let proof = first_proof_mut(&mut mutated, |p| matches!(p, StorageProof::Existing(_)))?;
        let StorageProof::Existing(entry) = proof else {
            unreachable!("the predicate selected an Existing proof");
        };
        if entry.siblings.is_empty() {
            return None;
        }
        entry.siblings.remove(0);
        entry.index /= 2;
        Some(mutated)
    }
}

/// An `Existing` proof with a zero sibling prepended at depth 0, shifting
/// every honest sibling one level up. The depth-0 sibling of a real leaf is
/// never the zero hash, so the recovered root must move.
pub struct ZeroPrefixedSiblingPath;

impl WitnessOracle for ZeroPrefixedSiblingPath {
    fn name(&self) -> &str {
        "zero_prefixed_sibling_path"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let proof = first_proof_mut(&mut mutated, |p| matches!(p, StorageProof::Existing(_)))?;
        let StorageProof::Existing(entry) = proof else {
            unreachable!("the predicate selected an Existing proof");
        };
        entry.siblings.insert(0, B256::ZERO);
        Some(mutated)
    }
}

/// A duplicate proof for a slot already proved, claiming a different value.
/// Every proof in the witness is verified against the pinned root before the
/// first-wins map insert runs, so the conflicting copy — the value is inside
/// the leaf hash — must fail the per-proof root assert. There is no shape in
/// which two proofs of one key against one root disagree on the value.
pub struct ConflictingDuplicateStorageProof;

impl WitnessOracle for ConflictingDuplicateStorageProof {
    fn name(&self) -> &str {
        "conflicting_duplicate_storage_proof"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let proofs = &mut mutated.blocks.first_mut()?.storage_proofs;
        let (key, forged) = proofs.iter().find_map(|(key, proof)| {
            let StorageProof::Existing(entry) = proof else {
                return None;
            };
            let mut forged = entry.clone();
            forged.value.0[0] ^= 0xff;
            Some((*key, StorageProof::Existing(forged)))
        })?;
        proofs.push((key, forged));
        Some(mutated)
    }
}

/// A duplicate of the first `Existing` proof, reshaped to an equivalent path
/// (trailing canonical siblings dropped, or a junk sibling appended past
/// depth 64 when nothing drops) and placed BEFORE the honest copy. Both
/// proofs verify to the same (root, value), so the first-wins map insert
/// keeps an equivalent value and the commitment must not move. Pins that
/// proof-shape diversity within one slot is inert.
pub struct ShadowedEquivalentDuplicate;

impl WitnessOracle for ShadowedEquivalentDuplicate {
    fn name(&self) -> &str {
        "shadowed_equivalent_duplicate"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let proofs = &mut mutated.blocks.first_mut()?.storage_proofs;
        let (key, reshaped) = proofs.iter().find_map(|(key, proof)| {
            let StorageProof::Existing(entry) = proof else {
                return None;
            };
            let mut reshaped = entry.clone();
            let mut dropped = false;
            while let Some(&last) = reshaped.siblings.last() {
                let depth = reshaped.siblings.len() as u8 - 1;
                if last != merkle::empty_subtree_hash(depth) {
                    break;
                }
                reshaped.siblings.pop();
                dropped = true;
            }
            if !dropped {
                reshaped.siblings.push(B256::repeat_byte(0xe7));
            }
            Some((*key, StorageProof::Existing(reshaped)))
        })?;
        proofs.insert(0, (key, reshaped));
        Some(mutated)
    }
}

/// A `NonExisting` proof duplicated by an appended `Existing` claim for the
/// same key, built from the bracket's own left neighbour entry. The original
/// proof would win the first-wins insert, but the appended claim never gets
/// there: the queried key is inside the leaf hash, so the copy fails the
/// per-proof root assert. The mixed-shape duplicate of an absent key cannot
/// conjure it into existence.
pub struct DuplicateNonExistingClaimsExisting;

impl WitnessOracle for DuplicateNonExistingClaimsExisting {
    fn name(&self) -> &str {
        "duplicate_nonexisting_claims_existing"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let proofs = &mut mutated.blocks.first_mut()?.storage_proofs;
        let (key, forged) = proofs.iter().find_map(|(key, proof)| {
            let StorageProof::NonExisting { left_neighbor, .. } = proof else {
                return None;
            };
            Some((*key, StorageProof::Existing(left_neighbor.entry.clone())))
        })?;
        proofs.push((key, forged));
        Some(mutated)
    }
}

/// A ring-slot forgery made consistent across the two witness fields: an
/// in-window `block_hashes` entry and the matching `previous_block_hashes`
/// slot are moved to the same forged hash. The witness-consistency guard
/// compares the two witness fields against each other, so a consistent
/// forgery passes it; what must still fire is the authentication of the
/// reconstructed ring against the L1-pinned `block_hashes_blake_before` —
/// the only check that binds the ring to native's actual block hashes.
/// Site-gated to batches at block ≥ 255, where the guard is active at all.
pub struct ConsistentRingForgery;

impl WitnessOracle for ConsistentRingForgery {
    fn name(&self) -> &str {
        "consistent_ring_forgery"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let last_num = honest.blocks.last()?.number;
        if last_num < 255 {
            return None;
        }
        let oldest_available = last_num - 255;
        let mut mutated = honest.clone();
        let previous = &honest.batch_meta.previous_block_hashes;
        let block = mutated.blocks.first_mut()?;
        let position = block.block_hashes.iter().position(|(num, _)| {
            if *num < oldest_available || *num >= last_num {
                return false;
            }
            previous
                .get((*num - oldest_available) as usize)
                .is_some_and(|hash| !hash.is_zero())
        })?;
        let (num, _) = block.block_hashes[position];
        let forged = keccak256(b"ws-proofs consistent ring forgery");
        block.block_hashes[position].1 = forged;
        mutated.batch_meta.previous_block_hashes[(num - oldest_available) as usize] = forged;
        Some(mutated)
    }
}

/// The first block's `block_hashes` list reversed. The ring fold places each
/// entry by block number, and the witness-consistency guard is per-entry, so
/// the order of distinct entries binds nothing: the correct verdict is
/// accepted with the honest commitment. Complements the round-2 duplicate
/// pair, which pinned that order matters only for same-number duplicates.
pub struct BlockHashesOrderInverted;

impl WitnessOracle for BlockHashesOrderInverted {
    fn name(&self) -> &str {
        "block_hashes_order_inverted"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let block = mutated.blocks.first_mut()?;
        if block.block_hashes.len() < 2 {
            return None;
        }
        block.block_hashes.reverse();
        Some(mutated)
    }
}

/// A block-hash entry for a block OLDER than the 256-block ring window. The
/// ring reconstruction skips it, the consistency guard's window starts later,
/// and the intra-batch check never computes it, so the entry binds nothing:
/// the correct verdict is accepted with the honest commitment. Site-gated to
/// batches at block ≥ 257, where a left-of-window block number exists.
pub struct OutOfWindowBlockHashEntry;

impl WitnessOracle for OutOfWindowBlockHashEntry {
    fn name(&self) -> &str {
        "out_of_window_block_hash_entry"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let block = mutated.blocks.first_mut()?;
        if block.number < 257 {
            return None;
        }
        block
            .block_hashes
            .push((block.number - 257, B256::repeat_byte(0x0b)));
        Some(mutated)
    }
}

/// A block-hash entry naming the batch's own first block — the witness claims
/// a hash for the block being executed. The ring window ends at the parent,
/// the intra-batch check runs before the block's own hash exists, and the
/// consistency guard covers only earlier numbers, so the entry binds nothing:
/// the block's real hash is pinned by the recomputed-header assert, never by
/// this list. The correct verdict is accepted with the honest commitment.
pub struct OwnBlockHashEntry;

impl WitnessOracle for OwnBlockHashEntry {
    fn name(&self) -> &str {
        "own_block_hash_entry"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let block = mutated.blocks.first_mut()?;
        let number = block.number;
        block.block_hashes.push((number, B256::repeat_byte(0x0c)));
        Some(mutated)
    }
}

/// The parent block's entry dropped from `block_hashes`. The parent's slot is
/// the ring's head (`ring[255]`), so the reconstructed ring's Blake2s
/// commitment must move away from the L1-pinned `block_hashes_blake_before`:
/// an omitted ring slot is a zeroed slot, and a zeroed parent is a forged
/// ring.
pub struct ParentHashEntryDropped;

impl WitnessOracle for ParentHashEntryDropped {
    fn name(&self) -> &str {
        "parent_hash_entry_dropped"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let block = mutated.blocks.first_mut()?;
        let parent = block.number.checked_sub(1)?;
        let before = block.block_hashes.len();
        block.block_hashes.retain(|(num, _)| *num != parent);
        (block.block_hashes.len() != before).then_some(mutated)
    }
}

/// A non-zero `previous_block_hashes` slot zeroed. The witness-consistency
/// guard skips zero slots (a zero there means "no opinion"), and nothing else
/// in the collecting path reads the field — the after-ring is rebuilt from
/// the authenticated before-ring and the guest's own header hashes — so the
/// mutation binds nothing and the correct verdict is accepted with the honest
/// commitment. Complements the metadata axis's `unbound_previous_block_hashes`
/// (a non-zero perturbation, which the guard catches on batches at block
/// ≥ 255).
pub struct PreviousBlockHashesSlotZeroed;

impl WitnessOracle for PreviousBlockHashesSlotZeroed {
    fn name(&self) -> &str {
        "previous_block_hashes_slot_zeroed"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let slot = mutated
            .batch_meta
            .previous_block_hashes
            .iter_mut()
            .find(|hash| !hash.is_zero())?;
        *slot = B256::ZERO;
        Some(mutated)
    }
}

/// A dense depth-64 Blake2s-256 tree over fabricated leaves, in the layout/// the honest witness uses: MIN/MAX guard leaves at indices 0 and 1, data
/// leaves dense from index 2, sibling paths padded to `TREE_DEPTH` with the
/// canonical empty-subtree hashes. Every proof it emits recovers its root, so
/// the forged witness is internally consistent.
struct FabricatedTree {
    root: B256,
    leaves: Vec<(u64, TreeLeaf)>,
    levels: Vec<Vec<B256>>,
}

fn node_hash(left: &B256, right: &B256) -> B256 {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left.as_slice());
    buf[32..].copy_from_slice(right.as_slice());
    merkle::blake2s(&buf)
}

impl FabricatedTree {
    fn build(data: &[(B256, B256)]) -> Self {
        let mut records: Vec<(u64, B256, B256)> =
            vec![(0, B256::ZERO, B256::ZERO), (1, B256::repeat_byte(0xff), B256::ZERO)];
        records.extend(
            data.iter()
                .enumerate()
                .map(|(i, (key, value))| (2 + i as u64, *key, *value)),
        );
        // The sorted linked list over the keys, MAX closing onto itself.
        let mut order: Vec<usize> = (0..records.len()).collect();
        order.sort_by_key(|&i| records[i].1);
        let mut next = vec![0u64; records.len()];
        for w in order.windows(2) {
            next[w[0]] = records[w[1]].0;
        }
        next[*order.last().expect("the guard leaves exist")] = 1;
        let leaves: Vec<(u64, TreeLeaf)> = records
            .iter()
            .zip(&next)
            .map(|((index, key, value), next_index)| {
                (
                    *index,
                    TreeLeaf {
                        key: *key,
                        value: *value,
                        next_index: *next_index,
                    },
                )
            })
            .collect();

        let mut levels: Vec<Vec<B256>> = vec![leaves
            .iter()
            .map(|(_, leaf)| merkle::hash_leaf(&leaf.key, &leaf.value, leaf.next_index))
            .collect()];
        while levels.last().expect("level 0 exists").len() > 1 {
            let depth = levels.len() - 1;
            let current = levels.last().expect("level 0 exists");
            let up: Vec<B256> = (0..current.len().div_ceil(2))
                .map(|i| {
                    let right = current
                        .get(2 * i + 1)
                        .copied()
                        .unwrap_or(merkle::empty_subtree_hash(depth as u8));
                    node_hash(&current[2 * i], &right)
                })
                .collect();
            levels.push(up);
        }
        let mut root = levels
            .last()
            .and_then(|level| level.first())
            .copied()
            .expect("the tree holds at least the guard leaves");
        for depth in (levels.len() - 1)..(TREE_DEPTH as usize) {
            root = node_hash(&root, &merkle::empty_subtree_hash(depth as u8));
        }
        FabricatedTree {
            root,
            leaves,
            levels,
        }
    }

    fn siblings(&self, index: u64) -> Vec<B256> {
        (0..TREE_DEPTH as usize)
            .map(|depth| {
                let position = ((index >> depth) ^ 1) as usize;
                self.levels
                    .get(depth)
                    .and_then(|level| level.get(position).copied())
                    .unwrap_or(merkle::empty_subtree_hash(depth as u8))
            })
            .collect()
    }

    fn entry(&self, index: u64) -> SlotProofEntry {
        let (_, leaf) = &self.leaves[index as usize];
        SlotProofEntry {
            index,
            value: leaf.value,
            next_index: leaf.next_index,
            siblings: self.siblings(index),
        }
    }

    /// Prove `key` against this tree: `Existing` with the stored value when
    /// the leaf is present, `NonExisting` bracketed by its linked-list
    /// neighbours otherwise.
    fn prove(&self, key: &B256) -> StorageProof {
        if let Some((index, _)) = self.leaves.iter().find(|(_, leaf)| &leaf.key == key) {
            return StorageProof::Existing(self.entry(*index));
        }
        let (left_index, left) = self
            .leaves
            .iter()
            .filter(|(_, leaf)| &leaf.key < key)
            .max_by_key(|(_, leaf)| leaf.key)
            .expect("the MIN guard brackets every key from below");
        let (right_index, right) = self
            .leaves
            .iter()
            .find(|(index, _)| *index == left.next_index)
            .expect("the linked list is closed");
        StorageProof::NonExisting {
            left_neighbor: NeighborProofEntry {
                entry: self.entry(*left_index),
                leaf_key: left.key,
            },
            right_neighbor: NeighborProofEntry {
                entry: self.entry(*right_index),
                leaf_key: right.key,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fabricated tree must be a well-formed lie: every proof it emits
    /// recovers its root, so only the read-root gate — never a malformed
    /// proof — can stop the forged witness.
    #[test]
    fn fabricated_tree_proofs_verify_against_its_root() {
        let keys: Vec<B256> = (1u8..=4).map(|i| keccak256(&[i])).collect();
        let data: Vec<(B256, B256)> = keys
            .iter()
            .map(|key| (*key, keccak256(key.as_slice())))
            .collect();
        let tree = FabricatedTree::build(&data);
        for (key, value) in &data {
            let proof = tree.prove(key);
            let (root, proven) = proof.verify(key).expect("a fabricated proof must verify");
            assert_eq!(root, tree.root);
            assert_eq!(proven, Some(*value));
        }
        let absent = keccak256(b"absent");
        let proof = tree.prove(&absent);
        let (root, proven) = proof
            .verify(&absent)
            .expect("a fabricated non-existence proof must verify");
        assert_eq!(root, tree.root);
        assert_eq!(proven, None);
    }

    /// Forging one value must move the fabricated root away from the honest
    /// tree over the same keys, or the oracle would lie about nothing.
    #[test]
    fn forging_a_value_moves_the_fabricated_root() {
        let keys: Vec<B256> = (1u8..=3).map(|i| keccak256(&[i])).collect();
        let honest: Vec<(B256, B256)> = keys.iter().map(|key| (*key, B256::ZERO)).collect();
        let mut forged = honest.clone();
        forged[0].1 = B256::repeat_byte(0x66);
        assert_ne!(
            FabricatedTree::build(&honest).root,
            FabricatedTree::build(&forged).root
        );
    }

    /// The harness's dump conversion always emits a dense tree update (every
    /// pre-state leaf in `sorted_leaves`, no intermediate hashes), so
    /// `SortedAnchorLeafForged` can never find a free old-tree position
    /// through the tool. This test pins the guest-side behaviour the oracle
    /// cannot reach: on a SPARSE witness, an extra anchor with fabricated
    /// content at a free position below `leaf_count_before` never reconciles —
    /// with the honest intermediate list the walk's hash accounting trips, and
    /// with a shortened list the old-root assert fires.
    #[test]
    fn sparse_anchor_forgery_never_reconciles() {
        let k = |b: u8| B256::repeat_byte(b);
        let leaf0 = merkle::TreeLeaf { key: B256::ZERO, value: B256::ZERO, next_index: 2 };
        let leaf1 = merkle::TreeLeaf { key: B256::repeat_byte(0xff), value: B256::ZERO, next_index: 1 };
        let leaf2 = merkle::TreeLeaf { key: k(0x20), value: k(0xa2), next_index: 3 };
        let leaf3 = merkle::TreeLeaf { key: k(0x30), value: k(0xa3), next_index: 1 };
        let leaves = vec![
            (0u64, leaf0.clone()),
            (1u64, leaf1.clone()),
            (2u64, leaf2.clone()),
            (3u64, leaf3.clone()),
        ];
        // Dense root over indices 0..4, padding with canonical empty subtrees.
        let h = |l: &merkle::TreeLeaf| merkle::hash_leaf(&l.key, &l.value, l.next_index);
        let d0: Vec<B256> = leaves.iter().map(|(_, l)| h(l)).collect();
        let d1 = vec![node_hash(&d0[0], &d0[1]), node_hash(&d0[2], &d0[3])];
        let mut root = node_hash(&d1[0], &d1[1]);
        for depth in 2..TREE_DEPTH {
            root = node_hash(&root, &merkle::empty_subtree_hash(depth));
        }

        // Honest sparse witness: leaves {0,1,2} named, leaf 3's hash supplied
        // as the single intermediate the walk consumes at depth 0.
        let honest_sparse = merkle::BatchTreeUpdate {
            operations: vec![],
            entries: vec![],
            sorted_leaves: vec![(0, leaf0.clone()), (1, leaf1.clone()), (2, leaf2.clone())],
            intermediate_hashes: vec![h(&leaf3)],
            leaf_count_before: 4,
        };
        let (new_root, new_count) = honest_sparse.apply(&root);
        assert_eq!((new_root, new_count), (root, 4), "the honest sparse witness reconciles");

        // The forgery: an extra anchor at the free position 3 with fabricated
        // content, intermediates untouched. The forged leaf pairs with leaf 2
        // at depth 0, so the honest intermediate is never consumed.
        let forged = merkle::TreeLeaf { key: k(0x77), value: k(0x88), next_index: 1 };
        let mut with_anchor = honest_sparse.clone();
        with_anchor.sorted_leaves.push((3, forged.clone()));
        let result = std::panic::catch_unwind(|| with_anchor.apply(&root));
        assert!(
            result.is_err(),
            "a forged anchor with stale intermediates must trip the hash accounting"
        );

        // With the intermediate dropped instead, the walk reaches the top and
        // the computed old root must mismatch the pinned root.
        let mut with_anchor_no_intermediates = honest_sparse.clone();
        with_anchor_no_intermediates.sorted_leaves.push((3, forged));
        with_anchor_no_intermediates.intermediate_hashes = vec![];
        let result = std::panic::catch_unwind(|| with_anchor_no_intermediates.apply(&root));
        assert!(
            result.is_err(),
            "a forged anchor without intermediates must fail the old-root assert"
        );
    }
}
