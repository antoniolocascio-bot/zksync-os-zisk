//! Campaign oracles: forged values that reach `batch_output_hash` directly.
//! Owned by the `ws-metadata` campaign agent. Other agents must not edit this
//! file.
//!
//! Every input of `batch_output_hash`, `state_before`, `state_after` and
//! `chain_config_hash` is either a statement field, a guest-derived value, or
//! a witness field the guest authenticates. The oracles below probe each
//! witness-side binding of that set: the authenticated ones must reject, the
//! deliberately unbound ones must be accepted with the honest commitment. A
//! rejection names the assertion that fired, which is what tells the two
//! apart.

use revm::primitives::B256;
use zksync_os_zisk_lib::merkle::StorageProof;
use zksync_os_zisk_lib::types::BatchInput;

use super::WitnessOracle;

/// The oracles this axis contributes to a sweep.
pub fn oracles() -> Vec<Box<dyn WitnessOracle>> {
    vec![
        Box::new(ForgedUpgradeTxHash),
        Box::new(UnboundSlChainId),
        Box::new(UnboundMultichainRoot),
        Box::new(UnboundPreviousBlockHashes),
        Box::new(CorruptBlockHeaderHash),
        Box::new(AbsentBlockHeaderHash),
        Box::new(ForgedRingBlockHash),
        Box::new(UnauthenticatedBlockHashEntry),
        Box::new(DecorativeExpectedTreeRoot),
        Box::new(MissingInteropProofs),
        Box::new(MissingCommitmentTreeProofs),
        Box::new(ForgedCommitmentTreeProof),
        Box::new(ForgedMultichainHeightProof),
        Box::new(ForgedGasUsedOverride),
        Box::new(UnpinnedGasUsedOverride),
        // Round 2 (2026-08-27): ordering/fold probes on the ring, the
        // remaining interop-proof sites and boundary swap, the reject arm of
        // `expected_tree_root`, and the other shapes of the two hints.
        Box::new(InjectedRingBlockHashEntry),
        Box::new(ShadowedRingBlockHashEntry),
        Box::new(ForgedSlChainIdProof),
        Box::new(ForgedMultichainRootProof),
        Box::new(SwappedCommitmentTreeBoundaries),
        Box::new(ForgedExpectedTreeRoot),
        Box::new(DroppedGasUsedOverride),
        Box::new(FlippedForceFail),
        // Round 3 (2026-08-28): the three individually unforged interop
        // commitment-tree proof fields, the zero-overwrite and self-naming
        // shapes of the block-hash ring, the clamp boundary of the gas hint,
        // and all-positions variants of the two execution hints.
        Box::new(ForgedCommitmentTreeRootBeginProof),
        Box::new(ForgedCommitmentTreeHeightEndProof),
        Box::new(ForgedCommitmentTreeRootEndProof),
        Box::new(ZeroedRingBlockHashEntry),
        Box::new(SelfReferentialBlockHashEntry),
        Box::new(ClampedGasUsedOverride),
        Box::new(ForgedAllGasUsedOverrides),
        Box::new(FlippedForceFailLastTx),
    ]
}

/// Minimal, deterministic change to a hash: flip one bit of the last byte.
fn perturb(value: &mut B256) {
    let mut bytes = *value;
    bytes[31] ^= 0x01;
    *value = B256::from(bytes);
}

/// Claims a protocol-upgrade transaction the batch does not carry.
///
/// `upgrade_tx_hash` is the one witness field folded into
/// `batch_output_hash` verbatim. The guest authenticates it bidirectionally
/// against the batch's own transactions: nonzero iff exactly one Upgrade tx
/// is present, and equal to that transaction's hash. A correct guest rejects
/// this witness at that assertion; acceptance with a moved commitment would
/// prove a batch that applied an upgrade the chain never ordered.
pub struct ForgedUpgradeTxHash;

impl WitnessOracle for ForgedUpgradeTxHash {
    fn name(&self) -> &str {
        "forged_upgrade_tx_hash"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        if !honest.batch_meta.upgrade_tx_hash.is_zero() {
            return None;
        }
        let mut mutated = honest.clone();
        mutated.batch_meta.upgrade_tx_hash = B256::repeat_byte(0xee);
        Some(mutated)
    }
}

/// Moves the legacy witness scalar `sl_chain_id`.
///
/// The guest derives the settlement-layer chain id from the authenticated
/// `0x800b` slot proof on v31+, and the v30 batch-output layout commits no
/// such word at all, so the scalar must bind nothing either way. Accepted
/// with the honest commitment is the correct verdict; anything else means a
/// critical batch-output word moved onto server-supplied data.
pub struct UnboundSlChainId;

impl WitnessOracle for UnboundSlChainId {
    fn name(&self) -> &str {
        "unbound_sl_chain_id"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        mutated.batch_meta.sl_chain_id = honest.batch_meta.sl_chain_id.wrapping_add(1);
        Some(mutated)
    }
}

/// Moves the legacy witness scalar `multichain_root`.
///
/// Same shape as `sl_chain_id`: the guest derives the multichain root from
/// the authenticated MessageRoot slot proofs (zero on v30) and never reads
/// this field. The commitment must not move.
pub struct UnboundMultichainRoot;

impl WitnessOracle for UnboundMultichainRoot {
    fn name(&self) -> &str {
        "unbound_multichain_root"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        mutated.batch_meta.multichain_root = B256::repeat_byte(0x7a);
        Some(mutated)
    }
}

/// Moves the witness block-hash ring `previous_block_hashes`.
///
/// The after-ring folded into `state_after` is reconstructed from
/// authenticated data alone — the L1-pinned before-ring and the guest's own
/// computed header hashes — so this list must bind nothing. An empty honest
/// list gets a bogus entry appended: a mutation with a site on every case.
pub struct UnboundPreviousBlockHashes;

impl WitnessOracle for UnboundPreviousBlockHashes {
    fn name(&self) -> &str {
        "unbound_previous_block_hashes"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        match mutated.batch_meta.previous_block_hashes.first_mut() {
            Some(entry) => perturb(entry),
            None => mutated
                .batch_meta
                .previous_block_hashes
                .push(B256::repeat_byte(0x5b)),
        }
        Some(mutated)
    }
}

/// Corrupts the sealed `block_header_hash` of the first block.
///
/// The guest recomputes the header from its own execution and asserts
/// equality against the sealed value. The recomputed header is what reaches
/// `state_after` through the after-ring, so this pin is what ties the
/// witness's execution hints to the block native sealed. A correct guest
/// rejects at the equality assertion.
pub struct CorruptBlockHeaderHash;

impl WitnessOracle for CorruptBlockHeaderHash {
    fn name(&self) -> &str {
        "corrupt_block_header_hash"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let hash = &mut mutated.blocks.first_mut()?.block_header_hash;
        if hash.is_zero() {
            return None;
        }
        perturb(hash);
        Some(mutated)
    }
}

/// Erases the sealed `block_header_hash` of the first block.
///
/// The pin is mandatory from AtlasV4 on, so a correct AtlasV4 guest rejects
/// a zero hash. On earlier specs the check is optional: acceptance there
/// must still commit the honest value, because the commitment is built from
/// the guest's own recomputed header.
pub struct AbsentBlockHeaderHash;

impl WitnessOracle for AbsentBlockHeaderHash {
    fn name(&self) -> &str {
        "absent_block_header_hash"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let hash = &mut mutated.blocks.first_mut()?.block_header_hash;
        if hash.is_zero() {
            return None;
        }
        *hash = B256::ZERO;
        Some(mutated)
    }
}

/// Forges a historical hash inside the authenticated block-hash ring window.
///
/// The first block's `block_hashes` entries for the 256 blocks preceding it
/// reconstruct the pre-state ring, which the guest authenticates against the
/// L1-pinned `block_hashes_blake_before`. A forged in-window slot moves that
/// Blake2s commitment, so a correct guest rejects.
pub struct ForgedRingBlockHash;

impl WitnessOracle for ForgedRingBlockHash {
    fn name(&self) -> &str {
        "forged_ring_block_hash"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let first = mutated.blocks.first_mut()?;
        let owner = first.number;
        let entry = first
            .block_hashes
            .iter_mut()
            .find(|(num, _)| *num < owner && owner - *num <= 256)?;
        perturb(&mut entry.1);
        Some(mutated)
    }
}

/// Appends a block-hash entry no check can see.
///
/// The entry names a block far beyond the batch, so it falls outside the
/// reconstructed ring window, outside the intra-batch computed set, and
/// outside the `previous_block_hashes` consistency guard. A correct guest
/// ignores it and commits the honest value; a rejection would mean a check
/// reads witness entries it was never meant to read.
pub struct UnauthenticatedBlockHashEntry;

impl WitnessOracle for UnauthenticatedBlockHashEntry {
    fn name(&self) -> &str {
        "unauthenticated_block_hash_entry"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let last = mutated.blocks.last()?.number;
        mutated
            .blocks
            .first_mut()?
            .block_hashes
            .push((last + 1000, B256::repeat_byte(0x0d)));
        Some(mutated)
    }
}

/// Rewrites `expected_tree_root` to the other value the validator accepts.
///
/// The field is retained for wire compatibility: the guest requires it to be
/// zero or the L1-pinned `tree_root_before`, and authenticates every read
/// against the pinned root regardless. Both accepted forms must commit the
/// honest value.
pub struct DecorativeExpectedTreeRoot;

impl WitnessOracle for DecorativeExpectedTreeRoot {
    fn name(&self) -> &str {
        "decorative_expected_tree_root"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let pinned = honest.batch_meta.tree_root_before;
        let mut mutated = honest.clone();
        let field = &mut mutated.blocks.first_mut()?.expected_tree_root;
        if field.is_zero() {
            *field = pinned;
        } else if *field == pinned {
            *field = B256::ZERO;
        } else {
            return None;
        }
        Some(mutated)
    }
}

/// Drops the interop slot proofs of a v31+ batch.
///
/// The guest derives `sl_chain_id`, the multichain root and the AtlasV4
/// commitment-tree roots from these proofs and demands them present whenever
/// the executing spec commits those values. A correct v31+ guest rejects the
/// absence loudly rather than falling back to the witness scalars.
pub struct MissingInteropProofs;

impl WitnessOracle for MissingInteropProofs {
    fn name(&self) -> &str {
        "missing_interop_proofs"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        honest.batch_meta.interop_proofs.as_ref()?;
        let mut mutated = honest.clone();
        mutated.batch_meta.interop_proofs = None;
        Some(mutated)
    }
}

/// Drops only the AtlasV4 interop commitment-tree proofs, keeping the
/// sl_chain_id / multichain proofs in place.
///
/// The two commitment-tree roots are leaves of the AtlasV4 chain batch root,
/// so a spec that commits them must demand their proofs. A correct AtlasV4
/// guest rejects the absence rather than folding zero roots in silently.
pub struct MissingCommitmentTreeProofs;

impl WitnessOracle for MissingCommitmentTreeProofs {
    fn name(&self) -> &str {
        "missing_commitment_tree_proofs"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        honest.batch_meta.interop_proofs.as_ref()?.commitment_tree.as_ref()?;
        let mut mutated = honest.clone();
        mutated
            .batch_meta
            .interop_proofs
            .as_mut()?
            .commitment_tree = None;
        Some(mutated)
    }
}

/// Forges one AtlasV4 interop commitment-tree proof.
///
/// The commitment-tree roots at the two batch boundaries are leaves of the
/// AtlasV4 chain batch root, and each of the four proofs is verified against
/// the pinned pre-state root or the guest-computed post-state root. The lie
/// is well-formed: a self-consistent proof that recovers a root of the
/// adversary's choosing, so the rejection must come from the pinned-root
/// equality and not from a malformed-proof check.
pub struct ForgedCommitmentTreeProof;

impl WitnessOracle for ForgedCommitmentTreeProof {
    fn name(&self) -> &str {
        "forged_commitment_tree_proof"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let proofs = mutated.batch_meta.interop_proofs.as_mut()?;
        let proof = &mut proofs.commitment_tree.as_mut()?.height_begin;
        *proof = StorageProof::Existing(zksync_os_zisk_lib::merkle::SlotProofEntry {
            index: 0,
            value: B256::repeat_byte(0x77),
            next_index: 0,
            siblings: vec![],
        });
        Some(mutated)
    }
}

/// Forges the multichain aggregation-height proof.
///
/// The multichain root is a leaf of the chain batch root folded into
/// `batch_output_hash`, and the guest derives it from the MessageRoot slot
/// proofs instead of trusting the witness scalar. The lie is well-formed: a
/// self-consistent proof that recovers a root of the adversary's choosing,
/// so the rejection must come from the pinned post-state root equality.
pub struct ForgedMultichainHeightProof;

impl WitnessOracle for ForgedMultichainHeightProof {
    fn name(&self) -> &str {
        "forged_multichain_height_proof"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let proofs = mutated.batch_meta.interop_proofs.as_mut()?;
        proofs.multichain_height =
            StorageProof::Existing(zksync_os_zisk_lib::merkle::SlotProofEntry {
                index: 0,
                value: B256::repeat_byte(0x55),
                next_index: 0,
                siblings: vec![],
            });
        Some(mutated)
    }
}

/// Lies about one transaction's gas while the header pin stays armed.
///
/// `gas_used_override` is a server execution hint the statement digest
/// deliberately leaves mutable. The guest folds it into the recomputed
/// header hash, so the sealed `block_header_hash` pin is the binding that
/// stops the lie from reaching `state_after`. A correct guest rejects at
/// the header equality assertion.
pub struct ForgedGasUsedOverride;

impl WitnessOracle for ForgedGasUsedOverride {
    fn name(&self) -> &str {
        "forged_gas_used_override"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let tx = mutated.blocks.first_mut()?.transactions.first_mut()?;
        let override_gas = tx.gas_used_override.as_mut()?;
        *override_gas = override_gas.saturating_add(1);
        Some(mutated)
    }
}

/// Lies about one transaction's gas with the header pin removed.
///
/// This is the optional-pin seam: where the sealed `block_header_hash` is
/// not mandatory, erasing it skips the only in-guest check that observes
/// the gas lie, and the forged gas reaches `state_after` through the
/// recomputed header hash. AtlasV4 makes the pin mandatory, so a correct
/// AtlasV4 guest rejects; acceptance with a moved commitment is two
/// witnesses for one statement.
pub struct UnpinnedGasUsedOverride;

impl WitnessOracle for UnpinnedGasUsedOverride {
    fn name(&self) -> &str {
        "unpinned_gas_used_override"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let block = mutated.blocks.first_mut()?;
        if block.block_header_hash.is_zero() {
            return None;
        }
        block.block_header_hash = B256::ZERO;
        let tx = block.transactions.first_mut()?;
        let override_gas = tx.gas_used_override.as_mut()?;
        *override_gas = override_gas.saturating_add(1);
        Some(mutated)
    }
}

/// Appends a forged entry for an in-window ring slot the honest witness
/// leaves zero — the first block's parent.
///
/// `reconstruct_ring` places every in-window entry into the authenticated
/// ring, so an omitted slot and a zero-valued slot are the same encoding,
/// but a nonzero value at the slot must move the ring's Blake2s commitment
/// away from the L1-pinned `block_hashes_blake_before`. This is the
/// empty-vs-absent edge of the ring encoding: a correct guest rejects at
/// the ring-authentication assertion. Complements round 1's
/// `unauthenticated_block_hash_entry` (the same append out of window, where
/// inert is correct) and `forged_ring_block_hash` (a mutated existing
/// entry, which has a site only where the honest list is non-empty).
pub struct InjectedRingBlockHashEntry;

impl WitnessOracle for InjectedRingBlockHashEntry {
    fn name(&self) -> &str {
        "injected_ring_block_hash_entry"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let first = mutated.blocks.first_mut()?;
        let parent = first.number.checked_sub(1)?;
        // In-window for every block: the parent is always within 256 of it.
        // When the honest list already carries the parent slot the appended
        // duplicate still moves the ring, because the fold is
        // last-write-wins.
        first.block_hashes.push((parent, B256::repeat_byte(0x33)));
        Some(mutated)
    }
}

/// Prepends a forged duplicate of an in-window ring entry, shadowed by the
/// honest occurrence that follows it.
///
/// The ring fold is last-write-wins (`reconstruct_ring`), so the forged
/// first occurrence never reaches the commitment: the honest duplicate
/// restores the slot before the Blake2s commitment is computed. The
/// BLOCKHASH map and the parent hash are seeded from the authenticated
/// ring, never from a first-match scan of this list (evm.rs), so the forged
/// value is unread anywhere. A correct guest accepts with the honest
/// commitment — the verdict that pins the fold order; a first-match read
/// anywhere would turn this into a finding.
pub struct ShadowedRingBlockHashEntry;

impl WitnessOracle for ShadowedRingBlockHashEntry {
    fn name(&self) -> &str {
        "shadowed_ring_block_hash_entry"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let first = mutated.blocks.first_mut()?;
        let owner = first.number;
        let entry = first
            .block_hashes
            .iter()
            .find(|(num, _)| *num < owner && owner - *num <= 256)?;
        let (num, mut forged) = *entry;
        perturb(&mut forged);
        first.block_hashes.insert(0, (num, forged));
        Some(mutated)
    }
}

/// Forges the sl_chain_id slot proof (SystemContext `0x800b` slot 0).
///
/// The settlement-layer chain id is a leaf of the v31+ batch-output
/// preimage, derived from this proof against the guest-computed post-state
/// root — never from the witness scalar. Round 1 forged the multichain
/// height and the commitment-tree begin height; this is the third site of
/// the same derivation. The lie is well-formed: a self-consistent proof
/// that recovers a root of the adversary's choosing, so the rejection must
/// come from the pinned-root equality.
pub struct ForgedSlChainIdProof;

impl WitnessOracle for ForgedSlChainIdProof {
    fn name(&self) -> &str {
        "forged_sl_chain_id_proof"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let proofs = mutated.batch_meta.interop_proofs.as_mut()?;
        proofs.sl_chain_id =
            StorageProof::Existing(zksync_os_zisk_lib::merkle::SlotProofEntry {
                index: 0,
                value: B256::repeat_byte(0x2a),
                next_index: 0,
                siblings: vec![],
            });
        Some(mutated)
    }
}

/// Forges the multichain root proof (MessageRoot `0x10005`
/// `nodes[height][0]`), keeping the height proof honest.
///
/// The multichain root is a leaf of the chain batch root folded into
/// `batch_output_hash`. Round 1 forged the height proof; this is the second
/// site of that two-read derivation, so the rejection must come from the
/// pinned post-state root equality on the root read itself.
pub struct ForgedMultichainRootProof;

impl WitnessOracle for ForgedMultichainRootProof {
    fn name(&self) -> &str {
        "forged_multichain_root_proof"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let proofs = mutated.batch_meta.interop_proofs.as_mut()?;
        proofs.multichain_root =
            StorageProof::Existing(zksync_os_zisk_lib::merkle::SlotProofEntry {
                index: 0,
                value: B256::repeat_byte(0x66),
                next_index: 0,
                siblings: vec![],
            });
        Some(mutated)
    }
}

/// Swaps the interop commitment-tree proofs of the two batch boundaries.
///
/// The begin pair is authenticated against the L1-pinned pre-state root and
/// the end pair against the guest-computed post-state root, and the two
/// roots always differ on AtlasV4 (the EIP-2935 pre-block write moves the
/// root of every block). The swapped begin pair therefore recovers the
/// post-state root under the pre-state anchor, and a correct guest rejects
/// at the begin pair's pinned-root equality — the proof that the two leaves
/// of the chain batch root are not interchangeable.
pub struct SwappedCommitmentTreeBoundaries;

impl WitnessOracle for SwappedCommitmentTreeBoundaries {
    fn name(&self) -> &str {
        "swapped_commitment_tree_boundaries"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let tree = mutated
            .batch_meta
            .interop_proofs
            .as_mut()?
            .commitment_tree
            .as_mut()?;
        std::mem::swap(&mut tree.height_begin, &mut tree.height_end);
        std::mem::swap(&mut tree.root_begin, &mut tree.root_end);
        Some(mutated)
    }
}

/// Sets the first block's `expected_tree_root` to a value that is neither
/// zero nor the pinned pre-state root.
///
/// Round 1 showed both accepted forms commit the honest value; this probes
/// the reject arm. The field survives for wire compatibility only, and
/// `validate_expected_tree_roots` must fail loudly on any other value so a
/// witness-chosen per-block read root can never reach proof verification.
pub struct ForgedExpectedTreeRoot;

impl WitnessOracle for ForgedExpectedTreeRoot {
    fn name(&self) -> &str {
        "forged_expected_tree_root"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let pinned = honest.batch_meta.tree_root_before;
        let forged = B256::repeat_byte(0x1f);
        if forged == pinned {
            return None;
        }
        let mut mutated = honest.clone();
        mutated.blocks.first_mut()?.expected_tree_root = forged;
        Some(mutated)
    }
}

/// Drops the server's gas hint for one transaction, leaving REVM's own gas.
///
/// The guest models none of native's pubdata/resource charging and commits
/// `gas_used` into the recomputed header, so a self-computed gas that
/// differs from native's moves the header and the mandatory AtlasV4 pin
/// rejects. This is the absent-hint shape of round 1's +1 mutation: it
/// answers whether the hint is load-bearing or decorative on cases where
/// the two gas models might agree.
pub struct DroppedGasUsedOverride;

impl WitnessOracle for DroppedGasUsedOverride {
    fn name(&self) -> &str {
        "dropped_gas_used_override"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let tx = mutated.blocks.first_mut()?.transactions.first_mut()?;
        tx.gas_used_override.take()?;
        Some(mutated)
    }
}

/// Flips one transaction's `force_fail` flag.
///
/// The flag is a witness-side execution hint the statement digest
/// deliberately leaves mutable, and flipping it is the "excluded failed
/// transaction" shape: the witness now claims a successful transaction
/// reverted. A correct guest must observe the lie — the synthesized revert
/// changes the receipt leaf (status, logs) and drops the transaction's
/// writes. On AtlasV4 the receipt leaf feeds the header's receipts root, so
/// the mandatory header pin rejects first, with the tree-update set
/// equality standing behind it.
pub struct FlippedForceFail;

impl WitnessOracle for FlippedForceFail {
    fn name(&self) -> &str {
        "flipped_force_fail"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let tx = mutated.blocks.first_mut()?.transactions.first_mut()?;
        tx.force_fail = !tx.force_fail;
        Some(mutated)
    }
}

/// Forges the interop commitment-tree root proof at the PRE-batch boundary.
///
/// Round 1 forged the begin HEIGHT proof and round 2 swapped the boundary
/// pairs; the begin root read itself has never faced an individual lie. The
/// lie is well-formed (a self-consistent `Existing` entry), so the rejection
/// must come from the pinned pre-state root equality, naming the begin-root
/// check.
pub struct ForgedCommitmentTreeRootBeginProof;

impl WitnessOracle for ForgedCommitmentTreeRootBeginProof {
    fn name(&self) -> &str {
        "forged_commitment_tree_root_begin_proof"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let tree = mutated
            .batch_meta
            .interop_proofs
            .as_mut()?
            .commitment_tree
            .as_mut()?;
        tree.root_begin =
            StorageProof::Existing(zksync_os_zisk_lib::merkle::SlotProofEntry {
                index: 0,
                value: B256::repeat_byte(0x9b),
                next_index: 0,
                siblings: vec![],
            });
        Some(mutated)
    }
}

/// Forges the interop commitment-tree height proof at the POST-batch
/// boundary.
///
/// The end pair is anchored at the guest-computed `tree_root_after`, and the
/// honest begin pair passes first, so the rejection must name the end-height
/// check — direct evidence that the post-state anchor is enforced on the
/// height read, which selects the slot the committed end root is read from.
pub struct ForgedCommitmentTreeHeightEndProof;

impl WitnessOracle for ForgedCommitmentTreeHeightEndProof {
    fn name(&self) -> &str {
        "forged_commitment_tree_height_end_proof"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let tree = mutated
            .batch_meta
            .interop_proofs
            .as_mut()?
            .commitment_tree
            .as_mut()?;
        tree.height_end =
            StorageProof::Existing(zksync_os_zisk_lib::merkle::SlotProofEntry {
                index: 0,
                value: B256::repeat_byte(0x9c),
                next_index: 0,
                siblings: vec![],
            });
        Some(mutated)
    }
}

/// Forges the interop commitment-tree root proof at the POST-batch boundary.
///
/// The end root is a leaf of the AtlasV4 chain batch root. Round 2's swap
/// probe only ever tripped the BEGIN pair's anchor, so the post-state
/// equality on the end root has never been observed directly. The lie is
/// well-formed, so the rejection must name it.
pub struct ForgedCommitmentTreeRootEndProof;

impl WitnessOracle for ForgedCommitmentTreeRootEndProof {
    fn name(&self) -> &str {
        "forged_commitment_tree_root_end_proof"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let tree = mutated
            .batch_meta
            .interop_proofs
            .as_mut()?
            .commitment_tree
            .as_mut()?;
        tree.root_end =
            StorageProof::Existing(zksync_os_zisk_lib::merkle::SlotProofEntry {
                index: 0,
                value: B256::repeat_byte(0x9d),
                next_index: 0,
                siblings: vec![],
            });
        Some(mutated)
    }
}

/// Appends a ZERO-valued entry for an in-window ring slot — the first block's
/// parent.
///
/// The ring encoding makes an omitted slot and a zero-valued slot
/// interchangeable, so on a case whose honest list leaves the parent slot
/// zero this overwrite must be accepted with the honest commitment. On a
/// case whose honest list carries the parent (the corpus dump), the same
/// append is an erasure: last-write-wins zeroes the honest hash, the ring's
/// Blake2s commitment moves, and the L1-pinned `block_hashes_blake_before`
/// must reject it. The pair of verdicts pins both directions of the
/// zero-vs-absent edge that round 2's `injected_ring_block_hash_entry`
/// probed from the nonzero side alone.
pub struct ZeroedRingBlockHashEntry;

impl WitnessOracle for ZeroedRingBlockHashEntry {
    fn name(&self) -> &str {
        "zeroed_ring_block_hash_entry"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let first = mutated.blocks.first_mut()?;
        let parent = first.number.checked_sub(1)?;
        first.block_hashes.push((parent, B256::ZERO));
        Some(mutated)
    }
}

/// Appends a block-hash entry that names the batch's own first block.
///
/// The entry sits outside every consumer of the list: the ring window holds
/// only blocks strictly before the owner, the intra-batch consistency check
/// runs before the block's own hash is computed, and the witness-consistency
/// guard covers only numbers below the last block. A correct guest therefore
/// ignores it and commits the honest value; any other verdict means a check
/// lets a block witness its own hash.
pub struct SelfReferentialBlockHashEntry;

impl WitnessOracle for SelfReferentialBlockHashEntry {
    fn name(&self) -> &str {
        "self_referential_block_hash_entry"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let first = mutated.blocks.first_mut()?;
        let own = first.number;
        first.block_hashes.push((own, B256::repeat_byte(0x44)));
        Some(mutated)
    }
}

/// Sets one transaction's gas hint to `u64::MAX`, far above its gas limit.
///
/// The handler clamps the override to the transaction's gas limit
/// (`used = override.min(gas_limit)`), and the mandatory AtlasV4 header pin
/// observes whatever the clamp yields. On a transaction that did not consume
/// its whole limit the clamped value differs from the honest gas, so the pin
/// must reject. On one that did (the gas-tight scenario) the clamp erases
/// the lie: the effective gas equals the honest value and acceptance with
/// the honest commitment is the correct verdict. The two verdicts together
/// pin the exact boundary of the hint's binding.
pub struct ClampedGasUsedOverride;

impl WitnessOracle for ClampedGasUsedOverride {
    fn name(&self) -> &str {
        "clamped_gas_used_override"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let tx = mutated.blocks.first_mut()?.transactions.first_mut()?;
        *tx.gas_used_override.as_mut()? = u64::MAX;
        Some(mutated)
    }
}

/// Lies about EVERY transaction's gas by +1, not just the first.
///
/// The header's `gas_used` and each receipt leaf's cumulative gas fold every
/// transaction, so the pin must reject wherever in the block the lie lands.
/// Round 1 mutated transaction 0 alone; this oracle covers the remaining
/// positions in one pass, so a hypothetical first-transaction-only binding
/// cannot hide.
pub struct ForgedAllGasUsedOverrides;

impl WitnessOracle for ForgedAllGasUsedOverrides {
    fn name(&self) -> &str {
        "forged_all_gas_used_overrides"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let mut sites = 0;
        for block in &mut mutated.blocks {
            for tx in &mut block.transactions {
                if let Some(override_gas) = tx.gas_used_override.as_mut() {
                    *override_gas = override_gas.saturating_add(1);
                    sites += 1;
                }
            }
        }
        (sites > 0).then_some(mutated)
    }
}

/// Flips the LAST transaction's `force_fail` flag.
///
/// Round 2's `flipped_force_fail` acts on transaction 0. The binding runs
/// through the receipts root, which folds every transaction's leaf, so the
/// pin must reject a lie at the last position exactly as at the first.
pub struct FlippedForceFailLastTx;

impl WitnessOracle for FlippedForceFailLastTx {
    fn name(&self) -> &str {
        "flipped_force_fail_last_tx"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let tx = mutated.blocks.first_mut()?.transactions.last_mut()?;
        tx.force_fail = !tx.force_fail;
        Some(mutated)
    }
}
