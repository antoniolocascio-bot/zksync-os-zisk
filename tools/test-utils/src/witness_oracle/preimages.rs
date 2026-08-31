//! Campaign oracles: forged account preimages, bytecodes, tree-update entries
//! and their after-images. Owned by the `ws-preimages` campaign agent. Other
//! agents must not edit this file.
//!
//! The bindings under test, in the order the guest applies them:
//! - `load_bytecodes`: keccak256(code) must equal the key it is filed under.
//! - `build_verified_accounts`: blake2s(preimage) must equal the
//!   merkle-authenticated 0x8003 value; a preimage for a proven-nonexistent
//!   account is discarded unread.
//! - `build_revm_write_map`: every provided after-preimage is pinned to REVM's
//!   post-state (nonce/balance verbatim, code fields derived), an after-preimage
//!   for an account execution never wrote is rejected outside upgrade batches,
//!   and every account whose nonce or balance changed must be provided.
//! - `verify_tree_update`: the tree update is a set equal to the computed write
//!   map, its leaf_count_before is pinned to the committed count, and `apply`
//!   re-derives the old root from `sorted_leaves` before producing the new one.
//!
//! The completeness loop in `build_revm_write_map` compares only nonce and
//! balance endpoints, so an account whose 0x8003 leaf changed while both
//! endpoints stayed (0, 0) — a contract created and destroyed inside one batch
//! (EIP-6780) — is invisible to it. The `create_destroy_*` oracles probe that
//! seam from both directions and re-forge the post-state interop proofs, which
//! is possible because the witness carries the full pre-state tree.
//!
//! Round 2 adds the order axis of `verify_tree_update`: the set equality is
//! order-blind, but `BatchTreeUpdate::apply` assigns inserted leaves their
//! dense tree indices in WITNESS order, so the order of `operations`/`entries`
//! is itself commitment-bearing. The `tree_*_order_permuted` oracles probe
//! whether the guest pins that order, and the `tree_entry_key_duplicated*`
//! oracles pin the duplicate-key guard the count check relies on.
//!
//! Round 3 refines the order axis and maps the list semantics around it:
//! - `tree_insert_order_rotated` extends the insert-order seam from
//!   transpositions to a 3-cycle (any permutation moves the root, not only
//!   swaps), while `tree_insert_update_interleaved` pins the boundary from
//!   the other side: an update sliding across an insert changes nothing,
//!   because updates address pre-existing leaves by index and only inserts
//!   consume the dense-index counter.
//! - `tree_insert_update_same_key` answers whether one batch may carry an
//!   insert and an update of the SAME key (the duplicate-key guard rejects
//!   before any value lands).
//! - `warmed_account_after_image_injected` probes the injection guard's
//!   `AccountState::None` arm: an account READ but never written is
//!   `Unwritten`, so even a truthful, value-identity after-image must be
//!   rejected.
//! - `create_only_leaf_content_zeroed` pins the content side of the
//!   create-without-destroy boundary, and doubles as the check that an
//!   account destroyed and re-created in one batch classifies as `Written`
//!   (cache-first), never as `Destroyed`.
//! - the `*_list_reordered` oracles answer whether any committed value
//!   depends on the ORDER of the `account_preimages`, `bytecodes` or
//!   `account_preimages_after` lists (all keyed maps, so all inert).

use std::collections::HashMap;

use revm::primitives::{Address, B256, U256};
use zksync_os_zisk_lib::hash::keccak256;
use zksync_os_zisk_lib::merkle::{
    self, NeighborProofEntry, SlotProofEntry, StorageProof, TreeLeaf, WriteOp,
};
use zksync_os_zisk_lib::types::BatchInput;

use super::WitnessOracle;

/// The oracles this axis contributes to a sweep.
pub fn oracles() -> Vec<Box<dyn WitnessOracle>> {
    vec![
        Box::new(PreimageBalanceForged),
        Box::new(PreimageWithoutStorageProof),
        Box::new(PreimageDuplicateShadowed),
        Box::new(PreimageOfProvenNonexistent),
        Box::new(AfterPreimageBalanceForged),
        Box::new(AfterPreimageNonceForged),
        Box::new(AfterPreimageArtifactsLenForged),
        Box::new(AfterPreimageObservableHashForged),
        Box::new(AfterPreimageDropped),
        Box::new(AfterPreimageInjectedUntouched),
        Box::new(AfterPreimageDuplicateShadowed),
        Box::new(BytecodeHashKeySwapped),
        Box::new(BytecodeReferencedDropped),
        Box::new(BytecodeAppendedUnused),
        Box::new(BytecodeDroppedUnreferenced),
        Box::new(TreeEntryValueForged),
        Box::new(TreeEntryKeyForged),
        Box::new(TreeLeafCountInflated),
        Box::new(SortedLeafValueForged),
        Box::new(CreateDestroyLeafDropped),
        Box::new(CreateDestroyLeafInjected),
        Box::new(CreateDestroyLeafContentForged),
        Box::new(CreateDestroyPreimageWithoutEntry),
        Box::new(CreateOnlyLeafDropped),
        Box::new(TouchedAccountAfterImageZeroed),
        Box::new(TouchedAccountAfterImageRedundant),
        Box::new(AfterPreimageDuplicateAppended),
        Box::new(BytecodeDuplicateShadowed),
        Box::new(BytecodeCreatedCodeDropped),
        Box::new(TreeInsertOrderPermuted),
        Box::new(TreeUpdateOrderPermuted),
        Box::new(TreeEntryKeyDuplicated),
        Box::new(TreeEntryKeyDuplicatedValueForged),
        Box::new(TreeOperationsTruncated),
        Box::new(SortedLeafIndexDuplicated),
        Box::new(SortedLeafIndexBeyondCount),
        Box::new(TreeUpdateDropped),
        Box::new(TreeIntermediateHashAppended),
        Box::new(TreeUpdateOpIndexForged),
        Box::new(TreeInsertUpdateInterleaved),
        Box::new(TreeInsertOrderRotated),
        Box::new(TreeInsertUpdateSameKey),
        Box::new(WarmedAccountAfterImageInjected),
        Box::new(CreateOnlyLeafContentZeroed),
        Box::new(AccountPreimageListReordered),
        Box::new(BytecodeListReordered),
        Box::new(AfterPreimageListReordered),
        Box::new(Create2DestroyLeafInjected),
    ]
}

// ---------------------------------------------------------------------------
// Round 3: the create+destroy seam via CREATE2
// ---------------------------------------------------------------------------
//
// `create_destroy_sites` reconstructs created-and-destroyed accounts from
// creator NONCES, so it only ever sees CREATE targets. A CREATE2-created
// account destroyed in the same batch lands in exactly the same blind spot
// (its nonce and balance read (0, 0) at both ends) but is invisible to that
// detector. The oracle below derives the one CREATE2 target the
// `create2_recreate` scenario produces — the address appears nowhere in the
// witness, so it is recomputed from the factory address, the salt and the
// init code — and injects the zeroed after-leaf there.

/// The deployment parameters of the `create2_recreate` scenario's child.
const CREATE2_SCENARIO_FACTORY: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0f, 0xaa,
];
const CREATE2_SCENARIO_INIT: [u8; 14] = [
    0x60, 0x02, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, 0x02, 0x60, 0x00, 0xf3, 0x33, 0xff,
];

/// The address `CREATE2` assigns: keccak256(0xff ‖ deployer ‖ salt ‖
/// keccak256(init_code))[12..].
fn create2_address(deployer: &Address, salt: &B256, init_code: &[u8]) -> Address {
    let mut preimage = Vec::with_capacity(85);
    preimage.push(0xff);
    preimage.extend_from_slice(deployer.as_slice());
    preimage.extend_from_slice(salt.as_slice());
    preimage.extend_from_slice(keccak256(init_code).as_slice());
    Address::from_slice(&keccak256(&preimage)[12..])
}

/// Injects the zeroed after-state leaf of an account created by CREATE2 and
/// destroyed inside the same batch, when the honest witness carries none.
///
/// Same seam as `create_destroy_leaf_injected`, on a shape its site detector
/// cannot enumerate: the child was created and destroyed in one transaction
/// (EIP-6780), the post-6780 recreate under the same salt fails on both
/// lanes (the account's deletion commits only at transaction end), so the
/// batch's endpoints for it are (0, 0) -> (0, 0) and the completeness loop
/// never asks for its write. A guest that accepts commits a post-state root
/// whose tree provably CONTAINS the destroyed child's zeroed leaf where
/// native's provably does not: two witnesses for one statement.
pub struct Create2DestroyLeafInjected;

impl WitnessOracle for Create2DestroyLeafInjected {
    fn name(&self) -> &str {
        "create2_destroy_leaf_injected"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let update = honest.batch_meta.tree_update.as_ref()?;
        let child = create2_address(
            &Address::from(CREATE2_SCENARIO_FACTORY),
            &B256::ZERO,
            &CREATE2_SCENARIO_INIT,
        );
        let flat_key = account_flat_key(&child);
        // The site: proven non-existent pre-batch, untouched by the tree
        // update, and absent from both preimage lists — the witness shape of
        // an account that lived and died inside the batch.
        if !has_nonexistence_proof(honest, &flat_key)
            || update.entries.iter().any(|(key, _)| key == &flat_key)
            || pre_imaged_addresses(honest).contains(&child)
            || honest
                .batch_meta
                .account_preimages_after
                .iter()
                .any(|(addr, _)| addr == &child)
        {
            return None;
        }
        let (honest_leaves, _) = apply_write_ops(
            &update.sorted_leaves,
            update.leaf_count_before,
            &update.operations,
            &update.entries,
        )?;
        let prev_index = honest_leaves
            .iter()
            .filter(|(_, leaf)| leaf.key < flat_key)
            .max_by_key(|(_, leaf)| leaf.key)?
            .0;
        let mut mutated = honest.clone();
        mutated
            .batch_meta
            .account_preimages_after
            .push((child, vec![0u8; merkle::AccountProperties::ENCODED_SIZE]));
        push_insert(&mut mutated, flat_key, prev_index, &[0u8; 124])?;
        let (leaves, levels) = forged_post_state(honest, &mutated)?;
        reforge_interop_proofs(&mut mutated, &leaves, &levels)?;
        Some(mutated)
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Byte offsets of the fields a 124-byte account-properties blob carries, as
/// `merkle::AccountProperties::decode` reads them.
const NONCE_OFFSET: usize = 8;
const BALANCE_OFFSET: usize = 16;
const ARTIFACTS_LEN_OFFSET: usize = 84;
const OBSERVABLE_HASH_OFFSET: usize = 88;

/// The zeroed account leaf: native's encoding of an account destruction
/// removed, and the only content pin the guest accepts for one.
fn is_zeroed_blob(blob: &[u8]) -> bool {
    blob.len() == merkle::AccountProperties::ENCODED_SIZE && blob.iter().all(|b| *b == 0)
}

/// Flip one bit of a blob field, deterministically: the last byte of the field.
fn perturb_field(blob: &mut [u8], offset: usize, len: usize) {
    blob[offset + len - 1] ^= 0x01;
}

/// The 0x8003 flat key under which an account's properties leaf lives.
fn account_flat_key(addr: &Address) -> B256 {
    merkle::derive_account_properties_key(&addr.into_array())
}

/// Every address that carries a pre-state account preimage in any block.
fn pre_imaged_addresses(honest: &BatchInput) -> Vec<Address> {
    honest
        .blocks
        .iter()
        .flat_map(|block| block.account_preimages.iter().map(|(addr, _)| *addr))
        .collect()
}

/// Whether the witness proves the key absent (a NonExisting proof in some block).
fn has_nonexistence_proof(honest: &BatchInput, flat_key: &B256) -> bool {
    honest.blocks.iter().any(|block| {
        block
            .storage_proofs
            .iter()
            .any(|(k, proof)| k == flat_key && matches!(proof, StorageProof::NonExisting { .. }))
    })
}

/// Whether the witness proves the key present (an Existing proof in some block).
fn has_existence_proof(honest: &BatchInput, flat_key: &B256) -> bool {
    honest.blocks.iter().any(|block| {
        block
            .storage_proofs
            .iter()
            .any(|(k, proof)| k == flat_key && matches!(proof, StorageProof::Existing(_)))
    })
}

/// The observable code hash every account blob in `blobs` references.
fn referenced_code_hashes<'a>(blobs: impl Iterator<Item = &'a Vec<u8>>) -> Vec<B256> {
    blobs
        .filter_map(|blob| merkle::AccountProperties::decode(blob).ok())
        .map(|props| props.observable_bytecode_hash)
        .filter(|hash| !hash.is_zero())
        .collect()
}

// ---------------------------------------------------------------------------
// Pre-state account preimages
// ---------------------------------------------------------------------------

/// Inflates the balance of a pre-state account preimage.
///
/// The preimage binds to the merkle-authenticated 0x8003 value only through
/// blake2s(preimage), so a correct guest rejects at the hash equality before
/// the forged balance reaches execution.
pub struct PreimageBalanceForged;

impl WitnessOracle for PreimageBalanceForged {
    fn name(&self) -> &str {
        "preimage_balance_forged"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let (_, blob) = mutated.blocks.first_mut()?.account_preimages.first_mut()?;
        perturb_field(blob, BALANCE_OFFSET, 32);
        Some(mutated)
    }
}

/// Attaches a well-formed preimage for an account the witness never proves.
///
/// A preimage is accepted only alongside a proof of the account's 0x8003 leaf;
/// without one the guest has nothing to bind the blob to and must reject.
pub struct PreimageWithoutStorageProof;

impl WitnessOracle for PreimageWithoutStorageProof {
    fn name(&self) -> &str {
        "preimage_without_storage_proof"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let addr = Address::repeat_byte(0x42);
        let flat_key = account_flat_key(&addr);
        let already_proven = honest
            .blocks
            .iter()
            .any(|block| block.storage_proofs.iter().any(|(k, _)| k == &flat_key));
        if already_proven {
            return None;
        }
        let mut mutated = honest.clone();
        mutated
            .blocks
            .first_mut()?
            .account_preimages
            .push((addr, vec![0u8; merkle::AccountProperties::ENCODED_SIZE]));
        Some(mutated)
    }
}

/// Appends a second, garbage preimage for an account that already has one.
///
/// `build_verified_accounts` lets the first occurrence win and never reads a
/// later copy, so the duplicate must bind nothing: accepted with the honest
/// commitment. A rejection here would mean the guest hashes data it never uses.
pub struct PreimageDuplicateShadowed;

impl WitnessOracle for PreimageDuplicateShadowed {
    fn name(&self) -> &str {
        "preimage_duplicate_shadowed"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let (addr, _) = honest.blocks.first()?.account_preimages.first()?;
        let mut mutated = honest.clone();
        mutated
            .blocks
            .first_mut()?
            .account_preimages
            .push((*addr, vec![0xab; merkle::AccountProperties::ENCODED_SIZE]));
        Some(mutated)
    }
}

/// Attaches a garbage preimage to an account the witness proves NON-EXISTENT.
///
/// The verified-nonexistent branch of `build_verified_accounts` discards the
/// blob without hashing it, so the garbage must bind nothing: accepted with
/// the honest commitment. The candidate set is fixed protocol addresses, which
/// keeps the site deterministic.
pub struct PreimageOfProvenNonexistent;

impl WitnessOracle for PreimageOfProvenNonexistent {
    fn name(&self) -> &str {
        "preimage_of_proven_nonexistent"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let candidates = [
            // The EIP-2935 history contract, read by the AtlasV4 pre-block step.
            Address::from_slice(&[
                0x00, 0x00, 0xf9, 0x08, 0x27, 0xf1, 0xc5, 0x3a, 0x10, 0xcb, 0x7a, 0x02, 0x33, 0x5b,
                0x17, 0x53, 0x20, 0x00, 0x29, 0x35,
            ]),
            Address::ZERO,
            Address::repeat_byte(0xde),
        ];
        let pre_imaged = pre_imaged_addresses(honest);
        let addr = candidates.iter().find(|addr| {
            !pre_imaged.contains(addr) && has_nonexistence_proof(honest, &account_flat_key(addr))
        })?;
        let mut mutated = honest.clone();
        mutated
            .blocks
            .first_mut()?
            .account_preimages
            .push((*addr, vec![0xab; merkle::AccountProperties::ENCODED_SIZE]));
        Some(mutated)
    }
}

// ---------------------------------------------------------------------------
// After-state account preimages
// ---------------------------------------------------------------------------

/// Site iterator: after-preimages of accounts execution wrote (non-zeroed
/// blobs, so the nonce/balance pins rather than the destroyed-account pin
/// decide). Returns indices into `account_preimages_after`.
fn written_after_preimage_indices(honest: &BatchInput) -> Vec<usize> {
    honest
        .batch_meta
        .account_preimages_after
        .iter()
        .enumerate()
        .filter(|(_, (_, blob))| !is_zeroed_blob(blob))
        .map(|(i, _)| i)
        .collect()
}

/// Inflates the balance of an after-state preimage.
///
/// For an account execution wrote, the guest pins the after-preimage's balance
/// to REVM's output, so a correct guest rejects at the balance equality. The
/// tree entry still carries the honest value, so this also records whether the
/// pin fires before the write-set comparison.
pub struct AfterPreimageBalanceForged;

impl WitnessOracle for AfterPreimageBalanceForged {
    fn name(&self) -> &str {
        "after_preimage_balance_forged"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let index = *written_after_preimage_indices(honest).first()?;
        let mut mutated = honest.clone();
        let (_, blob) = &mut mutated.batch_meta.account_preimages_after[index];
        perturb_field(blob, BALANCE_OFFSET, 32);
        Some(mutated)
    }
}

/// Bumps the nonce of an after-state preimage.
///
/// Same pin as the balance: the guest asserts the preimage's nonce equals
/// REVM's output for every account execution wrote.
pub struct AfterPreimageNonceForged;

impl WitnessOracle for AfterPreimageNonceForged {
    fn name(&self) -> &str {
        "after_preimage_nonce_forged"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let index = *written_after_preimage_indices(honest).first()?;
        let mut mutated = honest.clone();
        let (_, blob) = &mut mutated.batch_meta.account_preimages_after[index];
        perturb_field(blob, NONCE_OFFSET, 8);
        Some(mutated)
    }
}

/// Inflates `artifacts_len` of an after-state preimage for an account with code.
///
/// `artifacts_len` is a field REVM never reads during execution; the question
/// is whether the commitment still binds it. The guest derives every code field
/// from the code itself and asserts equality, so a correct guest rejects at the
/// code-fields pin — acceptance with a moved commitment would mean an
/// operator-chosen field inside a committed leaf.
pub struct AfterPreimageArtifactsLenForged;

impl WitnessOracle for AfterPreimageArtifactsLenForged {
    fn name(&self) -> &str {
        "after_preimage_artifacts_len_forged"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let index = written_after_preimage_indices(honest)
            .into_iter()
            .find(|i| {
                merkle::AccountProperties::decode(&honest.batch_meta.account_preimages_after[*i].1)
                    .is_ok_and(|props| props.observable_bytecode_len > 0)
            })?;
        let mut mutated = honest.clone();
        let (_, blob) = &mut mutated.batch_meta.account_preimages_after[index];
        perturb_field(blob, ARTIFACTS_LEN_OFFSET, 4);
        Some(mutated)
    }
}

/// Retargets `observable_bytecode_hash` of an after-state preimage for an
/// account with code.
///
/// The observable hash is what execution reads code by, so it looks like the
/// one field that must stay consistent — but the guest derives it from the
/// code rather than trusting the blob, so a correct guest rejects at the
/// code-fields pin like for any other code field.
pub struct AfterPreimageObservableHashForged;

impl WitnessOracle for AfterPreimageObservableHashForged {
    fn name(&self) -> &str {
        "after_preimage_observable_hash_forged"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let index = written_after_preimage_indices(honest)
            .into_iter()
            .find(|i| {
                merkle::AccountProperties::decode(&honest.batch_meta.account_preimages_after[*i].1)
                    .is_ok_and(|props| props.observable_bytecode_len > 0)
            })?;
        let mut mutated = honest.clone();
        let (_, blob) = &mut mutated.batch_meta.account_preimages_after[index];
        perturb_field(blob, OBSERVABLE_HASH_OFFSET, 32);
        Some(mutated)
    }
}

/// Drops one after-state preimage without touching the tree update.
///
/// Either the dropped account's nonce or balance changed and the completeness
/// loop rejects, or the tree update still carries its write and the write-set
/// count rejects. The verdict records which of the two guards fires.
pub struct AfterPreimageDropped;

impl WitnessOracle for AfterPreimageDropped {
    fn name(&self) -> &str {
        "after_preimage_dropped"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        if honest.batch_meta.account_preimages_after.is_empty() {
            return None;
        }
        let mut mutated = honest.clone();
        mutated.batch_meta.account_preimages_after.remove(0);
        Some(mutated)
    }
}

/// Injects an after-state preimage for an account no transaction touched.
///
/// Outside an upgrade batch the only legal 0x8003 writes are accounts REVM
/// executed; the injection guard must reject this before the write-set
/// comparison, or an operator could mint properties onto a dormant account.
pub struct AfterPreimageInjectedUntouched;

impl WitnessOracle for AfterPreimageInjectedUntouched {
    fn name(&self) -> &str {
        "after_preimage_injected_untouched"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let addr = Address::repeat_byte(0x42);
        let already_present = honest
            .batch_meta
            .account_preimages_after
            .iter()
            .any(|(a, _)| a == &addr);
        if already_present {
            return None;
        }
        let mut mutated = honest.clone();
        mutated
            .batch_meta
            .account_preimages_after
            .push((addr, vec![0u8; merkle::AccountProperties::ENCODED_SIZE]));
        Some(mutated)
    }
}

/// Prepends a garbage after-preimage for an account the honest list carries.
///
/// The after-preimage map is built by collecting into a HashMap, so the last
/// copy of a duplicated address wins and the earlier one is never decoded. The
/// garbage copy must bind nothing: accepted with the honest commitment.
pub struct AfterPreimageDuplicateShadowed;

impl WitnessOracle for AfterPreimageDuplicateShadowed {
    fn name(&self) -> &str {
        "after_preimage_duplicate_shadowed"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let (addr, _) = honest.batch_meta.account_preimages_after.first()?;
        let mut mutated = honest.clone();
        mutated.batch_meta.account_preimages_after.insert(
            0,
            (*addr, vec![0xab; merkle::AccountProperties::ENCODED_SIZE]),
        );
        Some(mutated)
    }
}

// ---------------------------------------------------------------------------
// Bytecodes
// ---------------------------------------------------------------------------

/// Swaps the hash keys of the first two bytecode entries, keeping the codes.
///
/// The lie is well-formed apart from the hash binding itself: both entries are
/// real batch bytecodes, so only the keccak256(code) == key assertion can
/// reject it.
pub struct BytecodeHashKeySwapped;

impl WitnessOracle for BytecodeHashKeySwapped {
    fn name(&self) -> &str {
        "bytecode_hash_key_swapped"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        if honest.bytecodes.len() < 2 {
            return None;
        }
        let mut mutated = honest.clone();
        let first_key = mutated.bytecodes[0].0;
        mutated.bytecodes[0].0 = mutated.bytecodes[1].0;
        mutated.bytecodes[1].0 = first_key;
        Some(mutated)
    }
}

/// Drops the bytecode an executed contract's pre-state preimage references.
///
/// The account's properties blob names its code by observable hash; with the
/// code gone, REVM has nothing to execute and the run must fail — the verdict
/// records whether the ProvenDB miss or a later write-set guard fires.
pub struct BytecodeReferencedDropped;

impl WitnessOracle for BytecodeReferencedDropped {
    fn name(&self) -> &str {
        "bytecode_referenced_dropped"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let referenced: Vec<B256> = referenced_code_hashes(
            honest
                .blocks
                .iter()
                .flat_map(|block| block.account_preimages.iter().map(|(_, blob)| blob)),
        );
        let index = honest
            .bytecodes
            .iter()
            .position(|(hash, _)| referenced.contains(hash))?;
        let mut mutated = honest.clone();
        mutated.bytecodes.remove(index);
        Some(mutated)
    }
}

/// Appends a self-consistent bytecode entry no account references.
///
/// `load_bytecodes` verifies keccak256(code) == key for every entry, so the
/// entry is valid; nothing reads it, so it must bind nothing: accepted with
/// the honest commitment.
pub struct BytecodeAppendedUnused;

impl WitnessOracle for BytecodeAppendedUnused {
    fn name(&self) -> &str {
        "bytecode_appended_unused"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let code = vec![0xde, 0xad];
        let mut mutated = honest.clone();
        mutated.bytecodes.push((keccak256(&code), code));
        Some(mutated)
    }
}

/// Drops a bytecode no account blob references.
///
/// The witness carries every code found in the dump's preimage store, including
/// contracts the batch never executes; a code no pre- or after-image names can
/// never be fetched, so it must bind nothing: accepted with the honest
/// commitment.
pub struct BytecodeDroppedUnreferenced;

impl WitnessOracle for BytecodeDroppedUnreferenced {
    fn name(&self) -> &str {
        "bytecode_dropped_unreferenced"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut referenced = referenced_code_hashes(
            honest
                .blocks
                .iter()
                .flat_map(|block| block.account_preimages.iter().map(|(_, blob)| blob)),
        );
        referenced.extend(referenced_code_hashes(
            honest
                .batch_meta
                .account_preimages_after
                .iter()
                .map(|(_, blob)| blob),
        ));
        let index = honest
            .bytecodes
            .iter()
            .position(|(hash, _)| !referenced.contains(hash))?;
        let mut mutated = honest.clone();
        mutated.bytecodes.remove(index);
        Some(mutated)
    }
}

// ---------------------------------------------------------------------------
// Tree update
// ---------------------------------------------------------------------------

/// Forges the value of the first tree-update entry.
///
/// The write set is built from REVM's journal and the after-preimages, so a
/// witness value that disagrees must be rejected at the per-entry equality in
/// `verify_tree_update`.
pub struct TreeEntryValueForged;

impl WitnessOracle for TreeEntryValueForged {
    fn name(&self) -> &str {
        "tree_entry_value_forged"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let update = mutated.batch_meta.tree_update.as_mut()?;
        let (_, value) = update.entries.first_mut()?;
        let mut bytes = *value;
        bytes[31] ^= 0x01;
        *value = B256::from(bytes);
        Some(mutated)
    }
}

/// Retitles the first tree-update entry to a key the write set does not carry.
///
/// Set equality requires every entry key to be a computed write; a correct
/// guest rejects naming the unknown key.
pub struct TreeEntryKeyForged;

impl WitnessOracle for TreeEntryKeyForged {
    fn name(&self) -> &str {
        "tree_entry_key_forged"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let update = mutated.batch_meta.tree_update.as_mut()?;
        let entry = update.entries.first_mut()?;
        entry.0 = B256::repeat_byte(0x5c);
        Some(mutated)
    }
}

/// Inflates the tree update's `leaf_count_before` above the committed count.
///
/// `apply` trusts the field as the insert start index and the empty-subtree
/// boundary, so it is pinned to `meta.leaf_count_before`; a correct guest
/// rejects at that equality.
pub struct TreeLeafCountInflated;

impl WitnessOracle for TreeLeafCountInflated {
    fn name(&self) -> &str {
        "tree_leaf_count_inflated"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let update = mutated.batch_meta.tree_update.as_mut()?;
        update.leaf_count_before = update.leaf_count_before.checked_add(1)?;
        Some(mutated)
    }
}

/// Forges the value of a pre-state leaf inside `sorted_leaves`.
///
/// `apply` recomputes the old root from these leaves and asserts it equals the
/// L1-pinned `tree_root_before`; a forged leaf moves that recomputation, so a
/// correct guest rejects at the old-root equality.
pub struct SortedLeafValueForged;

impl WitnessOracle for SortedLeafValueForged {
    fn name(&self) -> &str {
        "sorted_leaf_value_forged"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let update = mutated.batch_meta.tree_update.as_mut()?;
        let middle = update.sorted_leaves.len() / 2;
        let leaf = &mut update.sorted_leaves.get_mut(middle)?.1;
        let mut bytes = leaf.value;
        bytes[31] ^= 0x01;
        leaf.value = B256::from(bytes);
        Some(mutated)
    }
}

// ---------------------------------------------------------------------------
// The create+destroy completeness seam
// ---------------------------------------------------------------------------
//
// `build_revm_write_map`'s completeness loop requires an after-preimage only
// for accounts whose nonce or balance ENDPOINTS differ. A contract created and
// destroyed inside one batch (EIP-6780) leaves nonce 0 and balance 0 at both
// ends, so its 0x8003 write — the zeroed leaf native records — is invisible to
// that loop, and the write-set equality cannot see it either as long as the
// after-preimage and the tree entry move together. The two oracles below probe
// the seam from both directions, and re-forge the post-state interop proofs so
// no unrelated guard can reject first: the witness carries the full pre-state
// tree (`sorted_leaves`) and the full write set, which fixes the whole
// post-state tree up to the probed difference.

/// The post-state leaf set the guest's `BatchTreeUpdate::apply` derives,
/// recomputed host-side. Mirrors `apply_writes` with checked lookups: returns
/// None where the guest would reject.
fn apply_write_ops(
    sorted_leaves: &[(u64, TreeLeaf)],
    leaf_count_before: u64,
    operations: &[WriteOp],
    entries: &[(B256, B256)],
) -> Option<(Vec<(u64, TreeLeaf)>, u64)> {
    if operations.len() != entries.len() {
        return None;
    }
    let mut leaves: Vec<(u64, TreeLeaf)> = sorted_leaves.to_vec();
    let mut next_tree_index = leaf_count_before;
    let mut pos_of: HashMap<u64, usize> = leaves
        .iter()
        .enumerate()
        .map(|(pos, (idx, _))| (*idx, pos))
        .collect();

    for (op, (key, new_value)) in operations.iter().zip(entries) {
        match op {
            WriteOp::Update { index } => {
                let pos = *pos_of.get(index)?;
                if leaves[pos].1.key != *key {
                    return None;
                }
                leaves[pos].1.value = *new_value;
            }
            WriteOp::Insert { prev_index } => {
                let this_index = next_tree_index;
                next_tree_index += 1;
                let prev_pos = *pos_of.get(prev_index)?;
                let old_next = leaves[prev_pos].1.next_index;
                let next_pos = *pos_of.get(&old_next)?;
                if !(leaves[prev_pos].1.key < *key && *key < leaves[next_pos].1.key) {
                    return None;
                }
                leaves.push((
                    this_index,
                    TreeLeaf {
                        key: *key,
                        value: *new_value,
                        next_index: old_next,
                    },
                ));
                pos_of.insert(this_index, leaves.len() - 1);
                leaves[prev_pos].1.next_index = this_index;
            }
        }
    }
    leaves.sort_by_key(|(idx, _)| *idx);
    Some((leaves, next_tree_index))
}

/// One hash per tree level over a leaf set dense on `[0, leaf_count)`, padded
/// with empty subtrees — the same dense-tree construction the dump conversion
/// uses to build the honest proofs.
fn dense_levels(leaves: &[(u64, TreeLeaf)], leaf_count: u64) -> Option<Vec<Vec<B256>>> {
    if leaves.len() as u64 != leaf_count
        || leaves
            .iter()
            .enumerate()
            .any(|(pos, (idx, _))| *idx != pos as u64)
    {
        return None;
    }
    let mut levels = vec![
        leaves
            .iter()
            .map(|(_, leaf)| merkle::hash_leaf(&leaf.key, &leaf.value, leaf.next_index))
            .collect::<Vec<B256>>(),
    ];
    while levels.last()?.len() > 1 {
        let depth = levels.len() - 1;
        let current = levels.last()?;
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        let mut j = 0;
        while j < current.len() {
            let left = current[j];
            let right = current
                .get(j + 1)
                .copied()
                .unwrap_or(merkle::empty_subtree_hash(depth as u8));
            next.push(merkle::blake2s(
                &[left.as_slice(), right.as_slice()].concat(),
            ));
            j += 2;
        }
        levels.push(next);
    }
    Some(levels)
}

/// The root of a dense tree, padding the top level with empty subtrees up to
/// the full depth.
fn dense_root(levels: &[Vec<B256>]) -> Option<B256> {
    let mut node = *levels.last()?.first()?;
    for depth in (levels.len() - 1)..(merkle::TREE_DEPTH as usize) {
        node = merkle::blake2s(
            &[node.as_slice(), merkle::empty_subtree_hash(depth as u8).as_slice()].concat(),
        );
    }
    Some(node)
}

/// The 64-long sibling path of the leaf at `index` in a dense tree.
fn sibling_path(levels: &[Vec<B256>], index: u64) -> Vec<B256> {
    (0..merkle::TREE_DEPTH as usize)
        .map(|depth| {
            let pos = ((index >> depth) ^ 1) as usize;
            levels
                .get(depth)
                .and_then(|level| level.get(pos).copied())
                .unwrap_or(merkle::empty_subtree_hash(depth as u8))
        })
        .collect()
}

/// A proof of `key` against a dense tree: `Existing` when the leaf is present,
/// `NonExisting` bracketed by its linked-list neighbours otherwise. Returns
/// None when the leaf set's linked list is inconsistent around the key.
fn prove_key(
    leaves: &[(u64, TreeLeaf)],
    levels: &[Vec<B256>],
    key: &B256,
) -> Option<StorageProof> {
    let entry_for = |index: u64, leaf: &TreeLeaf| SlotProofEntry {
        index,
        value: leaf.value,
        next_index: leaf.next_index,
        siblings: sibling_path(levels, index),
    };
    if let Some((index, leaf)) = leaves.iter().find(|(_, leaf)| leaf.key == *key) {
        return Some(StorageProof::Existing(entry_for(*index, leaf)));
    }
    let (left_index, left_leaf) = leaves
        .iter()
        .filter(|(_, leaf)| leaf.key < *key)
        .max_by_key(|(_, leaf)| leaf.key)?;
    let (right_index, right_leaf) = leaves
        .iter()
        .find(|(idx, _)| *idx == left_leaf.next_index)?;
    if right_leaf.key <= *key {
        return None;
    }
    Some(StorageProof::NonExisting {
        left_neighbor: NeighborProofEntry {
            entry: entry_for(*left_index, left_leaf),
            leaf_key: left_leaf.key,
        },
        right_neighbor: NeighborProofEntry {
            entry: entry_for(*right_index, right_leaf),
            leaf_key: right_leaf.key,
        },
    })
}

/// The value stored at `key`, or zero when the leaf is absent.
fn value_at(leaves: &[(u64, TreeLeaf)], key: &B256) -> B256 {
    leaves
        .iter()
        .find(|(_, leaf)| leaf.key == *key)
        .map(|(_, leaf)| leaf.value)
        .unwrap_or(B256::ZERO)
}

/// SystemContext (`0x800b`), MessageRoot (`0x10005`) and the interop
/// commitment tree (`0x10012`): the contracts whose slots the guest reads at
/// the batch boundaries.
const SYSTEM_CONTEXT_ADDRESS: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80, 0x0b,
];
const MESSAGE_ROOT_ADDRESS: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00, 0x05,
];
const INTEROP_COMMITMENT_TREE_ADDRESS: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00, 0x12,
];

/// Storage slot of `_nodes[height][0]` for a solidity `FullMerkle` engine,
/// mirroring the guest's `executor::interop::nodes_root_slot`.
fn nodes_root_slot(nodes_base_slot: u8, height: &B256) -> B256 {
    let base = U256::from_be_bytes(keccak256(B256::with_last_byte(nodes_base_slot).as_slice()).0);
    let slot = base.wrapping_add(U256::from_be_bytes(height.0));
    keccak256(&slot.to_be_bytes::<32>())
}

/// Rebuild the post-state-anchored interop proofs against the forged tree the
/// guest will derive. The begin-boundary commitment-tree proofs authenticate
/// against the pre-state root, which the mutation does not move, so they stay
/// honest. Returns None when the forged tree cannot prove a slot.
fn reforge_interop_proofs(
    mutated: &mut BatchInput,
    leaves: &[(u64, TreeLeaf)],
    levels: &[Vec<B256>],
) -> Option<()> {
    let proofs = mutated.batch_meta.interop_proofs.as_mut()?;

    let sl_key = merkle::derive_flat_storage_key(&SYSTEM_CONTEXT_ADDRESS, &B256::ZERO);
    proofs.sl_chain_id = prove_key(leaves, levels, &sl_key)?;

    let multichain_height_key =
        merkle::derive_flat_storage_key(&MESSAGE_ROOT_ADDRESS, &B256::with_last_byte(0x04));
    proofs.multichain_height = prove_key(leaves, levels, &multichain_height_key)?;
    let multichain_height = value_at(leaves, &multichain_height_key);
    let multichain_root_key = merkle::derive_flat_storage_key(
        &MESSAGE_ROOT_ADDRESS,
        &nodes_root_slot(0x06, &multichain_height),
    );
    proofs.multichain_root = prove_key(leaves, levels, &multichain_root_key)?;

    if let Some(commitment_tree) = proofs.commitment_tree.as_mut() {
        let height_key =
            merkle::derive_flat_storage_key(&INTEROP_COMMITMENT_TREE_ADDRESS, &B256::ZERO);
        commitment_tree.height_end = prove_key(leaves, levels, &height_key)?;
        let height = value_at(leaves, &height_key);
        let root_key = merkle::derive_flat_storage_key(
            &INTEROP_COMMITMENT_TREE_ADDRESS,
            &nodes_root_slot(0x02, &height),
        );
        commitment_tree.root_end = prove_key(leaves, levels, &root_key)?;
    }
    Some(())
}

/// Cross-check a mutated batch's tree update against the guest's own `apply`
/// and return the forged post-state tree (leaves and dense levels) the guest
/// will derive. Returns None when the mutation does not survive `apply` or
/// does not move the post-state root — in both cases there is nothing to judge.
fn forged_post_state(
    honest: &BatchInput,
    mutated: &BatchInput,
) -> Option<(Vec<(u64, TreeLeaf)>, Vec<Vec<B256>>)> {
    let update = mutated.batch_meta.tree_update.as_ref()?;
    let (leaves, leaf_count) = apply_write_ops(
        &update.sorted_leaves,
        update.leaf_count_before,
        &update.operations,
        &update.entries,
    )?;
    let levels = dense_levels(&leaves, leaf_count)?;
    let forged_root = dense_root(&levels)?;
    let applied = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        update.apply(&honest.batch_meta.tree_root_before)
    }))
    .ok()?;
    if applied != (forged_root, leaf_count) {
        return None;
    }
    let honest_update = honest.batch_meta.tree_update.as_ref()?;
    let honest_root = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        honest_update.apply(&honest.batch_meta.tree_root_before)
    }))
    .ok()?
    .0;
    if honest_root == forged_root {
        return None;
    }
    Some((leaves, levels))
}

/// Drops the zeroed after-state leaf of a contract created and destroyed
/// inside the batch, together with its tree-update entry and operation.
///
/// The completeness loop sees only nonce and balance endpoints — (0, 0) at
/// both ends for such an account — so it never asks for the write, and the
/// write-set equality stays consistent because both sides lose the entry. A
/// guest that accepts commits a post-state root that omits the zeroing native
/// recorded: two witnesses for one statement.
pub struct CreateDestroyLeafDropped;

impl WitnessOracle for CreateDestroyLeafDropped {
    fn name(&self) -> &str {
        "create_destroy_leaf_dropped"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let update = honest.batch_meta.tree_update.as_ref()?;
        let pre_imaged = pre_imaged_addresses(honest);
        for (addr, blob) in &honest.batch_meta.account_preimages_after {
            if !is_zeroed_blob(blob) || pre_imaged.contains(addr) {
                continue;
            }
            let flat_key = account_flat_key(addr);
            let Some(position) = update
                .entries
                .iter()
                .position(|(key, value)| {
                    *key == flat_key && *value == merkle::AccountProperties::hash(blob)
                })
            else {
                continue;
            };
            if !matches!(update.operations.get(position), Some(WriteOp::Insert { .. })) {
                continue;
            }
            let mut mutated = honest.clone();
            {
                let mutated_update = mutated.batch_meta.tree_update.as_mut()?;
                mutated_update.entries.remove(position);
                mutated_update.operations.remove(position);
            }
            mutated
                .batch_meta
                .account_preimages_after
                .retain(|(a, _)| a != addr);
            let Some((leaves, levels)) = forged_post_state(honest, &mutated) else {
                continue;
            };
            if reforge_interop_proofs(&mut mutated, &leaves, &levels).is_none() {
                continue;
            }
            return Some(mutated);
        }
        None
    }
}

/// Candidate sites for the create+destroy seam: the CREATE targets of every
/// pre-imaged account that were created and destroyed inside the batch, with
/// the flat key of the target's 0x8003 leaf and its insert predecessor.
///
/// The destroyed account's address never appears in the witness, so the
/// targets are reconstructed from each creator's authenticated pre-state
/// nonce. A target that was created and survived carries an after-preimage
/// and a tree entry; a target of a reverted create reads as `Unwritten` and
/// the injection guard rejects it — only an actually-destroyed account is a
/// site. Each entry is `(child, flat_key, prev_index)`, where `prev_index` is
/// the insert's predecessor in the linked list as it stands after the honest
/// write set.
fn create_destroy_sites(honest: &BatchInput) -> Option<Vec<(Address, B256, u64)>> {
    let update = honest.batch_meta.tree_update.as_ref()?;
    let pre_imaged: Vec<(Address, u64)> = honest
        .blocks
        .iter()
        .flat_map(|block| block.account_preimages.iter())
        .filter_map(|(addr, blob)| {
            merkle::AccountProperties::decode(blob)
                .ok()
                .map(|props| (*addr, props.nonce))
        })
        .collect();
    let mut sites = Vec::new();
    for (creator, nonce) in &pre_imaged {
        for k in *nonce..nonce.saturating_add(4) {
            let Some(child) = create_address(creator, k) else {
                continue;
            };
            let flat_key = account_flat_key(&child);
            if !has_nonexistence_proof(honest, &flat_key) {
                continue;
            }
            if update.entries.iter().any(|(key, _)| key == &flat_key) {
                continue;
            }
            if pre_imaged.iter().any(|(addr, _)| addr == &child)
                || honest
                    .batch_meta
                    .account_preimages_after
                    .iter()
                    .any(|(addr, _)| addr == &child)
            {
                continue;
            }
            let (honest_leaves, _) = apply_write_ops(
                &update.sorted_leaves,
                update.leaf_count_before,
                &update.operations,
                &update.entries,
            )?;
            let prev_index = honest_leaves
                .iter()
                .filter(|(_, leaf)| leaf.key < flat_key)
                .max_by_key(|(_, leaf)| leaf.key)?
                .0;
            sites.push((child, flat_key, prev_index));
        }
    }
    Some(sites)
}

/// The tree-update insert of `flat_key` carrying the hash of `blob`, appended
/// after the honest write set.
fn push_insert(mutated: &mut BatchInput, flat_key: B256, prev_index: u64, blob: &[u8]) -> Option<()> {
    let update = mutated.batch_meta.tree_update.as_mut()?;
    update.operations.push(WriteOp::Insert { prev_index });
    update
        .entries
        .push((flat_key, merkle::AccountProperties::hash(blob)));
    Some(())
}

/// Injects the zeroed after-state leaf of a contract created and destroyed
/// inside the batch when the honest witness carries none.
///
/// The injection guard in `build_revm_write_map` admits any after-preimage
/// whose account is not `Unwritten`, and a destroyed account is recognised
/// from the journal's destruction set — so the zeroed-leaf content pin is the
/// only check, and the zeroed blob passes it. A guest that accepts commits a
/// post-state root that adds a leaf native's tree update does not carry: two
/// witnesses for one statement.
pub struct CreateDestroyLeafInjected;

impl WitnessOracle for CreateDestroyLeafInjected {
    fn name(&self) -> &str {
        "create_destroy_leaf_injected"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        for (child, flat_key, prev_index) in create_destroy_sites(honest)? {
            let mut mutated = honest.clone();
            mutated
                .batch_meta
                .account_preimages_after
                .push((child, vec![0u8; merkle::AccountProperties::ENCODED_SIZE]));
            push_insert(&mut mutated, flat_key, prev_index, &[0u8; 124])?;
            let Some((leaves, levels)) = forged_post_state(honest, &mutated) else {
                continue;
            };
            if reforge_interop_proofs(&mut mutated, &leaves, &levels).is_none() {
                continue;
            }
            return Some(mutated);
        }
        None
    }
}

/// Injects a NON-zeroed after-state leaf for a created-and-destroyed account,
/// with its tree-update entry.
///
/// The companion of `create_destroy_leaf_injected`, pinning the seam's
/// boundary from the content side: presence of the zeroed leaf is unpinned,
/// but a destroyed account's CONTENT has exactly one legal encoding, so a
/// correct guest rejects at the destroyed-account pin before the write set is
/// compared.
pub struct CreateDestroyLeafContentForged;

impl WitnessOracle for CreateDestroyLeafContentForged {
    fn name(&self) -> &str {
        "create_destroy_leaf_content_forged"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let (child, flat_key, prev_index) = create_destroy_sites(honest)?.into_iter().next()?;
        let mut blob = vec![0u8; merkle::AccountProperties::ENCODED_SIZE];
        perturb_field(&mut blob, BALANCE_OFFSET, 32);
        let mut mutated = honest.clone();
        mutated
            .batch_meta
            .account_preimages_after
            .push((child, blob.clone()));
        push_insert(&mut mutated, flat_key, prev_index, &blob)?;
        Some(mutated)
    }
}

/// Injects the zeroed after-state preimage of a created-and-destroyed account
/// WITHOUT its tree-update entry.
///
/// The write map then carries one 0x8003 write the entries do not, so a
/// correct guest rejects at the write-set count: the tree-update equality is
/// what forces an after-preimage and its tree entry to move together, and
/// this oracle records that the guard stands.
pub struct CreateDestroyPreimageWithoutEntry;

impl WitnessOracle for CreateDestroyPreimageWithoutEntry {
    fn name(&self) -> &str {
        "create_destroy_preimage_without_entry"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let (child, _, _) = create_destroy_sites(honest)?.into_iter().next()?;
        let mut mutated = honest.clone();
        mutated
            .batch_meta
            .account_preimages_after
            .push((child, vec![0u8; merkle::AccountProperties::ENCODED_SIZE]));
        Some(mutated)
    }
}

/// The address `CREATE` assigns: keccak256(rlp([creator, nonce]))[12..].
/// Handles single-byte nonces and nonce 0 (empty RLP string); larger nonces
/// have no site in these scenarios and return None.
fn create_address(creator: &Address, nonce: u64) -> Option<Address> {
    let nonce_rlp: Vec<u8> = match nonce {
        0 => vec![0x80],
        1..=0x7f => vec![nonce as u8],
        _ => return None,
    };
    let payload_len = 21 + nonce_rlp.len();
    let mut rlp = vec![0xc0 + payload_len as u8, 0x94];
    rlp.extend_from_slice(creator.as_slice());
    rlp.extend_from_slice(&nonce_rlp);
    Some(Address::from_slice(&keccak256(&rlp)[12..]))
}

// ---------------------------------------------------------------------------
// Round 2: the create-without-destroy boundary of the completeness loop
// ---------------------------------------------------------------------------

/// Drops the after-state leaf of a contract created in the batch that
/// SURVIVED it, together with its tree-update entry and operation.
///
/// The create+destroy seam (`create_destroy_leaf_injected`) exists because a
/// destroyed account reads (0, 0) at both ends. A surviving creation reads
/// nonce 0 -> 1 instead, so the completeness loop must demand the
/// after-preimage: this oracle records that the (0,0)-endpoint invisibility
/// does not extend to creations that survive.
pub struct CreateOnlyLeafDropped;

impl WitnessOracle for CreateOnlyLeafDropped {
    fn name(&self) -> &str {
        "create_only_leaf_dropped"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let update = honest.batch_meta.tree_update.as_ref()?;
        let pre_imaged = pre_imaged_addresses(honest);
        for (addr, blob) in &honest.batch_meta.account_preimages_after {
            // A created-and-survived account: absent from the pre-state
            // preimages (so its pre-state reads (0, 0)) and carrying a real
            // nonce in its after-image.
            if pre_imaged.contains(addr) || is_zeroed_blob(blob) {
                continue;
            }
            let Ok(props) = merkle::AccountProperties::decode(blob) else {
                continue;
            };
            if props.nonce == 0 {
                continue;
            }
            let flat_key = account_flat_key(addr);
            let Some(position) = update.entries.iter().position(|(key, _)| *key == flat_key)
            else {
                continue;
            };
            let mut mutated = honest.clone();
            {
                let mutated_update = mutated.batch_meta.tree_update.as_mut()?;
                mutated_update.entries.remove(position);
                mutated_update.operations.remove(position);
            }
            mutated
                .batch_meta
                .account_preimages_after
                .retain(|(a, _)| a != addr);
            return Some(mutated);
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Round 2: touched-but-props-unchanged accounts
// ---------------------------------------------------------------------------
//
// A contract whose storage moved but whose nonce, balance and code did not
// (the common case) is absent from the honest after-image list: the
// completeness loop only requires accounts whose nonce/balance changed, and
// nothing else records the touch. The two oracles below ask what the guest
// does with an UNSOLICITED after-image for such an account: the injection
// guard admits it (the account is `Written`), so the whole weight falls on
// the post-state pins and the write-set equality.

/// Site iterator: accounts with a code-carrying pre-state preimage that are
/// absent from the honest after-image list, with the index of their existing
/// 0x8003 leaf in `sorted_leaves`. Only accounts execution wrote are offered:
/// an untouched pre-imaged account is the injection guard's own site, already
/// covered by `after_preimage_injected_untouched`.
fn touched_unchanged_code_accounts(honest: &BatchInput) -> Vec<(Address, Vec<u8>, u64)> {
    let Some(update) = honest.batch_meta.tree_update.as_ref() else {
        return Vec::new();
    };
    honest
        .blocks
        .iter()
        .flat_map(|block| block.account_preimages.iter())
        .filter(|(addr, blob)| {
            let already_after = honest
                .batch_meta
                .account_preimages_after
                .iter()
                .any(|(a, _)| a == addr);
            let carries_code = merkle::AccountProperties::decode(blob)
                .is_ok_and(|props| props.observable_bytecode_len > 0);
            !already_after && carries_code
        })
        .filter_map(|(addr, blob)| {
            let flat_key = account_flat_key(addr);
            let index = update
                .sorted_leaves
                .iter()
                .find(|(_, leaf)| leaf.key == flat_key)
                .map(|(index, _)| *index)?;
            Some((*addr, blob.clone(), index))
        })
        .collect()
}

/// Injects a ZEROED after-image (the destroyed-account encoding) for an
/// account that executed and survived with its code intact, plus the matching
/// tree-update entry.
///
/// The injection guard admits the site (the account is `Written`), so the
/// post-state pin is the only defence: the account has exactly one legal
/// leaf, derived from the code REVM left, and the zeroed blob must be
/// rejected at the code-fields pin. Acceptance with a moved commitment would
/// mean an operator can zero a live contract's leaf.
pub struct TouchedAccountAfterImageZeroed;

impl WitnessOracle for TouchedAccountAfterImageZeroed {
    fn name(&self) -> &str {
        "touched_account_after_image_zeroed"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let (addr, _, index) = touched_unchanged_code_accounts(honest).into_iter().next()?;
        let blob = vec![0u8; merkle::AccountProperties::ENCODED_SIZE];
        let mut mutated = honest.clone();
        mutated
            .batch_meta
            .account_preimages_after
            .push((addr, blob.clone()));
        let update = mutated.batch_meta.tree_update.as_mut()?;
        update.operations.push(WriteOp::Update { index });
        update
            .entries
            .push((account_flat_key(&addr), merkle::AccountProperties::hash(&blob)));
        Some(mutated)
    }
}

/// Injects a TRUTHFUL but redundant after-image for an account that executed
/// without its properties changing: the blob is the account's own
/// merkle-authenticated pre-state, and the tree entry rewrites the leaf to
/// the value it already holds.
///
/// The post-state pins all pass (the blob is the honest content), and the
/// write is value-identity, so the root cannot move: accepted with the honest
/// commitment. The oracle pins the boundary of the injection guard — a
/// `Written` account's after-image is accepted only when it commits nothing
/// new.
pub struct TouchedAccountAfterImageRedundant;

impl WitnessOracle for TouchedAccountAfterImageRedundant {
    fn name(&self) -> &str {
        "touched_account_after_image_redundant"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let (addr, blob, index) = touched_unchanged_code_accounts(honest).into_iter().next()?;
        let mut mutated = honest.clone();
        mutated
            .batch_meta
            .account_preimages_after
            .push((addr, blob.clone()));
        let update = mutated.batch_meta.tree_update.as_mut()?;
        update.operations.push(WriteOp::Update { index });
        update
            .entries
            .push((account_flat_key(&addr), merkle::AccountProperties::hash(&blob)));
        Some(mutated)
    }
}

/// Appends a garbage after-preimage for an account the honest list already
/// carries, AFTER the honest copy.
///
/// `after_preimage_duplicate_shadowed` places the garbage first and binds
/// nothing, establishing that the map keeps one copy; this oracle places it
/// last to learn WHICH copy the guest pins. A rejection at the balance pin
/// means the last copy is the one verified (HashMap collect, last wins);
/// acceptance would mean the honest copy shadows the lie.
pub struct AfterPreimageDuplicateAppended;

impl WitnessOracle for AfterPreimageDuplicateAppended {
    fn name(&self) -> &str {
        "after_preimage_duplicate_appended"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let index = *written_after_preimage_indices(honest).first()?;
        let (addr, blob) = honest.batch_meta.account_preimages_after[index].clone();
        let mut garbage = blob;
        perturb_field(&mut garbage, BALANCE_OFFSET, 32);
        let mut mutated = honest.clone();
        mutated
            .batch_meta
            .account_preimages_after
            .push((addr, garbage));
        Some(mutated)
    }
}

// ---------------------------------------------------------------------------
// Round 2: bytecodes
// ---------------------------------------------------------------------------

/// Appends an exact duplicate of the first bytecode entry.
///
/// `load_bytecodes` keys the map by keccak256(code), so a verbatim duplicate
/// re-inserts the same value under the same key: it must bind nothing.
pub struct BytecodeDuplicateShadowed;

impl WitnessOracle for BytecodeDuplicateShadowed {
    fn name(&self) -> &str {
        "bytecode_duplicate_shadowed"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let entry = honest.bytecodes.first()?.clone();
        let mut mutated = honest.clone();
        mutated.bytecodes.push(entry);
        Some(mutated)
    }
}

/// Drops a bytecode that only a created contract's after-image names.
///
/// A contract created in the batch has no pre-state preimage, so its runtime
/// code is referenced from the after-side alone; nobody needs to CALL it, so
/// execution itself may never fetch the code. The pin that remains is
/// `expected_code_fields`, which resolves the code REVM left through the
/// verified bytecode map: with the entry gone the guest must fail there, not
/// silently write a leaf whose code fields it could not derive.
pub struct BytecodeCreatedCodeDropped;

impl WitnessOracle for BytecodeCreatedCodeDropped {
    fn name(&self) -> &str {
        "bytecode_created_code_dropped"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let pre_referenced = referenced_code_hashes(
            honest
                .blocks
                .iter()
                .flat_map(|block| block.account_preimages.iter().map(|(_, blob)| blob)),
        );
        let after_only: Vec<B256> = referenced_code_hashes(
            honest
                .batch_meta
                .account_preimages_after
                .iter()
                .map(|(_, blob)| blob),
        )
        .into_iter()
        .filter(|hash| !pre_referenced.contains(hash))
        .collect();
        let index = honest
            .bytecodes
            .iter()
            .position(|(hash, _)| after_only.contains(hash))?;
        let mut mutated = honest.clone();
        mutated.bytecodes.remove(index);
        Some(mutated)
    }
}

// ---------------------------------------------------------------------------
// Round 2: tree-update order and multiplicity
// ---------------------------------------------------------------------------
//
// `verify_tree_update` compares the witness entries against the computed
// write map as a SET: a length check plus a key-by-key pass. `apply`, in
// contrast, is order-sensitive: every `Insert` takes the next dense tree
// index in the order the operations are listed, and the leaf's index is part
// of what the root commits (the leaf hash carries the linked-list pointers
// the insert rewrote). Nothing pins the order of the entries to the order
// native applied them, so the oracles below permute the witness and ask
// whether the commitment notices.

/// The positions of every `Insert`/`Update` operation in the tree update.
fn op_positions(update: &merkle::BatchTreeUpdate, inserts: bool) -> Vec<usize> {
    update
        .operations
        .iter()
        .enumerate()
        .filter(|(_, op)| matches!(op, WriteOp::Insert { .. }) == inserts)
        .map(|(i, _)| i)
        .collect()
}

/// Permutes the tree update by swapping two INSERT operations (with their
/// entries), keeping the write set itself untouched.
///
/// The set equality cannot see the permutation — same keys, same values —
/// but `apply` hands out the fresh tree indices in the permuted order, so the
/// two inserted leaves swap positions and the derived `tree_root_after` is
/// one native's canonical update never produces. The pair is chosen so the
/// linked-list bracket checks still pass (chained predecessors are skipped),
/// the mutated update is cross-checked against the guest's own `apply`, and
/// the post-state interop proofs are re-forged against the forged tree so no
/// unrelated guard can reject first. A guest that accepts commits a post-state
/// root that is not a function of the write set alone: two witnesses for one
/// statement.
pub struct TreeInsertOrderPermuted;

impl WitnessOracle for TreeInsertOrderPermuted {
    fn name(&self) -> &str {
        "tree_insert_order_permuted"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let update = honest.batch_meta.tree_update.as_ref()?;
        let inserts = op_positions(update, true);
        for (pos, &a) in inserts.iter().enumerate() {
            for &b in &inserts[pos + 1..] {
                let mut mutated = honest.clone();
                {
                    let update = mutated.batch_meta.tree_update.as_mut()?;
                    update.operations.swap(a, b);
                    update.entries.swap(a, b);
                }
                let Some((leaves, levels)) = forged_post_state(honest, &mutated) else {
                    continue;
                };
                if mutated.batch_meta.interop_proofs.is_some()
                    && reforge_interop_proofs(&mut mutated, &leaves, &levels).is_none()
                {
                    continue;
                }
                return Some(mutated);
            }
        }
        None
    }
}

/// Permutes the tree update by swapping two UPDATE operations (with their
/// entries).
///
/// Updates address pre-existing leaves by index, so they commute: the
/// permutation must be accepted with the honest commitment. The negative
/// control of the pair — it separates "the guest pins the write SET" from
/// "the guest pins the write ORDER", and isolates the insert case as the one
/// where order is commitment-bearing.
pub struct TreeUpdateOrderPermuted;

impl WitnessOracle for TreeUpdateOrderPermuted {
    fn name(&self) -> &str {
        "tree_update_order_permuted"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let update = honest.batch_meta.tree_update.as_ref()?;
        let updates = op_positions(update, false);
        let (&a, &b) = updates.first().zip(updates.get(1))?;
        let mut mutated = honest.clone();
        let update = mutated.batch_meta.tree_update.as_mut()?;
        update.operations.swap(a, b);
        update.entries.swap(a, b);
        Some(mutated)
    }
}

/// Duplicates the first tree-update entry verbatim, with its operation.
///
/// The count check is a set-cardinality comparison only if the entries' keys
/// are a genuine set: a duplicated key inflates the length while the forward
/// pass never examines the omitted key. The duplicate-key guard must reject
/// before the count is ever compared.
pub struct TreeEntryKeyDuplicated;

impl WitnessOracle for TreeEntryKeyDuplicated {
    fn name(&self) -> &str {
        "tree_entry_key_duplicated"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let update = mutated.batch_meta.tree_update.as_mut()?;
        let op = update.operations.first()?.clone();
        let entry = *update.entries.first()?;
        update.operations.push(op);
        update.entries.push(entry);
        Some(mutated)
    }
}

/// Duplicates the first tree-update entry's KEY under a forged value.
///
/// The shadowing shape of the duplicate-key attack: with the copy last, a
/// last-wins reader would take the forged value. The duplicate-key guard must
/// reject on the key alone, before any value is compared.
pub struct TreeEntryKeyDuplicatedValueForged;

impl WitnessOracle for TreeEntryKeyDuplicatedValueForged {
    fn name(&self) -> &str {
        "tree_entry_key_duplicated_value_forged"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let update = mutated.batch_meta.tree_update.as_mut()?;
        let op = update.operations.first()?.clone();
        let (key, value) = *update.entries.first()?;
        let mut forged = value;
        forged.0[31] ^= 0x01;
        update.operations.push(op);
        update.entries.push((key, forged));
        Some(mutated)
    }
}

/// Drops the last tree-update operation, leaving the entries intact.
///
/// `apply` zips operations with entries and stops at the shorter vector, so a
/// truncated operations vector would silently drop the trailing write. The
/// length equality must reject before the zip.
pub struct TreeOperationsTruncated;

impl WitnessOracle for TreeOperationsTruncated {
    fn name(&self) -> &str {
        "tree_operations_truncated"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let update = mutated.batch_meta.tree_update.as_mut()?;
        if update.operations.is_empty() {
            return None;
        }
        update.operations.pop();
        Some(mutated)
    }
}

/// Duplicates the first `sorted_leaves` entry, keeping the indices equal.
///
/// A repeated position puts two nodes at one slot of the old tree: the walk
/// would carry both upward and reconcile the pinned old root from one while
/// the other forges the new root. The strict-increase guard must reject
/// before the walk.
pub struct SortedLeafIndexDuplicated;

impl WitnessOracle for SortedLeafIndexDuplicated {
    fn name(&self) -> &str {
        "sorted_leaf_index_duplicated"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let update = mutated.batch_meta.tree_update.as_mut()?;
        let first = update.sorted_leaves.first()?.clone();
        update.sorted_leaves.insert(1, first);
        Some(mutated)
    }
}

/// Appends a `sorted_leaves` entry AT `leaf_count_before`, a position the old
/// tree holds empty.
///
/// The old side of the walk would reconcile the pinned root from the empty
/// subtree while the witness leaf enters the new root covered by no `entries`
/// pair — the write-set equality never sees it. The index bound must reject
/// before the walk.
pub struct SortedLeafIndexBeyondCount;

impl WitnessOracle for SortedLeafIndexBeyondCount {
    fn name(&self) -> &str {
        "sorted_leaf_index_beyond_count"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let update = mutated.batch_meta.tree_update.as_mut()?;
        let phantom = merkle::TreeLeaf {
            key: B256::repeat_byte(0x77),
            value: B256::ZERO,
            next_index: 1,
        };
        update
            .sorted_leaves
            .push((update.leaf_count_before, phantom));
        Some(mutated)
    }
}

/// Drops the whole tree update from a batch whose execution produced writes.
///
/// With no `tree_update` the guest would have to keep the pre-state root while
/// the write map is non-empty, so the `None` branch must reject — this is the
/// guard that forces every batch with writes to carry its authenticated
/// update at all.
pub struct TreeUpdateDropped;

impl WitnessOracle for TreeUpdateDropped {
    fn name(&self) -> &str {
        "tree_update_dropped"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        honest.batch_meta.tree_update.as_ref()?;
        let mut mutated = honest.clone();
        mutated.batch_meta.tree_update = None;
        Some(mutated)
    }
}

/// Appends one garbage intermediate hash to the tree update.
///
/// The walk in `apply` consumes `intermediate_hashes` in traversal order and
/// asserts none are left over: an unconsumed hash means the witness and the
/// walk disagree about the tree's shape, so a correct guest rejects at the
/// consumption check even though the hash itself is never read.
pub struct TreeIntermediateHashAppended;

impl WitnessOracle for TreeIntermediateHashAppended {
    fn name(&self) -> &str {
        "tree_intermediate_hash_appended"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let mut mutated = honest.clone();
        let update = mutated.batch_meta.tree_update.as_mut()?;
        update.intermediate_hashes.push(B256::repeat_byte(0x5e));
        Some(mutated)
    }
}

/// Retargets the first UPDATE operation at a different pre-existing leaf.
///
/// The op and its entry are left mutually inconsistent on purpose: the entry
/// still names the honest key, so the write-set equality passes, and only
/// `apply`'s update-key binding (`update key mismatch`) can reject it.
pub struct TreeUpdateOpIndexForged;

impl WitnessOracle for TreeUpdateOpIndexForged {
    fn name(&self) -> &str {
        "tree_update_op_index_forged"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let update = honest.batch_meta.tree_update.as_ref()?;
        let op_pos = *op_positions(update, false).first()?;
        let honest_key = update.entries[op_pos].0;
        let other_index = update
            .sorted_leaves
            .iter()
            .find(|(_, leaf)| leaf.key != honest_key)
            .map(|(index, _)| *index)?;
        let mut mutated = honest.clone();
        let update = mutated.batch_meta.tree_update.as_mut()?;
        update.operations[op_pos] = WriteOp::Update {
            index: other_index,
        };
        Some(mutated)
    }
}

// ---------------------------------------------------------------------------
// Round 3: the order axis beyond transpositions
// ---------------------------------------------------------------------------

/// Swaps one INSERT (op, entry) pair with one UPDATE (op, entry) pair.
///
/// The boundary oracle for `tree_insert_order_permuted`: updates address
/// pre-existing leaves by index and change only leaf VALUES, inserts change
/// only the linked-list pointers and draw the next dense index from a counter
/// that counts inserts alone — so sliding an update across an insert changes
/// neither the index assignment nor any leaf of the resulting tree. The
/// commitment must be the honest one; anything else would mean the guest's
/// post-state depends on an interleaving the write set does not determine.
pub struct TreeInsertUpdateInterleaved;

impl WitnessOracle for TreeInsertUpdateInterleaved {
    fn name(&self) -> &str {
        "tree_insert_update_interleaved"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let update = honest.batch_meta.tree_update.as_ref()?;
        let insert_pos = *op_positions(update, true).first()?;
        let update_pos = *op_positions(update, false).first()?;
        let mut mutated = honest.clone();
        let update = mutated.batch_meta.tree_update.as_mut()?;
        update.operations.swap(insert_pos, update_pos);
        update.entries.swap(insert_pos, update_pos);
        Some(mutated)
    }
}

/// Rotates three INSERT (op, entry) pairs: `(a, b, c)` becomes `(b, c, a)`.
///
/// `tree_insert_order_permuted` shows a transposition suffices; this oracle
/// shows the seam is not swap-specific — a cyclic permutation that moves
/// every insert off its honest dense index is accepted too. Candidates are
/// filtered through the guest's own `apply` (chained triples cannot survive a
/// rotation) and the derived root must actually move; the post-state interop
/// proofs are re-forged so no unrelated guard can reject first.
pub struct TreeInsertOrderRotated;

impl WitnessOracle for TreeInsertOrderRotated {
    fn name(&self) -> &str {
        "tree_insert_order_rotated"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let update = honest.batch_meta.tree_update.as_ref()?;
        let inserts = op_positions(update, true);
        for (i, &a) in inserts.iter().enumerate() {
            for (j, &b) in inserts[i + 1..].iter().enumerate() {
                for &c in &inserts[i + 1 + j + 1..] {
                    let mut mutated = honest.clone();
                    {
                        let update = mutated.batch_meta.tree_update.as_mut()?;
                        update.operations.swap(a, b);
                        update.operations.swap(a, c);
                        update.entries.swap(a, b);
                        update.entries.swap(a, c);
                    }
                    let Some((leaves, levels)) = forged_post_state(honest, &mutated) else {
                        continue;
                    };
                    if mutated.batch_meta.interop_proofs.is_some()
                        && reforge_interop_proofs(&mut mutated, &leaves, &levels).is_none()
                    {
                        continue;
                    }
                    return Some(mutated);
                }
            }
        }
        None
    }
}

/// Appends an UPDATE operation naming the same key as an existing INSERT
/// entry, with the insert's honest value.
///
/// Answers whether one batch may carry an insert and an update of the SAME
/// key: the entries then hold the key twice, so the duplicate-key guard must
/// reject before the write-set comparison — and before `apply` could ever
/// decide which of the two operations' value lands.
pub struct TreeInsertUpdateSameKey;

impl WitnessOracle for TreeInsertUpdateSameKey {
    fn name(&self) -> &str {
        "tree_insert_update_same_key"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let update = honest.batch_meta.tree_update.as_ref()?;
        let insert_pos = *op_positions(update, true).first()?;
        let (key, value) = update.entries[insert_pos];
        // Never applied (the duplicate-key guard fires first), but keep the
        // op well-formed: point it at a leaf the old tree actually holds.
        let (index, _) = update.sorted_leaves.first()?;
        let mut mutated = honest.clone();
        let update = mutated.batch_meta.tree_update.as_mut()?;
        update.operations.push(WriteOp::Update { index: *index });
        update.entries.push((key, value));
        Some(mutated)
    }
}

// ---------------------------------------------------------------------------
// Round 3: the injection guard's read-only arm, and the create-only content pin
// ---------------------------------------------------------------------------

/// Injects a TRUTHFUL after-image for an account the batch READ but never
/// wrote, plus the value-identity tree entry.
///
/// `touched_account_after_image_redundant` shows the guard admits a `Written`
/// account; this probes the other arm: an account REVM only read sits in the
/// cache with `AccountState::None`, classifies `Unwritten`, and must be
/// rejected at the injection guard even though the lie is perfectly
/// self-consistent (the blob is the merkle-authenticated pre-state and the
/// tree entry rewrites the leaf to the value it already holds). Acceptance
/// would mean warmth, not a write, unlocks account-property writes.
///
/// Site order: the designated read target of the `warmed_account` scenario
/// (a code-carrying contract that is EXTCODEHASH-read and never called), then
/// any pre-imaged codeless account absent from the after-list — the shape of
/// a BALANCE-read EOA. An account must carry an Existing proof so the
/// identity write can name its leaf index.
pub struct WarmedAccountAfterImageInjected;

impl WitnessOracle for WarmedAccountAfterImageInjected {
    fn name(&self) -> &str {
        "warmed_account_after_image_injected"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        honest.batch_meta.tree_update.as_ref()?;
        // The `warmed_account` scenario's read-only probe contract.
        let mut designated = [0u8; 20];
        designated[18] = 0xbe;
        designated[19] = 0xef;
        let designated = Address::from(designated);
        let mut candidates: Vec<(&Address, &Vec<u8>)> = Vec::new();
        for block in &honest.blocks {
            for (addr, blob) in &block.account_preimages {
                if *addr == designated {
                    candidates.insert(0, (addr, blob));
                    continue;
                }
                // Fallback: codeless accounts only, so a written-but-
                // props-unchanged contract (the `touched_account_*` site) is
                // never mistaken for the read-only one.
                let codeless = merkle::AccountProperties::decode(blob)
                    .is_ok_and(|props| props.observable_bytecode_len == 0);
                if codeless {
                    candidates.push((addr, blob));
                }
            }
        }
        for (addr, blob) in candidates {
            let after_listed = honest
                .batch_meta
                .account_preimages_after
                .iter()
                .any(|(a, _)| a == addr);
            if after_listed {
                continue;
            }
            let flat_key = account_flat_key(addr);
            let index = honest.blocks.iter().find_map(|block| {
                block.storage_proofs.iter().find_map(|(k, proof)| {
                    if k != &flat_key {
                        return None;
                    }
                    match proof {
                        StorageProof::Existing(entry) => Some(entry.index),
                        StorageProof::NonExisting { .. } => None,
                    }
                })
            });
            let Some(index) = index else { continue };
            let mut mutated = honest.clone();
            mutated
                .batch_meta
                .account_preimages_after
                .push((*addr, blob.clone()));
            let update = mutated.batch_meta.tree_update.as_mut()?;
            update.operations.push(WriteOp::Update { index });
            update
                .entries
                .push((flat_key, merkle::AccountProperties::hash(blob)));
            return Some(mutated);
        }
        None
    }
}

/// Replaces the after-image of an account CREATED in the batch that survived
/// it with the zeroed (destroyed-account) encoding, retargeting its tree
/// entry to the zeroed blob's hash.
///
/// The content side of `create_only_leaf_dropped`: a created-and-surviving
/// account has nonce 1, so the zeroed blob must be rejected at the nonce pin.
/// On a scenario whose account was destroyed and re-created in one batch
/// (same-tx CREATE2 recreate), the same verdict also pins the
/// classification: the recreated account has a live cache entry, so
/// `post_state` reads `Written` — never `Destroyed`, whose zeroed-content pin
/// would otherwise admit the lie.
pub struct CreateOnlyLeafContentZeroed;

impl WitnessOracle for CreateOnlyLeafContentZeroed {
    fn name(&self) -> &str {
        "create_only_leaf_content_zeroed"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        let update = honest.batch_meta.tree_update.as_ref()?;
        for (position, (addr, blob)) in
            honest.batch_meta.account_preimages_after.iter().enumerate()
        {
            // Created and survived: the 0x8003 leaf is proven non-existing
            // pre-batch (or never proven at all), and the after-image carries
            // the nonce a completed deployment sets. An account CREATED in the
            // batch can still appear in `account_preimages` — a later CALL
            // reads its (nonexistent) pre-state — so membership there says
            // nothing; only an Existing proof marks a pre-existing account.
            if is_zeroed_blob(blob) || has_existence_proof(honest, &account_flat_key(addr)) {
                continue;
            }
            let Ok(props) = merkle::AccountProperties::decode(blob) else {
                continue;
            };
            if props.nonce == 0 {
                continue;
            }
            let flat_key = account_flat_key(addr);
            let Some(entry_pos) = update.entries.iter().position(|(key, _)| *key == flat_key)
            else {
                continue;
            };
            let zeroed = vec![0u8; merkle::AccountProperties::ENCODED_SIZE];
            let mut mutated = honest.clone();
            mutated.batch_meta.account_preimages_after[position].1 = zeroed.clone();
            let update = mutated.batch_meta.tree_update.as_mut()?;
            update.entries[entry_pos].1 = merkle::AccountProperties::hash(&zeroed);
            return Some(mutated);
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Round 3: list-order leaks outside the tree
// ---------------------------------------------------------------------------
//
// Every consumer of these lists builds a keyed map (`build_verified_accounts`
// first-wins per address, `load_bytecodes` keyed by keccak256(code), the
// after-preimage HashMap collect), so a permutation of a list with distinct
// keys must bind nothing: accepted with the honest commitment. The tree
// update is the contrast — its order IS commitment-bearing (F-5) precisely
// because `apply` consumes it as a sequence, not a map.

/// Reverses the first block's `account_preimages` list.
///
/// With distinct addresses the first-wins map is unchanged, so the
/// commitment must not move; a moved commitment would mean the guest reads a
/// positional list where it must read a keyed map.
pub struct AccountPreimageListReordered;

impl WitnessOracle for AccountPreimageListReordered {
    fn name(&self) -> &str {
        "account_preimage_list_reordered"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        if honest.blocks.first()?.account_preimages.len() < 2 {
            return None;
        }
        let mut mutated = honest.clone();
        mutated.blocks.first_mut()?.account_preimages.reverse();
        Some(mutated)
    }
}

/// Reverses the batch's `bytecodes` list.
///
/// `load_bytecodes` re-hashes every entry into a keccak-keyed map, so the
/// order carries no information and the commitment must not move.
pub struct BytecodeListReordered;

impl WitnessOracle for BytecodeListReordered {
    fn name(&self) -> &str {
        "bytecode_list_reordered"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        if honest.bytecodes.len() < 2 {
            return None;
        }
        let mut mutated = honest.clone();
        mutated.bytecodes.reverse();
        Some(mutated)
    }
}

/// Reverses the batch's `account_preimages_after` list.
///
/// The list collects into a HashMap before any use (last-wins on duplicates,
/// which honest witnesses never carry), so a permutation must bind nothing.
pub struct AfterPreimageListReordered;

impl WitnessOracle for AfterPreimageListReordered {
    fn name(&self) -> &str {
        "after_preimage_list_reordered"
    }

    fn witness(&self, honest: &BatchInput) -> Option<BatchInput> {
        if honest.batch_meta.account_preimages_after.len() < 2 {
            return None;
        }
        let mut mutated = honest.clone();
        mutated.batch_meta.account_preimages_after.reverse();
        Some(mutated)
    }
}
