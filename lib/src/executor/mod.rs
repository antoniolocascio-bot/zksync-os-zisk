//! REVM-based block executor for ZKsync OS with merkle proof verification.
//!
//! Every storage and account read is verified against a merkle proof that
//! recovers the expected state root. Values come FROM the proofs, not from
//! a separate data path.

mod evm;
mod proven_db;
pub mod tx;
mod verify;

use std::collections::HashMap;

use revm::database::CacheDB;
use revm::primitives::B256;
use zksync_os_revm::ZkSpecId;

use crate::commitment;
use crate::types::*;

/// Execute a batch with full merkle proof verification and compute the
/// BatchPublicInput hash matching the server/L1 format.
///
/// Borrowing entry point (used by tests). Clones into an owned `BatchInput`
/// and dispatches to `execute_and_commit_owned`; the clone means this path
/// does NOT get the memory-reuse benefit (the caller keeps its own copy), but
/// it exercises the identical commitment logic. Memory-sensitive callers (the
/// guest `main`, `execute_and_commit_from_bincode`) use the owned path.
pub fn execute_and_commit(input: &BatchInput) -> (BatchOutput, B256) {
    execute_and_commit_owned(input.clone())
}

/// Owned entry point — the memory-reuse path. Takes the `BatchInput` by value
/// so the executor can drop the read-only witness siblings (and the raw
/// bytecode blob) after proof verification, before the block execution loop.
pub fn execute_and_commit_owned(input: BatchInput) -> (BatchOutput, B256) {
    let (output, commitment, _, _, _) = execute_and_commit_inner(input);
    (output, commitment)
}

/// Same as `execute_and_commit` but also returns the three commitment
/// sub-components for debugging.
pub fn execute_and_commit_debug(input: &BatchInput) -> (BatchOutput, B256, B256, B256, B256) {
    execute_and_commit_inner(input.clone())
}

fn execute_and_commit_inner(mut input: BatchInput) -> (BatchOutput, B256, B256, B256, B256) {
    assert_eq!(
        input.version,
        crate::types::BATCH_INPUT_VERSION,
        "unsupported BatchInput wire-format version {} (this guest understands {})",
        input.version,
        crate::types::BATCH_INPUT_VERSION,
    );
    let spec_id = match input.spec_id {
        0 => ZkSpecId::AtlasV1,
        1 => ZkSpecId::AtlasV2,
        2 => ZkSpecId::AtlasV3,
        _ => panic!("unknown spec_id: {}", input.spec_id),
    };

    validate_block_sequence(&input);

    // Execute all blocks with merkle-verified state. `build_proven_db` consumes
    // and frees the read-only witness siblings (`blocks[].storage_proofs`) and
    // the raw `bytecodes` blob, so they do not stay resident during the block
    // execution loop below — only the verified values survive in `ProvenDB`.
    let proven_db = proven_db::build_proven_db(&mut input);
    let mut cache_db = CacheDB::new(proven_db);
    let meta = &input.batch_meta;

    let mut block_results = Vec::with_capacity(input.blocks.len());
    let mut computed_block_hashes: HashMap<u64, B256> = HashMap::new();

    // Batch write set: union of the per-block net storage changes, each key
    // carrying the value of its last change (matches the native tree update,
    // which merges per-block diffs — including writes that net to zero
    // against the batch pre-state).
    let mut storage_writes: std::collections::HashMap<(revm::primitives::Address, revm::primitives::U256), revm::primitives::U256> =
        std::collections::HashMap::new();
    for block in &input.blocks {
        verify_intra_batch_hashes(block, &computed_block_hashes);

        let (result, net_changes) = evm::execute_block_proven(
            input.chain_id, spec_id, block, &mut cache_db,
        );
        computed_block_hashes.insert(block.number, result.computed_block_header_hash);
        block_results.push(result);
        storage_writes.extend(net_changes);
    }

    let output = BatchOutput { chain_id: input.chain_id, block_results };

    // Build complete write map (storage + 0x8003 account properties) and verify.
    let revm_writes =
        verify::build_revm_write_map(&storage_writes, &cache_db, &meta.account_preimages_after);
    let (tree_root_after, new_leaf_count) = verify::verify_tree_update(meta, &revm_writes);

    // Authenticate the historical block-hash ring against the L1-pinned
    // `block_hashes_blake_before` before it is folded into `state_before` and
    // carried forward (as the seed of the BLOCKHASH-visible history and of
    // `block_hashes_blake_after`). Without this, the ring rests only on the
    // untrusted witness.
    verify_block_hashes_blake_before(meta, input.blocks.first().unwrap());

    // State before.
    let state_before = commitment::state_commitment_hash(
        &meta.tree_root_before, meta.leaf_count_before,
        meta.block_number_before, &meta.block_hashes_blake_before,
        meta.last_block_timestamp_before,
    );

    // State after.
    let last_block = input.blocks.last().unwrap();
    let last_block_result = output.block_results.last().unwrap();
    let block_hashes_blake_after = commitment::block_hashes_blake(
        &meta.previous_block_hashes,
        &last_block_result.computed_block_header_hash,
    );
    let state_after = commitment::state_commitment_hash(
        &tree_root_after, new_leaf_count,
        last_block.number, &block_hashes_blake_after, last_block.timestamp,
    );

    // Batch output hash
    let mut l1_tx_hashes = Vec::new();
    let mut l2_to_l1_encoded_logs = Vec::new();
    let mut num_l1_txs: u64 = 0;
    let mut num_l2_txs: u64 = 0;
    let mut interop_roots_rolling_hash = B256::ZERO;

    for block in &input.blocks {
        for tx in &block.transactions {
            match &tx.auth {
                TxAuth::L1 { tx_hash, .. } => {
                    l1_tx_hashes.push(*tx_hash);
                    num_l1_txs += 1;
                }
                TxAuth::Upgrade { tx_hash, .. } => {
                    assert_eq!(
                        *tx_hash, meta.upgrade_tx_hash,
                        "upgrade tx hash {tx_hash} != batch_meta.upgrade_tx_hash {}",
                        meta.upgrade_tx_hash
                    );
                }
                TxAuth::L2 { .. } => {
                    num_l2_txs += 1;
                }
                TxAuth::System { tx_hash, encoded_2718 } => {
                    // System txs count as L2 txs in the batch commitment;
                    // interop-root imports additionally fold every imported
                    // root into the dependency-roots rolling hash. Both facts
                    // are derived from the hash-authenticated encoding.
                    num_l2_txs += 1;
                    tx::fold_system_tx_interop_roots(
                        tx_hash,
                        encoded_2718,
                        &mut interop_roots_rolling_hash,
                    );
                }
            }
        }
    }
    for br in &output.block_results {
        for log in &br.l2_to_l1_logs {
            l2_to_l1_encoded_logs.push(log.encode());
        }
    }

    let priority_ops_hash = commitment::priority_ops_rolling_hash(&l1_tx_hashes);
    let l2_logs_local_root = commitment::l2_to_l1_logs_root(&l2_to_l1_encoded_logs);
    // For protocol v30, multichain_root is zero in the l2_logs_root computation.
    // For v31+, use the actual multichain_root.
    let effective_multichain_root = if input.protocol_version_minor >= 31 {
        meta.multichain_root
    } else {
        B256::ZERO
    };
    let l2_logs_root_hash = commitment::keccak_two(&l2_logs_local_root, &effective_multichain_root);

    let da_commitment = match meta.da_commitment_scheme {
        0 | 1 => B256::ZERO,                                          // None / EmptyNoDA
        2 | 3 => commitment::da_commitment_calldata(&meta.pubdata),       // PubdataKeccak / BlobsAndPubdataKeccak
        4 => commitment::da_commitment_blobs(&meta.blob_versioned_hashes), // BlobsZKsyncOS
        _ => panic!("unsupported DA commitment scheme: {}", meta.da_commitment_scheme),
    };

    // Batch output hash — released-line layouts, gated on the protocol minor
    // exactly like the native `public_input_hash`: v31 packs the layer-2 tx
    // count and the settlement-layer chain id, v30 does not. Both are
    // chain_id-prefixed; the draft-0.4.0 chain_id-less layout returns at the
    // AtlasV4 bump.
    let batch_hash = commitment::batch_output_hash_native(
        input.protocol_version_minor >= 31,
        input.chain_id,
        input.blocks.first().unwrap().timestamp,
        last_block.timestamp,
        meta.da_commitment_scheme,
        &da_commitment,
        num_l1_txs,
        num_l2_txs,
        &priority_ops_hash,
        &l2_logs_root_hash,
        &meta.upgrade_tx_hash,
        &interop_roots_rolling_hash,
        meta.sl_chain_id,
    );

    // Top-level PI commits to the chain config (draft-0.4.0 `BatchPublicInput::hash`).
    let chain_config_hash = commitment::chain_config_hash(
        input.chain_id,
        meta.fri_proof_verification_enabled,
        meta.max_tx_gas_limit,
    );
    let commitment = commitment::batch_public_input_hash(
        &state_before,
        &state_after,
        &chain_config_hash,
        &batch_hash,
    );
    (output, commitment, state_before, state_after, batch_hash)
}

fn validate_block_sequence(input: &BatchInput) {
    let meta = &input.batch_meta;
    assert!(!input.blocks.is_empty(), "batch must contain at least one block");
    assert!(
        input.blocks[0].number == meta.block_number_before + 1,
        "first block number {} must follow block_number_before {}",
        input.blocks[0].number, meta.block_number_before,
    );
    for w in input.blocks.windows(2) {
        assert!(w[1].number == w[0].number + 1, "block numbers must be consecutive");
        assert!(w[1].timestamp >= w[0].timestamp, "block timestamps must be non-decreasing");
    }
}

fn verify_intra_batch_hashes(block: &BlockInput, computed: &HashMap<u64, B256>) {
    for &(num, hash) in &block.block_hashes {
        if let Some(&expected) = computed.get(&num) {
            assert_eq!(hash, expected,
                "intra-batch block hash mismatch for block {num}: \
                 server={hash}, computed={expected}");
        }
    }
}

/// Authenticate the pre-batch historical block-hash ring against the L1-pinned
/// `block_hashes_blake_before`.
///
/// `block_hashes_blake_before` is part of `state_before`, which L1 chains to the
/// previous batch's `state_after`, so it is trustworthy. The ring the guest
/// actually *uses* is the separate witness field `first_block.block_hashes`: it
/// feeds the `BLOCKHASH` opcode (via `ProvenDB::block_hash_ref`), supplies the
/// first block's parent hash (`evm.rs`), and is carried into
/// `block_hashes_blake_after` / `state_after`. Nothing else ties that ring to
/// the pinned pre-state value — the only prior check compares two witness fields
/// (`block.block_hashes` vs `meta.previous_block_hashes`) against each other, and
/// `verify_intra_batch_hashes` covers only blocks computed *within* the batch.
///
/// A malicious sequencer could therefore supply a forged-but-internally-
/// consistent historical ring, making `BLOCKHASH(old_block)` return arbitrary
/// values and forging the ring commitment carried forward. Reconstructing the
/// pinned commitment from the witnessed history and asserting equality anchors
/// the whole ring to the L1-pinned value; combined with the intra-batch checks
/// and L1 chaining, the ring becomes authenticated end-to-end.
pub(crate) fn verify_block_hashes_blake_before(meta: &BatchMeta, first_block: &BlockInput) {
    let reconstructed =
        reconstruct_block_hashes_blake_before(first_block.number, &first_block.block_hashes);
    assert_eq!(
        reconstructed, meta.block_hashes_blake_before,
        "pre-state block-hash ring is not authenticated by the L1-pinned \
         block_hashes_blake_before: reconstructed={reconstructed}, \
         pinned={}",
        meta.block_hashes_blake_before,
    );
}

/// Rebuild the 256-entry pre-state block-hash ring from the first block's
/// witnessed `BLOCKHASH` history and return its canonical Blake2s commitment,
/// matching how the server computes `block_hashes_blake_before`.
///
/// The server hashes the first block's 256-entry context ring in array order
/// (Blake2s over `ring[0] ‖ … ‖ ring[255]`) and derives `first_block.block_hashes`
/// from that same ring via `block_number = first_block_number - (256 - index)`,
/// dropping zero (genesis padding) and out-of-range entries. We invert that map:
/// each witnessed `(block_number, hash)` in the pre-state window
/// `[first-256, first-1]` is placed at `index = block_number + 256 - first`
/// (oldest at 0, the first block's parent at 255); every other slot stays zero.
/// Hashing the full ring via the canonical `block_hashes_blake` (the same routine
/// that commits the "after" ring) makes the reconstruction byte-identical to the
/// original commitment, so every honest batch — single- or multi-block, and the
/// short early-chain ring where `block_number_before < 255` — still passes.
pub(crate) fn reconstruct_block_hashes_blake_before(
    first_block_number: u64,
    first_block_hashes: &[(u64, B256)],
) -> B256 {
    let mut ring = [B256::ZERO; 256];
    for &(num, hash) in first_block_hashes {
        // Only blocks in the pre-state window [first-256, first-1] populate the
        // ring; anything else is irrelevant to `block_hashes_blake_before`.
        if num < first_block_number && first_block_number - num <= 256 {
            let idx = (num + 256 - first_block_number) as usize;
            ring[idx] = hash;
        }
    }
    // Blake2s(ring[0] ‖ … ‖ ring[254] ‖ ring[255]) — identical to the server's
    // full-ring hash and to `block_hashes_blake_after`.
    commitment::block_hashes_blake(&ring[..255], &ring[255])
}

/// Execute a batch from bincode-serialized BatchInput bytes.
/// Returns the output and batch commitment hash.
/// Used by the server to compute ZiSK commitments in-process.
pub fn execute_and_commit_from_bincode(
    bincode_data: &[u8],
) -> Result<(BatchOutput, B256), String> {
    let batch_input: BatchInput =
        bincode::deserialize(bincode_data).map_err(|e| format!("deserialize: {e}"))?;
    Ok(execute_and_commit_owned(batch_input))
}
