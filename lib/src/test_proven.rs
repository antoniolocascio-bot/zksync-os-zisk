//! Test that the proven execution path works end-to-end with real merkle proofs.

#[cfg(test)]
mod tests {
    use crate::executor;
    use crate::merkle::*;
    use crate::types::*;
    use alloy_primitives::{Address, B256, U256};

    /// Build a minimal merkle tree with MIN_GUARD (idx 0), MAX_GUARD (idx 1),
    /// and one data leaf (idx 2). Returns (root_hash, leaf_count, sibling_hashes_for_leaf2).
    fn build_minimal_tree(data_key: &B256, data_value: &B256) -> (B256, u64, Vec<B256>) {
        let empty = empty_subtree_hashes_vec();

        // Leaf 0: MIN_GUARD (key=0, value=0, next_index=2 -> points to data leaf)
        let leaf0 = hash_leaf(&B256::ZERO, &B256::ZERO, 2);
        // Leaf 1: MAX_GUARD (key=0xff..ff, value=0, next_index=1 -> self-loop)
        let leaf1 = hash_leaf(&B256::repeat_byte(0xff), &B256::ZERO, 1);
        // Leaf 2: data leaf (key=data_key, value=data_value, next_index=1 -> MAX_GUARD)
        let leaf2 = hash_leaf(data_key, data_value, 1);

        let leaf_count: u64 = 3;

        // Build the tree bottom-up. We need to compute the root and collect siblings for leaf 2.
        // Tree structure at depth 0 (leaves):
        //   idx 0: leaf0, idx 1: leaf1, idx 2: leaf2, idx 3...: empty
        //
        // For proof of leaf at index 2:
        //   depth 0: sibling is idx 3 (empty[0])
        //   depth 1: sibling is hash(leaf0, leaf1) at idx 0 on level 1
        //   depth 2..63: empty subtree hashes

        // Level 0 -> Level 1
        let node_01 = blake2s_compress_pub(&leaf0, &leaf1);  // index 0 on level 1
        let node_23 = blake2s_compress_pub(&leaf2, &empty[0]); // index 1 on level 1

        // Level 1 -> Level 2
        let node_0123 = blake2s_compress_pub(&node_01, &node_23); // index 0 on level 2

        // Level 2..63: pair with empty subtrees
        let mut current = node_0123;
        for d in 2..TREE_DEPTH {
            current = blake2s_compress_pub(&current, &empty[d as usize]);
        }
        let root = current;

        // Siblings for leaf at index 2:
        // depth 0: sibling at idx 3 = empty[0]
        // depth 1: sibling at idx 0 = node_01
        // depth 2..63: empty[depth]
        let mut siblings = vec![empty[0], node_01];
        for d in 2..TREE_DEPTH {
            siblings.push(empty[d as usize]);
        }

        (root, leaf_count, siblings)
    }

    // Expose the compress function for test
    fn blake2s_compress_pub(lhs: &B256, rhs: &B256) -> B256 {
        use blake2::Digest;
        let mut h = blake2::Blake2s256::new();
        h.update(lhs.as_slice());
        h.update(rhs.as_slice());
        B256::from_slice(&h.finalize())
    }

    fn empty_subtree_hashes_vec() -> Vec<B256> {
        let mut hashes = vec![empty_subtree_hash(0)];
        for d in 1..=TREE_DEPTH {
            hashes.push(empty_subtree_hash(d));
        }
        hashes
    }

    /// Encode account properties into 124-byte blob.
    fn encode_account_props(nonce: u64, balance: U256) -> Vec<u8> {
        let mut data = vec![0u8; 124];
        // bytes 0-7: versioning (all zero = not deployed)
        // bytes 8-15: nonce BE
        data[8..16].copy_from_slice(&nonce.to_be_bytes());
        // bytes 16-47: balance BE
        data[16..48].copy_from_slice(&balance.to_be_bytes::<32>());
        // bytes 48-79: bytecode_hash (zero = no code)
        // bytes 80-83: unpadded_code_len (zero)
        // bytes 84-87: artifacts_len (zero)
        // bytes 88-119: observable_bytecode_hash (zero)
        // bytes 120-123: observable_bytecode_len (zero)
        data
    }

    #[test]
    fn test_proven_path_with_real_merkle_proofs() {
        // Setup: a sender with 10 ETH, nonce 0
        let sender: Address = "0x1000000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let recipient: Address = "0x2000000000000000000000000000000000000002"
            .parse()
            .unwrap();

        // Encode sender account properties
        let sender_balance = U256::from(10_000_000_000_000_000_000u128); // 10 ETH
        let sender_props = encode_account_props(0, sender_balance);
        let sender_props_hash = AccountProperties::hash(&sender_props);

        // Compute the flat key for the sender's account properties
        let sender_addr_bytes: [u8; 20] = sender.into_array();
        let sender_flat_key = derive_account_properties_key(&sender_addr_bytes);

        // Build a minimal merkle tree with this one data leaf
        let (tree_root, leaf_count, siblings) =
            build_minimal_tree(&sender_flat_key, &sender_props_hash);

        // Verify our proof works
        let proof = StorageProof::Existing(SlotProofEntry {
            index: 2, // data leaf is at index 2
            value: sender_props_hash,
            next_index: 1, // points to MAX_GUARD
            siblings: siblings.clone(),
        });
        let (recovered_root, value) = proof.verify(&sender_flat_key).unwrap();
        assert_eq!(recovered_root, tree_root, "proof should recover tree root");
        assert_eq!(value.unwrap(), sender_props_hash, "proof should return correct value");

        // Build proper ABI-encoded L2CanonicalTransaction for the L1 tx.
        let l1_abi = {
            let mut abi = vec![0u8; 32 + 19 * 32 + 5 * 32];
            abi[31] = 0x20; // outer offset
            abi[32 + 31] = 0x7f; // txType
            abi[32 + 32 + 12..32 + 32 + 32].copy_from_slice(sender.as_slice()); // from
            abi[32 + 64 + 12..32 + 64 + 32].copy_from_slice(recipient.as_slice()); // to
            abi[32 + 96 + 24..32 + 96 + 32].copy_from_slice(&21_000u64.to_be_bytes()); // gasLimit
            abi[32 + 160 + 16..32 + 160 + 32].copy_from_slice(&250_000_000u128.to_be_bytes()); // maxFeePerGas
            abi[32 + 352 + 12..32 + 352 + 32].copy_from_slice(sender.as_slice()); // reserved[1]=refund
            let dyn_base = 19u32 * 32;
            for j in 0..5u32 {
                let off = 32 + (14 + j as usize) * 32;
                abi[off + 28..off + 32].copy_from_slice(&(dyn_base + j * 32).to_be_bytes());
            }
            abi
        };
        let l1_tx_hash = alloy_primitives::keccak256(&l1_abi);

        // Now build a BatchInput with this proof
        let batch_input = BatchInput {
            version: crate::types::BATCH_INPUT_VERSION,
            chain_id: 270,
            spec_id: 1, // AtlasV2
            protocol_version_minor: 30,
            batch_meta: BatchMeta {
                tree_root_before: tree_root,
                leaf_count_before: leaf_count,
                block_number_before: 0,
                last_block_timestamp_before: 0,
                block_hashes_blake_before: B256::ZERO,
                previous_block_hashes: vec![],
                upgrade_tx_hash: B256::ZERO,
                da_commitment_scheme: 2,
                pubdata: vec![],
                multichain_root: B256::ZERO,
                sl_chain_id: 0, blob_versioned_hashes: vec![],
                tree_update: None,
                account_preimages_after: vec![],
                fri_proof_verification_enabled: false,
                max_tx_gas_limit: 1 << 24,
            },
            blocks: vec![BlockInput {
                number: 1,
                timestamp: 1700000000,
                base_fee: 250_000_000,
                gas_limit: 80_000_000,
                coinbase: sender,  // use sender as coinbase so no extra proof needed
                prev_randao: B256::from([1u8; 32]),
                block_header_hash: B256::ZERO,
                // The merkle proof for the sender's account properties
                storage_proofs: vec![(sender_flat_key, proof)],
                // Account preimage for decoding
                account_preimages: vec![(sender, sender_props)],
                // Use force_fail to avoid full execution (which would access
                // accounts we don't have proofs for in this minimal tree).
                // This test focuses on verifying proof + preimage decoding.
                transactions: vec![TxInput {
                    chain_id: Some(270),
                    gas_used_override: Some(0),
                    force_fail: true,
                    auth: TxAuth::L1 { tx_hash: l1_tx_hash, abi_encoded: l1_abi.clone() },
                }],
                block_hashes: vec![],
                l2_to_l1_logs: vec![L2ToL1LogEntry {
                    l2_shard_id: 0,
                    is_service: true,
                    tx_number_in_block: 0,
                    sender: "0x0000000000000000000000000000000000008001".parse().unwrap(),
                    key: l1_tx_hash,  // tx_hash from the ABI encoding
                    value: B256::ZERO,  // force_fail → success=false → value=0
                }],
                expected_tree_root: B256::ZERO,
            }],
            bytecodes: vec![],
        };

        // Run the proven execution path
        let (output, commitment) = executor::execute_and_commit(&batch_input);

        // Verify execution produced results
        assert_eq!(output.block_results.len(), 1);
        let br = &output.block_results[0];
        assert!(!br.tx_results.is_empty(), "should have tx results");

        let tx = &br.tx_results[0];
        assert!(!tx.success, "force_fail tx should fail");
        println!("tx[0]: success={}, gas_used={}", tx.success, tx.gas_used);

        // Commitment should be non-zero
        assert_ne!(commitment, B256::ZERO, "commitment should be non-zero");
        println!("BatchPublicInput commitment: {commitment}");
    }

    #[test]
    fn export_proven_input_for_emulator() {
        // Same setup as test_proven_path_with_real_merkle_proofs
        let sender: Address = "0x1000000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let recipient: Address = "0x2000000000000000000000000000000000000002"
            .parse()
            .unwrap();

        let sender_balance = U256::from(10_000_000_000_000_000_000u128);
        let sender_props = encode_account_props(0, sender_balance);
        let sender_props_hash = AccountProperties::hash(&sender_props);
        let sender_addr_bytes: [u8; 20] = sender.into_array();
        let sender_flat_key = derive_account_properties_key(&sender_addr_bytes);

        let (tree_root, leaf_count, siblings) =
            build_minimal_tree(&sender_flat_key, &sender_props_hash);

        let proof = StorageProof::Existing(SlotProofEntry {
            index: 2,
            value: sender_props_hash,
            next_index: 1,
            siblings,
        });

        // Build a proper ABI-encoded L2CanonicalTransaction so the batch actually
        // executes. (The previous dummy 11-byte abi_encoded panicked in tx.rs's ABI
        // decoder — it was not a runnable batch.) Mirrors the force_fail path in
        // test_proven_path_with_real_merkle_proofs.
        let l1_abi = {
            let mut abi = vec![0u8; 32 + 19 * 32 + 5 * 32];
            abi[31] = 0x20; // outer offset
            abi[32 + 31] = 0x7f; // txType
            abi[32 + 32 + 12..32 + 32 + 32].copy_from_slice(sender.as_slice()); // from
            abi[32 + 64 + 12..32 + 64 + 32].copy_from_slice(recipient.as_slice()); // to
            abi[32 + 96 + 24..32 + 96 + 32].copy_from_slice(&21_000u64.to_be_bytes()); // gasLimit
            abi[32 + 160 + 16..32 + 160 + 32].copy_from_slice(&250_000_000u128.to_be_bytes()); // maxFeePerGas
            abi[32 + 352 + 12..32 + 352 + 32].copy_from_slice(sender.as_slice()); // reserved[1]=refund
            let dyn_base = 19u32 * 32;
            for j in 0..5u32 {
                let off = 32 + (14 + j as usize) * 32;
                abi[off + 28..off + 32].copy_from_slice(&(dyn_base + j * 32).to_be_bytes());
            }
            abi
        };
        let l1_tx_hash = alloy_primitives::keccak256(&l1_abi);

        let batch_input = BatchInput {
            version: crate::types::BATCH_INPUT_VERSION,
            chain_id: 270,
            spec_id: 1,
            protocol_version_minor: 30,
            batch_meta: BatchMeta {
                tree_root_before: tree_root,
                leaf_count_before: leaf_count,
                block_number_before: 0,
                last_block_timestamp_before: 0,
                block_hashes_blake_before: B256::ZERO,
                previous_block_hashes: vec![],
                upgrade_tx_hash: B256::ZERO,
                da_commitment_scheme: 2,
                pubdata: vec![],
                multichain_root: B256::ZERO,
                sl_chain_id: 0, blob_versioned_hashes: vec![],
                tree_update: None,
                account_preimages_after: vec![],
                fri_proof_verification_enabled: false,
                max_tx_gas_limit: 1 << 24,
            },
            blocks: vec![BlockInput {
                number: 1,
                timestamp: 1700000000,
                base_fee: 250_000_000,
                gas_limit: 80_000_000,
                coinbase: sender, // coinbase = sender so no extra account proof is needed
                prev_randao: B256::from([1u8; 32]),
                block_header_hash: B256::ZERO,
                storage_proofs: vec![(sender_flat_key, proof)],
                account_preimages: vec![(sender, sender_props)],
                transactions: vec![TxInput {
                    chain_id: Some(270),
                    gas_used_override: Some(0),
                    force_fail: true,
                    auth: TxAuth::L1 { tx_hash: l1_tx_hash, abi_encoded: l1_abi.clone() },
                }],
                block_hashes: vec![],
                l2_to_l1_logs: vec![L2ToL1LogEntry {
                    l2_shard_id: 0,
                    is_service: true,
                    tx_number_in_block: 0,
                    sender: "0x0000000000000000000000000000000000008001".parse().unwrap(),
                    key: l1_tx_hash,
                    value: B256::ZERO,
                }],
                expected_tree_root: B256::ZERO,
            }],
            bytecodes: vec![],
        };

        // Serialize in ZiSK stdin format
        let data = bincode::serialize(&batch_input).unwrap();
        let len = data.len() as u64;
        let mut buf = Vec::new();
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(&data);
        let total = 8 + data.len();
        let padding = (8 - (total % 8)) % 8;
        buf.extend(std::iter::repeat(0u8).take(padding));

        std::fs::write("/tmp/proven_input.bin", &buf).unwrap();
        println!("Wrote proven input to /tmp/proven_input.bin ({} bytes)", buf.len());
    }

    /// Compute the native reference commitment for the exact bytes in
    /// /tmp/proven_input.bin — the value the ZiSK guest must reproduce.
    #[test]
    #[ignore = "manual helper: run export_proven_input_for_emulator first"]
    fn print_input_bin_commitment() {
        let data = std::fs::read("/tmp/proven_input.bin").unwrap();
        let len = u64::from_le_bytes(data[..8].try_into().unwrap()) as usize;
        let bi: BatchInput = bincode::deserialize(&data[8..8 + len]).unwrap();
        let (_o, c) = crate::executor::execute_and_commit(&bi);
        println!("INPUT_BIN_COMMITMENT: {c}");
    }

    #[test]
    fn test_proof_verification_catches_wrong_value() {
        let sender: Address = "0x1000000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let sender_addr_bytes: [u8; 20] = sender.into_array();
        let sender_flat_key = derive_account_properties_key(&sender_addr_bytes);

        // Real account: 10 ETH
        let real_props = encode_account_props(0, U256::from(10_000_000_000_000_000_000u128));
        let real_hash = AccountProperties::hash(&real_props);

        // Build tree with real value
        let (tree_root, _leaf_count, siblings) =
            build_minimal_tree(&sender_flat_key, &real_hash);

        // Try to use a FAKE preimage (1000 ETH instead of 10 ETH)
        let fake_props = encode_account_props(0, U256::from(1_000_000_000_000_000_000_000u128));

        // The proof is valid for the real_hash, but the fake preimage has a different hash
        let fake_hash = AccountProperties::hash(&fake_props);
        assert_ne!(real_hash, fake_hash, "hashes should differ");

        // Constructing a BatchInput with mismatched preimage should be caught
        // by build_proven_db which asserts preimage_hash == proven_value
        let proof = StorageProof::Existing(SlotProofEntry {
            index: 2,
            value: real_hash, // tree has real_hash
            next_index: 1,
            siblings,
        });

        // Verify the proof works with the real key
        let (root, _) = proof.verify(&sender_flat_key).unwrap();
        assert_eq!(root, tree_root);

        // Now build BatchInput with the fake preimage — this should panic
        let batch_input = BatchInput {
            version: crate::types::BATCH_INPUT_VERSION,
            chain_id: 270,
            spec_id: 1,
            protocol_version_minor: 30,
            batch_meta: BatchMeta {
                tree_root_before: tree_root,
                leaf_count_before: 3,
                block_number_before: 0,
                last_block_timestamp_before: 0,
                block_hashes_blake_before: B256::ZERO,
                previous_block_hashes: vec![],
                upgrade_tx_hash: B256::ZERO,
                da_commitment_scheme: 2,
                pubdata: vec![],
                multichain_root: B256::ZERO,
                sl_chain_id: 0, blob_versioned_hashes: vec![],
                tree_update: None,
                account_preimages_after: vec![],
                fri_proof_verification_enabled: false,
                max_tx_gas_limit: 1 << 24,
            },
            blocks: vec![BlockInput {
                number: 1,
                timestamp: 1700000000,
                base_fee: 250_000_000,
                gas_limit: 80_000_000,
                coinbase: Address::ZERO,
                prev_randao: B256::from([1u8; 32]),
                block_header_hash: B256::ZERO,
                storage_proofs: vec![(sender_flat_key, proof)],
                account_preimages: vec![(sender, fake_props)], // FAKE
                transactions: vec![],
                block_hashes: vec![],
                l2_to_l1_logs: vec![],
                expected_tree_root: B256::ZERO,
            }],
            bytecodes: vec![],
        };

        // This should panic because preimage hash != proven value
        let result = std::panic::catch_unwind(|| {
            executor::execute_and_commit(&batch_input);
        });
        assert!(result.is_err(), "should panic on fake preimage");
        println!("Correctly caught fake account preimage!");
    }

    /// Execute a dumped batch input (a divergence repro bundle or a
    /// `ZISK_DUMP_DIR` capture) through the proven executor.
    /// Invoke with:
    ///   ZISK_BATCH_PATH=... cargo test --release execute_batch_dump -- --ignored --nocapture
    #[test]
    #[ignore]
    fn execute_batch_dump() {
        let path = std::env::var("ZISK_BATCH_PATH").expect("set ZISK_BATCH_PATH to a dump file");
        let data = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        // ZiSK stdin framing: [len: u64 LE][bincode][zero pad].
        let len = u64::from_le_bytes(data[..8].try_into().unwrap()) as usize;
        match crate::executor::execute_and_commit_from_bincode(&data[8..8 + len]) {
            Ok((output, commitment)) => println!(
                "OK: {} blocks, commitment {commitment}",
                output.block_results.len()
            ),
            Err(e) => panic!("executor failed: {e:#}"),
        }
    }
}
