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

    /// Dense tree over MIN/MAX guards + data leaves with a correct sorted
    /// linked list. Returns (root, all leaves by index, per-leaf sibling paths).
    fn build_dense_tree(
        data: &[(B256, B256)],
    ) -> (B256, Vec<(u64, TreeLeaf)>, Vec<Vec<B256>>) {
        // Indices: 0 = MIN guard, 1 = MAX guard, 2.. = data in given order.
        let mut recs: Vec<(u64, B256, B256)> = vec![
            (0, B256::ZERO, B256::ZERO),
            (1, B256::repeat_byte(0xff), B256::ZERO),
        ];
        for (i, (k, v)) in data.iter().enumerate() {
            recs.push((2 + i as u64, *k, *v));
        }
        // next pointers follow key order; MAX guard self-loops.
        let mut order: Vec<usize> = (0..recs.len()).collect();
        order.sort_by(|&a, &b| recs[a].1.cmp(&recs[b].1));
        let mut next = vec![0u64; recs.len()];
        for w in order.windows(2) {
            next[w[0]] = recs[w[1]].0;
        }
        next[*order.last().unwrap()] = 1;

        let leaves: Vec<(u64, TreeLeaf)> = recs
            .iter()
            .zip(&next)
            .map(|((idx, k, v), n)| (*idx, TreeLeaf { key: *k, value: *v, next_index: *n }))
            .collect();

        // Dense levels bottom-up.
        let mut levels: Vec<Vec<B256>> = vec![leaves
            .iter()
            .map(|(_, l)| hash_leaf(&l.key, &l.value, l.next_index))
            .collect()];
        while levels.last().unwrap().len() > 1 {
            let d = levels.len() - 1;
            let cur = levels.last().unwrap();
            let next_level: Vec<B256> = (0..cur.len().div_ceil(2))
                .map(|i| {
                    let l = cur[2 * i];
                    let r = cur.get(2 * i + 1).copied().unwrap_or(empty_subtree_hash(d as u8));
                    blake2s_compress_pub(&l, &r)
                })
                .collect();
            levels.push(next_level);
        }
        let mut root = levels.last().unwrap()[0];
        for d in (levels.len() - 1)..(TREE_DEPTH as usize) {
            root = blake2s_compress_pub(&root, &empty_subtree_hash(d as u8));
        }

        let siblings: Vec<Vec<B256>> = (0..leaves.len() as u64)
            .map(|i| {
                (0..TREE_DEPTH as usize)
                    .map(|d| {
                        let pos = ((i >> d) ^ 1) as usize;
                        levels
                            .get(d)
                            .and_then(|lvl| lvl.get(pos).copied())
                            .unwrap_or(empty_subtree_hash(d as u8))
                    })
                    .collect()
            })
            .collect();
        (root, leaves, siblings)
    }

    /// Production fee semantics: the operator (coinbase) is credited the FULL
    /// effective gas price per unit of gas used. Production zksync-os is built
    /// WITHOUT the `burn_base_fee` cargo feature (the server pins
    /// forward_system with `features = ["production", "no_print"]`), so there
    /// is no EIP-1559-style base-fee burn — see basic_bootloader
    /// transaction_flow/zk/mod.rs, non-burn branch of `gas_price_for_operator`.
    ///
    /// gas_price 10 vs base_fee 7 makes the two models distinguishable:
    /// full price credits 10/gas, mainnet burn semantics would credit 3/gas.
    /// A guest regression to burn semantics fails this test both ways.
    #[test]
    fn coinbase_reward_is_full_effective_gas_price() {
        use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
        use alloy_eips::eip2718::Encodable2718;
        use k256::ecdsa::SigningKey;

        // Deterministic sender key.
        let sk = SigningKey::from_bytes((&[0x42u8; 32]).into()).unwrap();
        let pubkey = sk.verifying_key().to_encoded_point(false);
        let sender = Address::from_slice(
            &alloy_primitives::keccak256(&pubkey.as_bytes()[1..])[12..],
        );
        let coinbase: Address = "0x00000000000000000000000000000000c01badde".parse().unwrap();

        const GAS_PRICE: u64 = 10;
        const BASE_FEE: u64 = 7;
        const GAS_USED: u64 = 21_000;
        let sender_balance_before = U256::from(1_000_000_000_000_000_000u128);
        let coinbase_balance_before = U256::from(5u64);

        // Signed legacy self-transfer (value 0), gas_price 10.
        let tx = TxLegacy {
            chain_id: Some(1),
            nonce: 0,
            gas_price: GAS_PRICE as u128,
            gas_limit: 100_000,
            to: alloy_primitives::TxKind::Call(sender),
            value: U256::ZERO,
            input: Default::default(),
        };
        let sighash = tx.signature_hash();
        let (sig, recid) = sk.sign_prehash_recoverable(sighash.as_slice()).unwrap();
        let sig_bytes = sig.to_bytes();
        let signature = alloy_primitives::Signature::new(
            U256::from_be_slice(&sig_bytes[..32]),
            U256::from_be_slice(&sig_bytes[32..]),
            recid.is_y_odd(),
        );
        let envelope = TxEnvelope::Legacy(tx.into_signed(signature));
        let mut signed_bytes = Vec::new();
        envelope.encode_2718(&mut signed_bytes);

        // Pre-state tree: sender + coinbase as existing accounts.
        let sender_props = encode_account_props(0, sender_balance_before);
        let coinbase_props = encode_account_props(0, coinbase_balance_before);
        let k_sender = derive_account_properties_key(&sender.into_array());
        let k_coinbase = derive_account_properties_key(&coinbase.into_array());
        let (root, leaves, siblings) = build_dense_tree(&[
            (k_sender, AccountProperties::hash(&sender_props)),
            (k_coinbase, AccountProperties::hash(&coinbase_props)),
        ]);

        let proof_for = |idx: u64| {
            let (_, leaf) = &leaves[idx as usize];
            StorageProof::Existing(SlotProofEntry {
                index: idx,
                value: leaf.value,
                next_index: leaf.next_index,
                siblings: siblings[idx as usize].clone(),
            })
        };

        // Build the batch for a given claimed after-state of the coinbase.
        let fee = U256::from(GAS_USED) * U256::from(GAS_PRICE as u128);
        let build = |coinbase_balance_after: U256| -> BatchInput {
            let sender_after = encode_account_props(1, sender_balance_before - fee);
            let coinbase_after = encode_account_props(0, coinbase_balance_after);
            let tree_update = BatchTreeUpdate {
                operations: vec![WriteOp::Update { index: 2 }, WriteOp::Update { index: 3 }],
                entries: vec![
                    (k_sender, AccountProperties::hash(&sender_after)),
                    (k_coinbase, AccountProperties::hash(&coinbase_after)),
                ],
                sorted_leaves: leaves.clone(),
                intermediate_hashes: vec![],
                leaf_count_before: 4,
            };
            BatchInput {
                version: crate::types::BATCH_INPUT_VERSION,
                chain_id: 1,
                spec_id: 2, // AtlasV3
                protocol_version_minor: 31,
                batch_meta: BatchMeta {
                    tree_root_before: root,
                    leaf_count_before: 4,
                    block_number_before: 0,
                    last_block_timestamp_before: 0,
                    block_hashes_blake_before: B256::ZERO,
                    previous_block_hashes: vec![],
                    upgrade_tx_hash: B256::ZERO,
                    da_commitment_scheme: 2,
                    pubdata: vec![],
                    multichain_root: B256::ZERO,
                    sl_chain_id: 1,
                    blob_versioned_hashes: vec![],
                    tree_update: Some(tree_update),
                    account_preimages_after: vec![
                        (sender, sender_after.clone()),
                        (coinbase, coinbase_after.clone()),
                    ],
                    fri_proof_verification_enabled: false,
                    max_tx_gas_limit: 1 << 24,
                },
                blocks: vec![BlockInput {
                    number: 1,
                    timestamp: 1700000000,
                    base_fee: BASE_FEE,
                    gas_limit: 1_000_000,
                    coinbase,
                    prev_randao: B256::from([1u8; 32]),
                    block_header_hash: B256::ZERO,
                    storage_proofs: vec![(k_sender, proof_for(2)), (k_coinbase, proof_for(3))],
                    account_preimages: vec![
                        (sender, sender_props.clone()),
                        (coinbase, coinbase_props.clone()),
                    ],
                    transactions: vec![TxInput {
                        chain_id: Some(1),
                        gas_used_override: Some(GAS_USED),
                        force_fail: false,
                        auth: TxAuth::L2 { signed_bytes: signed_bytes.clone() },
                    }],
                    block_hashes: vec![],
                    l2_to_l1_logs: vec![],
                    expected_tree_root: B256::ZERO,
                }],
                bytecodes: vec![],
            }
        };

        // Full-price credit must verify end to end.
        let full_price = build(coinbase_balance_before + fee);
        let (output, _commitment) = executor::execute_and_commit(&full_price);
        let tx_out = &output.block_results[0].tx_results[0];
        assert!(tx_out.success, "self-transfer must succeed");
        assert_eq!(tx_out.gas_used, GAS_USED);

        // Mainnet burn semantics (tip-only credit) must be REJECTED: a witness
        // claiming coinbase += gas_used * (effective - base_fee) fails the
        // after-preimage balance check against REVM's full-price credit.
        let tip_only = build(
            coinbase_balance_before
                + U256::from(GAS_USED) * U256::from((GAS_PRICE - BASE_FEE) as u128),
        );
        let result = std::panic::catch_unwind(|| executor::execute_and_commit(&tip_only));
        assert!(
            result.is_err(),
            "tip-only (burn-semantics) coinbase credit must fail verification"
        );
    }

    /// Full 124-byte props blob for an account WITH code (code version 1).
    fn encode_account_props_code(nonce: u64, balance: U256, code: &[u8]) -> Vec<u8> {
        let mut data = encode_account_props(nonce, balance);
        if !code.is_empty() {
            let f = crate::account_props::evm_code_fields(code, 1);
            data[0..8].copy_from_slice(&f.versioning.to_be_bytes());
            data[48..80].copy_from_slice(f.bytecode_hash.as_slice());
            data[80..84].copy_from_slice(&f.unpadded_code_len.to_be_bytes());
            data[84..88].copy_from_slice(&f.artifacts_len.to_be_bytes());
            data[88..120].copy_from_slice(f.observable_bytecode_hash.as_slice());
            data[120..124].copy_from_slice(&f.observable_bytecode_len.to_be_bytes());
        }
        data
    }

    /// Non-existence proof for `fk` from a `build_dense_tree` result.
    fn non_existence_proof(
        leaves: &[(u64, TreeLeaf)],
        siblings: &[Vec<B256>],
        fk: &B256,
    ) -> StorageProof {
        let (li, lleaf) = leaves
            .iter()
            .filter(|(_, l)| l.key < *fk)
            .max_by_key(|(_, l)| l.key)
            .expect("MIN guard");
        let (ri, rleaf) = leaves.iter().find(|(i, _)| *i == lleaf.next_index).unwrap();
        let entry = |i: u64, l: &TreeLeaf| SlotProofEntry {
            index: i,
            value: l.value,
            next_index: l.next_index,
            siblings: siblings[i as usize].clone(),
        };
        StorageProof::NonExisting {
            left_neighbor: NeighborProofEntry { entry: entry(*li, lleaf), leaf_key: lleaf.key },
            right_neighbor: NeighborProofEntry { entry: entry(*ri, rleaf), leaf_key: rleaf.key },
        }
    }

    /// Sign a legacy tx (chain 1, gas_price 10) with a deterministic key.
    fn sign_legacy(
        sk_bytes: [u8; 32],
        nonce: u64,
        to: Address,
        data: Vec<u8>,
        gas_limit: u64,
    ) -> (Address, Vec<u8>) {
        use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
        use alloy_eips::eip2718::Encodable2718;
        use k256::ecdsa::SigningKey;
        let sk = SigningKey::from_bytes((&sk_bytes).into()).unwrap();
        let pubkey = sk.verifying_key().to_encoded_point(false);
        let sender =
            Address::from_slice(&alloy_primitives::keccak256(&pubkey.as_bytes()[1..])[12..]);
        let tx = TxLegacy {
            chain_id: Some(1),
            nonce,
            gas_price: 10,
            gas_limit,
            to: alloy_primitives::TxKind::Call(to),
            value: U256::ZERO,
            input: data.into(),
        };
        let sighash = tx.signature_hash();
        let (sig, recid) = sk.sign_prehash_recoverable(sighash.as_slice()).unwrap();
        let sig_bytes = sig.to_bytes();
        let signature = alloy_primitives::Signature::new(
            U256::from_be_slice(&sig_bytes[..32]),
            U256::from_be_slice(&sig_bytes[32..]),
            recid.is_y_odd(),
        );
        let envelope = TxEnvelope::Legacy(tx.into_signed(signature));
        let mut signed = Vec::new();
        envelope.encode_2718(&mut signed);
        (sender, signed)
    }

    /// `keccak256(rlp([deployer, nonce]))[12..]` for a single-byte nonce.
    fn create_address(deployer: Address, nonce: u8) -> Address {
        assert!(nonce > 0 && nonce < 0x80);
        let mut rlp = vec![0xd6, 0x94];
        rlp.extend_from_slice(deployer.as_slice());
        rlp.push(nonce);
        Address::from_slice(&alloy_primitives::keccak256(&rlp)[12..])
    }

    /// Assemble a single-block batch around the variable witness parts.
    fn selfdestruct_test_batch(
        root: B256,
        sorted_leaves: Vec<(u64, TreeLeaf)>,
        operations: Vec<WriteOp>,
        entries: Vec<(B256, B256)>,
        account_preimages_after: Vec<(Address, Vec<u8>)>,
        block: BlockInput,
        bytecodes: Vec<(B256, Vec<u8>)>,
    ) -> BatchInput {
        let leaf_count = sorted_leaves.len() as u64;
        BatchInput {
            version: crate::types::BATCH_INPUT_VERSION,
            chain_id: 1,
            spec_id: 2, // AtlasV3
            protocol_version_minor: 31,
            batch_meta: BatchMeta {
                tree_root_before: root,
                leaf_count_before: leaf_count,
                block_number_before: 0,
                last_block_timestamp_before: 0,
                block_hashes_blake_before: B256::ZERO,
                previous_block_hashes: vec![],
                upgrade_tx_hash: B256::ZERO,
                da_commitment_scheme: 2,
                pubdata: vec![],
                multichain_root: B256::ZERO,
                sl_chain_id: 1,
                blob_versioned_hashes: vec![],
                tree_update: Some(BatchTreeUpdate {
                    operations,
                    entries,
                    sorted_leaves,
                    intermediate_hashes: vec![],
                    leaf_count_before: leaf_count,
                }),
                account_preimages_after,
                fri_proof_verification_enabled: false,
                max_tx_gas_limit: 1 << 24,
            },
            blocks: vec![block],
            bytecodes,
        }
    }

    /// Runtime payload: `SSTORE(1, 1); SELFDESTRUCT(CALLER)`.
    const SD_RUNTIME: [u8; 7] = [0x60, 0x01, 0x60, 0x01, 0x55, 0x33, 0xff];

    /// EIP-6780 arm 1: a contract created and selfdestructed within the same
    /// tx is destroyed — its SSTORE must NOT enter the guest's write set
    /// (native's tree diff has nothing for it). The witness claims only the
    /// surviving writes (sender/factory/coinbase props); before the
    /// `is_selfdestructed` filter this batch failed verification with a
    /// phantom (created, slot 1) write. Mirrors the corpus'
    /// prague/eip7702 factory fixtures.
    #[test]
    fn selfdestruct_created_same_tx_excluded_from_write_set() {
        // Factory: CALLDATACOPY(0,0,cds); CREATE(0,0,cds); CALL(gas, created,
        // 0,0,0,0,0); STOP.
        let factory_code: Vec<u8> = vec![
            0x36, 0x60, 0x00, 0x60, 0x00, 0x37, // calldatacopy
            0x36, 0x60, 0x00, 0x60, 0x00, 0xf0, // create
            0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, // ret/arg/value zeros
            0x85, 0x5a, 0xf1, 0x00, // dup6(addr) gas call stop
        ];
        // Initcode returning SD_RUNTIME: PUSH7 runtime; MSTORE@0; RETURN(25,7).
        let mut initcode: Vec<u8> = vec![0x66];
        initcode.extend_from_slice(&SD_RUNTIME);
        initcode.extend_from_slice(&[0x60, 0x00, 0x52, 0x60, 0x07, 0x60, 0x19, 0xf3]);

        let factory: Address = "0x00000000000000000000000000000000000fac70".parse().unwrap();
        let coinbase: Address = "0x00000000000000000000000000000000c01badde".parse().unwrap();
        let (sender, signed) = sign_legacy([0x51u8; 32], 0, factory, initcode, 1_000_000);
        let created = create_address(factory, 1);

        const GAS_USED: u64 = 100_000;
        let fee = U256::from(GAS_USED) * U256::from(10u64);
        let sender_before = U256::from(1_000_000_000_000_000_000u128);

        let sender_props = encode_account_props(0, sender_before);
        let factory_props = encode_account_props_code(1, U256::ZERO, &factory_code);
        let coinbase_props = encode_account_props(0, U256::from(5u64));
        let k_sender = derive_account_properties_key(&sender.into_array());
        let k_factory = derive_account_properties_key(&factory.into_array());
        let k_coinbase = derive_account_properties_key(&coinbase.into_array());
        let k_created = derive_account_properties_key(&created.into_array());

        let (root, leaves, siblings) = build_dense_tree(&[
            (k_sender, AccountProperties::hash(&sender_props)),
            (k_factory, AccountProperties::hash(&factory_props)),
            (k_coinbase, AccountProperties::hash(&coinbase_props)),
        ]);
        let existing = |idx: u64| {
            let (_, leaf) = &leaves[idx as usize];
            StorageProof::Existing(SlotProofEntry {
                index: idx,
                value: leaf.value,
                next_index: leaf.next_index,
                siblings: siblings[idx as usize].clone(),
            })
        };

        // Surviving after-state: sender pays, factory nonce 1->2 (CREATE),
        // coinbase collects. The destroyed contract contributes NOTHING.
        let sender_after = encode_account_props(1, sender_before - fee);
        let factory_after = encode_account_props_code(2, U256::ZERO, &factory_code);
        let coinbase_after = encode_account_props(0, U256::from(5u64) + fee);

        let bi = selfdestruct_test_batch(
            root,
            leaves.clone(),
            vec![
                WriteOp::Update { index: 2 },
                WriteOp::Update { index: 3 },
                WriteOp::Update { index: 4 },
            ],
            vec![
                (k_sender, AccountProperties::hash(&sender_after)),
                (k_factory, AccountProperties::hash(&factory_after)),
                (k_coinbase, AccountProperties::hash(&coinbase_after)),
            ],
            vec![
                (sender, sender_after),
                (factory, factory_after),
                (coinbase, coinbase_after),
            ],
            BlockInput {
                number: 1,
                timestamp: 1700000000,
                base_fee: 7,
                gas_limit: 10_000_000,
                coinbase,
                prev_randao: B256::from([1u8; 32]),
                block_header_hash: B256::ZERO,
                storage_proofs: vec![
                    (k_sender, existing(2)),
                    (k_factory, existing(3)),
                    (k_coinbase, existing(4)),
                    (k_created, non_existence_proof(&leaves, &siblings, &k_created)),
                ],
                account_preimages: vec![
                    (sender, sender_props),
                    (factory, factory_props.clone()),
                    (coinbase, coinbase_props),
                ],
                transactions: vec![TxInput {
                    chain_id: Some(1),
                    gas_used_override: Some(GAS_USED),
                    force_fail: false,
                    auth: TxAuth::L2 { signed_bytes: signed },
                }],
                block_hashes: vec![],
                l2_to_l1_logs: vec![],
                expected_tree_root: B256::ZERO,
            },
            vec![(alloy_primitives::keccak256(&factory_code), factory_code.clone())],
        );

        let (output, _c) = executor::execute_and_commit(&bi);
        assert!(output.block_results[0].tx_results[0].success, "factory tx must succeed");
    }

    /// EIP-6780 arm 2: SELFDESTRUCT of a PRE-EXISTING account is only a
    /// balance transfer post-Cancun — the account and its storage writes
    /// survive. The witness claims the SSTORE (a tree insert); if the
    /// selfdestruct filter over-skipped, the write would go missing and
    /// verification would fail.
    #[test]
    fn selfdestruct_of_preexisting_account_keeps_storage_writes() {
        let d_addr: Address = "0x00000000000000000000000000000000000dcafe".parse().unwrap();
        let coinbase: Address = "0x00000000000000000000000000000000c01badde".parse().unwrap();
        let d_code = SD_RUNTIME.to_vec();
        let (sender, signed) = sign_legacy([0x52u8; 32], 0, d_addr, vec![], 1_000_000);

        const GAS_USED: u64 = 100_000;
        let fee = U256::from(GAS_USED) * U256::from(10u64);
        let sender_before = U256::from(1_000_000_000_000_000_000u128);

        let sender_props = encode_account_props(0, sender_before);
        let d_props = encode_account_props_code(1, U256::ZERO, &d_code);
        let coinbase_props = encode_account_props(0, U256::from(5u64));
        let k_sender = derive_account_properties_key(&sender.into_array());
        let k_d = derive_account_properties_key(&d_addr.into_array());
        let k_coinbase = derive_account_properties_key(&coinbase.into_array());
        let k_slot1 = derive_flat_storage_key(
            &d_addr.into_array(),
            &B256::from(U256::from(1u64).to_be_bytes::<32>()),
        );

        let (root, leaves, siblings) = build_dense_tree(&[
            (k_sender, AccountProperties::hash(&sender_props)),
            (k_d, AccountProperties::hash(&d_props)),
            (k_coinbase, AccountProperties::hash(&coinbase_props)),
        ]);
        let existing = |idx: u64| {
            let (_, leaf) = &leaves[idx as usize];
            StorageProof::Existing(SlotProofEntry {
                index: idx,
                value: leaf.value,
                next_index: leaf.next_index,
                siblings: siblings[idx as usize].clone(),
            })
        };
        // Insert predecessor for the new (D, slot 1) leaf.
        let prev_index = leaves
            .iter()
            .filter(|(_, l)| l.key < k_slot1)
            .max_by_key(|(_, l)| l.key)
            .unwrap()
            .0;

        let sender_after = encode_account_props(1, sender_before - fee);
        let coinbase_after = encode_account_props(0, U256::from(5u64) + fee);

        let bi = selfdestruct_test_batch(
            root,
            leaves.clone(),
            vec![
                WriteOp::Update { index: 2 },
                WriteOp::Update { index: 4 },
                WriteOp::Insert { prev_index },
            ],
            vec![
                (k_sender, AccountProperties::hash(&sender_after)),
                (k_coinbase, AccountProperties::hash(&coinbase_after)),
                (k_slot1, B256::from(U256::from(1u64).to_be_bytes::<32>())),
            ],
            vec![(sender, sender_after), (coinbase, coinbase_after)],
            BlockInput {
                number: 1,
                timestamp: 1700000000,
                base_fee: 7,
                gas_limit: 10_000_000,
                coinbase,
                prev_randao: B256::from([1u8; 32]),
                block_header_hash: B256::ZERO,
                storage_proofs: vec![
                    (k_sender, existing(2)),
                    (k_d, existing(3)),
                    (k_coinbase, existing(4)),
                    (k_slot1, non_existence_proof(&leaves, &siblings, &k_slot1)),
                ],
                account_preimages: vec![
                    (sender, sender_props),
                    (d_addr, d_props),
                    (coinbase, coinbase_props),
                ],
                transactions: vec![TxInput {
                    chain_id: Some(1),
                    gas_used_override: Some(GAS_USED),
                    force_fail: false,
                    auth: TxAuth::L2 { signed_bytes: signed },
                }],
                block_hashes: vec![],
                l2_to_l1_logs: vec![],
                expected_tree_root: B256::ZERO,
            },
            vec![(alloy_primitives::keccak256(&d_code), d_code.clone())],
        );

        let (output, _c) = executor::execute_and_commit(&bi);
        assert!(output.block_results[0].tx_results[0].success, "call to D must succeed");
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
