//! Post-execution verification.
//!
//! Builds the complete write map (storage + 0x8003 account properties) from
//! REVM's CacheDB and verifies it against the tree_update merkle proof.

use std::collections::HashMap;

use revm::database::CacheDB;
use revm::DatabaseRef;
use revm::primitives::{Address, B256, KECCAK_EMPTY, U256};

use crate::account_props;
use crate::merkle;
use crate::types::*;
use super::proven_db::ProvenDB;

/// Build the complete write map: flat_key → new_value for both regular storage
/// writes and 0x8003 account-property writes. For 0x8003, the server provides
/// after-state preimages; we verify nonce/balance match REVM output, then use
/// blake2s(preimage) as the value.
pub(super) fn build_revm_write_map(
    cache_db: &CacheDB<ProvenDB>,
    after_preimages: &[(Address, Vec<u8>)],
) -> HashMap<B256, B256> {
    let proven_db = &cache_db.db;
    let after_map: HashMap<&Address, &Vec<u8>> = after_preimages.iter()
        .map(|(a, p)| (a, p)).collect();

    let mut writes = HashMap::new();

    for (addr, db_account) in cache_db.cache.accounts.iter() {
        if matches!(
            db_account.account_state,
            revm::database::AccountState::None | revm::database::AccountState::NotExisting
        ) {
            continue;
        }

        // Regular storage writes.
        let addr_bytes: [u8; 20] = addr.into_array();
        for (slot, value) in db_account.storage.iter() {
            let slot_u256 = U256::from_limbs((*slot).into_limbs());
            let slot_b256 = B256::from(slot_u256.to_be_bytes::<32>());
            let flat_key = merkle::derive_flat_storage_key(&addr_bytes, &slot_b256);
            let old_val = proven_db.verified_storage
                .get(&flat_key)
                .and_then(|v| *v)
                .map(|v| U256::from_be_bytes(v.0))
                .unwrap_or(U256::ZERO);
            let new_val = U256::from_limbs((*value).into_limbs());
            if old_val != new_val {
                writes.insert(flat_key, B256::from(new_val.to_be_bytes::<32>()));
            }
        }

        // 0x8003 account-property write: witness-provided after-preimage,
        // every field verified against REVM's execution.
        if let Some(after_preimage) = after_map.get(addr) {
            let props = merkle::AccountProperties::decode(after_preimage);
            let info = &db_account.info;

            // Nonce and balance match REVM's execution directly.
            assert_eq!(props.nonce, info.nonce,
                "after-preimage nonce mismatch for {addr}: preimage={}, revm={}",
                props.nonce, info.nonce);
            assert_eq!(U256::from_be_bytes(props.balance), info.balance,
                "after-preimage balance mismatch for {addr}");

            // The code-derived fields (versioning, blake2s bytecode hash,
            // artifact/code lengths, observable hash) are a pure function of
            // the post-state code — recompute them instead of trusting the
            // witness. A forged blake2s hash would otherwise become the tree
            // leaf unchecked, letting the witness bind wrong code to the
            // account for every later batch.
            let expected = if info.code_hash == KECCAK_EMPTY || info.code_hash.is_zero() {
                account_props::CodeFields::empty()
            } else {
                let code = match info.code.as_ref() {
                    Some(code) => code.original_bytes(),
                    None => proven_db
                        .code_by_hash_ref(info.code_hash)
                        .unwrap_or_else(|e| panic!(
                            "post-state code {} for {addr} unavailable: {e}",
                            info.code_hash
                        ))
                        .original_bytes(),
                };
                // Code version 0 (no cached artifacts) and 1 (jumpdest
                // bitmap) are both deterministically derivable; anything
                // else — including non-EVM execution environments — is
                // unsupported and must fail loudly rather than be trusted.
                let code_version = (props.versioning >> 40) as u8;
                assert!(code_version <= 1,
                    "unsupported code version {code_version} for {addr}");
                let ee_byte = (props.versioning >> 48) as u8;
                assert_eq!(ee_byte, account_props::EVM_EE_BYTE,
                    "non-EVM execution environment {ee_byte} for {addr} is not \
                     supported by the second proof system");
                account_props::evm_code_fields(&code, code_version)
            };
            assert_eq!(account_props::CodeFields::of(&props), expected,
                "after-preimage code fields mismatch for {addr}");

            let flat_key = merkle::derive_account_properties_key(&addr_bytes);
            writes.insert(flat_key, merkle::AccountProperties::hash(after_preimage));
        }
    }

    writes
}

/// Verify tree_update entries match computed writes.
/// Uses the set-theoretic identity: |A| == |B| ∧ A ⊆ B ⟹ A == B.
/// One length check + one forward pass — no reverse iteration needed.
pub(super) fn verify_tree_update(
    meta: &BatchMeta,
    revm_writes: &HashMap<B256, B256>,
) -> (B256, u64) {
    match meta.tree_update {
        Some(ref tree_update) => {
            assert_eq!(
                revm_writes.len(), tree_update.entries.len(),
                "write count mismatch: computed {} writes, tree_update has {}",
                revm_writes.len(), tree_update.entries.len(),
            );
            for (key, tree_val) in &tree_update.entries {
                let computed_val = revm_writes.get(key).unwrap_or_else(||
                    panic!("tree_update has {key} not in computed writes"));
                assert_eq!(tree_val, computed_val,
                    "tree_update value mismatch for {key}: tree={tree_val}, computed={computed_val}");
            }
            tree_update.apply(&meta.tree_root_before)
        }
        None => {
            assert!(revm_writes.is_empty(), "writes exist but no tree_update provided");
            (meta.tree_root_before, meta.leaf_count_before)
        }
    }
}
