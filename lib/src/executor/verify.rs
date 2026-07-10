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
    storage_writes: &HashMap<(Address, U256), U256>,
    cache_db: &CacheDB<ProvenDB>,
    after_preimages: &[(Address, Vec<u8>)],
) -> HashMap<B256, B256> {
    let proven_db = &cache_db.db;
    let after_map: HashMap<&Address, &Vec<u8>> = after_preimages.iter()
        .map(|(a, p)| (a, p)).collect();

    let mut writes = HashMap::new();

    // Regular storage writes come from the execution journal (per-block net
    // changes, merged batch-wide) — NOT from a cache-vs-pre-state diff,
    // which would drop writes that net to zero across the batch while the
    // native tree update still carries them.
    for ((addr, slot), value) in storage_writes {
        let slot_b256 = B256::from(slot.to_be_bytes::<32>());
        let flat_key = merkle::derive_flat_storage_key(&addr.into_array(), &slot_b256);
        writes.insert(flat_key, B256::from(value.to_be_bytes::<32>()));
    }

    // 0x8003 account-property writes. Every after-preimage the server
    // provides becomes a tree write with value blake2s(preimage), which
    // `verify_tree_update` checks against the merkle-authenticated tree entry
    // — so a forged preimage produces the wrong value and fails there.
    // Accounts changed only by a system force-deploy are absent from the REVM
    // cache; they rest on that tree authentication plus the code-field
    // self-consistency check below. For accounts REVM executed we also pin
    // nonce/balance to REVM's output.
    for (&addr, &after_preimage) in &after_map {
        let props = merkle::AccountProperties::decode(after_preimage);

        let executed = cache_db.cache.accounts.get(addr).filter(|a| {
            !matches!(
                a.account_state,
                revm::database::AccountState::None | revm::database::AccountState::NotExisting
            )
        });
        if let Some(db_account) = executed {
            let info = &db_account.info;
            assert_eq!(props.nonce, info.nonce,
                "after-preimage nonce mismatch for {addr}: preimage={}, revm={}",
                props.nonce, info.nonce);
            assert_eq!(U256::from_be_bytes(props.balance), info.balance,
                "after-preimage balance mismatch for {addr}");
        }

        // Code-derived fields are a pure function of the post-state code:
        // recompute them from the referenced code so a preimage cannot bind
        // wrong code to the account.
        let observable = props.observable_bytecode_hash;
        if observable == KECCAK_EMPTY || observable.is_zero() {
            // No observable code: never-deployed (all-zero fields) or
            // deployed-with-empty-code (native materializes every completed
            // deployment, empty code included). See `no_code_fields_valid`.
            assert!(account_props::no_code_fields_valid(&props),
                "after-preimage code fields mismatch for {addr}: no observable \
                 code, but fields are neither all-zero nor deployed-empty: {:?}",
                account_props::CodeFields::of(&props));
        } else {
            let code = proven_db
                .code_by_hash_ref(observable)
                .unwrap_or_else(|e| panic!(
                    "post-state code {observable} for {addr} unavailable: {e}"
                ))
                .original_bytes();
            let code_version = (props.versioning >> 40) as u8;
            assert!(code_version <= 1,
                "unsupported code version {code_version} for {addr}");
            let ee_byte = (props.versioning >> 48) as u8;
            assert_eq!(ee_byte, account_props::EVM_EE_BYTE,
                "non-EVM execution environment {ee_byte} for {addr} is not \
                 supported by the second proof system");
            assert_eq!(
                account_props::CodeFields::of(&props),
                account_props::evm_code_fields(&code, code_version),
                "after-preimage code fields mismatch for {addr}"
            );
        }

        let flat_key = merkle::derive_account_properties_key(&(*addr).into_array());
        writes.insert(flat_key, merkle::AccountProperties::hash(after_preimage));
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
            if revm_writes.len() != tree_update.entries.len() {
                // Name the differing keys: a bare count is undebuggable.
                let tree_keys: std::collections::HashSet<_> =
                    tree_update.entries.iter().map(|(k, _)| *k).collect();
                let missing: Vec<_> = tree_keys
                    .iter()
                    .filter(|k| !revm_writes.contains_key(*k))
                    .collect();
                let extra: Vec<_> = revm_writes
                    .keys()
                    .filter(|k| !tree_keys.contains(*k))
                    .collect();
                panic!(
                    "write count mismatch: computed {} writes, tree_update has {};                      native-only keys: {missing:?}; guest-only keys: {extra:?}",
                    revm_writes.len(),
                    tree_update.entries.len(),
                );
            }
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
