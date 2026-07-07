//! Deterministic derivation of native ZKsync OS `AccountProperties` fields
//! for EVM code.
//!
//! Mirrors `basic_system/.../flat_storage_model/account_cache.rs` +
//! `evm_interpreter` (draft-0.4.0): every code-derived field of an account's
//! 124-byte properties blob is a pure function of the deployed code, so the
//! guest can recompute and verify them instead of trusting the witness.
//!
//! Native recipe (EVM):
//! - artifacts = jumpdest bitmap: `ceil(code_len / 64)` u64 words,
//!   little-endian, bit `i` set iff `code[i]` is a JUMPDEST outside PUSH
//!   immediates (code version 1, `ARTIFACTS_CACHING_CODE_VERSION_BYTE`);
//!   code version 0 predates artifact caching and has no artifacts.
//! - padding: code zero-padded to 8-byte (`BYTECODE_ALIGNMENT`) alignment.
//! - `bytecode_hash = blake2s256(code || padding || artifacts)`; the preimage
//!   blob stored under it is exactly that concatenation.
//! - `observable_bytecode_hash = keccak256(code)`;
//!   `unpadded_code_len = observable_bytecode_len = code.len()`.
//! - versioning u64: deployment status byte 7 (1 = deployed, 2 = EIP-7702
//!   delegated), EE type byte 6 (EVM = 1), code version byte 5; aux bytes
//!   unused.
//! - EIP-7702 delegation: code = `0xef0100 || address` (23 bytes), no
//!   artifacts, same hashing; clearing a delegation zeroes every field.

use crate::merkle::AccountProperties;
use blake2::{Blake2s256, Digest};
use revm::primitives::{keccak256, B256};

pub const EVM_EE_BYTE: u8 = 1;
pub const DEPLOYED_STATUS_BYTE: u8 = 1;
pub const DELEGATED_STATUS_BYTE: u8 = 2;
pub const ARTIFACTS_CACHING_CODE_VERSION: u8 = 1;
pub const EIP7702_DELEGATION_MARKER: [u8; 3] = [0xef, 0x01, 0x00];

const BYTECODE_ALIGNMENT: usize = 8;

const JUMPDEST: u8 = 0x5b;
const PUSH1: u8 = 0x60;
const PUSH32: u8 = 0x7f;

/// The code-derived subset of `AccountProperties` (everything except nonce
/// and balance, which REVM verifies directly).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeFields {
    pub versioning: u64,
    pub bytecode_hash: B256,
    pub unpadded_code_len: u32,
    pub artifacts_len: u32,
    pub observable_bytecode_hash: B256,
    pub observable_bytecode_len: u32,
}

impl CodeFields {
    /// An account with no code (EOA or cleared delegation): every field zero.
    pub fn empty() -> Self {
        Self {
            versioning: 0,
            bytecode_hash: B256::ZERO,
            unpadded_code_len: 0,
            artifacts_len: 0,
            observable_bytecode_hash: B256::ZERO,
            observable_bytecode_len: 0,
        }
    }

    /// Extract the code-derived fields from a decoded witness blob.
    pub fn of(props: &AccountProperties) -> Self {
        Self {
            versioning: props.versioning,
            bytecode_hash: props.bytecode_hash,
            unpadded_code_len: props.unpadded_code_len,
            artifacts_len: props.artifacts_len,
            observable_bytecode_hash: props.observable_bytecode_hash,
            observable_bytecode_len: props.observable_bytecode_len,
        }
    }
}

/// EVM jumpdest bitmap exactly as `evm_interpreter::analyze` builds it:
/// bit `i` (byte `i / 8`, bit `i % 8`, little-endian u64 words) set iff
/// `code[i]` is JUMPDEST and not inside PUSH immediate data. Length is
/// `ceil(code_len / 64)` u64 words.
pub fn evm_jumpdest_bitmap(code: &[u8]) -> Vec<u8> {
    let words = code.len().div_ceil(64);
    let mut bitmap = vec![0u8; words * 8];
    let mut i = 0;
    while i < code.len() {
        let op = code[i];
        if op == JUMPDEST {
            bitmap[i / 8] |= 1 << (i % 8);
            i += 1;
        } else if (PUSH1..=PUSH32).contains(&op) {
            i += 1 + (op - PUSH1 + 1) as usize;
        } else {
            i += 1;
        }
    }
    bitmap
}

fn versioning(status: u8, code_version: u8) -> u64 {
    ((status as u64) << 56) | ((EVM_EE_BYTE as u64) << 48) | ((code_version as u64) << 40)
}

/// Derive every code-dependent `AccountProperties` field for EVM code under
/// the given code version (0 = no cached artifacts, 1 = jumpdest bitmap).
///
/// A 23-byte `0xef0100 || address` blob is an EIP-7702 delegation designator:
/// delegated status, no artifacts, code version 1 — matching native
/// `set_delegation`.
pub fn evm_code_fields(code: &[u8], code_version: u8) -> CodeFields {
    let is_delegation =
        code.len() == 23 && code[..3] == EIP7702_DELEGATION_MARKER;

    let artifacts = if is_delegation || code_version == 0 {
        Vec::new()
    } else {
        evm_jumpdest_bitmap(code)
    };

    let padding_len = (BYTECODE_ALIGNMENT - (code.len() % BYTECODE_ALIGNMENT)) % BYTECODE_ALIGNMENT;
    let mut hasher = Blake2s256::new();
    hasher.update(code);
    hasher.update(&[0u8; BYTECODE_ALIGNMENT - 1][..padding_len]);
    hasher.update(&artifacts);
    let bytecode_hash = B256::from_slice(&hasher.finalize());

    let (status, code_version) = if is_delegation {
        (DELEGATED_STATUS_BYTE, ARTIFACTS_CACHING_CODE_VERSION)
    } else {
        (DEPLOYED_STATUS_BYTE, code_version)
    };

    CodeFields {
        versioning: versioning(status, code_version),
        bytecode_hash,
        unpadded_code_len: code.len() as u32,
        artifacts_len: artifacts.len() as u32,
        observable_bytecode_hash: keccak256(code),
        observable_bytecode_len: code.len() as u32,
    }
}

/// The full preimage blob stored under `bytecode_hash`:
/// `code || zero padding to 8 || artifacts`.
pub fn evm_bytecode_preimage(code: &[u8], code_version: u8) -> Vec<u8> {
    let is_delegation =
        code.len() == 23 && code[..3] == EIP7702_DELEGATION_MARKER;
    let artifacts = if is_delegation || code_version == 0 {
        Vec::new()
    } else {
        evm_jumpdest_bitmap(code)
    };
    let padding_len = (BYTECODE_ALIGNMENT - (code.len() % BYTECODE_ALIGNMENT)) % BYTECODE_ALIGNMENT;
    let mut blob = Vec::with_capacity(code.len() + padding_len + artifacts.len());
    blob.extend_from_slice(code);
    blob.extend_from_slice(&[0u8; BYTECODE_ALIGNMENT - 1][..padding_len]);
    blob.extend_from_slice(&artifacts);
    blob
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jumpdest_bitmap_skips_push_data() {
        // PUSH1 0x5b (immediate, not a jumpdest), JUMPDEST, STOP
        let code = [0x60, 0x5b, 0x5b, 0x00];
        let bitmap = evm_jumpdest_bitmap(&code);
        assert_eq!(bitmap.len(), 8); // one u64 word
        assert_eq!(bitmap[0], 0b0000_0100); // only offset 2 set
    }

    #[test]
    fn bitmap_length_is_u64_granular() {
        assert_eq!(evm_jumpdest_bitmap(&[0u8; 64]).len(), 8);
        assert_eq!(evm_jumpdest_bitmap(&[0u8; 65]).len(), 16);
        assert_eq!(evm_jumpdest_bitmap(&[]).len(), 0);
    }

    #[test]
    fn delegation_designator_fields() {
        let mut code = vec![0xef, 0x01, 0x00];
        code.extend_from_slice(&[0x11; 20]);
        let fields = evm_code_fields(&code, ARTIFACTS_CACHING_CODE_VERSION);
        assert_eq!(fields.artifacts_len, 0);
        assert_eq!(fields.unpadded_code_len, 23);
        assert_eq!(fields.versioning >> 56, DELEGATED_STATUS_BYTE as u64);
        assert_eq!((fields.versioning >> 48) as u8, EVM_EE_BYTE);
        // blake2s over code + 1 byte of padding (23 -> 24), no artifacts
        let mut h = Blake2s256::new();
        h.update(&code);
        h.update([0u8]);
        assert_eq!(fields.bytecode_hash, B256::from_slice(&h.finalize()));
    }

    #[test]
    fn deployed_code_fields_roundtrip_with_preimage() {
        let code = [0x5b, 0x60, 0x01, 0x00, 0x5b]; // 5 bytes -> pad 3
        let fields = evm_code_fields(&code, ARTIFACTS_CACHING_CODE_VERSION);
        let blob = evm_bytecode_preimage(&code, ARTIFACTS_CACHING_CODE_VERSION);
        assert_eq!(blob.len(), 5 + 3 + 8);
        let mut h = Blake2s256::new();
        h.update(&blob);
        assert_eq!(fields.bytecode_hash, B256::from_slice(&h.finalize()));
        assert_eq!(fields.artifacts_len, 8);
        assert_eq!(fields.versioning, 0x0101_0100_0000_0000);
        assert_eq!(fields.observable_bytecode_hash, keccak256(code));
    }
}
