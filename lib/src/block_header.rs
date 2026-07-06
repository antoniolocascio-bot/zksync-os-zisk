//! Block header hash computation (RLP encoding + Keccak256).
//!
//! Computes the ZKsync OS block header hash using the same Ethereum block
//! header format as zksync-os's `basic_bootloader::block_header::BlockHeader`.
//! Several fields are fixed (post-merge constants, zero state/receipts roots).

use alloy_primitives::B256;

use crate::commitment::keccak256;
use crate::merkle::blake2s;

/// Keccak256(RLP([])) — the empty ommers hash (post-merge constant).
const EMPTY_OMMER_HASH: B256 = B256::new([
    0x1d, 0xcc, 0x4d, 0xe8, 0xde, 0xc7, 0x5d, 0x7a, 0xab, 0x85, 0xb5, 0x67,
    0xb6, 0xcc, 0xd4, 0x1a, 0xd3, 0x12, 0x45, 0x1b, 0x94, 0x8a, 0x74, 0x13,
    0xf0, 0xa1, 0x42, 0xfd, 0x40, 0xd4, 0x93, 0x47,
]);

/// Compute the ZKsync OS block header hash.
///
/// This is `keccak256(RLP([parent_hash, ommers_hash, beneficiary, state_root,
///   transactions_root, receipts_root, logs_bloom, difficulty, number,
///   gas_limit, gas_used, timestamp, extra_data, mix_hash, nonce, base_fee_per_gas]))`.
///
/// Fixed fields: `ommers_hash` = EMPTY_OMMER_HASH, `state_root` = 0, `receipts_root` = 0,
/// `logs_bloom` = 0, `difficulty` = 0, `extra_data` = empty, `nonce` = 0.
#[allow(clippy::too_many_arguments)]
pub fn compute_block_header_hash(
    parent_hash: &B256,
    beneficiary: &[u8; 20],
    transactions_root: &B256,
    receipts_root: &B256,
    number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    mix_hash: &B256,
    base_fee_per_gas: u64,
) -> B256 {
    let mut inner = Vec::with_capacity(650);

    rlp_encode_bytes(&mut inner, parent_hash.as_slice());
    rlp_encode_bytes(&mut inner, EMPTY_OMMER_HASH.as_slice());
    rlp_encode_bytes(&mut inner, beneficiary);
    rlp_encode_bytes(&mut inner, B256::ZERO.as_slice()); // state_root
    rlp_encode_bytes(&mut inner, transactions_root.as_slice());
    rlp_encode_bytes(&mut inner, receipts_root.as_slice()); // receipts_root
    rlp_encode_bytes(&mut inner, &[0u8; 256]); // logs_bloom
    rlp_encode_number(&mut inner, &[0u8; 32]); // difficulty
    rlp_encode_number(&mut inner, &number.to_be_bytes());
    rlp_encode_number(&mut inner, &gas_limit.to_be_bytes());
    rlp_encode_number(&mut inner, &gas_used.to_be_bytes());
    rlp_encode_number(&mut inner, &timestamp.to_be_bytes());
    rlp_encode_bytes(&mut inner, &[]); // extra_data
    rlp_encode_bytes(&mut inner, mix_hash.as_slice());
    rlp_encode_bytes(&mut inner, &[0u8; 8]); // nonce
    rlp_encode_number(&mut inner, &base_fee_per_gas.to_be_bytes());

    let mut buf = Vec::with_capacity(inner.len() + 5);
    rlp_encode_list_header(&mut buf, inner.len());
    buf.extend_from_slice(&inner);

    keccak256(&buf)
}

// ---------------------------------------------------------------------------
// Minimal RLP encoding (matching zksync-os's rlp module)
// ---------------------------------------------------------------------------

fn rlp_encode_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    if data.len() == 1 && data[0] < 0x80 {
        buf.push(data[0]);
    } else if data.len() < 56 {
        buf.push(0x80 + data.len() as u8);
        buf.extend_from_slice(data);
    } else {
        let len_bytes = be_bytes_trimmed(data.len());
        buf.push(0xb7 + len_bytes.len() as u8);
        buf.extend_from_slice(&len_bytes);
        buf.extend_from_slice(data);
    }
}

fn rlp_encode_number(buf: &mut Vec<u8>, be_bytes: &[u8]) {
    let stripped = strip_leading_zeros(be_bytes);
    if stripped.is_empty() {
        buf.push(0x80); // RLP encoding of zero = empty byte string
    } else {
        rlp_encode_bytes(buf, stripped);
    }
}

fn rlp_encode_list_header(buf: &mut Vec<u8>, content_len: usize) {
    if content_len < 56 {
        buf.push(0xc0 + content_len as u8);
    } else {
        let len_bytes = be_bytes_trimmed(content_len);
        buf.push(0xf7 + len_bytes.len() as u8);
        buf.extend_from_slice(&len_bytes);
    }
}

fn strip_leading_zeros(data: &[u8]) -> &[u8] {
    let first_nonzero = data.iter().position(|&b| b != 0).unwrap_or(data.len());
    &data[first_nonzero..]
}

/// Encode a usize as minimal big-endian bytes.
fn be_bytes_trimmed(val: usize) -> Vec<u8> {
    let bytes = val.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1);
    bytes[start..].to_vec()
}

// ---------------------------------------------------------------------------
// Per-block transactions_root / receipts_root (Blake2s Merkle, depth 32).
//
// Matches zksync-os draft-0.4.0 `zk_block_tx_tree_root_in_place` /
// `merkle_root_in_place::<Blake2s256>` (basic_bootloader .../zk/block_data.rs):
// leaves are folded pairwise with Blake2s(left || right), a ZERO empty leaf,
// and empty-subtree hashes `empty[i] = blake2s(empty[i-1] || empty[i-1])`.
// ---------------------------------------------------------------------------

const BLOCK_TX_TREE_DEPTH: usize = 32;

fn blake2s_node(l: &B256, r: &B256) -> B256 {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(l.as_slice());
    buf[32..].copy_from_slice(r.as_slice());
    blake2s(&buf)
}

/// Fold `leaves` into the per-block tx/receipt Merkle root.
pub fn block_tx_merkle_root(leaves: &[B256]) -> B256 {
    let mut empty = [B256::ZERO; BLOCK_TX_TREE_DEPTH + 1];
    for i in 1..=BLOCK_TX_TREE_DEPTH {
        empty[i] = blake2s_node(&empty[i - 1], &empty[i - 1]);
    }
    let mut count = leaves.len();
    if count == 0 {
        return empty[BLOCK_TX_TREE_DEPTH];
    }
    let mut nodes = leaves.to_vec();
    for level in 0..BLOCK_TX_TREE_DEPTH {
        let pairs = count.div_ceil(2);
        for i in 0..pairs {
            let l = nodes[i * 2];
            let r = if i * 2 + 1 < count { nodes[i * 2 + 1] } else { empty[level] };
            nodes[i] = blake2s_node(&l, &r);
        }
        count = pairs;
    }
    nodes[0]
}

/// A minimal EVM log for ZK receipt-hash encoding.
pub struct LogEntry {
    pub address: [u8; 20],
    pub topics: Vec<B256>,
    pub data: Vec<u8>,
}

/// ZK receipt-hash leaf, matching zksync-os draft-0.4.0 `compute_receipt_hash`:
/// `blake2s(type? || rlp([status, cumulative_gas_used, zero_bloom(256), [logs]]))`,
/// where the logs_bloom is always the 256-byte zero bloom (ZK convention).
pub fn receipt_hash(
    tx_type: u8,
    success: bool,
    cumulative_gas_used: u64,
    logs: &[LogEntry],
) -> B256 {
    let mut inner = Vec::new();
    // status: Eip658Value uint (0/1)
    rlp_encode_number(&mut inner, &(success as u64).to_be_bytes());
    rlp_encode_number(&mut inner, &cumulative_gas_used.to_be_bytes());
    rlp_encode_bytes(&mut inner, &[0u8; 256]); // logs_bloom = zero
    // logs list
    let mut logs_inner = Vec::new();
    for lg in logs {
        let mut le = Vec::new();
        rlp_encode_bytes(&mut le, &lg.address);
        let mut topics_inner = Vec::new();
        for t in &lg.topics {
            rlp_encode_bytes(&mut topics_inner, t.as_slice());
        }
        rlp_encode_list_header(&mut le, topics_inner.len());
        le.extend_from_slice(&topics_inner);
        rlp_encode_bytes(&mut le, &lg.data);
        rlp_encode_list_header(&mut logs_inner, le.len());
        logs_inner.extend_from_slice(&le);
    }
    rlp_encode_list_header(&mut inner, logs_inner.len());
    inner.extend_from_slice(&logs_inner);
    // outer receipt list
    let mut list = Vec::new();
    rlp_encode_list_header(&mut list, inner.len());
    list.extend_from_slice(&inner);
    // typed-tx prefix
    let mut payload = Vec::new();
    if tx_type != 0 {
        payload.push(tx_type);
    }
    payload.extend_from_slice(&list);
    blake2s(&payload)
}
